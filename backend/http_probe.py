import http.client
import ipaddress
import os
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit


TIMEOUT = 8
MAX_BODY_BYTES = 1024 * 1024
HTTP_RESPONDED = "RESPONDED"
HTTP_NO_RESPONSE = "NO_RESPONSE"
HTTP_FAILED = "FAILED"
HTTP_UNKNOWN = "UNKNOWN"
DEFAULT_MAX_REDIRECT_HOPS = 5
MAX_REDIRECT_HOPS_LIMIT = 10


class AuthorizationDeniedError(RuntimeError):
    """A fresh policy check denied a direct target operation."""


def _empty_result(status, *, requested_url=None, stop_reason="observation_unavailable"):
    return {
        "http_observation_status": status,
        "http_status": 0,
        "http_reason": "",
        "final_url": None,
        "final_status": None,
        "redirect_count": 0,
        "redirect_evidence": {
            "requested_url": requested_url,
            "http_status": None,
            "first_hop_location": None,
            "first_hop_destination": None,
            "last_observed_destination": None,
            "observed_hops": [],
            "verified_terminal_url": None,
            "completion_status": "UNKNOWN",
            "stop_reason": stop_reason,
        },
        "title": ""
    }


def _prohibited_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return not address.is_global or any((
        address.is_private,
        address.is_loopback,
        address.is_link_local,
        address.is_multicast,
        address.is_reserved,
        address.is_unspecified,
    ))


def _resolve_allowed_addresses(domain, port, expected_ip=None):
    try:
        literal = ipaddress.ip_address(domain.rstrip("."))
        addresses = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            return []
        addresses = []
        for _family, _kind, _proto, _canonname, sockaddr in infos:
            address = sockaddr[0]
            if address not in addresses:
                addresses.append(address)

    # Reject the entire DNS answer if any destination is unsafe.  Filtering
    # only the unsafe records could hide an unstable or mixed answer set.
    if any(_prohibited_address(address) for address in addresses):
        return []

    if expected_ip is not None:
        try:
            expected = str(ipaddress.ip_address(expected_ip))
        except ValueError:
            return []
        if expected not in addresses:
            return []
        addresses = [expected]

    return addresses


def _connect_pinned(domain, scheme, address):
    port = 443 if scheme == "https" else 80
    raw = socket.create_connection((address, port), timeout=TIMEOUT)
    try:
        peer_ip = ipaddress.ip_address(raw.getpeername()[0])
        if peer_ip != ipaddress.ip_address(address):
            raise OSError("connected destination changed during validation")
        if scheme == "https":
            return ssl.create_default_context().wrap_socket(
                raw, server_hostname=domain
            )
        return raw
    except Exception:
        raw.close()
        raise


def open_validated_tls_socket(domain, *, expected_ip=None, before_request=None):
    """Open one validated TLS connection for SAN/certificate observation."""
    if before_request is None:
        raise AuthorizationDeniedError("authorization check is required")
    addresses = _resolve_allowed_addresses(domain, 443, expected_ip)
    if not addresses:
        raise OSError("no permitted TLS destination address")
    last_error = None
    for address in addresses:
        if not before_request():
            raise AuthorizationDeniedError("authorization is no longer valid")
        try:
            return _connect_pinned(domain, "https", address)
        except AuthorizationDeniedError:
            raise
        except Exception as exc:
            last_error = exc
    raise last_error or OSError("TLS observation failed")


def _title(text):
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def _max_redirect_hops():
    try:
        configured = int(os.environ.get("ASIP_MAX_REDIRECT_HOPS", DEFAULT_MAX_REDIRECT_HOPS))
    except (TypeError, ValueError):
        return DEFAULT_MAX_REDIRECT_HOPS
    return min(max(configured, 0), MAX_REDIRECT_HOPS_LIMIT)


def _normalize_http_url(value, base_url=None):
    value = str(value or "").strip()
    if (
        not value
        or any(ord(char) < 0x20 or char.isspace() for char in value)
        or "\\" in value
        or re.search(r"%(?![0-9a-fA-F]{2})", value)
    ):
        raise ValueError("invalid URL characters")
    candidate = urljoin(base_url, value) if base_url else value
    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("unsupported URL scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo URLs are not permitted")
    if not parsed.hostname:
        raise ValueError("URL hostname is required")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise ValueError("nonstandard URL port is not permitted")

    host = parsed.hostname.rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode("idna").decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    path = parsed.path or "/"
    return urlunsplit((scheme, host, path, parsed.query, ""))


def _redirect_evidence(requested_url, status, location):
    """Describe an observed redirect response without following it."""
    is_redirect = 300 <= int(status or 0) < 400
    evidence = {
        "requested_url": requested_url,
        "http_status": int(status or 0),
        "first_hop_location": location if is_redirect else None,
        "first_hop_destination": None,
        "last_observed_destination": None,
        "observed_hops": [],
        "verified_terminal_url": requested_url if not is_redirect else None,
        "completion_status": "COMPLETE" if not is_redirect else "UNRESOLVED",
        "stop_reason": None,
    }
    if not is_redirect:
        return evidence

    if not location or not str(location).strip():
        evidence["stop_reason"] = "missing_location"
        return evidence

    try:
        destination = _normalize_http_url(location, requested_url)
    except (TypeError, ValueError):
        evidence["stop_reason"] = "invalid_location"
        return evidence

    evidence["first_hop_destination"] = destination
    evidence["last_observed_destination"] = destination
    evidence["observed_hops"] = [{
        "source_url": requested_url,
        "http_status": int(status),
        "location": str(location),
        "destination_url": destination,
        "followed": False,
    }]
    evidence["stop_reason"] = "redirect_traversal_disabled"
    return evidence


def _request_url(url, *, expected_ip=None, before_request=None, on_request=None):
    if before_request is None:
        raise AuthorizationDeniedError("authorization check is required")
    normalized_url = _normalize_http_url(url)
    parsed = urlsplit(normalized_url)
    domain = parsed.hostname
    scheme = parsed.scheme
    port = 443 if scheme == "https" else 80
    target_domain = domain
    # Do not even resolve a redirect destination until its exact hostname has
    # passed a fresh current-scan authorization check.
    def recheck():
        try:
            return bool(before_request(target_domain))
        except Exception as exc:
            raise AuthorizationDeniedError("authorization check failed") from exc

    if not recheck():
        raise AuthorizationDeniedError("authorization is no longer valid")
    addresses = _resolve_allowed_addresses(domain, port, expected_ip)
    if not addresses:
        raise OSError("no permitted destination address")

    last_error = None
    for address in addresses:
        if not recheck():
            raise AuthorizationDeniedError("authorization is no longer valid")
        connection = None
        sock = None
        request_started = False
        try:
            sock = _connect_pinned(domain, scheme, address)
            connection = http.client.HTTPConnection(domain, port=port, timeout=TIMEOUT)
            connection.sock = sock
            authority = f"[{domain}]" if ":" in domain else domain
            if not recheck():
                raise AuthorizationDeniedError("authorization is no longer valid")
            if on_request is not None:
                on_request()
            request_started = True
            connection.request(
                "GET", urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                headers={
                    "Host": authority,
                    "User-Agent": "ShadowRecon-observer/1.0",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            try:
                body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
                read_error = None
            except (OSError, TimeoutError, http.client.HTTPException) as exc:
                body = ""
                read_error = exc
            location = response.getheader("Location")
            redirect_evidence = _redirect_evidence(
                normalized_url, response.status, location
            )
            return {
                "http_observation_status": HTTP_RESPONDED,
                "http_status": response.status,
                "http_reason": response.reason or "",
                "final_url": normalized_url if not 300 <= response.status < 400 and read_error is None else None,
                "final_status": response.status if not 300 <= response.status < 400 and read_error is None else None,
                "redirect_count": len(redirect_evidence["observed_hops"]),
                "redirect_evidence": redirect_evidence,
                "title": _title(body),
                "read_error": read_error,
            }
        except AuthorizationDeniedError:
            raise
        except Exception as exc:
            if request_started:
                # Do not duplicate an HTTP request after an ambiguous timeout
                # or response failure. The current hop ends unresolved.
                raise
            last_error = exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            elif sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise last_error or OSError("observation failed")


def _observe_once(domain, scheme, expected_ip=None, before_request=None):
    """Observe one URL without redirects; retained for existing callers/tests."""
    url = _normalize_http_url(f"{scheme}://{domain}/")
    return _request_url(
        url,
        expected_ip=expected_ip,
        before_request=before_request,
    )


def _observe_chain(start_url, *, expected_ip=None, before_request=None):
    evidence = {
        "requested_url": start_url,
        "http_status": None,
        "first_hop_location": None,
        "first_hop_destination": None,
        "last_observed_destination": None,
        "observed_hops": [],
        "verified_terminal_url": None,
        "completion_status": "UNRESOLVED",
        "stop_reason": None,
    }
    first_status = None
    first_reason = ""
    title = ""
    current_url = start_url
    seen = {_normalize_http_url(start_url)}
    followed_hops = 0
    max_hops = _max_redirect_hops()
    pending_hop = None

    while True:
        is_initial = current_url == start_url

        def mark_followed():
            if pending_hop is not None:
                pending_hop["followed"] = True

        try:
            response = _request_url(
                current_url,
                expected_ip=expected_ip if is_initial else None,
                before_request=before_request,
                on_request=None if is_initial else mark_followed,
            )
        except AuthorizationDeniedError:
            evidence["stop_reason"] = "authorization_denied"
            break
        except (OSError, TimeoutError, http.client.HTTPException, ValueError):
            evidence["stop_reason"] = "network_or_url_error"
            break

        status = int(response["http_status"])
        if pending_hop is not None:
            pending_hop = None
        if first_status is None:
            first_status = status
            first_reason = response["http_reason"]
            title = response["title"]
            evidence["http_status"] = status
        if not 300 <= status < 400:
            if response.get("read_error") is not None:
                evidence["stop_reason"] = "response_read_timeout"
                break
            evidence["verified_terminal_url"] = current_url
            evidence["completion_status"] = "COMPLETE"
            evidence["stop_reason"] = None
            return {
                "http_observation_status": HTTP_RESPONDED,
                "http_status": first_status,
                "http_reason": first_reason,
                "final_url": current_url,
                "final_status": status,
                "redirect_count": len(evidence["observed_hops"]),
                "redirect_evidence": evidence,
                "title": response["title"] or title,
            }

        hop_evidence = response["redirect_evidence"]
        location = hop_evidence.get("first_hop_location")
        destination = hop_evidence.get("first_hop_destination")
        if evidence["first_hop_location"] is None:
            evidence["first_hop_location"] = location
            evidence["first_hop_destination"] = destination
        if not destination:
            evidence["stop_reason"] = hop_evidence.get("stop_reason") or "invalid_location"
            break

        evidence["last_observed_destination"] = destination
        hop = {
            "source_url": current_url,
            "http_status": status,
            "location": location,
            "destination_url": destination,
            "followed": False,
        }
        evidence["observed_hops"].append(hop)
        canonical_destination = _normalize_http_url(destination)
        if canonical_destination in seen:
            evidence["stop_reason"] = "redirect_loop"
            break
        if followed_hops >= max_hops:
            evidence["stop_reason"] = "maximum_redirect_hops"
            break

        # Authorization occurs before destination DNS resolution inside
        # _request_url, and again immediately before each pinned connection.
        pending_hop = hop
        seen.add(canonical_destination)
        followed_hops += 1
        current_url = canonical_destination

    return {
        "http_observation_status": (
            HTTP_RESPONDED if first_status is not None
            else HTTP_UNKNOWN if evidence["stop_reason"] == "authorization_denied"
            else HTTP_NO_RESPONSE
        ),
        "http_status": first_status or 0,
        "http_reason": first_reason,
        "final_url": None,
        "final_status": None,
        "redirect_count": len(evidence["observed_hops"]),
        "redirect_evidence": evidence,
        "title": title,
    }


def http_probe(domain, *, before_request=None, expected_ip=None):
    """Perform a bounded authorized request chain using individually pinned hops."""
    if before_request is None:
        return _empty_result(HTTP_UNKNOWN, stop_reason="authorization_required")

    attempted = False
    last_requested_url = None
    for scheme in ("https", "http"):
        # Keep policy failures outside the transport exception handler.  A
        # transient database error must stop this target rather than allowing
        # a later fallback authorization query to initiate network traffic.
        if not before_request():
            return _empty_result(
                HTTP_UNKNOWN,
                requested_url=last_requested_url,
                stop_reason="authorization_denied",
            )
        attempted = True
        try:
            last_requested_url = _normalize_http_url(f"{scheme}://{domain}/")
        except ValueError:
            return _empty_result(
                HTTP_UNKNOWN,
                requested_url=None,
                stop_reason="invalid_requested_url",
            )
        try:
            result = _observe_chain(
                last_requested_url,
                expected_ip=expected_ip,
                before_request=before_request,
            )
            if (
                scheme == "https"
                and result["http_observation_status"] == HTTP_NO_RESPONSE
                and result["redirect_evidence"].get("stop_reason") == "network_or_url_error"
            ):
                continue
            return result
        except AuthorizationDeniedError:
            return _empty_result(
                HTTP_UNKNOWN,
                requested_url=last_requested_url,
                stop_reason="authorization_denied",
            )
        except Exception:
            continue
    return _empty_result(
        HTTP_NO_RESPONSE if attempted else HTTP_UNKNOWN,
        requested_url=last_requested_url,
        stop_reason="no_response" if attempted else "authorization_unavailable",
    )
