import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit


TIMEOUT = 8
MAX_BODY_BYTES = 1024 * 1024
HTTP_RESPONDED = "RESPONDED"
HTTP_NO_RESPONSE = "NO_RESPONSE"
HTTP_FAILED = "FAILED"
HTTP_UNKNOWN = "UNKNOWN"


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


def _redirect_evidence(requested_url, status, location):
    """Describe only the response observed; never request its Location."""
    is_redirect = 300 <= int(status or 0) < 400
    evidence = {
        "requested_url": requested_url,
        "http_status": int(status or 0),
        "first_hop_location": location if is_redirect else None,
        "first_hop_destination": None,
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
        destination = urljoin(requested_url, str(location).strip())
        parsed = urlsplit(destination)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Location must resolve to an HTTP(S) URL")
        # Accessing port validates malformed port syntax without making a request.
        _ = parsed.port
    except (TypeError, ValueError):
        evidence["stop_reason"] = "invalid_location"
        return evidence

    evidence["first_hop_destination"] = destination
    evidence["observed_hops"] = [{
        "source_url": requested_url,
        "http_status": int(status),
        "location": str(location),
        "destination_url": destination,
        "followed": False,
    }]
    evidence["stop_reason"] = "redirect_traversal_disabled"
    return evidence


def _observe_once(domain, scheme, expected_ip=None, before_request=None):
    if before_request is None:
        raise AuthorizationDeniedError("authorization check is required")
    port = 443 if scheme == "https" else 80
    addresses = _resolve_allowed_addresses(domain, port, expected_ip)
    if not addresses:
        raise OSError("no permitted destination address")

    last_error = None
    for address in addresses:
        if not before_request():
            raise AuthorizationDeniedError("authorization is no longer valid")
        connection = None
        sock = None
        try:
            sock = _connect_pinned(domain, scheme, address)
            connection = http.client.HTTPConnection(domain, timeout=TIMEOUT)
            connection.sock = sock
            connection.request(
                "GET", "/",
                headers={
                    "Host": domain,
                    "User-Agent": "ShadowRecon-observer/1.0",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
            location = response.getheader("Location")
            requested_url = f"{scheme}://{domain}/"
            redirect_evidence = _redirect_evidence(
                requested_url, response.status, location
            )
            terminal_url = redirect_evidence["verified_terminal_url"]
            terminal_status = response.status if terminal_url else None
            return {
                "http_observation_status": HTTP_RESPONDED,
                "http_status": response.status,
                "http_reason": response.reason or "",
                # Redirect destinations are evidence only; traversal stays disabled.
                "final_url": terminal_url,
                "final_status": terminal_status,
                "redirect_count": len(redirect_evidence["observed_hops"]),
                "redirect_evidence": redirect_evidence,
                "title": _title(body),
            }
        except AuthorizationDeniedError:
            raise
        except Exception as exc:
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


def http_probe(domain, *, before_request=None, expected_ip=None):
    """Perform bounded observation only after a fresh policy recheck."""
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
        last_requested_url = f"{scheme}://{domain}/"
        try:
            return _observe_once(
                domain,
                scheme,
                expected_ip=expected_ip,
                before_request=before_request,
            )
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
