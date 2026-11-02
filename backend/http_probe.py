import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin


TIMEOUT = 8
MAX_BODY_BYTES = 1024 * 1024
HTTP_RESPONDED = "RESPONDED"
HTTP_NO_RESPONSE = "NO_RESPONSE"
HTTP_FAILED = "FAILED"
HTTP_UNKNOWN = "UNKNOWN"


def _empty_result(status):
    return {
        "http_observation_status": status,
        "http_status": 0,
        "http_reason": "",
        "final_url": "",
        "final_status": 0,
        "redirect_count": 0,
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

    if expected_ip is not None:
        try:
            expected = str(ipaddress.ip_address(expected_ip))
        except ValueError:
            return []
        if expected not in addresses:
            return []
        addresses = [expected]

    return [address for address in addresses if not _prohibited_address(address)]


def _connect_pinned(domain, scheme, address):
    port = 443 if scheme == "https" else 80
    raw = socket.create_connection((address, port), timeout=TIMEOUT)
    try:
        if raw.getpeername()[0] != address:
            raise OSError("connected destination changed during validation")
        if scheme == "https":
            return ssl.create_default_context().wrap_socket(
                raw, server_hostname=domain
            )
        return raw
    except Exception:
        raw.close()
        raise


def open_validated_tls_socket(domain, *, expected_ip=None):
    """Open one validated TLS connection for SAN/certificate observation."""
    addresses = _resolve_allowed_addresses(domain, 443, expected_ip)
    if not addresses:
        raise OSError("no permitted TLS destination address")
    last_error = None
    for address in addresses:
        try:
            return _connect_pinned(domain, "https", address)
        except Exception as exc:
            last_error = exc
    raise last_error or OSError("TLS observation failed")


def _title(text):
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def _observe_once(domain, scheme, expected_ip=None):
    port = 443 if scheme == "https" else 80
    addresses = _resolve_allowed_addresses(domain, port, expected_ip)
    if not addresses:
        raise OSError("no permitted destination address")

    last_error = None
    for address in addresses:
        connection = None
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
            return {
                "http_observation_status": HTTP_RESPONDED,
                "http_status": response.status,
                "http_reason": response.reason or "",
                # Location is metadata only; it is never requested.
                "final_url": urljoin(requested_url, location) if location else requested_url,
                "final_status": response.status,
                "redirect_count": 1 if location else 0,
                "title": _title(body),
            }
        except Exception as exc:
            last_error = exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
    raise last_error or OSError("observation failed")


def http_probe(domain, *, before_request=None, expected_ip=None):
    """Perform bounded observation only after a fresh policy recheck."""
    if before_request is None:
        return _empty_result(HTTP_UNKNOWN)

    attempted = False
    for scheme in ("https", "http"):
        try:
            if not before_request():
                return _empty_result(HTTP_UNKNOWN)
            attempted = True
            return _observe_once(domain, scheme, expected_ip=expected_ip)
        except Exception:
            continue
    return _empty_result(HTTP_NO_RESPONSE if attempted else HTTP_UNKNOWN)
