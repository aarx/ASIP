"""Shared immutable scope constants and origin validation for CAPD approval."""

from urllib.parse import urlsplit, urlunsplit


CAPD_HTTP_HEADER_VERIFY = "CAPD_HTTP_HEADER_VERIFY"
APACHE_CHECK_ID = "APACHE_HTTP_VERSION"
APACHE_CHECK_REVISION = "1.0.0"


def canonical_host(value):
    return str(value or "").strip().lower().rstrip(".")


def validate_apache_origin(url, approved_domain):
    try:
        parsed = urlsplit(str(url))
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid observed HTTP origin") from exc
    host = canonical_host(parsed.hostname)
    if (parsed.scheme.lower() not in {"http", "https"}
            or not host
            or host != canonical_host(approved_domain)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("Request origin is outside the selected asset boundary")
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))
