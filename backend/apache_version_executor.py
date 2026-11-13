"""Single-request Apache version verification behind CAPD approval consumption.

The executor is intentionally not wired to a CLI or HTTP route. Callers must
provide the resolver and transport explicitly; the production CLI remains
dry-run-only until a separately reviewed release enables an operator path.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from apache_version_verification import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_TIMEOUT_SECONDS,
    ApacheVerificationError,
    classify_apache_http_response,
    validate_public_destination,
)
from capd_approval_consumption import ApprovalConsumptionError, consume_approval
from capd_approval_contract import validate_apache_origin
from capd_local_approval import approval_matches_target, verify_approval


MAX_HTTP_HEADER_BYTES = 65536
MAX_HTTP_HEADER_COUNT = 100
_SENSITIVE_HEADER_VALUE = re.compile(
    r"(?i)(authorization|bearer|api[_-]?key|token|secret|password|cookie)"
    r"\s*[:=]\s*[^; ,]+"
)


class ApacheHTTPTransportError(RuntimeError):
    """Sanitized transport failure with a precise HTTP-send boundary."""

    def __init__(self, error_code, *, request_was_sent):
        super().__init__(error_code)
        self.error_code = error_code
        self.request_was_sent = bool(request_was_sent)


class _HeaderOnlyResponse:
    def __init__(self, status_code, headers):
        self.status_code = status_code
        self.headers = headers


class BoundedApacheHTTPTransport:
    """Direct HTTP(S) transport pinned to one previously validated IP.

    It makes one GET for `/`, sends only Host and Connection headers, does not
    use proxies, cookies, authentication, redirects, retries, or read a body.
    TLS uses the original hostname for SNI and certificate verification.
    """

    def request(self, origin, pinned_ip, *, method, timeout):
        if method != "GET":
            raise ApacheVerificationError("Only the signed GET method is allowed")
        try:
            parsed = urlsplit(origin)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            address = ipaddress.ip_address(pinned_ip)
        except (TypeError, ValueError) as exc:
            raise ApacheVerificationError("Approved destination is invalid") from exc
        if (not host or not address.is_global
                or validate_apache_origin(origin, host) != origin):
            raise ApacheVerificationError("Approved destination is not public")

        raw_socket = None
        connection = None
        request_was_sent = False
        try:
            raw_socket = socket.create_connection((str(address), port), timeout=timeout)
            raw_socket.settimeout(timeout)
            if parsed.scheme == "https":
                tls_context = ssl.create_default_context()
                # The IP is pinned for routing; the hostname remains the TLS
                # identity so normal CA and hostname checks remain enabled.
                connection_socket = tls_context.wrap_socket(
                    raw_socket, server_hostname=host,
                )
            else:
                connection_socket = raw_socket
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
            connection.sock = connection_socket
            connection.putrequest("GET", "/", skip_accept_encoding=True)
            connection.putheader("Connection", "close")
            connection.endheaders()
            request_was_sent = True
            response = connection.getresponse()
            # http.client bounds status/header line sizes and header count
            # at these standard limits. Only the Server header is retained;
            # the body is never read and the connection is closed below.
            if (len(response.headers) > MAX_HTTP_HEADER_COUNT
                    or sum(len(k) + len(v) for k, v in response.headers.items())
                    > MAX_HTTP_HEADER_BYTES):
                raise ApacheHTTPTransportError(
                    "response_headers_exceeded", request_was_sent=request_was_sent,
                )
            headers = {"Server": response.getheader("Server")} if response.getheader("Server") is not None else {}
            return _HeaderOnlyResponse(response.status, headers)
        except ApacheHTTPTransportError:
            raise
        except Exception as exc:
            if isinstance(exc, ssl.SSLError):
                error_code = "tls_validation_failed"
            elif isinstance(exc, (TimeoutError, socket.timeout)):
                error_code = "timeout"
            else:
                error_code = "request_failed"
            raise ApacheHTTPTransportError(
                error_code, request_was_sent=request_was_sent,
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            elif raw_socket is not None:
                try:
                    raw_socket.close()
                except Exception:
                    pass


def _resolved_public_addresses(resolver, origin):
    """Resolve once, reject mixed/private answers, and return one stable IP."""
    parsed_origin = urlsplit(origin)
    host = parsed_origin.hostname
    port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
    records = resolver(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for record in records:
        value = record if isinstance(record, str) else record[4][0]
        try:
            parsed = ipaddress.ip_address(str(value))
        except ValueError as exc:
            raise ApacheVerificationError("Destination resolution returned an invalid address") from exc
        addresses.append(str(parsed))
    # Validate every answer, not just the chosen one, to fail closed on mixed
    # public/private DNS responses. Then pin exactly one address for the request.
    if not addresses:
        raise ApacheVerificationError("Destination resolution returned no addresses")
    validate_public_destination(origin, host, addresses)
    normalized = sorted(set(addresses), key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
    return normalized[0]


def _result_base(payload, receipt, *, now):
    payload = payload if isinstance(payload, dict) else {}
    asset = payload.get("asset") if isinstance(payload.get("asset"), dict) else {}
    return {
        "asset_id": asset.get("asset_id"),
        "approved_origin": asset.get("origin"),
        "check_id": payload.get("check_id"),
        "check_revision": payload.get("check_revision"),
        "source_scan_id": payload.get("source_scan_id"),
        "observed_at": now.isoformat(),
        "authorization_receipt_reference": (
            receipt.get("approval_sha256") if isinstance(receipt, dict) else None
        ),
        "authorization_consumed_at": (
            receipt.get("consumed_at").isoformat()
            if isinstance(receipt, dict) and hasattr(receipt.get("consumed_at"), "isoformat")
            else None
        ),
        "http_request_count": 0,
        "product": None,
        "version": None,
        "server_header_evidence": None,
        "source_http_server_header": None,
        "confidence": None,
        "limitations": [
            "Version identification is evidence collection only; it does not establish vulnerability.",
        ],
    }


def _server_header(response):
    headers = getattr(response, "headers", None)
    if hasattr(headers, "items"):
        return next((value for key, value in headers.items() if str(key).lower() == "server"), None)
    return None


def execute_approved_apache_check(
    conn, document, public_key, context, target, *, resolver, transport,
    now=None, timeout=DEFAULT_TIMEOUT_SECONDS,
):
    """Consume one signed approval, then attempt at most one bounded GET.

    Resolver and transport are required dependencies so no CLI/API can
    accidentally acquire a live network path by calling this function with
    implicit defaults. The dry-run path does not call this function.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    try:
        bounded_timeout = float(timeout)
        if not 0 < bounded_timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout outside allowed range")
        if (not callable(resolver)
                or not isinstance(transport, BoundedApacheHTTPTransport)):
            raise ValueError("approved resolver and bounded transport are required")
        payload = verify_approval(document, public_key, now=now)
        if not approval_matches_target(payload, context, target):
            raise ValueError("approval binding mismatch")
        origin = validate_apache_origin(
            payload["asset"]["origin"], payload["asset"]["domain"],
        )
        if origin != payload["asset"]["origin"] or payload["method"] != "GET" or payload["max_requests"] != 1:
            raise ValueError("approval request scope is invalid")
    except Exception:
        result = _result_base({}, None, now=now)
        result.update({
            "outcome": "NOT_AUTHORIZED", "error_code": "approval_or_execution_scope_invalid",
            "http_request_count": 0,
        })
        return result

    try:
        receipt = consume_approval(
            conn, document, public_key, context, target, now=now,
        )
    except ApprovalConsumptionError as exc:
        error = str(exc)
        outcome = "ERROR" if "could not be persisted" in error else "NOT_AUTHORIZED"
        result = _result_base(payload, None, now=now)
        result.update({
            "outcome": outcome,
            "error_code": "approval_receipt_persistence_failed" if outcome == "ERROR" else "authorization_denied",
            "http_request_count": 0,
        })
        return result

    result = _result_base(payload, receipt, now=now)
    try:
        pinned_ip = _resolved_public_addresses(resolver, origin)
        # The signed origin is revalidated against fresh stored evidence by
        # consume_approval. The direct transport is pinned to this one IP.
        response = transport.request(
            origin, pinned_ip, method=payload["method"], timeout=bounded_timeout,
        )
        result["http_request_count"] = 1
        classified = classify_apache_http_response(
            target, response, request_url=origin, resolved_addresses=[pinned_ip],
        )
        result.update({
            "outcome": classified.get("outcome", "ERROR"),
            "product": classified.get("product"),
            "version": classified.get("version"),
            "server_header_evidence": classified.get("evidence"),
            "source_http_server_header": _SENSITIVE_HEADER_VALUE.sub(
                r"\1=[REDACTED]", str(_server_header(response) or "")[:200],
            ) or None,
            "confidence": classified.get("confidence"),
        })
        if classified.get("error_code"):
            result["error_code"] = classified["error_code"]
        if classified.get("http_status") is not None:
            result["http_status"] = classified["http_status"]
        result["redirect_followed"] = False
        return result
    except ApacheHTTPTransportError as exc:
        result.update({
            "outcome": "ERROR", "error_code": exc.error_code,
            "http_request_count": int(exc.request_was_sent),
        })
        return result
    except ssl.SSLError:
        result.update({"outcome": "ERROR", "error_code": "tls_validation_failed"})
        return result
    except (TimeoutError, socket.timeout) as exc:
        result.update({"outcome": "ERROR", "error_code": "timeout"})
        result["http_request_count"] = max(
            result["http_request_count"], int(getattr(exc, "request_was_sent", False)),
        )
        return result
    except Exception as exc:
        result.update({
            "outcome": "ERROR",
            "error_code": "destination_rejected" if isinstance(exc, ApacheVerificationError) else "request_failed",
        })
        result["http_request_count"] = max(
            result["http_request_count"], int(getattr(exc, "request_was_sent", False)),
        )
        return result
