"""Offline parser for Apache HTTP Server version evidence.

This module only interprets a supplied Server header. It performs no I/O.
"""

from __future__ import annotations

import re


VERSION_RE = re.compile(r"\bapache/(\d+\.\d+(?:\.\d+)?)(?=$|[\s(;)])", re.IGNORECASE)
PRODUCT_RE = re.compile(r"\bapache\b", re.IGNORECASE)
NON_HTTPD_RE = re.compile(r"\bapache-coyote\b", re.IGNORECASE)
SECRET_RE = re.compile(
    r"(?i)(authorization|bearer|api[_-]?key|token|secret|password|cookie)"
    r"\s*[:=]\s*[^; ,]+"
)


def parse_apache_server_header(value):
    """Classify one Server header without treating connectors as httpd."""
    if not isinstance(value, str):
        return {"outcome": "INSUFFICIENT_EVIDENCE", "product": None, "version": None,
                "confidence": None, "evidence": None}
    header = re.sub(r"\s+", " ", value).strip()[:200]
    header = SECRET_RE.sub(r"\1=[REDACTED]", header)
    if not header:
        return {"outcome": "INSUFFICIENT_EVIDENCE", "product": None, "version": None,
                "confidence": None, "evidence": None}
    if NON_HTTPD_RE.search(header) or not PRODUCT_RE.search(header):
        return {"outcome": "PRODUCT_NOT_CONFIRMED", "product": None, "version": None,
                "confidence": None, "evidence": header}
    match = VERSION_RE.search(header)
    if match:
        return {"outcome": "VERSION_IDENTIFIED", "product": "apache", "version": match.group(1),
                "confidence": "high", "evidence": f"apache/{match.group(1)}"}
    return {"outcome": "PRODUCT_IDENTIFIED_VERSION_UNKNOWN", "product": "apache", "version": None,
            "confidence": "medium", "evidence": "marker=apache"}
