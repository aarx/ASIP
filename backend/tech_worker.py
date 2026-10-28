from dataclasses import dataclass
import logging
import os
import re
import sys

import requests

from authorization_policy import explicit_t2_authorization_sql
from db import get_conn, require_running_scan

scan_id = int(sys.argv[1])

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
DETECTOR_VERSION = "sr-tech-02"
TECH_AUTHORIZATION_PREDICATE = explicit_t2_authorization_sql("d")

TECH_HEADERS = {
    "nginx": "nginx",
    "apache": "apache",
    "iis": "microsoft-iis",
    "php": "php",
    "asp": "asp",
    "cloudflare": "cloudflare"
}


@dataclass(frozen=True)
class Fingerprint:
    """Internal, non-persistent technology observation."""

    technology: str
    version: str | None
    confidence: str
    evidence_type: str
    evidence: str

    def __post_init__(self):
        object.__setattr__(self, "evidence", _sanitize_evidence(self.evidence))

    def as_dict(self):
        return {
            "technology": self.technology,
            "version": self.version,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class DetectionResult:
    fingerprints: tuple
    observed_url: str


VERSION_PATTERN = r"(\d+\.\d+(?:\.\d+)?)"


def _sanitize_evidence(value):
    """Keep only short, redacted evidence suitable for internal diagnostics."""
    value = re.sub(r"\s+", " ", str(value or "")).strip()[:200]
    value = re.sub(
        r"(?i)(authorization|bearer|api[_-]?key|token|secret|password|cookie)"
        r"\s*[:=]\s*[^; ,]+",
        r"\1=[REDACTED]",
        value,
    )
    return value or "[empty]"


def _observation(technology, version, confidence, evidence_type, evidence):
    return Fingerprint(
        technology=technology,
        version=version,
        confidence=confidence,
        evidence_type=evidence_type,
        evidence=_sanitize_evidence(evidence),
    )


def _versioned_header(value, technology, pattern, evidence_type):
    value = str(value or "")
    match = re.search(pattern, value, re.IGNORECASE)
    if match:
        return _observation(
            technology,
            match.group(1),
            "high",
            evidence_type,
            f"{technology}/{match.group(1)}",
        )
    return None


def parse_php_header(value, evidence_type="header"):
    value = str(value or "")
    if not re.search(r"\bphp\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "php",
            rf"\bphp/{VERSION_PATTERN}(?=$|[\s;,)])",
            evidence_type,
        )
        or _observation("php", None, "medium", evidence_type, "marker=php")
    )


def parse_apache_header(value, evidence_type="server_header"):
    value = str(value or "")
    if re.search(r"\bapache-coyote\b", value, re.IGNORECASE):
        return None
    if not re.search(r"\bapache\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "apache",
            rf"\bapache/{VERSION_PATTERN}(?=$|[\s(;)])",
            evidence_type,
        )
        or _observation("apache", None, "medium", evidence_type, "marker=apache")
    )


def parse_nginx_header(value, evidence_type="server_header"):
    value = str(value or "")
    if not re.search(r"\bnginx\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "nginx",
            rf"\bnginx/{VERSION_PATTERN}(?=$|[\s(;)])",
            evidence_type,
        )
        or _observation("nginx", None, "medium", evidence_type, "marker=nginx")
    )


def parse_iis_header(value, evidence_type="server_header"):
    value = str(value or "")
    if not re.search(r"\bmicrosoft-iis\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "microsoft-iis",
            rf"\bmicrosoft-iis/{VERSION_PATTERN}(?=$|[\s(;)])",
            evidence_type,
        )
        or _observation(
            "microsoft-iis", None, "medium", evidence_type, "marker=microsoft-iis"
        )
    )


def parse_tomcat_header(value, evidence_type="server_header"):
    value = str(value or "")
    if re.search(r"\bapache-coyote\b", value, re.IGNORECASE):
        return _observation(
            "tomcat", None, "low", evidence_type, "marker=apache-coyote"
        )
    if not re.search(r"\b(?:apache\s+)?tomcat\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "tomcat",
            rf"\btomcat/{VERSION_PATTERN}(?=$|[\s(;)])",
            evidence_type,
        )
        or _observation("tomcat", None, "medium", evidence_type, "marker=tomcat")
    )


def parse_aspnet_header(value, evidence_type="x-powered-by_header"):
    value = str(value or "")
    if not re.search(r"\basp\.net\b", value, re.IGNORECASE):
        return None
    return (
        _versioned_header(
            value,
            "asp.net",
            rf"\basp\.net/{VERSION_PATTERN}(?=$|[\s(;)])",
            evidence_type,
        )
        or _observation("asp.net", None, "medium", evidence_type, "marker=asp.net")
    )


def parse_asp_header(value, evidence_type="x-powered-by_header"):
    value = str(value or "")
    if re.search(r"\basp\.net\b", value, re.IGNORECASE):
        return None
    if not re.search(r"\basp(?:/|\b)", value, re.IGNORECASE):
        return None
    return _observation("asp", None, "medium", evidence_type, "marker=asp")


def _add_unique(observations, observation):
    if observation is None:
        return
    key = (
        observation.technology,
        observation.version,
        observation.evidence_type,
        observation.evidence,
    )
    if not any(
        (
            item.technology,
            item.version,
            item.evidence_type,
            item.evidence,
        ) == key
        for item in observations
    ):
        observations.append(observation)


def _header_value(headers, name):
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value
    return ""


def fingerprint_response(headers=None, body="", cookies=""):
    """Return deterministic, sanitized fingerprints without performing I/O."""
    headers = headers or {}
    server = _header_value(headers, "Server")
    powered = _header_value(headers, "X-Powered-By")
    aspnet_version = _header_value(headers, "X-AspNet-Version")
    header_text = str(headers).lower()
    body_text = str(body or "").lower()
    cookie_text = str(cookies or "").lower()
    observations = []

    for value, evidence_type in (
        (server, "server_header"),
        (powered, "x-powered-by_header"),
    ):
        for parser in (
            parse_php_header,
            parse_apache_header,
            parse_nginx_header,
            parse_iis_header,
            parse_tomcat_header,
            parse_aspnet_header,
            parse_asp_header,
        ):
            _add_unique(observations, parser(value, evidence_type))

        aspnet = parse_aspnet_header(value, evidence_type)
        if aspnet is not None:
            # Keep the historical broad label for existing consumers while
            # exposing the specific ASP.NET observation to new consumers.
            _add_unique(observations, aspnet)
            _add_unique(
                observations,
                _observation(
                    "asp",
                    None,
                    "low",
                    evidence_type,
                    "compatibility_alias=asp.net",
                ),
            )

    if aspnet_version:
        _add_unique(
            observations,
            _versioned_header(
                f"asp.net/{aspnet_version}",
                "asp.net",
                rf"^{VERSION_PATTERN}$",
                "x-aspnet-version_header",
            )
            or _observation(
                "asp.net",
                None,
                "low",
                "x-aspnet-version_header",
                aspnet_version,
            ),
        )

    header_markers = (
        ("cf-ray", "cloudflare", "header_marker"),
        ("akamai", "akamai", "header_marker"),
        ("azure", "azure", "header_marker"),
        ("x-azure", "azure", "header_marker"),
        ("x-amz", "aws", "header_marker"),
        ("amazon", "aws", "header_marker"),
        ("fastly", "fastly", "header_marker"),
    )
    for marker, technology, evidence_type in header_markers:
        if marker in header_text:
            _add_unique(
                observations,
                _observation(
                    technology,
                    None,
                    "low",
                    evidence_type,
                    f"marker={marker}",
                ),
            )

    body_markers = (
        ("wp-content", "wordpress"),
        ("react", "react/nextjs"),
        ("_next", "react/nextjs"),
        ("vue", "vue"),
        ("angular", "angular"),
        ("jquery", "jquery"),
        ("bootstrap", "bootstrap"),
        ("shopify", "shopify"),
        ("cdn.jsdelivr", "cdn"),
    )
    for marker, technology in body_markers:
        if marker in body_text:
            _add_unique(
                observations,
                _observation(
                    technology,
                    None,
                    "low",
                    "body_marker",
                    f"marker={marker}",
                ),
            )

    if "wordpress" in cookie_text:
        _add_unique(
            observations,
            _observation(
                "wordpress",
                None,
                "low",
                "cookie_marker",
                "marker=wordpress",
            ),
        )

    if not observations:
        return [
            _observation(
                "unknown",
                None,
                "none",
                "none",
                "no_positive_marker",
            )
        ]

    return sorted(observations, key=lambda item: (item.technology, item.version or ""))


_last_detections = {}


def detect_tech_observations(domain):

    try:
        observed_url = f"http://{domain}"
        r = requests.get(
            observed_url,
            timeout=4,
            allow_redirects=False,
            verify=False
        )

        return DetectionResult(
            fingerprints=tuple(fingerprint_response(
                headers=r.headers,
                body=r.text,
                cookies=r.cookies,
            )),
            observed_url=observed_url,
        )

    except Exception as exc:
        logger.warning(
            "Technology detection failed for %s (%s)",
            domain,
            type(exc).__name__,
        )
        return None


def detect_tech(domain):
    detection = detect_tech_observations(domain)
    _last_detections[domain] = detection
    if detection is None:
        return None
    return sorted({item.technology for item in detection.fingerprints})

def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
    JOIN scan_results sr
      ON sr.domain_id = s.domain_id
      AND sr.scan_id = s.scan_id
    LEFT JOIN domain_technology_observations dto
      ON d.id = dto.domain_id
      AND dto.scan_id = %s
    
    WHERE s.scan_id = %s
    AND dto.domain_id IS NULL
    AND s.http_status > 0
    AND {TECH_AUTHORIZATION_PREDICATE}
    
    ORDER BY d.id, s.scan_id DESC
    """,
    (scan_id, scan_id))
    
    rows = cur.fetchall()
    
    print("Rows to process:", len(rows))

    for domain_id, domain in rows:

        techs = detect_tech(domain)
        detection = _last_detections.pop(domain, None)

        print("Tech detect →", domain, techs)

        if techs is None:
            continue
        
        if isinstance(techs, str):
            techs = [techs]
            
        if not techs:
            techs = ["Unknown"]
        
        for tech in techs:
        
            print("DEBUG → inserting into domain_tech")
            cur.execute("""
            SELECT 1 FROM domain_tech
            WHERE domain_id=%s AND scan_id=%s AND tech=%s
            """, (domain_id, scan_id, tech))
            
            if not cur.fetchone():
                cur.execute("""
                INSERT INTO domain_tech(domain_id, scan_id, tech)
                SELECT %s, %s, %s
                WHERE EXISTS (
                    SELECT 1 FROM scan_results sr
                    WHERE sr.scan_id = %s AND sr.domain_id = %s
                )
                """, (domain_id, scan_id, tech, scan_id, domain_id))

        if detection is None:
            continue

        for fingerprint in detection.fingerprints:
            cur.execute("""
            INSERT INTO domain_technology_observations(
                scan_id,
                domain_id,
                technology,
                version,
                confidence,
                evidence_type,
                sanitized_evidence,
                observed_url,
                detector_version
            )
            SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s
            WHERE EXISTS (
                SELECT 1 FROM scan_results sr
                WHERE sr.scan_id = %s AND sr.domain_id = %s
            )
            ON CONFLICT DO NOTHING
            """, (
                scan_id,
                domain_id,
                fingerprint.technology,
                fingerprint.version,
                fingerprint.confidence,
                fingerprint.evidence_type,
                fingerprint.evidence,
                detection.observed_url,
                DETECTOR_VERSION,
                scan_id,
                domain_id,
            ))

    conn.commit()
    conn.close()

    print("Tech enrichment complete")


if __name__ == "__main__":
    main()
