"""Conservative rule-based classification of persisted HTTP page titles."""

from html import unescape
from html.parser import HTMLParser
import re
import unicodedata
import hashlib


HTTP_TITLE_CATEGORIES = frozenset({
    "ADMIN_INTERFACE",
    "DEVELOPER_TOOL",
    "MONITORING_DASHBOARD",
    "API_DOCUMENTATION",
    "DIRECTORY_LISTING",
    "DEFAULT_SERVER_PAGE",
})


class _VisibleTitleText(HTMLParser):
    """Extract text without treating title contents as executable markup."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self._ignored += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self._ignored:
            self._ignored -= 1

    def handle_data(self, data):
        if not self._ignored:
            self.parts.append(data)


def normalize_title(title):
    """Normalize for matching while callers retain and return the raw title."""
    if not isinstance(title, str) or not title:
        return ""
    parser = _VisibleTitleText()
    try:
        parser.feed(unescape(title))
        parser.close()
    except Exception:
        # A malformed title is evidence text, not markup to execute.
        return ""
    visible = unicodedata.normalize("NFKC", " ".join(parser.parts))
    return re.sub(r"\s+", " ", visible).strip().casefold()


# Order is deliberate: specific product identifiers precede general categories.
TITLE_RULES = (
    {
        "rule_id": "http-title-jenkins",
        "product_label": "Jenkins",
        "category": "ADMIN_INTERFACE",
        "match_expression": r"^jenkins(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*jenkins$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The persisted title identifies a Jenkins interface; exposure alone does not establish a vulnerability.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-phpmyadmin",
        "product_label": "phpMyAdmin",
        "category": "ADMIN_INTERFACE",
        "match_expression": r"^php\s*my\s*admin(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*php\s*my\s*admin$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The persisted title identifies a phpMyAdmin interface; verify intended access and exposure.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-tomcat-manager",
        "product_label": "Apache Tomcat Manager",
        "category": "ADMIN_INTERFACE",
        "match_expression": r"\b(?:apache\s+)?tomcat\b.{0,50}\b(?:manager|administration|admin)\b|\b(?:manager|administration|admin)\b.{0,50}\btomcat\b",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title refers to a Tomcat management interface; no access-control or vulnerability conclusion is implied.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-portainer",
        "product_label": "Portainer",
        "category": "ADMIN_INTERFACE",
        "match_expression": r"^portainer(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*portainer$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The persisted title identifies Portainer; verify that the management interface is expected.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-kubernetes-dashboard",
        "product_label": "Kubernetes Dashboard",
        "category": "ADMIN_INTERFACE",
        "match_expression": r"\bkubernetes\s+dashboard\b",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The persisted title identifies a Kubernetes Dashboard interface; exposure is not proof of compromise.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-jupyter",
        "product_label": "Jupyter",
        "category": "DEVELOPER_TOOL",
        "match_expression": r"\bjupyter(?:\s*(?:notebook|lab))?\b",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies a Jupyter interface; confirm its intended audience and access controls.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-code-server",
        "product_label": "code-server",
        "category": "DEVELOPER_TOOL",
        "match_expression": r"\b(?:code-server|visual studio code server|vscode server)\b",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies a browser-based development environment; verify whether external exposure is intended.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-grafana",
        "product_label": "Grafana",
        "category": "MONITORING_DASHBOARD",
        "match_expression": r"^grafana(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*grafana$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies Grafana; this is an interface exposure indicator, not a vulnerability finding.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-prometheus",
        "product_label": "Prometheus",
        "category": "MONITORING_DASHBOARD",
        "match_expression": r"^prometheus(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*prometheus$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies a Prometheus interface; verify expected reachability and access controls.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-kibana",
        "product_label": "Kibana",
        "category": "MONITORING_DASHBOARD",
        "match_expression": r"^kibana(?:\s*(?:[-|:]|—)\s*.+)?$|^.+(?:[-|:]|—)\s*kibana$",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies Kibana; the title does not establish data access or a security defect.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-swagger-ui",
        "product_label": "Swagger UI",
        "category": "API_DOCUMENTATION",
        "match_expression": r"\bswagger\s+ui\b|\bswagger\s+editor\b",
        "confidence": "HIGH",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title identifies Swagger API documentation tooling; review whether the documentation is intended to be public.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-openapi-docs",
        "product_label": "OpenAPI documentation",
        "category": "API_DOCUMENTATION",
        "match_expression": r"\bopenapi\b.{0,40}\b(?:documentation|docs|explorer)\b|\b(?:documentation|docs|explorer)\b.{0,40}\bopenapi\b",
        "confidence": "MEDIUM",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title suggests an OpenAPI documentation interface; verify the content and intended audience.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-redoc",
        "product_label": "ReDoc API documentation",
        "category": "API_DOCUMENTATION",
        "match_expression": r"\bredoc\b.{0,40}\b(?:api|documentation|docs)\b|\b(?:api|documentation|docs)\b.{0,40}\bredoc\b",
        "confidence": "MEDIUM",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title suggests ReDoc API documentation; verify the content and intended audience.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-directory-listing",
        "product_label": "Directory listing",
        "category": "DIRECTORY_LISTING",
        "match_expression": r"^index of\s+/[^\n]*$",
        "confidence": "MEDIUM",
        "signal_classification": "EXPOSURE_SIGNAL",
        "explanation": "The title resembles a directory index; verify the response body and whether listing is intentional.",
        "verification_required": True,
    },
    {
        "rule_id": "http-title-default-nginx",
        "product_label": "Default nginx page",
        "category": "DEFAULT_SERVER_PAGE",
        "match_expression": r"^welcome to nginx!?$",
        "confidence": "HIGH",
        "signal_classification": "INFORMATIONAL",
        "explanation": "The title matches the standard nginx welcome page; it does not establish a vulnerability or server version.",
        "verification_required": False,
    },
    {
        "rule_id": "http-title-default-apache-debian",
        "product_label": "Apache Debian default page",
        "category": "DEFAULT_SERVER_PAGE",
        "match_expression": r"^apache2? debian default page(?:: it works)?$",
        "confidence": "HIGH",
        "signal_classification": "INFORMATIONAL",
        "explanation": "The title matches a common Apache Debian default page; it does not establish a vulnerability or server version.",
        "verification_required": False,
    },
    {
        "rule_id": "http-title-default-test-page",
        "product_label": "Default HTTP server test page",
        "category": "DEFAULT_SERVER_PAGE",
        "match_expression": r"^test page for the .{1,80} http server$|^http server test page powered by .{1,80}$",
        "confidence": "MEDIUM",
        "signal_classification": "INFORMATIONAL",
        "explanation": "The title resembles a packaged HTTP server test page; confirm whether it is an unintended default deployment.",
        "verification_required": False,
    },
    {
        "rule_id": "http-title-default-it-works",
        "product_label": "Generic default HTTP page",
        "category": "DEFAULT_SERVER_PAGE",
        "match_expression": r"^it works!?$",
        "confidence": "LOW",
        "signal_classification": "INFORMATIONAL",
        "explanation": "The exact generic default-page title is informational only and may require manual confirmation.",
        "verification_required": False,
    },
)

_COMPILED_RULES = tuple((rule, re.compile(rule["match_expression"], re.IGNORECASE)) for rule in TITLE_RULES)


def classify_title(title):
    """Return every deterministic match; the original title is not modified."""
    normalized = normalize_title(title)
    if not normalized:
        return []
    matches = []
    for rule, expression in _COMPILED_RULES:
        if expression.search(normalized):
            matches.append(dict(rule))
    return matches


def signal_identity(*, scan_id, domain_id, rule_id, service_url=None):
    """Stable source-scan-local identity, including a URL discriminator if present."""
    identity = "\0".join((
        str(int(scan_id)), str(int(domain_id)), str(rule_id),
        str(service_url or "").strip(),
    ))
    return "http-title:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
