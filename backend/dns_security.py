"""Offline-testable, scan-scoped DNS security assessment primitives.

This module is intentionally not imported by orchestration or the legacy DNS
worker. Callers must provide the centralized, per-query authorization check.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Callable

import dns.exception
import dns.rcode
import dns.resolver

from authorization_policy import default_operation_enabled, recheck_active_authorization


DNS_SECURITY_OPERATION = "DNS_SECURITY"
SUPPORTED_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT"})
RESOLVER_OUTCOMES = frozenset({
    "ANSWER", "NODATA", "NXDOMAIN", "SERVFAIL", "REFUSED", "TIMEOUT",
    "INCONCLUSIVE",
})
ASSESSMENT_OUTCOMES = frozenset({
    "CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING",
    "INFORMATIONAL", "CLEAR", "NOT_CHECKED", "INCONCLUSIVE",
})
MAX_TIMEOUT_SECONDS = 3.0
MAX_ANSWERS = 50
MAX_ANSWER_LENGTH = 4096
MAX_EVIDENCE_BYTES = 8192
MAX_CHAIN_HOPS = 5
MAX_MX_TARGETS = 10
MAX_RUN_SCOPED_DNS_QUERIES = 60
_DMARC_LABEL = "_dmarc"
_SAFE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,79}$")

PROVIDER_INDICATORS = {
    "amazonaws.com": "aws",
    "github.io": "github_pages",
    "herokuapp.com": "heroku",
    "azurewebsites.net": "azure",
    "cloudapp.net": "azure",
    "appspot.com": "google_app_engine",
    "netlify.app": "netlify",
    "vercel.app": "vercel",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def normalize_dns_name(value, *, allow_dmarc=False):
    """Return a bounded lowercase IDNA name; allow only the DMARC owner label."""
    if not isinstance(value, str):
        raise ValueError("DNS name must be text")
    raw = value.strip()
    if raw.endswith(".."):
        raise ValueError("invalid DNS name")
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or len(raw) > 253 or "@" in raw or "/" in raw or "\\" in raw:
        raise ValueError("invalid DNS name")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError("DNS query name cannot be an IP literal")
    labels = raw.split(".")
    prefix = ""
    if allow_dmarc and labels[0].lower() == _DMARC_LABEL:
        prefix = _DMARC_LABEL + "."
        labels = labels[1:]
    if not labels:
        raise ValueError("invalid DNS name")
    try:
        normalized = ".".join(label.encode("idna").decode("ascii").lower() for label in labels)
    except UnicodeError as exc:
        raise ValueError("invalid IDNA name") from exc
    if len(normalized) > 253 or any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in normalized.split(".")
    ):
        raise ValueError("invalid DNS name")
    normalized = prefix + normalized
    if len(normalized) > 253:
        raise ValueError("DNS name is too long")
    return normalized


@dataclass(frozen=True)
class ResolverOutcome:
    requested_name: str
    record_type: str
    outcome: str
    answers: tuple
    queried_at: str
    evidence: dict

    def as_dict(self):
        return asdict(self)


class DnsQueryBudget:
    """Shared network-query counter for one bounded scan-run validation."""

    def __init__(self, maximum=MAX_RUN_SCOPED_DNS_QUERIES):
        self.maximum = max(0, min(int(maximum), MAX_RUN_SCOPED_DNS_QUERIES))
        self.attempted = 0
        self.exhausted = False

    def consume(self):
        if self.attempted >= self.maximum:
            self.exhausted = True
            return False
        self.attempted += 1
        return True


def _text_answer(rdata, record_type):
    if record_type in {"A", "AAAA"}:
        address = ipaddress.ip_address(rdata.to_text())
        expected = 4 if record_type == "A" else 6
        if address.version != expected:
            raise ValueError("address family mismatch")
        return str(address)
    if record_type == "CNAME":
        return normalize_dns_name(rdata.to_text())
    if record_type == "MX":
        preference = int(rdata.preference)
        exchange = normalize_dns_name(rdata.exchange.to_text()) if str(rdata.exchange) != "." else "."
        return f"{preference} {exchange}"
    if record_type == "TXT":
        chunks = getattr(rdata, "strings", None)
        if chunks is not None:
            value = b"".join(chunks).decode("utf-8", errors="replace")
        else:
            value = rdata.to_text().strip('"')
        return value[:MAX_ANSWER_LENGTH]
    raise ValueError("unsupported record type")


def _nameserver_outcome(exc):
    for error in getattr(exc, "kwargs", {}).get("errors", ()) or ():
        # dnspython error tuples include the response rcode at index 4.
        try:
            code = error[4]
            if code == dns.rcode.SERVFAIL:
                return "SERVFAIL"
            if code == dns.rcode.REFUSED:
                return "REFUSED"
        except (IndexError, TypeError):
            continue
    return "INCONCLUSIVE"


class BoundedDnsResolver:
    """Resolver with one bounded call per request and an auth callback per query."""

    def __init__(self, resolver_factory=None, timeout=1.0,
                 lifetime=MAX_TIMEOUT_SECONDS, *, operation_enabled=None,
                 query_budget=None):
        self.resolver_factory = resolver_factory or dns.resolver.Resolver
        self.timeout = max(0.1, min(float(timeout), MAX_TIMEOUT_SECONDS))
        self.lifetime = max(self.timeout, min(float(lifetime), MAX_TIMEOUT_SECONDS))
        self.operation_enabled = operation_enabled or (
            lambda: default_operation_enabled(DNS_SECURITY_OPERATION)
        )
        self.query_budget = query_budget
        self.query_attempts = 0
        self._scan_local_cache = {}

    def query(self, requested_name, record_type, *, authorize: Callable[[], object]):
        rrtype = str(record_type or "").strip().upper()
        try:
            qname = normalize_dns_name(requested_name, allow_dmarc=True)
        except ValueError:
            return ResolverOutcome(str(requested_name)[:253], rrtype, "INCONCLUSIVE", (), _now(),
                                   {"error_category": "INVALID_NAME"})
        if rrtype not in SUPPORTED_RECORD_TYPES:
            return ResolverOutcome(qname, rrtype[:8], "INCONCLUSIVE", (), _now(),
                                   {"error_category": "UNSUPPORTED_RECORD_TYPE"})
        try:
            operation_enabled = bool(self.operation_enabled())
        except Exception:
            operation_enabled = False
        if not operation_enabled:
            return ResolverOutcome(qname, rrtype, "INCONCLUSIVE", (), _now(),
                                   {"error_category": "OPERATION_DISABLED"})
        authorization_error = False
        try:
            allowed = authorize()
        except Exception:
            allowed = False
            authorization_error = True
        if isinstance(allowed, tuple):
            authorization_error = bool(
                len(allowed) > 1 and "check failed" in str(allowed[1]).lower()
            )
            allowed = bool(allowed[0]) if allowed else False
        if not allowed:
            return ResolverOutcome(qname, rrtype, "INCONCLUSIVE", (), _now(),
                                   {"error_category": (
                                       "AUTHORIZATION_ERROR" if authorization_error
                                       else "AUTHORIZATION_DENIED"
                                   )})

        # Reuse conclusive answers only within this resolver instance (one
        # assessed parent). Authorization above still runs for every logical
        # query, including cache hits.
        cache_key = (qname, rrtype)
        cached = self._scan_local_cache.get(cache_key)
        if cached is not None:
            return cached

        if self.query_budget is not None and not self.query_budget.consume():
            return ResolverOutcome(qname, rrtype, "INCONCLUSIVE", (), _now(),
                                   {"error_category": "QUERY_BUDGET_EXHAUSTED"})

        queried_at = _now()
        self.query_attempts += 1
        try:
            resolver = self.resolver_factory()
            resolver.timeout = self.timeout
            resolver.lifetime = self.lifetime
            if hasattr(resolver, "retry_servfail"):
                resolver.retry_servfail = False
            answer = resolver.resolve(qname, rrtype, search=False)
            values = []
            for record in answer:
                value = _text_answer(record, rrtype)
                if value not in values:
                    values.append(value)
                if len(values) >= MAX_ANSWERS:
                    break
            result = ResolverOutcome(qname, rrtype, "ANSWER", tuple(values), queried_at,
                                     {"truncated": len(values) == MAX_ANSWERS})
            self._scan_local_cache[cache_key] = result
            return result
        except dns.resolver.NXDOMAIN:
            outcome, category = "NXDOMAIN", "NAME_DOES_NOT_EXIST"
        except dns.resolver.NoAnswer:
            outcome, category = "NODATA", "NO_RECORD_OF_TYPE"
        except dns.resolver.LifetimeTimeout:
            outcome, category = "TIMEOUT", "RESOLVER_TIMEOUT"
        except dns.resolver.NoNameservers as exc:
            outcome = _nameserver_outcome(exc)
            category = "RESOLVER_FAILURE" if outcome == "INCONCLUSIVE" else outcome
        except (dns.exception.Timeout, TimeoutError):
            outcome, category = "TIMEOUT", "RESOLVER_TIMEOUT"
        except Exception as exc:
            outcome, category = "INCONCLUSIVE", type(exc).__name__[:64]
        result = ResolverOutcome(qname, rrtype, outcome, (), queried_at,
                                 {"error_category": category})
        if outcome in {"NODATA", "NXDOMAIN"}:
            self._scan_local_cache[cache_key] = result
        return result


def recheck_dns_security_authorization(cur, *, scan_id, domain_id=None, domain_name=None):
    """Use the shared, fail-closed authorization path for one DNS query target."""
    return recheck_active_authorization(
        cur,
        scan_id=scan_id,
        domain_id=domain_id,
        domain_name=domain_name,
        testing_level=DNS_SECURITY_OPERATION,
        required_scan_status="RUNNING",
    )


def dns_security_query_authorizer(cur, scan_id):
    """Build the per-query callback used by the resolver/assessor.

    The query name must itself be a current scan member. DMARC record-owner
    lookups pass their parent asset name as the authorization name; CNAME and
    MX target lookups pass the target hostname and therefore require their own
    current-scan authorization.
    """
    def authorize(query_authorization_name):
        return recheck_dns_security_authorization(
            cur, scan_id=scan_id, domain_name=query_authorization_name,
        )
    return authorize


def _assessment(check_key, outcome, *, severity="INFO", confidence="UNKNOWN",
                target_identity="", record_type=None, evidence=None, remediation=None):
    if outcome not in ASSESSMENT_OUTCOMES:
        raise ValueError("invalid DNS assessment outcome")
    return {
        "check_key": check_key,
        "target_identity": target_identity,
        "record_type": record_type,
        "outcome": outcome,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence or {},
        "remediation": remediation,
    }


def _resolver_assessment(key, result, target=""):
    if result.evidence.get("error_category") == "AUTHORIZATION_DENIED":
        return _assessment(key, "NOT_CHECKED", target_identity=target or result.requested_name,
                           record_type=result.record_type,
                           evidence={"resolver_outcome": result.outcome,
                                     "reason": "authorization_denied"})
    if result.outcome == "ANSWER":
        return _assessment(key, "INFORMATIONAL", confidence="HIGH",
                           target_identity=target or result.requested_name,
                           record_type=result.record_type,
                           evidence={"record_type": result.record_type,
                                     "answer_count": len(result.answers)})
    if result.outcome == "NODATA":
        return _assessment(key, "INFORMATIONAL", confidence="HIGH",
                           target_identity=target or result.requested_name,
                           record_type=result.record_type,
                           evidence={"resolver_outcome": result.outcome})
    if result.outcome == "NXDOMAIN":
        return _assessment(key, "WARNING", severity="LOW", confidence="HIGH",
                           target_identity=target or result.requested_name,
                           record_type=result.record_type,
                           evidence={"resolver_outcome": result.outcome})
    return _assessment(key, "INCONCLUSIVE", target_identity=target or result.requested_name,
                       record_type=result.record_type,
                       evidence={"resolver_outcome": result.outcome,
                                 "error_category": result.evidence.get("error_category")})


def parse_spf(txt_answers, *, mail_usage_known=False):
    records = [str(value).strip() for value in txt_answers
               if str(value).strip().lower().startswith("v=spf1")]
    if not records:
        return _assessment("spf_configuration",
                           "WARNING" if mail_usage_known else "INFORMATIONAL",
                           severity="LOW" if mail_usage_known else "INFO",
                           confidence="HIGH",
                           evidence={"spf_record_count": 0,
                                     "mail_usage_known": bool(mail_usage_known)},
                           remediation=("Publish an SPF policy if this domain sends email."
                                        if mail_usage_known else None))
    if len(records) > 1:
        return _assessment("spf_configuration", "CONFIRMED_ISSUE", severity="MEDIUM",
                           confidence="HIGH", evidence={"spf_record_count": len(records)},
                           remediation="Consolidate SPF mechanisms into one SPF record.")
    tokens = records[0].split()
    mechanisms = []
    unknown_syntax = False
    invalid = tokens[0].lower() != "v=spf1"
    for token in tokens[1:]:
        if "%{" in token:
            unknown_syntax = True
            continue
        term = token[1:] if token[:1] in {"+", "-", "~", "?"} else token
        if term.lower() == "all":
            mechanisms.append("all")
            continue
        if term.lower().startswith(("redirect=", "exp=")):
            key, value = term.split("=", 1)
            if not value or key.lower() not in {"redirect", "exp"}:
                invalid = True
            elif "%{" in value:
                unknown_syntax = True
            else:
                try:
                    normalize_dns_name(value)
                except ValueError:
                    invalid = True
            continue
        mechanism = term.split(":", 1)[0].split("/", 1)[0].lower()
        if mechanism not in {"a", "mx", "ptr", "include", "exists", "ip4", "ip6"}:
            invalid = True
            continue
        if mechanism in {"ip4", "ip6"}:
            address = term.partition(":")[2]
            try:
                network = ipaddress.ip_network(address, strict=False)
                if network.version != (4 if mechanism == "ip4" else 6):
                    invalid = True
            except ValueError:
                invalid = True
        elif mechanism in {"include", "exists"}:
            target = term.partition(":")[2]
            if "%{" in target:
                unknown_syntax = True
            else:
                try:
                    normalize_dns_name(target)
                except ValueError:
                    invalid = True
        elif mechanism in {"a", "mx", "ptr"}:
            suffix = term[len(mechanism):]
            target = ""
            if suffix.startswith(":"):
                target_and_cidr = suffix[1:]
                target, slash, rest = target_and_cidr.partition("/")
                if slash:
                    cidr = "/" + rest
                    if (mechanism == "ptr" or
                            not re.fullmatch(r"/\d{1,2}(?://\d{1,3})?", cidr)):
                        invalid = True
                    else:
                        numbers = [int(value) for value in re.findall(r"\d+", cidr)]
                        if numbers[0] > 32 or (len(numbers) > 1 and numbers[1] > 128):
                            invalid = True
            elif suffix and not suffix.startswith("/"):
                invalid = True
            elif suffix:
                if (mechanism == "ptr" or
                        not re.fullmatch(r"/\d{1,2}(?://\d{1,3})?", suffix)):
                    invalid = True
                else:
                    numbers = [int(value) for value in re.findall(r"\d+", suffix)]
                    if numbers[0] > 32 or (len(numbers) > 1 and numbers[1] > 128):
                        invalid = True
            if target:
                if "%{" in target:
                    unknown_syntax = True
                else:
                    try:
                        normalize_dns_name(target)
                    except ValueError:
                        invalid = True
    invalid = invalid or mechanisms.count("all") > 1
    if invalid:
        return _assessment("spf_configuration", "CONFIRMED_ISSUE", severity="MEDIUM",
                           confidence="MEDIUM", evidence={"spf_record_count": 1,
                                                           "syntax_check": "invalid"},
                           remediation="Review and correct the SPF record syntax.")
    if unknown_syntax:
        return _assessment("spf_configuration", "INCONCLUSIVE",
                           evidence={"spf_record_count": 1,
                                     "syntax_check": "not_fully_evaluated"})
    return _assessment("spf_configuration", "CLEAR", confidence="HIGH",
                       evidence={"spf_record_count": 1, "syntax_check": "basic_valid",
                                 "validation_scope": "basic_syntax_only"})


def parse_dmarc(txt_answers, *, mail_usage_known=False):
    records = [str(value).strip() for value in txt_answers
               if str(value).strip().lower().startswith("v=dmarc1")]
    if not records:
        return _assessment("dmarc_configuration",
                           "WARNING" if mail_usage_known else "INFORMATIONAL",
                           severity="LOW" if mail_usage_known else "INFO",
                           confidence="HIGH",
                           evidence={"dmarc_record_count": 0,
                                     "mail_usage_known": bool(mail_usage_known)},
                           remediation=("Publish a DMARC policy if this domain receives email."
                                        if mail_usage_known else None))
    if len(records) > 1:
        return _assessment("dmarc_configuration", "CONFIRMED_ISSUE", severity="MEDIUM",
                           confidence="HIGH", evidence={"dmarc_record_count": len(records)},
                           remediation="Publish a single DMARC policy record.")
    tags = {}
    malformed = False
    for part in records[0].split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            malformed = True
            continue
        key, value = (item.strip().lower() for item in part.split("=", 1))
        if not key or key in tags:
            malformed = True
        tags[key] = value
    if (malformed or tags.get("v") != "dmarc1" or
            tags.get("p") not in {"none", "quarantine", "reject"}):
        return _assessment("dmarc_configuration", "CONFIRMED_ISSUE", severity="MEDIUM",
                           confidence="HIGH", evidence={"dmarc_record_count": 1,
                                                         "syntax_check": "invalid"},
                           remediation="Correct the DMARC version and required policy tags.")
    if tags["p"] == "none":
        return _assessment("dmarc_configuration", "WARNING", severity="LOW",
                           confidence="HIGH", evidence={"policy": "none"},
                           remediation="Review whether enforcement is appropriate after monitoring.")
    return _assessment("dmarc_configuration", "CLEAR", confidence="HIGH",
                       evidence={"policy": tags["p"],
                                 "validation_scope": "basic_syntax_only"})


def _provider_indicator(name):
    for suffix, provider in PROVIDER_INDICATORS.items():
        if name == suffix or name.endswith("." + suffix):
            return provider
    return None


def assess_dns_domain(domain, resolver, authorize_query, *, mail_usage_known=False,
                      max_chain_hops=MAX_CHAIN_HOPS, max_mx_targets=MAX_MX_TARGETS):
    """Run bounded recursive-DNS observations; authorization is checked per query.

    ``authorize_query(name)`` must perform a fresh centralized policy check.
    Record-owner queries (SPF/DMARC) pass the authorized asset name; CNAME/MX
    target queries pass the target itself, so out-of-scope targets fail closed.
    """
    owner = normalize_dns_name(domain)
    query_limit = min(5, max(1, int(max_chain_hops)))
    mx_limit = min(MAX_MX_TARGETS, max(0, int(max_mx_targets)))
    observations = []

    def query(name, rrtype, auth_name):
        result = resolver.query(name, rrtype, authorize=lambda: authorize_query(auth_name))
        observations.append(result)
        return result

    a_result = query(owner, "A", owner)
    aaaa_result = query(owner, "AAAA", owner)
    cname_result = query(owner, "CNAME", owner)
    mx_result = query(owner, "MX", owner)
    txt_result = query(owner, "TXT", owner)
    dmarc_name = f"_dmarc.{owner}"
    dmarc_result = query(dmarc_name, "TXT", owner)

    checks = [
        _resolver_assessment("dns_a_resolution", a_result),
        _resolver_assessment("dns_aaaa_resolution", aaaa_result),
    ]

    cname_target = cname_result.answers[0] if cname_result.outcome == "ANSWER" and cname_result.answers else None
    if not cname_target:
            checks.append(_assessment("cname_health", "CLEAR" if cname_result.outcome == "NODATA"
                                  else "INCONCLUSIVE", confidence="HIGH" if cname_result.outcome == "NODATA" else "UNKNOWN",
                                  target_identity=owner,
                                  record_type="CNAME",
                                  evidence={"resolver_outcome": cname_result.outcome}))
    else:
        current = owner
        target = cname_target
        seen = {owner}
        chain = []
        status = "INCONCLUSIVE"
        for _ in range(query_limit):
            if target in seen:
                status = "CONFIRMED_ISSUE"
                chain.append({"target": target, "state": "loop"})
                break
            provider = _provider_indicator(target)
            if provider:
                chain.append({"target": target, "state": "provider_indicator", "provider": provider})
            seen.add(target)
            target_cname = query(target, "CNAME", target)
            if target_cname.evidence.get("error_category") == "AUTHORIZATION_DENIED":
                chain.append({"target": target, "state": "not_checked_authorization"})
                status = "POTENTIAL_EXPOSURE" if provider else "NOT_CHECKED"
                break
            if target_cname.outcome == "ANSWER" and target_cname.answers:
                current, target = target, target_cname.answers[0]
                chain.append({"target": current, "state": "cname", "next": target})
                continue
            # Terminal address records belong to the CNAME target. Querying
            # ``current`` validates the owner/previous hop instead.
            target_a = query(target, "A", target)
            target_aaaa = query(target, "AAAA", target)
            if target_a.outcome == "ANSWER" or target_aaaa.outcome == "ANSWER":
                status = "CLEAR"
            elif target_a.outcome == "NXDOMAIN" or target_aaaa.outcome == "NXDOMAIN":
                status = "POTENTIAL_EXPOSURE"
            elif (target_cname.outcome == "NODATA"
                  and target_a.outcome == "NODATA"
                  and target_aaaa.outcome == "NODATA"):
                status = "CLEAR"
            else:
                status = "INCONCLUSIVE"
            chain.append({"target": target, "state": status.lower()})
            break
        else:
            status = "INCONCLUSIVE"
            chain.append({"target": target, "state": "hop_limit"})
        if status == "CONFIRMED_ISSUE":
            checks.append(_assessment("cname_health", status, severity="LOW", confidence="HIGH",
                                      target_identity=owner, record_type="CNAME", evidence={"chain": chain},
                                      remediation="Review the observed CNAME loop."))
        elif status == "POTENTIAL_EXPOSURE":
            checks.append(_assessment("cname_health", status, severity="LOW", confidence="LOW",
                                      target_identity=owner, record_type="CNAME", evidence={"chain": chain,
                                                                      "takeover_confirmed": False},
                                      remediation="Review DNS target ownership and provider state."))
        else:
            checks.append(_assessment("cname_health", status, confidence="HIGH" if status == "CLEAR" else "UNKNOWN",
                                      target_identity=owner, record_type="CNAME", evidence={"chain": chain,
                                                                      "takeover_confirmed": False}))

    mx_records = mx_result.answers if mx_result.outcome == "ANSWER" else ()
    checks.append(_resolver_assessment("mx_observation", mx_result, owner))
    for mx in mx_records[:mx_limit]:
        try:
            preference, exchange = mx.split(" ", 1)
            exchange = normalize_dns_name(exchange) if exchange != "." else "."
        except (ValueError, TypeError):
            continue
        if exchange == ".":
            checks.append(_assessment("mx_target", "INFORMATIONAL", confidence="HIGH",
                                      target_identity=exchange,
                                      record_type="MX",
                                      evidence={"preference": int(preference), "null_mx": True}))
            continue
        for rrtype in ("A", "AAAA"):
            target_result = query(exchange, rrtype, exchange)
            checks.append(_resolver_assessment("mx_target", target_result, exchange))

    spf = parse_spf(txt_result.answers if txt_result.outcome == "ANSWER" else (),
                    mail_usage_known=mail_usage_known)
    if txt_result.outcome not in {"ANSWER", "NODATA"}:
        spf = _assessment("spf_configuration", "INCONCLUSIVE",
                          evidence={"txt_resolver_outcome": txt_result.outcome})
    spf["evidence"] = {**spf["evidence"], "txt_resolver_outcome": txt_result.outcome}
    spf["record_type"] = "TXT"
    checks.append(spf)
    dmarc = parse_dmarc(dmarc_result.answers if dmarc_result.outcome == "ANSWER" else (),
                        mail_usage_known=mail_usage_known)
    if dmarc_result.outcome not in {"ANSWER", "NODATA"}:
        dmarc = _assessment("dmarc_configuration", "INCONCLUSIVE",
                            evidence={"txt_resolver_outcome": dmarc_result.outcome})
    dmarc["target_identity"] = dmarc_name
    dmarc["record_type"] = "TXT"
    dmarc["evidence"] = {**dmarc["evidence"], "txt_resolver_outcome": dmarc_result.outcome}
    checks.append(dmarc)
    return {"domain": owner, "observations": [item.as_dict() for item in observations],
            "checks": checks}


def persist_dns_security_check(cur, *, scan_id, domain_id, check):
    """Persist one bounded, idempotent check only for an authorized RUNNING member."""
    check_key = str(check.get("check_key", "")).strip().lower()
    if not _SAFE_KEY_RE.fullmatch(check_key):
        raise ValueError("invalid DNS check key")
    outcome = check.get("outcome")
    if outcome not in ASSESSMENT_OUTCOMES:
        raise ValueError("invalid DNS assessment outcome")
    target = check.get("target_identity") or ""
    if target:
        target = "." if target == "." else normalize_dns_name(target, allow_dmarc=True)
    record_type = str(check.get("record_type") or "").upper()
    if record_type and record_type not in SUPPORTED_RECORD_TYPES:
        raise ValueError("invalid DNS record type")
    severity = check.get("severity", "INFO")
    confidence = check.get("confidence", "UNKNOWN")
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}:
        raise ValueError("invalid DNS severity")
    if confidence not in {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        raise ValueError("invalid DNS confidence")
    evidence = check.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise ValueError("DNS evidence must be an object")
    evidence_json = json.dumps(evidence, separators=(",", ":"), ensure_ascii=True)
    if len(evidence_json.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise ValueError("DNS evidence exceeds the bounded size")
    remediation = check.get("remediation")
    if remediation is not None and len(str(remediation)) > 1000:
        raise ValueError("DNS remediation exceeds the bounded size")

    authorized, reason = recheck_dns_security_authorization(
        cur, scan_id=scan_id, domain_id=domain_id,
    )
    if not authorized:
        if reason == "authorization check failed":
            raise RuntimeError("DNS Security persistence authorization failed")
        return False
    cur.execute("""
        INSERT INTO dns_security_checks(
            scan_id, domain_id, check_key, target_identity, record_type,
            outcome, severity, confidence, evidence, remediation, checked_at
        )
        SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, CURRENT_TIMESTAMP
        WHERE EXISTS (
            SELECT 1 FROM scan_results sr
            WHERE sr.scan_id = %s AND sr.domain_id = %s
        )
        ON CONFLICT (scan_id, domain_id, check_key, target_identity, record_type)
        DO UPDATE SET outcome = EXCLUDED.outcome,
                      severity = EXCLUDED.severity,
                      confidence = EXCLUDED.confidence,
                      evidence = EXCLUDED.evidence,
                      remediation = EXCLUDED.remediation,
                      checked_at = EXCLUDED.checked_at
        RETURNING id
    """, (scan_id, domain_id, check_key, target, record_type, outcome,
          severity, confidence, evidence_json, remediation, scan_id, domain_id))
    return cur.fetchone() is not None
