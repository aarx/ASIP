from dataclasses import dataclass
import json


RISK_WEIGHTS = {
    "new_asset": 3,
    "http_exposed": 1,
    "resolves_no_http": 1,
    "sensitive_ports": 3,
    "many_ports": 1,
    "shadow_asset": 2,
    "cloud": 1,
    "asset_exposure": 1,
    "ip_state_volatility": 3,
    "finding": 3,
    "high_finding": 2,
}

CLOUD_PROVIDER_KEYWORDS = (
    "amazon",
    "aws",
    "azure",
    "gcp",
    "google cloud",
)

ASSET_EXPOSURE_KEYWORDS = (
    "dev",
    "test",
    "uat",
    "qa",
    "admin",
    "mail",
    "temp",
    "stage",
    "staging",
    "sandbox",
    "preprod",
    "pre-prod",
    "nonprod",
    "non-prod",
    "lab",
    "demo",
)


@dataclass(frozen=True)
class RiskEvidence:
    scan_id: int
    domain_id: int
    domain: str
    first_seen_scan: int | None
    is_known: bool
    has_ip: bool
    http_observation_status: str = "UNKNOWN"
    port_count: int = 0
    sensitive_port_count: int = 0
    provider: str | None = None
    volatility_flips: int = 0
    finding_count: int = 0
    high_finding_count: int = 0
    ownership_status: str = "CONFIRMED"


@dataclass(frozen=True)
class RiskResult:
    score: int
    priority: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class DomainRisk:
    domain_id: int
    domain: str
    is_known: bool
    has_ip: bool
    http_observation_status: str
    ownership_status: str
    result: RiskResult


def priority_for_score(score):
    if score >= 8:
        return "High"
    if score >= 6:
        return "Elevated"
    if score >= 4:
        return "Review"
    return "Low"


def get_asset_exposure_keywords(domain):
    domain = (domain or "").lower()
    matched = []

    for keyword in ASSET_EXPOSURE_KEYWORDS:
        if keyword == "stage":
            if "stage" in domain and "staging" not in domain:
                matched.append("STAGE")
        elif keyword in domain:
            matched.append(keyword.upper())

    return matched


def calculate_risk(evidence):
    if evidence.ownership_status != "CONFIRMED":
        return RiskResult(score=0, priority="Low", reasons=())

    score = 0
    reasons = []

    def add(signal, reason=None):
        nonlocal score
        score += RISK_WEIGHTS[signal]
        reasons.append(reason or signal)

    if evidence.first_seen_scan == evidence.scan_id:
        add("new_asset")

    if evidence.http_observation_status == "RESPONDED":
        add("http_exposed")
    elif (
        evidence.http_observation_status == "NO_RESPONSE"
        and evidence.has_ip
    ):
        add("resolves_no_http")

    if evidence.sensitive_port_count > 0:
        add("sensitive_ports")

    if evidence.port_count > 3:
        add("many_ports")

    if evidence.is_known is False:
        add("shadow_asset")

    provider = (evidence.provider or "").lower()
    if provider and any(keyword in provider for keyword in CLOUD_PROVIDER_KEYWORDS):
        add("cloud")

    asset_keywords = get_asset_exposure_keywords(evidence.domain)
    if asset_keywords:
        add("asset_exposure", "asset_exposure:" + ",".join(asset_keywords))

    if evidence.volatility_flips >= 2:
        add("ip_state_volatility")

    if evidence.finding_count > 0:
        add("finding")

    if evidence.high_finding_count > 0:
        add("high_finding")

    return RiskResult(
        score=score,
        priority=priority_for_score(score),
        reasons=tuple(reasons),
    )


def serialize_reasons(reasons):
    return json.dumps(list(reasons), separators=(",", ":"))


def calculate_scan_risks(cursor, scan_id):
    cursor.execute("""
        SELECT
            d.id,
            d.domain,
            d.first_seen_scan,
            d.is_known,
            d.ownership_status,
            ds.has_ip,
            ds.http_observation_status
        FROM scan_results sr
        JOIN domains d
          ON d.id = sr.domain_id
        JOIN domain_states ds
          ON ds.domain_id = sr.domain_id
         AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s
          AND d.ownership_status = 'CONFIRMED'
        ORDER BY d.domain
    """, (scan_id,))
    base_rows = cursor.fetchall()

    cursor.execute("""
        SELECT
            dp.domain_id,
            COUNT(DISTINCT dp.port) AS port_count,
            COUNT(DISTINCT sp.port) AS sensitive_port_count
        FROM domain_ports dp
        JOIN scan_results sr
          ON sr.scan_id = dp.scan_id
         AND sr.domain_id = dp.domain_id
        LEFT JOIN sensitive_ports sp
          ON sp.port = dp.port
        WHERE dp.scan_id = %s
        GROUP BY dp.domain_id
    """, (scan_id,))
    port_map = {row[0]: (row[1] or 0, row[2] or 0) for row in cursor.fetchall()}

    cursor.execute("""
        SELECT dp.domain_id, dp.provider
        FROM domain_provider dp
        JOIN scan_results sr
          ON sr.scan_id = dp.scan_id
         AND sr.domain_id = dp.domain_id
        WHERE dp.scan_id = %s
    """, (scan_id,))
    provider_map = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT
            df.domain_id,
            COUNT(*) AS finding_count,
            COUNT(*) FILTER (WHERE UPPER(df.severity) = 'HIGH') AS high_findings
        FROM domain_findings df
        JOIN scan_results sr
          ON sr.scan_id = df.scan_id
         AND sr.domain_id = df.domain_id
        WHERE df.scan_id = %s
        GROUP BY df.domain_id
    """, (scan_id,))
    finding_map = {row[0]: (row[1] or 0, row[2] or 0) for row in cursor.fetchall()}

    cursor.execute("""
        WITH relevant_states AS (
            SELECT ds.domain_id, ds.scan_id, ds.has_ip
            FROM domain_states ds
            JOIN scan_results sr
              ON sr.scan_id = ds.scan_id
             AND sr.domain_id = ds.domain_id
            JOIN scans s
              ON s.id = ds.scan_id
            WHERE s.status = 'SUCCEEDED'
              AND ds.scan_id < %s

            UNION ALL

            SELECT ds.domain_id, ds.scan_id, ds.has_ip
            FROM domain_states ds
            JOIN scan_results sr
              ON sr.scan_id = ds.scan_id
             AND sr.domain_id = ds.domain_id
            WHERE ds.scan_id = %s
        ),
        ordered AS (
            SELECT
                domain_id,
                has_ip,
                LAG(has_ip) OVER (
                    PARTITION BY domain_id
                    ORDER BY scan_id
                ) AS previous_has_ip
            FROM relevant_states
        )
        SELECT domain_id, COUNT(*) AS flips
        FROM ordered
        WHERE previous_has_ip IS NOT NULL
          AND previous_has_ip != has_ip
        GROUP BY domain_id
    """, (scan_id, scan_id))
    volatility_map = {row[0]: row[1] or 0 for row in cursor.fetchall()}

    risks = []
    for (
        domain_id, domain, first_seen_scan, is_known, ownership_status,
        has_ip, http_outcome,
    ) in base_rows:
        port_count, sensitive_port_count = port_map.get(domain_id, (0, 0))
        finding_count, high_finding_count = finding_map.get(domain_id, (0, 0))
        evidence = RiskEvidence(
            scan_id=scan_id,
            domain_id=domain_id,
            domain=domain,
            first_seen_scan=first_seen_scan,
            is_known=is_known,
            ownership_status=ownership_status,
            has_ip=bool(has_ip),
            http_observation_status=http_outcome or "UNKNOWN",
            port_count=port_count,
            sensitive_port_count=sensitive_port_count,
            provider=provider_map.get(domain_id),
            volatility_flips=volatility_map.get(domain_id, 0),
            finding_count=finding_count,
            high_finding_count=high_finding_count,
        )
        risks.append(DomainRisk(
            domain_id=domain_id,
            domain=domain,
            is_known=is_known,
            has_ip=bool(has_ip),
            http_observation_status=http_outcome or "UNKNOWN",
            ownership_status=ownership_status,
            result=calculate_risk(evidence),
        ))

    return risks
