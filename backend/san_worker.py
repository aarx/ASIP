import logging
import os
import json
import signal
import socket
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)
from db import get_conn, require_running_scan
from http_probe import AuthorizationDeniedError, open_validated_tls_socket
from ownership import (
    load_trusted_domains,
    normalize_hostname,
    ownership_for_discovery,
)

scan_id = int(sys.argv[1])
DEFAULT_SAN_WORKERS = 2
MAX_SAN_WORKERS = 2
TESTING_LEVEL = "HTTP_TLS_OBSERVATION"
_fetch_state = threading.local()

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("san_worker")


def fetch_san_domains(domain, before_request=None):
    _fetch_state.category = None
    if before_request is None or not before_request():
        _fetch_state.category = "authorization_skipped"
        return None
    try:
        with open_validated_tls_socket(
            domain, before_request=before_request
        ) as ssock:
            cert = ssock.getpeercert()

        san = cert.get("subjectAltName", [])
        return [entry[1] for entry in san if entry[0] == "DNS"]

    except AuthorizationDeniedError:
        _fetch_state.category = "authorization_skipped"
        return None
    except (OSError, ValueError) as e:
        if isinstance(e, (TimeoutError, socket.timeout)):
            _fetch_state.category = "timeout"
        elif isinstance(e, OSError) and str(e) == "no permitted TLS destination address":
            _fetch_state.category = "no_permitted_destination"
        else:
            _fetch_state.category = "other_failure"
        return None


class SanCancellationGate:
    """Serialize cancellation registration against scan-scoped SAN commits."""

    def __init__(self):
        self._lock = threading.RLock()
        self._cancelled = False

    def is_set(self):
        with self._lock:
            return self._cancelled

    def set(self):
        with self._lock:
            self._cancelled = True

    def run_if_active(self, operation):
        with self._lock:
            if self._cancelled:
                return None
            return operation()


class SanAuthorizationError(RuntimeError):
    pass


class SanStageError(RuntimeError):
    pass


class SanInterrupted(SanStageError):
    pass


class _ConcurrencyTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.maximum = 0

    def enter(self):
        with self.lock:
            self.active += 1
            self.maximum = max(self.maximum, self.active)

    def exit(self):
        with self.lock:
            self.active -= 1


def configured_san_workers(value=None):
    if value is None:
        value = os.environ.get("ASIP_SAN_WORKERS", str(DEFAULT_SAN_WORKERS))
    try:
        requested = int(value)
    except (TypeError, ValueError):
        requested = DEFAULT_SAN_WORKERS
    return min(MAX_SAN_WORKERS, max(1, requested))


def _target_metric(target_scan_id, domain_id, started, tls_elapsed,
                   category, timeout, san_count):
    logger.info("san_target %s", json.dumps({
        "scan_id": target_scan_id,
        "domain_id": domain_id,
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "tls_elapsed_seconds": round(tls_elapsed, 4),
        "result": category,
        "timeout": bool(timeout),
        "san_count": int(san_count),
    }, separators=(",", ":")))


def get_san_targets(cur, target_scan_id):
    cur.execute(f"""
        SELECT DISTINCT ON (d.id) d.id, d.domain
        FROM domains d
        JOIN scan_results sr ON d.id=sr.domain_id AND sr.scan_id=%s
        JOIN domain_states ds ON d.id=ds.domain_id AND ds.scan_id=%s
        LEFT JOIN domain_san dsan ON d.id=dsan.domain_id AND dsan.scan_id=%s
        WHERE dsan.domain_id IS NULL
          AND {active_scan_authorization_sql('d', 'HTTP_TLS_OBSERVATION')}
        ORDER BY d.id, ds.scan_id DESC
    """, (target_scan_id, target_scan_id, target_scan_id))
    return cur.fetchall()


def _initial_scan_lifecycle_guard(cur):
    require_running_scan(cur, scan_id)


def add_current_scan_membership(cur, parent_domain_id, child_domain_id,
                                target_scan_id=None):
    target_scan_id = scan_id if target_scan_id is None else target_scan_id
    cur.execute("""
    SELECT seed
    FROM scan_results
    WHERE scan_id = %s
    AND domain_id = %s
    """, (target_scan_id, parent_domain_id))

    parent_scan_result = cur.fetchone()
    if not parent_scan_result:
        raise RuntimeError(
            f"Parent domain {parent_domain_id} is missing scan_results for scan {target_scan_id}"
        )

    cur.execute("""
    INSERT INTO scan_results(scan_id, domain_id, seed)
    VALUES (%s, %s, %s)
    ON CONFLICT (scan_id, domain_id) DO NOTHING
    """, (target_scan_id, child_domain_id, parent_scan_result[0]))
    return max(0, cur.rowcount)

def _persist_parent(cur, conn, parent_id, parent_domain, san_observation,
                    trusted_domains, target_scan_id):
    cur.execute("""
        SELECT 1 FROM scan_results WHERE scan_id=%s AND domain_id=%s
    """, (target_scan_id, parent_id))
    if cur.fetchone() is None:
        return 0
    cur.execute("""
        INSERT INTO domain_san(domain_id, scan_id)
        SELECT %s, %s WHERE EXISTS (
            SELECT 1 FROM scan_results sr
            WHERE sr.scan_id=%s AND sr.domain_id=%s
        ) ON CONFLICT (domain_id, scan_id) DO NOTHING
    """, (parent_id, target_scan_id, target_scan_id, parent_id))
    persisted = max(0, cur.rowcount)
    known_set = trusted_domains.known_domains
    parent_normalized = normalize_hostname(parent_domain)
    normalized_names = set()
    for raw_san in san_observation:
        candidate = str(raw_san).strip().lower()
        if candidate.startswith("*."):
            candidate = candidate[2:]
        normalized = normalize_hostname(candidate)
        if normalized and normalized != parent_normalized and "." in normalized:
            normalized_names.add(normalized)
    for san in sorted(normalized_names):
        is_known = san in known_set
        ownership_status = ownership_for_discovery(
            san, ("san",), (), trusted_domains=trusted_domains
        )
        cur.execute("""
            INSERT INTO domains(
                domain, first_seen_scan, last_seen_scan, first_seen_at,
                last_seen_at, is_known, source, ownership_status
            ) VALUES (%s,%s,%s,NOW(),NOW(),%s,%s,%s)
            ON CONFLICT (domain) DO UPDATE SET
                first_seen_scan = CASE
                    WHEN domains.first_seen_scan IS NULL THEN EXCLUDED.first_seen_scan
                    WHEN EXCLUDED.first_seen_scan IS NULL THEN domains.first_seen_scan
                    ELSE LEAST(domains.first_seen_scan, EXCLUDED.first_seen_scan) END,
                last_seen_scan = CASE
                    WHEN domains.last_seen_scan IS NULL THEN EXCLUDED.last_seen_scan
                    WHEN EXCLUDED.last_seen_scan IS NULL THEN domains.last_seen_scan
                    ELSE GREATEST(domains.last_seen_scan, EXCLUDED.last_seen_scan) END,
                last_seen_at = NOW(), is_known = EXCLUDED.is_known,
                ownership_status = CASE
                    WHEN domains.ownership_status = 'EXTERNAL' THEN 'EXTERNAL'
                    WHEN EXCLUDED.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                    WHEN domains.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                    ELSE domains.ownership_status END,
                source = CASE WHEN domains.source='seed' THEN 'san' ELSE domains.source END
            RETURNING id, (xmax=0) AS inserted
        """, (san, target_scan_id, target_scan_id, is_known, "san", ownership_status))
        child_id, _inserted = cur.fetchone()
        persisted += max(0, cur.rowcount)
        persisted += add_current_scan_membership(
            cur, parent_id, child_id, target_scan_id
        )
        cur.execute("""
            INSERT INTO domain_sources(domain_id, scan_id, source, seed)
            SELECT %s,%s,%s,%s WHERE EXISTS (
                SELECT 1 FROM scan_results sr
                WHERE sr.scan_id=%s AND sr.domain_id=%s
            ) ON CONFLICT DO NOTHING
        """, (child_id, target_scan_id, "san", parent_domain,
              target_scan_id, child_id))
        persisted += max(0, cur.rowcount)
    return persisted


def _process_parent(row, target_scan_id, trusted_domains, gate, tracker):
    parent_id, parent_domain = row
    tracker.enter()
    started = time.monotonic()
    tls_started = started
    conn = None
    try:
        if gate.is_set():
            _target_metric(target_scan_id, parent_id, started, 0,
                           "cancelled", False, 0)
            return {"kind": "cancelled", "domain_id": parent_id}
        conn = get_conn()
        cur = conn.cursor()
        if target_scan_id == scan_id:
            _initial_scan_lifecycle_guard(cur)
        else:
            require_running_scan(cur, target_scan_id)
        cur.execute("SELECT 1 FROM scan_results WHERE scan_id=%s AND domain_id=%s",
                    (target_scan_id, parent_id))
        if cur.fetchone() is None:
            conn.commit()
            _target_metric(target_scan_id, parent_id, started, 0,
                           "authorization_skipped", False, 0)
            return {"kind": "authorization_skips", "domain_id": parent_id}
        conn.commit()

        def authorized():
            if gate.is_set():
                return False
            allowed, reason = recheck_active_authorization(
                cur, scan_id=target_scan_id, domain_id=parent_id,
                testing_level=TESTING_LEVEL,
            )
            conn.commit()
            if not allowed and reason == "authorization check failed":
                raise SanAuthorizationError("SAN authorization database check failed")
            return allowed

        if not authorized():
            _target_metric(target_scan_id, parent_id, started, 0,
                           "authorization_skipped", False, 0)
            return {"kind": "authorization_skips", "domain_id": parent_id}
        tls_started = time.monotonic()
        san_observation = fetch_san_domains(parent_domain, before_request=authorized)
        tls_elapsed = time.monotonic() - tls_started
        if san_observation is None:
            category = getattr(_fetch_state, "category", None) or "other_failure"
            _target_metric(target_scan_id, parent_id, started, tls_elapsed,
                           category, category == "timeout", 0)
            return {"kind": category, "domain_id": parent_id}

        def persist_and_commit():
            require_running_scan(cur, target_scan_id)
            count = _persist_parent(
                cur, conn, parent_id, parent_domain,
                san_observation, trusted_domains, target_scan_id,
            )
            conn.commit()
            return count

        persisted = gate.run_if_active(persist_and_commit)
        if persisted is None:
            conn.rollback()
            return {"kind": "cancelled", "domain_id": parent_id}
        category = "successful"
        _target_metric(target_scan_id, parent_id, started, tls_elapsed,
                       category, False, len(san_observation))
        return {"kind": category, "domain_id": parent_id,
                "persisted": persisted, "san_count": len(san_observation)}
    except SanAuthorizationError:
        raise
    except Exception:
        if conn is not None:
            conn.rollback()
        raise
    finally:
        try:
            if conn is not None:
                conn.close()
        finally:
            tracker.exit()


def run_san_expansion(rows, target_scan_id, trusted_domains, workers=None,
                      cancel_gate=None):
    gate = cancel_gate or SanCancellationGate()
    worker_count = configured_san_workers(workers)
    selected_by_id = {}
    for row in rows:
        selected_by_id.setdefault(int(row[0]), (int(row[0]), row[1]))
    selected = list(selected_by_id.values())
    started = time.monotonic()
    counts = {key: 0 for key in (
        "successful", "no_permitted_destination", "timeout", "other_failure",
        "authorization_skips", "persisted_records", "worker_errors",
    )}
    tracker = _ConcurrencyTracker()
    next_index = 0
    pending = {}
    pool = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="san")
    failed = None

    def submit_one(row):
        future = pool.submit(_process_parent, row, target_scan_id,
                             trusted_domains, gate, tracker)
        pending[future] = row

    try:
        while next_index < len(selected) and len(pending) < worker_count and not gate.is_set():
            submit_one(selected[next_index]); next_index += 1
        while pending:
            done, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                try:
                    result = future.result()
                    kind = result["kind"]
                    if kind == "cancelled":
                        gate.set()
                    else:
                        if kind == "authorization_skipped":
                            kind = "authorization_skips"
                        counts[kind] = counts.get(kind, 0) + 1
                        counts["persisted_records"] += result.get("persisted", 0)
                except Exception as exc:
                    counts["worker_errors"] += 1
                    failed = exc
                    gate.set()
            while (failed is None and not gate.is_set() and next_index < len(selected)
                   and len(pending) < worker_count):
                submit_one(selected[next_index]); next_index += 1
        if gate.is_set() and failed is None:
            raise SanInterrupted("SAN expansion cancelled before completion")
        if failed is not None:
            raise SanStageError("SAN worker failed") from failed
    finally:
        pool.shutdown(wait=not gate.is_set(), cancel_futures=True)
        summary = {
            "selected": len(selected), **counts,
            "elapsed_seconds": round(time.monotonic() - started, 4),
            "maximum_concurrency": tracker.maximum,
            "workers": worker_count,
        }
        logger.info("san_stage %s", json.dumps(
            summary, sort_keys=True, separators=(",", ":")
        ))
    return summary


def main():
    gate = SanCancellationGate()
    previous_handlers = {}
    def cancel_handler(signum, _frame):
        gate.set()
        logger.warning("SAN cancellation registered signal=%s", signum)
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.signal(sig, cancel_handler)
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            require_running_scan(cur, scan_id)
            trusted_domains = load_trusted_domains(cur)
            domains = get_san_targets(cur, scan_id)
            rows = domains
            conn.commit()
            require_running_scan(cur, scan_id)
        finally:
            conn.close()
        logger.info("SAN scan=%s selected=%s", scan_id, len(rows))
        summary = run_san_expansion(rows, scan_id, trusted_domains, cancel_gate=gate)
        logger.info("SAN expansion complete %s", json.dumps(summary, sort_keys=True))
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    main()
