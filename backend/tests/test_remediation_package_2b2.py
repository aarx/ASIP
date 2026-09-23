"""Package 2B2 REST scan-isolation regression tests."""

import importlib.util
import inspect
import logging
import pathlib
import sys
import types
import unittest
from collections import Counter
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_module(path, replacements):
    name = f"pkg2b2_{path.stem}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_modules = {key: sys.modules.get(key) for key in replacements}
    try:
        sys.modules.update(replacements)
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        for key, previous in old_modules.items():
            if previous is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = previous
    return module


class SnapshotCursor:
    def __init__(self, statuses):
        self.statuses = statuses
        self.executions = []
        self.result = None
        self.domains = {1: "one.example.test", 2: "two.example.test"}
        self.states = [
            {"domain_id": 1, "scan_id": 8, "has_ip": True},
            {"domain_id": 1, "scan_id": 9, "has_ip": True},
            {"domain_id": 1, "scan_id": 10, "has_ip": True},
            {
                "domain_id": 1, "scan_id": 12, "has_ip": True,
                "ip": "192.0.2.12", "http_live": True,
            },
            {
                "domain_id": 2, "scan_id": 12, "has_ip": True,
                "ip": "192.0.2.22", "http_live": False,
            },
        ]
        self.providers = [
            {"domain_id": 1, "scan_id": 8, "provider": "Unknown Scan Cloud"},
            {"domain_id": 1, "scan_id": 9, "provider": "Failed Scan Cloud"},
            {"domain_id": 1, "scan_id": 10, "provider": "Running Scan Cloud"},
            {"domain_id": 1, "scan_id": 12, "provider": "Current Cloud"},
            {"domain_id": 2, "scan_id": 12, "provider": "Current Cloud"},
        ]
        self.tech = [
            {"domain_id": 1, "scan_id": 8, "tech": "Legacy Unknown"},
            {"domain_id": 1, "scan_id": 9, "tech": "Legacy Failed"},
            {"domain_id": 1, "scan_id": 10, "tech": "Legacy Running"},
            {"domain_id": 1, "scan_id": 12, "tech": "React"},
            {"domain_id": 1, "scan_id": 12, "tech": "Vite"},
            {"domain_id": 2, "scan_id": 12, "tech": "React"},
        ]
        self.ports = [
            {"domain_id": 1, "scan_id": 8, "port": 22},
            {"domain_id": 1, "scan_id": 9, "port": 80},
            {"domain_id": 1, "scan_id": 10, "port": 8080},
            {"domain_id": 1, "scan_id": 12, "port": 443},
            {"domain_id": 1, "scan_id": 12, "port": 8443},
            {"domain_id": 2, "scan_id": 12, "port": 443},
        ]
        self.asns = [
            {"domain_id": 1, "scan_id": 8, "asn": "AS-OLD"},
            {"domain_id": 1, "scan_id": 12, "asn": "AS-CURRENT"},
            {"domain_id": 2, "scan_id": 12, "asn": "AS-TWO"},
        ]

    @staticmethod
    def normalize(sql):
        return " ".join(sql.lower().split())

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        normalized = self.normalize(sql)

        if "from scans" in normalized:
            self.assert_authoritative_selector(normalized)
            successful = [
                scan_id for scan_id, status in self.statuses.items()
                if status == "SUCCEEDED"
            ]
            self.result = (max(successful),) if successful else None
            return

        if "select dp.provider, count(*)" in normalized:
            self.assert_provider_isolation(normalized, params)
            self.result = self.provider_rows(params[0])
            return

        if "select dt.tech, count(*)" in normalized:
            self.assert_tech_isolation(normalized, params)
            self.result = self.tech_rows(params[0])
            return

        if "select d.domain," in normalized:
            self.assert_target_isolation(normalized, params)
            self.result = self.target_rows(params[0])
            return

        raise AssertionError(f"Unexpected SQL in Package 2B2-A test: {normalized}")

    @staticmethod
    def assert_authoritative_selector(sql):
        assert "status = 'succeeded'" in sql
        assert "order by id desc" in sql
        assert "limit 1" in sql

    @staticmethod
    def assert_provider_isolation(sql, params):
        assert "dp.domain_id = ds.domain_id" in sql
        assert "dp.scan_id = ds.scan_id" in sql
        assert "ds.scan_id = %s" in sql
        assert "dp.scan_id = %s" in sql
        assert params == (12, 12)

    @staticmethod
    def assert_tech_isolation(sql, params):
        assert "dt.domain_id = ds.domain_id" in sql
        assert "dt.scan_id = ds.scan_id" in sql
        assert "ds.scan_id = %s" in sql
        assert "dt.scan_id = %s" in sql
        assert params == (12, 12)

    @staticmethod
    def assert_target_isolation(sql, params):
        for alias in ("dp", "da", "pr"):
            assert f"d.id = {alias}.domain_id" in sql
            assert f"{alias}.scan_id = ds.scan_id" in sql
        assert "where ds.scan_id = %s" in sql
        assert params == (12,)

    def provider_rows(self, scan_id):
        live_domains = {
            row["domain_id"] for row in self.states
            if row["scan_id"] == scan_id and row["has_ip"]
        }
        counts = Counter(
            row["provider"] for row in self.providers
            if row["scan_id"] == scan_id and row["domain_id"] in live_domains
        )
        return sorted(counts.items(), key=lambda row: (-row[1], row[0]))

    def tech_rows(self, scan_id):
        live_domains = {
            row["domain_id"] for row in self.states
            if row["scan_id"] == scan_id and row["has_ip"]
        }
        counts = Counter(
            row["tech"] for row in self.tech
            if row["scan_id"] == scan_id and row["domain_id"] in live_domains
        )
        return sorted(counts.items(), key=lambda row: (-row[1], row[0]))

    def target_rows(self, scan_id):
        rows = []
        for state in self.states:
            if state["scan_id"] != scan_id:
                continue
            domain_id = state["domain_id"]
            current_ports = [
                row["port"] for row in self.ports
                if row["domain_id"] == domain_id and row["scan_id"] == scan_id
            ]
            asn = next((
                row["asn"] for row in self.asns
                if row["domain_id"] == domain_id and row["scan_id"] == scan_id
            ), "unknown")
            provider = next((
                row["provider"] for row in self.providers
                if row["domain_id"] == domain_id and row["scan_id"] == scan_id
            ), "unknown")
            rows.append((
                self.domains[domain_id], state["ip"], state["http_live"],
                len(current_ports), asn, provider,
            ))
        return sorted(rows, key=lambda row: -row[3])

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


class HistoricalCursor:
    def __init__(self):
        self.statuses = {
            19: "UNKNOWN",
            20: "SUCCEEDED",
            21: "FAILED",
            22: "SUCCEEDED",
            23: "RUNNING",
            24: "SUCCEEDED",
        }
        self.domains = {
            1: {"name": "stable.example.test", "is_known": False},
            2: {"name": "changed.example.test", "is_known": True},
        }
        self.states = [
            {"domain_id": 1, "scan_id": 19, "has_ip": False, "http_live": False},
            {"domain_id": 1, "scan_id": 20, "has_ip": True, "http_live": True},
            {"domain_id": 1, "scan_id": 21, "has_ip": False, "http_live": False},
            {"domain_id": 1, "scan_id": 22, "has_ip": True, "http_live": True},
            {"domain_id": 1, "scan_id": 23, "has_ip": False, "http_live": False},
            {"domain_id": 1, "scan_id": 24, "has_ip": True, "http_live": True},
            {"domain_id": 2, "scan_id": 19, "has_ip": False, "http_live": False},
            {"domain_id": 2, "scan_id": 20, "has_ip": True, "http_live": False},
            {"domain_id": 2, "scan_id": 21, "has_ip": True, "http_live": False},
            {"domain_id": 2, "scan_id": 22, "has_ip": False, "http_live": False},
            {"domain_id": 2, "scan_id": 23, "has_ip": True, "http_live": True},
            {"domain_id": 2, "scan_id": 24, "has_ip": False, "http_live": False},
        ]
        self.executions = []
        self.result = None

    @staticmethod
    def normalize(sql):
        return " ".join(sql.lower().split())

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        normalized = self.normalize(sql)

        if "from scans" in normalized:
            successful = [
                scan_id for scan_id, status in self.statuses.items()
                if status == "SUCCEEDED"
            ]
            self.result = (max(successful),) if successful else None
            return

        if "as total_assets" in normalized:
            self.assert_succeeded_history(normalized)
            assert "d.is_known = false" in normalized
            self.result = self.asset_growth_rows()
            return

        if "as resolving" in normalized and "as http_live" in normalized:
            self.assert_succeeded_history(normalized)
            self.result = self.exposure_rows()
            return

        if "as volatility_score" in normalized:
            self.assert_authoritative_window(normalized)
            self.result = [
                (self.domains[domain_id]["name"], flips)
                for domain_id, flips in self.volatility_rows()
            ]
            return

        if "count(*) as flips" in normalized:
            self.assert_authoritative_window(normalized)
            self.result = self.volatility_rows()
            return

        if "d.first_seen_scan" in normalized:
            self.result = []
            return

        if "count(distinct dp.port)" in normalized:
            self.result = []
            return

        if "from domain_provider" in normalized:
            self.result = []
            return

        if "from domain_findings" in normalized:
            self.result = []
            return

        raise AssertionError(f"Unexpected SQL in Package 2B2-B test: {normalized}")

    @staticmethod
    def assert_succeeded_history(sql):
        assert "join scans s" in sql
        assert "s.id = ds.scan_id" in sql
        assert "s.status = 'succeeded'" in sql

    @staticmethod
    def assert_authoritative_window(sql):
        status_position = sql.index("s.status = 'succeeded'")
        lag_position = sql.index("lag(")
        assert "with authoritative_states as" in sql
        assert "from authoritative_states" in sql
        assert status_position < lag_position

    def successful_scan_ids(self):
        return sorted(
            scan_id for scan_id, status in self.statuses.items()
            if status == "SUCCEEDED"
        )

    def exposure_rows(self):
        rows = []
        for scan_id in self.successful_scan_ids():
            states = [row for row in self.states if row["scan_id"] == scan_id]
            rows.append((
                scan_id,
                len(states),
                sum(row["has_ip"] for row in states),
                sum(row["http_live"] for row in states),
            ))
        return rows

    def asset_growth_rows(self):
        rows = []
        for scan_id in self.successful_scan_ids():
            states = [row for row in self.states if row["scan_id"] == scan_id]
            rows.append((
                scan_id,
                len(states),
                sum(row["has_ip"] for row in states),
                sum(
                    row["has_ip"] and not self.domains[row["domain_id"]]["is_known"]
                    for row in states
                ),
            ))
        return rows

    def volatility_rows(self):
        rows = []
        successful = set(self.successful_scan_ids())
        for domain_id in self.domains:
            history = sorted(
                (
                    row for row in self.states
                    if row["domain_id"] == domain_id and row["scan_id"] in successful
                ),
                key=lambda row: row["scan_id"],
            )
            flips = sum(
                previous["has_ip"] != current["has_ip"]
                for previous, current in zip(history, history[1:])
            )
            if flips:
                rows.append((domain_id, flips))
        return sorted(rows, key=lambda row: -row[1])

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class McpCursor:
    def __init__(self, statuses=None):
        self.statuses = statuses if statuses is not None else {
            29: "SUCCEEDED",
            30: "UNKNOWN",
            31: "SUCCEEDED",
            32: "FAILED",
            33: "RUNNING",
        }
        self.domains = {
            1: {
                "domain": "current.example.test", "is_known": False,
                "scannable": True, "confidence_score": 90,
                "confidence_label": "high",
            },
            2: {
                "domain": "historical-live.example.test", "is_known": False,
                "scannable": False, "confidence_score": 85,
                "confidence_label": "high",
            },
            3: {
                "domain": "historical-risk.example.test", "is_known": False,
                "scannable": False, "confidence_score": 70,
                "confidence_label": "medium",
            },
            4: {
                "domain": "priority.example.test", "is_known": False,
                "scannable": False, "confidence_score": 95,
                "confidence_label": "high",
            },
        }
        self.states = [
            {"domain_id": 1, "scan_id": 29, "ip": "192.0.2.29", "http_status": 201, "has_ip": True},
            {"domain_id": 1, "scan_id": 30, "ip": "192.0.2.30", "http_status": 202, "has_ip": True},
            {"domain_id": 1, "scan_id": 31, "ip": "192.0.2.31", "http_status": 200, "has_ip": True},
            {"domain_id": 1, "scan_id": 32, "ip": "192.0.2.32", "http_status": 503, "has_ip": True},
            {"domain_id": 1, "scan_id": 33, "ip": "192.0.2.33", "http_status": 500, "has_ip": True},
            {"domain_id": 2, "scan_id": 29, "ip": "192.0.2.42", "http_status": 200, "has_ip": True},
            {"domain_id": 2, "scan_id": 31, "ip": None, "http_status": None, "has_ip": False},
            {"domain_id": 3, "scan_id": 31, "ip": "192.0.2.53", "http_status": 200, "has_ip": True},
            {"domain_id": 4, "scan_id": 31, "ip": "192.0.2.64", "http_status": 200, "has_ip": True},
        ]
        self.risks = [
            {"domain_id": 1, "scan_id": 29, "risk_score": 9, "reasons": ["old"]},
            {"domain_id": 1, "scan_id": 30, "risk_score": 7, "reasons": ["unknown"]},
            {"domain_id": 1, "scan_id": 31, "risk_score": 4, "reasons": ["current"]},
            {"domain_id": 1, "scan_id": 32, "risk_score": 10, "reasons": ["failed"]},
            {"domain_id": 1, "scan_id": 33, "risk_score": 11, "reasons": ["running"]},
            {"domain_id": 2, "scan_id": 29, "risk_score": 8, "reasons": ["old"]},
            {"domain_id": 2, "scan_id": 31, "risk_score": 6, "reasons": ["current"]},
            {"domain_id": 3, "scan_id": 29, "risk_score": 9, "reasons": ["old"]},
            {"domain_id": 3, "scan_id": 31, "risk_score": 1, "reasons": ["current"]},
            {"domain_id": 4, "scan_id": 31, "risk_score": 5, "reasons": ["current"]},
            {"domain_id": 4, "scan_id": 32, "risk_score": 12, "reasons": ["failed"]},
        ]
        self.executions = []
        self.result = None

    @staticmethod
    def normalize(sql):
        return " ".join(sql.lower().split())

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        normalized = self.normalize(sql)

        if "from scans" in normalized:
            successful = [
                scan_id for scan_id, status in self.statuses.items()
                if status == "SUCCEEDED"
            ]
            self.result = (max(successful),) if successful else None
            return

        if "dr.reasons" in normalized:
            self.assert_domain_isolation(normalized, params)
            self.result = self.domain_row(params[2], params[0])
            return

        if "where dr.scan_id = %s" in normalized and "dr.risk_score >= 3" in normalized:
            self.assert_high_risk_isolation(normalized, params)
            self.result = self.high_risk_rows(params[0])
            return

        if "d.confidence_label in ('medium', 'high')" in normalized:
            self.assert_priority_isolation(normalized, params)
            self.result = self.priority_rows(params[0])
            return

        raise AssertionError(f"Unexpected SQL in Package 2B2-C test: {normalized}")

    @staticmethod
    def assert_domain_isolation(sql, params):
        assert "ds.scan_id = %s" in sql
        assert "dr.scan_id = %s" in sql
        assert "order by ds.scan_id" not in sql
        assert "max(" not in sql
        assert params[:2] == (31, 31)

    @staticmethod
    def assert_high_risk_isolation(sql, params):
        assert "where dr.scan_id = %s" in sql
        assert "dr.risk_score >= 3" in sql
        assert "order by dr.risk_score desc" in sql
        assert "limit 20" in sql
        assert params == (31,)

    @staticmethod
    def assert_priority_isolation(sql, params):
        assert "dr.scan_id = %s" in sql
        assert "ds.scan_id = %s" in sql
        assert "ds.has_ip = true" in sql
        assert "order by coalesce(dr.risk_score, 0) desc" in sql
        assert "limit 20" in sql
        assert params == (31, 31)

    def domain_row(self, domain_name, scan_id):
        match = next((
            (domain_id, domain) for domain_id, domain in self.domains.items()
            if domain["domain"] == domain_name
        ), None)
        if match is None:
            return None
        domain_id, domain = match
        state = next((
            row for row in self.states
            if row["domain_id"] == domain_id and row["scan_id"] == scan_id
        ), None)
        risk = next((
            row for row in self.risks
            if row["domain_id"] == domain_id and row["scan_id"] == scan_id
        ), None)
        return (
            domain["domain"],
            domain["is_known"],
            state["ip"] if state else None,
            state["http_status"] if state else None,
            risk["risk_score"] if risk else None,
            risk["reasons"] if risk else None,
        )

    def high_risk_rows(self, scan_id):
        rows = [
            (self.domains[row["domain_id"]]["domain"], row["risk_score"])
            for row in self.risks
            if row["scan_id"] == scan_id and row["risk_score"] >= 3
        ]
        return sorted(rows, key=lambda row: -row[1])[:20]

    def priority_rows(self, scan_id):
        current_risk = {
            row["domain_id"]: row["risk_score"] for row in self.risks
            if row["scan_id"] == scan_id
        }
        current_live = {
            row["domain_id"] for row in self.states
            if row["scan_id"] == scan_id and row["has_ip"]
        }
        rows = []
        for domain_id, domain in self.domains.items():
            if domain["scannable"] is not False:
                continue
            if domain["confidence_label"] not in ("medium", "high"):
                continue
            if domain_id not in current_live:
                continue
            rows.append((
                domain["domain"], domain["scannable"],
                domain["confidence_score"], domain["confidence_label"],
                current_risk.get(domain_id, 0),
            ))
        return sorted(rows, key=lambda row: (row[4], row[2]), reverse=True)[:20]

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class CurrentSnapshotIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.SimpleNamespace(
            DB_HOST="unused", DB_NAME="unused", DB_USER="unused", DB_PASSWORD="unused"
        )
        cls.db = load_module(BACKEND / "db.py", {"config": fake_config})
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = cls.db.get_latest_authoritative_scan_id
        fake_db.get_previous_authoritative_scan_id = cls.db.get_previous_authoritative_scan_id
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: "unused"
        cls.main = load_module(BACKEND / "main.py", {
            "db": fake_db, "llm_service": fake_llm,
        })

    def run_endpoint(self, endpoint, statuses=None):
        cursor = SnapshotCursor(statuses or {
            8: "UNKNOWN", 9: "FAILED", 10: "RUNNING", 12: "SUCCEEDED",
        })
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        response = getattr(self.main, endpoint)()
        self.assertTrue(connection.closed)
        return response, cursor

    def test_providers_use_authoritative_scan_and_exclude_other_statuses(self):
        response, cursor = self.run_endpoint("providers")

        self.assertEqual(response, [{"provider": "Current Cloud", "count": 2}])
        self.assertEqual(len(cursor.executions), 2)
        self.assertIn("FROM scans", cursor.executions[0][0])
        self.assertEqual(cursor.executions[1][1], (12, 12))

    def test_providers_preserve_zero_authoritative_contract(self):
        response, cursor = self.run_endpoint(
            "providers", {8: "UNKNOWN", 9: "FAILED", 10: "RUNNING"}
        )

        self.assertEqual(response, [])
        self.assertEqual(len(cursor.executions), 1)

    def test_tech_preserves_current_multi_tech_and_excludes_old_rows(self):
        response, cursor = self.run_endpoint("tech")

        self.assertEqual(response, [
            {"tech": "React", "count": 2},
            {"tech": "Vite", "count": 1},
        ])
        self.assertEqual(len(cursor.executions), 2)
        self.assertEqual(cursor.executions[1][1], (12, 12))

    def test_tech_preserves_zero_authoritative_contract(self):
        response, cursor = self.run_endpoint(
            "tech", {8: "UNKNOWN", 9: "FAILED", 10: "RUNNING"}
        )

        self.assertEqual(response, [])
        self.assertEqual(len(cursor.executions), 1)

    def test_targets_align_all_enrichment_and_preserve_current_ports(self):
        response, cursor = self.run_endpoint("export_targets")

        self.assertEqual(response, [
            {
                "domain": "one.example.test",
                "ip": "192.0.2.12",
                "http_live": True,
                "open_ports": 2,
                "asn": "AS-CURRENT",
                "provider": "Current Cloud",
            },
            {
                "domain": "two.example.test",
                "ip": "192.0.2.22",
                "http_live": False,
                "open_ports": 1,
                "asn": "AS-TWO",
                "provider": "Current Cloud",
            },
        ])
        self.assertEqual(len(cursor.executions), 2)
        self.assertEqual(cursor.executions[1][1], (12,))

    def test_targets_preserve_zero_authoritative_contract(self):
        response, cursor = self.run_endpoint(
            "export_targets", {8: "UNKNOWN", 9: "FAILED", 10: "RUNNING"}
        )

        self.assertEqual(response, [])
        self.assertEqual(len(cursor.executions), 1)


class AuthoritativeHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.SimpleNamespace(
            DB_HOST="unused", DB_NAME="unused", DB_USER="unused", DB_PASSWORD="unused"
        )
        cls.db = load_module(BACKEND / "db.py", {"config": fake_config})
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = cls.db.get_latest_authoritative_scan_id
        fake_db.get_previous_authoritative_scan_id = cls.db.get_previous_authoritative_scan_id
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: "unused"
        cls.main = load_module(BACKEND / "main.py", {
            "db": fake_db, "llm_service": fake_llm,
        })

    def run_endpoint(self, endpoint):
        cursor = HistoricalCursor()
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        response = getattr(self.main, endpoint)()
        self.assertTrue(connection.closed)
        return response, cursor

    def test_exposure_trend_keeps_only_successful_snapshots(self):
        response, cursor = self.run_endpoint("exposure_trend")

        self.assertEqual(response, [
            {"scan_id": 20, "total": 2, "resolving": 2, "http_live": 1},
            {"scan_id": 22, "total": 2, "resolving": 1, "http_live": 1},
            {"scan_id": 24, "total": 2, "resolving": 1, "http_live": 1},
        ])
        self.assertEqual(len(cursor.executions), 1)

    def test_asset_growth_keeps_successes_and_global_known_semantics(self):
        response, cursor = self.run_endpoint("asset_growth")

        self.assertEqual(response, [
            {"scan_id": 20, "total": 2, "live": 2, "shadow": 1},
            {"scan_id": 22, "total": 2, "live": 1, "shadow": 1},
            {"scan_id": 24, "total": 2, "live": 1, "shadow": 1},
        ])
        sql = HistoricalCursor.normalize(cursor.executions[0][0])
        self.assertIn("d.is_known = false", sql)

    def test_volatile_domains_filters_before_lag(self):
        response, cursor = self.run_endpoint("volatile_domains")

        self.assertEqual(response, [
            {"domain": "changed.example.test", "volatility_score": 1},
        ])
        sql = HistoricalCursor.normalize(cursor.executions[0][0])
        self.assertLess(sql.index("s.status = 'succeeded'"), sql.index("lag("))

    def test_risky_domains_volatility_filters_before_lag(self):
        response, cursor = self.run_endpoint("risky_domains")

        self.assertEqual(response, [])
        volatility_sql = next(
            HistoricalCursor.normalize(sql)
            for sql, _ in cursor.executions
            if "COUNT(*) AS flips" in sql
        )
        self.assertLess(
            volatility_sql.index("s.status = 'succeeded'"),
            volatility_sql.index("lag("),
        )

    def test_risky_domains_scoring_model_is_unchanged(self):
        source = inspect.getsource(self.main.risky_domains)

        reason_weights = {
            "new_asset": 3,
            "http_exposed": 1,
            "resolves_no_http": 1,
            "sensitive_ports": 3,
            "many_ports": 1,
            "shadow_asset": 2,
            "cloud": 1,
            "ip_state_volatility": 3,
            "finding": 3,
            "high_finding": 2,
        }
        for reason, weight in reason_weights.items():
            with self.subTest(reason=reason):
                self.assertRegex(
                    source,
                    rf"score \+= {weight}\s+reasons\.append\(\"{reason}\"\)",
                )

        self.assertRegex(source, r"if asset_keywords:\s+score \+= 1")
        self.assertIn("if flips >= 2:", source)
        self.assertIn('reasons.append(\n                "asset_exposure:"', source)
        self.assertRegex(
            source,
            r'if score >= 8:\s+priority = "High"\s+'
            r'elif score >= 6:\s+priority = "Elevated"\s+'
            r'elif score >= 4:\s+priority = "Review"\s+'
            r'else:\s+priority = "Low"',
        )
        self.assertIn("return results[:100]", source)


class McpCurrentSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.SimpleNamespace(
            DB_HOST="unused", DB_NAME="unused", DB_USER="unused", DB_PASSWORD="unused"
        )
        cls.db = load_module(BACKEND / "db.py", {"config": fake_config})
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = cls.db.get_latest_authoritative_scan_id
        cls.mcp = load_module(BACKEND / "mcp_server.py", {"db": fake_db})

    def run_endpoint(self, endpoint, *args, statuses=None):
        cursor = McpCursor(statuses)
        connection = FakeConnection(cursor)
        self.mcp.get_conn = lambda: connection
        response = getattr(self.mcp, endpoint)(*args)
        self.assertTrue(connection.closed)
        return response, cursor

    def test_domain_uses_one_authoritative_state_and_risk_snapshot(self):
        response, cursor = self.run_endpoint(
            "get_domain", "current.example.test"
        )

        self.assertEqual(response, {
            "domain": "current.example.test",
            "is_known": False,
            "ip": "192.0.2.31",
            "http_status": 200,
            "risk_score": 4,
            "reasons": ["current"],
        })
        self.assertEqual(len(cursor.executions), 2)
        self.assertIn("FROM scans", cursor.executions[0][0])
        self.assertEqual(cursor.executions[1][1], (31, 31, "current.example.test"))

    def test_domain_zero_authoritative_uses_existing_not_found_shape(self):
        response, cursor = self.run_endpoint(
            "get_domain", "current.example.test",
            statuses={30: "UNKNOWN", 32: "FAILED", 33: "RUNNING"},
        )

        self.assertEqual(response, {"error": "domain not found"})
        self.assertEqual(len(cursor.executions), 1)

    def test_high_risk_uses_only_current_risk_without_history_duplicates(self):
        response, cursor = self.run_endpoint("high_risk")

        self.assertEqual(response, [
            {"domain": "historical-live.example.test", "risk": 6},
            {"domain": "priority.example.test", "risk": 5},
            {"domain": "current.example.test", "risk": 4},
        ])
        self.assertEqual(len({row["domain"] for row in response}), len(response))
        self.assertEqual(cursor.executions[1][1], (31,))

    def test_high_risk_zero_authoritative_returns_empty_list(self):
        response, cursor = self.run_endpoint(
            "high_risk",
            statuses={30: "UNKNOWN", 32: "FAILED", 33: "RUNNING"},
        )

        self.assertEqual(response, [])
        self.assertEqual(len(cursor.executions), 1)

    def test_priority_targets_align_current_risk_and_liveness(self):
        response, cursor = self.run_endpoint("priority_targets")

        self.assertEqual(response, [
            {
                "domain": "priority.example.test",
                "scannable": False,
                "confidence_score": 95,
                "confidence_label": "high",
                "risk_score": 5,
            },
            {
                "domain": "historical-risk.example.test",
                "scannable": False,
                "confidence_score": 70,
                "confidence_label": "medium",
                "risk_score": 1,
            },
        ])
        self.assertNotIn(
            "historical-live.example.test",
            {row["domain"] for row in response},
        )
        self.assertEqual(cursor.executions[1][1], (31, 31))

    def test_priority_targets_zero_authoritative_returns_empty_list(self):
        response, cursor = self.run_endpoint(
            "priority_targets",
            statuses={30: "UNKNOWN", 32: "FAILED", 33: "RUNNING"},
        )

        self.assertEqual(response, [])
        self.assertEqual(len(cursor.executions), 1)


if __name__ == "__main__":
    unittest.main()
