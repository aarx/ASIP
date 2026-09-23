"""Package 2B2-A REST current-snapshot isolation regression tests."""

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
