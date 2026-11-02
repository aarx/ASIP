"""Regression tests for the bounded current certificate-expiry contract."""

import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from datetime import date
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = BACKEND / "asm_schema_post_guardrails-schema-only.sql"
sys.path.insert(0, str(BACKEND))


def load_main():
    def get_latest_authoritative_scan_id(cursor):
        cursor.execute("""
            SELECT id
            FROM scans
            WHERE status = 'SUCCEEDED'
            ORDER BY id DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        return row[0] if row else None

    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = get_latest_authoritative_scan_id
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: None
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    module_name = f"cert_expiry_main_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / "main.py")
    module = importlib.util.module_from_spec(spec)
    previous = {name: sys.modules.get(name) for name in ("db", "llm_service")}
    try:
        sys.modules.update({"db": fake_db, "llm_service": fake_llm})
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module


class CertificateCursor:
    def __init__(self, rows, current_scan=16):
        self.rows = rows
        self.current_scan = current_scan
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return (self.current_scan,)

    def fetchall(self):
        return self.rows[:50]


class CertificateConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False

    def cursor(self):
        return self.cursor_value

    def close(self):
        self.closed = True


class CertificateExpiryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    @staticmethod
    def rows():
        # The stored days intentionally disagree with actual expiry ordering.
        return [
            ("expired.example", date(2025, 1, 1), 900, "healthy"),
            ("urgent.example", date(2026, 11, 3), -900, "expired"),
            ("upcoming.example", date(2026, 12, 1), 1, "critical"),
            ("missing.example", None, 0, "healthy"),
        ]

    def run_endpoint(self, rows=None, current_scan=16):
        cursor = CertificateCursor(rows or self.rows(), current_scan=current_scan)
        connection = CertificateConnection(cursor)
        self.main.get_conn = lambda: connection
        response = self.main.cert_expiry()
        self.assertTrue(connection.closed)
        return response, cursor

    def test_orders_by_actual_expiry_and_preserves_response_shape(self):
        response, cursor = self.run_endpoint()
        query, params = cursor.executions[1]
        normalized = " ".join(query.lower().split())

        self.assertIn("order by dc.expiry_date asc nulls last, d.domain asc", normalized)
        self.assertNotIn("order by dc.days_to_expiry", normalized)
        self.assertIn("limit 50", normalized)
        self.assertIn("d.ownership_status = 'confirmed'", normalized)
        self.assertEqual(params, (16,))
        self.assertEqual(response, [
            {"domain": "expired.example", "expiry": "2025-01-01", "days": 900, "status": "healthy"},
            {"domain": "urgent.example", "expiry": "2026-11-03", "days": -900, "status": "expired"},
            {"domain": "upcoming.example", "expiry": "2026-12-01", "days": 1, "status": "critical"},
            {"domain": "missing.example", "expiry": None, "days": 0, "status": "healthy"},
        ])

    def test_uses_latest_successful_scan_scope(self):
        _response, cursor = self.run_endpoint(current_scan=42)
        selector, _selector_params = cursor.executions[0]
        query, params = cursor.executions[1]
        selector_sql = " ".join(selector.lower().split())
        normalized = " ".join(query.lower().split())

        self.assertIn("where status = 'succeeded'", selector_sql)
        self.assertIn("order by id desc", selector_sql)
        self.assertIn("where dc.scan_id = %s", normalized)
        self.assertEqual(params, (42,))

    def test_schema_prevents_duplicate_current_scan_observations(self):
        schema = SCHEMA.read_text(encoding="utf-8")
        self.assertIn("expiry_date date", schema)
        self.assertIn(
            "ADD CONSTRAINT unique_domain_cert UNIQUE (domain_id, scan_id)",
            schema,
        )
        self.assertIn(
            "ADD CONSTRAINT domains_domain_key UNIQUE (domain)",
            schema,
        )
        worker = (BACKEND / "cert_worker.py").read_text(encoding="utf-8")
        self.assertIn('datetime.strptime(expiry, "%Y%m%d%H%M%SZ")', worker)
        self.assertIn("return None", worker)

    def test_limit_boundary_keeps_at_most_fifty_distinct_rows(self):
        rows = [
            (f"asset-{index:02d}.example", date(2026, 11, 3), -index, "expired")
            for index in range(51)
        ]
        response, cursor = self.run_endpoint(rows)

        self.assertEqual(len(response), 50)
        query, _params = cursor.executions[1]
        self.assertIn("LIMIT 50", query.upper())
        self.assertEqual(len({row["domain"] for row in response}), 50)


if __name__ == "__main__":
    unittest.main()
