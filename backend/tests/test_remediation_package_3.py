import ast
import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from risk_engine import (  # noqa: E402
    RISK_WEIGHTS,
    RiskEvidence,
    calculate_scan_risks,
    calculate_risk,
    get_asset_exposure_keywords,
    priority_for_score,
)


def evidence(**overrides):
    values = {
        "scan_id": 20,
        "domain_id": 1,
        "domain": "plain.example.com",
        "first_seen_scan": 10,
        "is_known": True,
        "has_ip": False,
        "http_observation_status": "UNKNOWN",
    }
    values.update(overrides)
    return RiskEvidence(**values)


class CanonicalCalculatorTests(unittest.TestCase):
    def test_zero_is_low(self):
        result = calculate_risk(evidence())
        self.assertEqual((result.score, result.priority, result.reasons), (0, "Low", ()))

    def test_each_approved_signal_has_exact_weight(self):
        cases = {
            "new_asset": evidence(first_seen_scan=20),
            "http_exposed": evidence(http_observation_status="RESPONDED"),
            "resolves_no_http": evidence(
                has_ip=True, http_observation_status="NO_RESPONSE"
            ),
            "sensitive_ports": evidence(sensitive_port_count=1),
            "many_ports": evidence(port_count=4),
            "shadow_asset": evidence(is_known=False),
            "cloud": evidence(provider="Amazon Web Services"),
            "asset_exposure": evidence(domain="dev.example.com"),
            "ip_state_volatility": evidence(volatility_flips=2),
            "finding": evidence(finding_count=1),
        }
        for signal, item in cases.items():
            with self.subTest(signal=signal):
                result = calculate_risk(item)
                self.assertEqual(result.score, RISK_WEIGHTS[signal])
                self.assertTrue(any(reason.startswith(signal) for reason in result.reasons))

        high = calculate_risk(evidence(finding_count=1, high_finding_count=1))
        self.assertEqual(
            high.score,
            RISK_WEIGHTS["finding"] + RISK_WEIGHTS["high_finding"],
        )
        self.assertEqual(high.reasons, ("finding", "high_finding"))

    def test_additive_score_is_uncapped(self):
        result = calculate_risk(evidence(
            first_seen_scan=20,
            is_known=False,
            has_ip=True,
            http_observation_status="RESPONDED",
            port_count=4,
            sensitive_port_count=1,
            provider="Google Cloud",
            domain="admin-dev.example.com",
            volatility_flips=2,
            finding_count=2,
            high_finding_count=1,
        ))
        self.assertEqual(result.score, 20)
        self.assertEqual(result.priority, "High")

    def test_priority_boundaries(self):
        expected = {
            0: "Low", 3: "Low", 4: "Review", 5: "Review",
            6: "Elevated", 7: "Elevated", 8: "High", 25: "High",
        }
        for score, priority in expected.items():
            with self.subTest(score=score):
                self.assertEqual(priority_for_score(score), priority)

    def test_http_outcomes_require_explicit_observation(self):
        self.assertEqual(
            calculate_risk(evidence(http_observation_status="RESPONDED")).reasons,
            ("http_exposed",),
        )
        self.assertEqual(
            calculate_risk(evidence(
                has_ip=True, http_observation_status="NO_RESPONSE"
            )).reasons,
            ("resolves_no_http",),
        )
        for status in ("FAILED", "UNKNOWN"):
            with self.subTest(status=status):
                self.assertEqual(
                    calculate_risk(evidence(
                        has_ip=True, http_observation_status=status
                    )).reasons,
                    (),
                )
        self.assertEqual(
            calculate_risk(evidence(
                has_ip=False, http_observation_status="NO_RESPONSE"
            )).reasons,
            (),
        )

    def test_ports_require_positive_rows(self):
        self.assertEqual(calculate_risk(evidence()).score, 0)
        self.assertEqual(
            calculate_risk(evidence(sensitive_port_count=1)).reasons,
            ("sensitive_ports",),
        )
        self.assertEqual(
            calculate_risk(evidence(port_count=4)).reasons,
            ("many_ports",),
        )

    def test_asset_keywords_preserve_stage_distinction(self):
        self.assertEqual(get_asset_exposure_keywords("stage.example"), ["STAGE"])
        self.assertEqual(get_asset_exposure_keywords("staging.example"), ["STAGING"])


class CanonicalIntegrationContractTests(unittest.TestCase):
    def test_evidence_adapter_calculates_one_exact_member_from_observed_data(self):
        class Cursor:
            def __init__(self):
                self.executions = []
                self.results = iter([
                    [(1, "dev.example.com", 20, False, "CONFIRMED", True, "NO_RESPONSE")],
                    [(1, 4, 1)],
                    [(1, "AWS")],
                    [(1, 1, 1)],
                    [(1, 2)],
                ])

            def execute(self, sql, params=None):
                self.executions.append((sql, params))

            def fetchall(self):
                return next(self.results)

        cursor = Cursor()
        risks = calculate_scan_risks(cursor, 20)

        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0].result.score, 20)
        self.assertEqual(risks[0].result.priority, "High")
        self.assertEqual(
            risks[0].result.reasons,
            (
                "new_asset", "resolves_no_http", "sensitive_ports",
                "many_ports", "shadow_asset", "cloud",
                "asset_exposure:DEV", "ip_state_volatility",
                "finding", "high_finding",
            ),
        )
        normalized = [" ".join(sql.upper().split()) for sql, _ in cursor.executions]
        self.assertTrue(all("SCAN_RESULTS SR" in sql for sql in normalized))
        self.assertIn("S.STATUS = 'SUCCEEDED'", normalized[-1])

    def test_worker_persists_shared_result_with_guard_and_retry_safe_upsert(self):
        class Cursor:
            rowcount = 1

            def __init__(self):
                self.executions = []

            def execute(self, sql, params=None):
                self.executions.append((sql, params))

        class Connection:
            def __init__(self):
                self.cur = Cursor()
                self.committed = False
                self.closed = False

            def cursor(self):
                return self.cur

            def commit(self):
                self.committed = True

            def close(self):
                self.closed = True

        connection = Connection()
        guard = mock.Mock()
        fake_db = types.ModuleType("db")
        fake_db.get_conn = mock.Mock(return_value=connection)
        fake_db.require_running_scan = guard
        module_name = f"package3_risk_worker_{len(sys.modules)}"
        spec = importlib.util.spec_from_file_location(
            module_name, BACKEND / "risk_worker.py"
        )
        module = importlib.util.module_from_spec(spec)
        previous_db = sys.modules.get("db")
        argv = sys.argv[:]
        try:
            sys.modules["db"] = fake_db
            sys.argv = ["risk_worker.py", "20"]
            with mock.patch(
                "logging.FileHandler", return_value=logging.NullHandler()
            ):
                spec.loader.exec_module(module)
            result = types.SimpleNamespace(
                score=8, priority="High", reasons=("new_asset", "finding", "shadow_asset")
            )
            module.calculate_scan_risks = mock.Mock(return_value=[
                types.SimpleNamespace(domain_id=1, result=result)
            ])
            module.main()
        finally:
            sys.argv = argv
            if previous_db is None:
                sys.modules.pop("db", None)
            else:
                sys.modules["db"] = previous_db

        guard.assert_called_once_with(connection.cur, 20)
        module.calculate_scan_risks.assert_called_once_with(connection.cur, 20)
        delete_sql, delete_params = connection.cur.executions[0]
        self.assertIn("DELETE FROM domain_risk", delete_sql)
        self.assertIn("ownership_status <> 'CONFIRMED'", delete_sql)
        self.assertEqual(delete_params, (20,))
        sql, params = connection.cur.executions[1]
        self.assertIn("ON CONFLICT(domain_id, scan_id)", sql)
        self.assertIn("FROM scan_results sr", sql)
        self.assertEqual(params, (1, 20, 8, '["new_asset","finding","shadow_asset"]', 20, 1))
        self.assertTrue(connection.committed)
        self.assertTrue(connection.closed)

    def test_evidence_adapter_anchors_membership_and_succeeded_history(self):
        source = (BACKEND / "risk_engine.py").read_text(encoding="utf-8")
        normalized = " ".join(source.upper().split())
        self.assertIn("FROM SCAN_RESULTS SR JOIN DOMAINS D", normalized)
        self.assertIn("S.STATUS = 'SUCCEEDED'", normalized)
        self.assertIn("DS.SCAN_ID < %S", normalized)
        self.assertIn("WHERE DS.SCAN_ID = %S", normalized)
        self.assertNotIn("HTTP_STATUS == 0", normalized)

    def test_worker_uses_only_shared_calculator_and_guarded_upsert(self):
        source = (BACKEND / "risk_worker.py").read_text(encoding="utf-8")
        self.assertIn("calculate_scan_risks(cur, scan_id)", source)
        self.assertIn("require_running_scan(cur, scan_id)", source)
        self.assertIn("ON CONFLICT(domain_id, scan_id)", source)
        self.assertIn("FROM scan_results sr", source)
        for legacy in (
            "unknown_stack", "unknown_hosting", "cert_expiring",
            "critical_port_exposed", "web_entrypoint_present",
            "infra_only_exposure", "high_risk_unknown_service",
        ):
            self.assertNotIn(legacy, source)

    def test_current_consumers_do_not_read_legacy_domain_risk(self):
        for filename in ("main.py", "mcp_server.py"):
            with self.subTest(filename=filename):
                source = (BACKEND / filename).read_text(encoding="utf-8")
                self.assertNotIn("domain_risk", source.lower())
                self.assertIn("calculate_scan_risks", source)

    def test_summary_risk_labels_use_shared_priority_and_observed_http(self):
        main = (BACKEND / "main.py").read_text(encoding="utf-8")
        for function_name in ("shadow_summary", "non_web_summary"):
            start = main.index(f"def {function_name}(")
            end = main.find("\n@app.get", start)
            block = main[start:end]
            self.assertIn("calculate_scan_risks(cur, scan_id)", block)
            self.assertIn('http_observation_status == "NO_RESPONSE"', block)
            self.assertNotIn("COUNT(sp.port)", block)

    def test_ai_uses_deterministic_results_without_recalculation(self):
        source = (BACKEND / "main.py").read_text(encoding="utf-8")
        self.assertIn("Do NOT recalculate the risk score", source)
        self.assertIn("risk_data = risky_domains()", source)
        self.assertIn("Canonical Risk Score:", source)

    def test_frontend_filters_on_backend_priority_not_numeric_score_thresholds(self):
        source = (
            BACKEND.parent
            / "frontend/asm-dashboard/src/components/InvestigationTable.js"
        ).read_text(encoding="utf-8")
        self.assertIn("priorityRank[d.priority]", source)
        self.assertIn('value="Review"', source)
        self.assertIn('value="Elevated"', source)
        self.assertIn('value="High"', source)
        self.assertNotIn('value="3"', source)

    def test_authorization_and_known_shadow_modules_are_unchanged_dependencies(self):
        authorization = (BACKEND / "authorization_policy.py").read_text(encoding="utf-8")
        self.assertIn("validation_source = 'manual'", authorization)
        engine = (BACKEND / "risk_engine.py").read_text(encoding="utf-8")
        self.assertNotIn("scannable", engine)
        self.assertNotIn("validation_source", engine)
        self.assertIn("evidence.is_known is False", engine)

    def test_no_schema_or_migration_is_added_for_package_3(self):
        migrations = sorted(path.name for path in (BACKEND / "migrations").glob("*.sql"))
        self.assertTrue({
            "001_add_scan_lifecycle.sql",
            "002_add_http_observation_status.sql",
            "003_add_ownership_status.sql",
        }.issubset(migrations))
        self.assertNotIn("009_add_package_3.sql", migrations)


if __name__ == "__main__":
    unittest.main()
