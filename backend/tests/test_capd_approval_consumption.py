import importlib
import pathlib
import sys
import threading
import unittest
import uuid
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

import optional_migrations  # noqa: E402
import capd_approval_consumption as consumption  # noqa: E402
from apache_version_verification import (  # noqa: E402
    APACHE_CHECK_ID, APACHE_CHECK_REVISION, create_authorization_context,
)
from capd_approval_contract import CAPD_HTTP_HEADER_VERIFY  # noqa: E402
from capd_approval_consumption import (  # noqa: E402
    ApprovalConsumptionError, consume_approval,
)
from apache_version_executor import (  # noqa: E402
    ApacheHTTPTransportError, BoundedApacheHTTPTransport,
    execute_approved_apache_check,
)
from capd_local_approval import build_approval_payload, sign_approval  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

_fixture = importlib.import_module("test_remediation_package_2d1c")


class MockBoundedApacheHTTPTransport(BoundedApacheHTTPTransport):
    def __init__(self):
        self.request = mock.Mock()


class CapdApprovalConsumptionPostgreSQLTests(unittest.TestCase):
    """Single-use receipt behavior against disposable PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        _fixture.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        connection = cls.connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_at timestamptz")
                    cursor.execute("ALTER TABLE domains ALTER COLUMN ownership_status DROP NOT NULL")
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS scannable boolean DEFAULT TRUE")
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS active_scan_scopes (
                            scope_domain text, include_subdomains boolean,
                            testing_level text, status text, expires_at timestamptz,
                            excluded_domains text[] DEFAULT ARRAY[]::text[]
                        )
                    """)
                    cursor.execute((BACKEND / "migrations/015_add_capd_runs.sql").read_text())
                    cursor.execute((BACKEND / "migrations/017_add_capd_approval_consumptions.sql").read_text())
                    cursor.execute("""
                        INSERT INTO scans(id,status,completed_at)
                        VALUES (991,'SUCCEEDED',CURRENT_TIMESTAMP)
                        ON CONFLICT (id) DO UPDATE SET status='SUCCEEDED';
                        INSERT INTO domains(id,domain,ownership_status,scannable)
                        VALUES (9991,'apache.example.test','CONFIRMED',TRUE)
                        ON CONFLICT (id) DO UPDATE SET ownership_status='CONFIRMED',scannable=TRUE
                    """)
        except Exception:
            _fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)
            raise
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        _fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)

    @classmethod
    def connect(cls):
        return cls.psycopg2.connect(**cls.connection_args)

    def setUp(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM capd_approval_consumptions")
        connection.close()
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.now = datetime.now(timezone.utc)
        self.run_id = str(uuid.uuid4())
        self.payload = build_approval_payload(
            run_id=self.run_id, source_scan_id=991, asset_id=9991,
            domain="apache.example.test", origin="https://apache.example.test/",
            operator_uid=1001, operator_name="capd-operator", now=self.now,
        )
        self.document = sign_approval(self.payload, self.private_key)
        self.context = create_authorization_context(
            APACHE_CHECK_ID, APACHE_CHECK_REVISION, 991, run_id=self.run_id,
            now=self.now, expires_at=datetime.fromisoformat(self.payload["expires_at"]),
        )
        self.target = {
            "domain_id": 9991, "domain": "apache.example.test",
            "source_scan_id": 991, "asset_class": "KNOWN", "scannable": True,
            "inventory_eligible": True, "classification": "VERSION_UNKNOWN",
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "confidence": "high",
                "observed_url": "https://apache.example.test/",
            }],
        }

    def consume(self, conn, *, document=None, target=None, context=None, recheck=None, now=None):
        with mock.patch.object(
            consumption, "recheck_apache_target_from_inventory",
            side_effect=recheck or (lambda *_args, **_kwargs: {
                "inventory_policy_passed": True, "reason_codes": [],
            }),
        ):
            return consume_approval(
                conn, document or self.document, self.public_key,
                context or self.context, target or self.target, now=now,
            )

    def test_first_consumption_persists_auditable_receipt_and_replay_fails(self):
        conn = self.connect()
        with conn.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM capd_runs")
            capd_runs_before = cursor.fetchone()[0]
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            receipt = self.consume(conn)
            self.assertTrue(receipt["consumption_committed"])
            self.assertEqual(receipt["request_budget"], 1)
        conn.close()  # Simulate process loss after the durable receipt commit.
        conn = self.connect()
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            with self.assertRaisesRegex(ApprovalConsumptionError, "already consumed"):
                self.consume(conn)
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT run_id, approval_sha256, check_id, check_revision,
                       source_scan_id, domain_id, origin, http_method,
                       request_budget, operator_uid, authorization_receipt
                  FROM capd_approval_consumptions
            """)
            row = cursor.fetchone()
        self.assertEqual(str(row[0]), self.run_id)
        self.assertEqual(row[1], receipt["approval_sha256"])
        self.assertEqual(row[2:10], (
            APACHE_CHECK_ID, APACHE_CHECK_REVISION, 991, 9991,
            "https://apache.example.test/", "GET", 1, 1001,
        ))
        self.assertEqual(row[10]["decision"], "AUTHORIZED")
        self.assertIsNotNone(receipt["consumed_at"])
        with conn.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM capd_runs")
            self.assertEqual(cursor.fetchone()[0], capd_runs_before)
        conn.close()

    def test_concurrent_replays_have_exactly_one_committed_winner(self):
        barrier = threading.Barrier(2)

        def fresh_recheck(*_args, **_kwargs):
            barrier.wait(timeout=5)
            return {"inventory_policy_passed": True, "reason_codes": []}

        def attempt():
            conn = self.connect()
            try:
                return consume_approval(
                    conn, self.document, self.public_key,
                    self.context, self.target,
                )["consumption_committed"]
            except ApprovalConsumptionError:
                return False
            finally:
                conn.close()

        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            with mock.patch.object(
                consumption, "recheck_apache_target_from_inventory",
                side_effect=fresh_recheck,
            ):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(lambda _index: attempt(), range(2)))
        self.assertEqual(sorted(results), [False, True])
        conn = self.connect()
        with conn.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM capd_approval_consumptions WHERE run_id=%s", (self.run_id,))
            self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_expired_tampered_wrong_scope_disabled_and_revoked_approvals_fail_closed(self):
        conn = self.connect()
        expired = self.now.replace(year=self.now.year - 1)
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            with self.assertRaises(ApprovalConsumptionError):
                self.consume(conn, now=expired)
            with self.assertRaises(ApprovalConsumptionError):
                self.consume(conn, document=self.document + "x")
            wrong_revision = dict(self.payload, check_revision="9.9.9")
            with self.assertRaises(ApprovalConsumptionError):
                self.consume(conn, document=sign_approval(wrong_revision, self.private_key))
            wrong_scan = build_approval_payload(
                run_id=str(uuid.uuid4()), source_scan_id=992, asset_id=9991,
                domain="apache.example.test", origin="https://apache.example.test/",
                operator_uid=1001, operator_name="capd-operator", now=self.now,
            )
            with self.assertRaisesRegex(ApprovalConsumptionError, "does not match"):
                self.consume(conn, document=sign_approval(wrong_scan, self.private_key))
            with self.assertRaisesRegex(ApprovalConsumptionError, "does not match"):
                self.consume(conn, target={**self.target, "domain_id": 9992})
            wrong_service = {**self.target, "evidence": [{
                **self.target["evidence"][0], "observed_url": "https://other.example.test/",
            }]}
            with self.assertRaisesRegex(ApprovalConsumptionError, "does not match"):
                self.consume(conn, target=wrong_service)
            with self.assertRaisesRegex(ApprovalConsumptionError, "authorization denied"):
                self.consume(conn, recheck=lambda *_a, **_k: {
                    "inventory_policy_passed": False,
                    "reason_codes": ["TARGET_NOT_SCANNABLE"],
                })
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "HTTP_TLS_OBSERVATION"}):
            with self.assertRaisesRegex(ApprovalConsumptionError, "authorization denied"):
                self.consume(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM capd_approval_consumptions")
            self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

    def test_database_failure_denies_permit_and_rolls_back(self):
        conn = mock.MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value

        def fail_receipt_insert(sql, *_args):
            if "INSERT INTO public.capd_approval_consumptions" in sql:
                raise RuntimeError("db down")

        cursor.execute.side_effect = fail_receipt_insert
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            with mock.patch.object(
                consumption, "recheck_apache_target_from_inventory",
                return_value={"inventory_policy_passed": True, "reason_codes": []},
            ):
                with self.assertRaisesRegex(ApprovalConsumptionError, "could not be persisted"):
                    consume_approval(
                        conn, self.document, self.public_key,
                        self.context, self.target,
                    )
        conn.rollback.assert_called_once()
        conn.commit.assert_not_called()

    def execute(self, conn, *, document=None, target=None, context=None,
                transport=None, resolver=None, now=None):
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            with mock.patch.object(
                consumption, "recheck_apache_target_from_inventory",
                return_value={"inventory_policy_passed": True, "reason_codes": []},
            ):
                return execute_approved_apache_check(
                    conn, document or self.document, self.public_key,
                    context or self.context, target or self.target,
                    resolver=resolver or (lambda *_args, **_kwargs: ["8.8.8.8"]),
                    transport=transport or mock.Mock(), now=now or self.now,
                )

    def test_end_to_end_executor_commits_before_exactly_one_request(self):
        conn = self.connect()
        response = type("Response", (), {
            "status_code": 200, "headers": {"sErVeR": "Apache/2.4.58 (Unix)"},
        })()
        transport = MockBoundedApacheHTTPTransport()
        transport.request.return_value = response
        result = self.execute(conn, transport=transport)
        self.assertEqual(result["outcome"], "VERSION_IDENTIFIED")
        self.assertEqual(result["version"], "2.4.58")
        self.assertEqual(result["product"], "apache")
        self.assertEqual(result["http_request_count"], 1)
        self.assertEqual(result["source_http_server_header"], "Apache/2.4.58 (Unix)")
        self.assertEqual(result["source_scan_id"], 991)
        self.assertEqual(result["check_revision"], APACHE_CHECK_REVISION)
        self.assertTrue(result["authorization_receipt_reference"])
        transport.request.assert_called_once_with(
            "https://apache.example.test/", "8.8.8.8", method="GET", timeout=3.0,
        )
        conn.close()

    def test_invalid_approval_disabled_operation_and_wrong_binding_block_before_request(self):
        conn = self.connect()
        transport = MockBoundedApacheHTTPTransport()
        resolver = mock.Mock(return_value=["8.8.8.8"])
        bad = self.document + "tampered"
        result = execute_approved_apache_check(
            conn, bad, self.public_key, self.context, self.target,
            resolver=resolver, transport=transport, now=self.now,
        )
        self.assertEqual(result["outcome"], "NOT_AUTHORIZED")
        resolver.assert_not_called()
        transport.request.assert_not_called()
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "HTTP_TLS_OBSERVATION"}):
            result = execute_approved_apache_check(
                conn, self.document, self.public_key, self.context, self.target,
                resolver=resolver, transport=transport, now=self.now,
            )
        self.assertEqual(result["outcome"], "NOT_AUTHORIZED")
        resolver.assert_not_called()
        transport.request.assert_not_called()
        with conn.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM capd_approval_consumptions")
            self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

    def test_executor_rejects_expired_wrong_asset_service_revision_and_revoked_target(self):
        cases = [
            ("expired", None),
            ("asset", None),
            ("service", None),
            ("revision", None),
            ("revoked", {
                "inventory_policy_passed": False,
                "reason_codes": ["TARGET_NOT_SCANNABLE"],
            }),
        ]
        for label, recheck_result in cases:
            with self.subTest(case=label):
                self.setUp()
                # Rebind the generated valid approval for each case while
                # retaining the requested failure condition.
                if label == "revision":
                    document = sign_approval(
                        {**self.payload, "check_revision": "9.9.9"}, self.private_key,
                    )
                else:
                    document = self.document
                context = self.context
                if label == "asset":
                    target_value = {**self.target, "domain_id": 9992}
                elif label == "service":
                    target_value = {**self.target, "evidence": [{
                        **self.target["evidence"][0],
                        "observed_url": "https://other.example.test/",
                    }]}
                else:
                    target_value = self.target
                if label == "expired":
                    now = self.now.replace(year=self.now.year + 1)
                else:
                    now = self.now
                resolver = mock.Mock(return_value=["8.8.8.8"])
                transport = MockBoundedApacheHTTPTransport()
                with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
                    with mock.patch.object(
                        consumption, "recheck_apache_target_from_inventory",
                        return_value=recheck_result or {
                            "inventory_policy_passed": True, "reason_codes": [],
                        },
                    ):
                        conn = self.connect()
                        result = execute_approved_apache_check(
                            conn, document, self.public_key, context,
                            target_value, resolver=resolver, transport=transport, now=now,
                        )
                        conn.close()
                self.assertEqual(result["outcome"], "NOT_AUTHORIZED")
                resolver.assert_not_called()
                transport.request.assert_not_called()

    def test_replay_redirect_timeout_and_tls_failure_never_retry(self):
        conn = self.connect()
        redirect = type("Response", (), {
            "status_code": 302, "headers": {"Location": "https://outside.invalid/"},
        })()
        transport = MockBoundedApacheHTTPTransport()
        transport.request.return_value = redirect
        first = self.execute(conn, transport=transport)
        second = self.execute(conn, transport=transport)
        self.assertEqual(first["outcome"], "INSUFFICIENT_EVIDENCE")
        self.assertFalse(first["redirect_followed"])
        self.assertEqual(first["http_request_count"], 1)
        self.assertEqual(second["outcome"], "NOT_AUTHORIZED")
        self.assertEqual(transport.request.call_count, 1)
        conn.close()

        self.setUp()
        conn = self.connect()
        tls_transport = MockBoundedApacheHTTPTransport()
        tls_transport.request.side_effect = ssl.SSLCertVerificationError("secret detail")
        failed = self.execute(conn, transport=tls_transport)
        self.assertEqual(failed["outcome"], "ERROR")
        self.assertEqual(failed["error_code"], "tls_validation_failed")
        self.assertEqual(failed["http_request_count"], 0)
        self.assertEqual(tls_transport.request.call_count, 1)
        conn.close()

    def test_process_crash_after_receipt_commit_cannot_reuse_approval(self):
        conn = self.connect()
        crash_transport = MockBoundedApacheHTTPTransport()
        crash_transport.request.side_effect = SystemExit("simulated process loss")
        with self.assertRaises(SystemExit):
            self.execute(conn, transport=crash_transport)
        conn.close()
        conn = self.connect()
        retry_transport = MockBoundedApacheHTTPTransport()
        retry = self.execute(conn, transport=retry_transport)
        self.assertEqual(retry["outcome"], "NOT_AUTHORIZED")
        retry_transport.request.assert_not_called()
        conn.close()

    def test_private_destination_and_resolution_failure_happen_after_receipt_without_http(self):
        conn = self.connect()
        transport = MockBoundedApacheHTTPTransport()
        result = self.execute(
            conn, transport=transport,
            resolver=lambda *_args, **_kwargs: ["8.8.8.8", "127.0.0.1"],
        )
        self.assertEqual(result["outcome"], "ERROR")
        self.assertEqual(result["error_code"], "destination_rejected")
        self.assertTrue(result["authorization_receipt_reference"])
        self.assertEqual(result["http_request_count"], 0)
        transport.request.assert_not_called()
        conn.close()

    def test_bounded_transport_pins_socket_and_preserves_tls_hostname(self):
        response = mock.Mock(status=200, headers={"Server": "Apache/2.4.58"})
        response.getheader.return_value = "Apache/2.4.58"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        tls_socket = mock.Mock()
        tls_context = mock.Mock()
        tls_context.wrap_socket.return_value = tls_socket
        with mock.patch("apache_version_executor.socket.create_connection", return_value=raw_socket) as connect, \
                mock.patch("apache_version_executor.ssl.create_default_context", return_value=tls_context), \
                mock.patch("apache_version_executor.http.client.HTTPConnection", return_value=connection):
            result = BoundedApacheHTTPTransport().request(
                "https://apache.example.test/", "8.8.8.8", method="GET", timeout=2.0,
            )
        connect.assert_called_once_with(("8.8.8.8", 443), timeout=2.0)
        tls_context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="apache.example.test")
        connection.putrequest.assert_called_once_with("GET", "/", skip_accept_encoding=True)
        connection.putheader.assert_called_once_with("Connection", "close")
        connection.endheaders.assert_called_once_with()
        connection.getresponse.assert_called_once_with()
        connection.close.assert_called_once_with()
        response.read.assert_not_called()
        self.assertEqual(result.status_code, 200)

    def test_dry_run_never_invokes_executor_dependencies(self):
        from apache_version_verification import build_apache_dry_run

        with mock.patch("apache_version_executor.socket.getaddrinfo") as resolver, \
                mock.patch("apache_version_executor.BoundedApacheHTTPTransport.request") as request:
            plan = build_apache_dry_run(self.target)
        resolver.assert_not_called()
        request.assert_not_called()
        self.assertEqual(plan["network_requests"], 0)
        self.assertEqual(plan["database_writes"], 0)

    def test_executor_classifies_hidden_missing_and_non_apache_headers(self):
        for header, expected, version in (
            ("Apache", "PRODUCT_IDENTIFIED_VERSION_UNKNOWN", None),
            (None, "INSUFFICIENT_EVIDENCE", None),
            ("nginx/1.25.1", "PRODUCT_NOT_CONFIRMED", None),
        ):
            with self.subTest(header=header):
                self.setUp()
                conn = self.connect()
                response = type("Response", (), {
                    "status_code": 200,
                    "headers": {} if header is None else {"Server": header},
                })()
                transport = MockBoundedApacheHTTPTransport()
                transport.request.return_value = response
                result = self.execute(conn, transport=transport)
                self.assertEqual(result["outcome"], expected)
                self.assertEqual(result["version"], version)
                self.assertEqual(result["http_request_count"], 1)
                conn.close()

    def test_database_consumption_failure_never_resolves_or_requests(self):
        conn = mock.MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value

        def fail_receipt(sql, *_args):
            if "INSERT INTO public.capd_approval_consumptions" in sql:
                raise RuntimeError("database unavailable")

        cursor.execute.side_effect = fail_receipt
        resolver = mock.Mock(return_value=["8.8.8.8"])
        transport = MockBoundedApacheHTTPTransport()
        result = self.execute(conn, resolver=resolver, transport=transport)
        self.assertEqual(result["outcome"], "ERROR")
        self.assertEqual(result["error_code"], "approval_receipt_persistence_failed")
        self.assertEqual(result["http_request_count"], 0)
        resolver.assert_not_called()
        transport.request.assert_not_called()
        conn.rollback.assert_called()

    def test_timeout_is_sanitized_and_does_not_retry(self):
        conn = self.connect()
        transport = MockBoundedApacheHTTPTransport()
        transport.request.side_effect = TimeoutError("secret timeout payload")
        result = self.execute(conn, transport=transport)
        self.assertEqual(result["outcome"], "ERROR")
        self.assertEqual(result["error_code"], "timeout")
        self.assertEqual(result["http_request_count"], 0)
        self.assertEqual(transport.request.call_count, 1)
        self.assertNotIn("secret", str(result))
        conn.close()

        self.setUp()
        conn = self.connect()
        sent_timeout = MockBoundedApacheHTTPTransport()
        sent_timeout.request.side_effect = ApacheHTTPTransportError(
            "timeout", request_was_sent=True,
        )
        result = self.execute(conn, transport=sent_timeout)
        self.assertEqual(result["outcome"], "ERROR")
        self.assertEqual(result["http_request_count"], 1)
        self.assertEqual(sent_timeout.request.call_count, 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
