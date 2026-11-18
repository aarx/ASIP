import importlib.util
import logging
import pathlib
import socket
import ssl
import sys
import threading
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_worker():
    name = f"san_concurrency_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, BACKEND / "san_worker.py")
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    previous_db = sys.modules.get("db")
    old_argv = sys.argv[:]
    try:
        sys.modules["db"] = fake_db
        sys.argv = ["san_worker.py", "17"]
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()), \
                mock.patch("os.makedirs"):
            spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
        if previous_db is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = previous_db
    return module


class Cursor:
    rowcount = 1

    def __init__(self, inserted=True):
        self.executions = []
        self.inserted = inserted
        self.result = (1,)

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        if "INSERT INTO domains(" in sql:
            self.result = (1, self.inserted)
        else:
            self.result = (1,)

    def fetchone(self):
        return self.result


class Connection:
    def __init__(self, identity, inserted=True):
        self.identity = identity
        self.cur = Cursor(inserted=inserted)
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class Trusted(list):
    known_domains = frozenset()

    def __init__(self):
        super().__init__(["example"])


class SanConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()
        self.connections = []
        self.lock = threading.Lock()
        self.domain_inserted = True

        def connect():
            with self.lock:
                connection = Connection(len(self.connections) + 1,
                                        inserted=self.domain_inserted)
                self.connections.append(connection)
                return connection

        self.worker.get_conn = connect
        self.worker.require_running_scan = mock.Mock()
        self.worker.recheck_active_authorization = mock.Mock(
            return_value=(True, "authorized")
        )

    @staticmethod
    def rows(count):
        return [(i, f"parent-{i}.example") for i in range(1, count + 1)]

    def test_two_worker_limit_and_independent_connections(self):
        barrier = threading.Barrier(2)
        count_lock = threading.Lock()
        active = maximum = 0

        def retrieve(_domain, before_request=None):
            nonlocal active, maximum
            self.assertTrue(before_request())
            with count_lock:
                active += 1
                maximum = max(maximum, active)
            barrier.wait(timeout=3)
            with count_lock:
                active -= 1
            return []

        self.worker.fetch_san_domains = retrieve
        summary = self.worker.run_san_expansion(self.rows(4), 17, Trusted())
        self.assertEqual(maximum, 2)
        self.assertEqual(summary["maximum_concurrency"], 2)
        self.assertEqual(summary["successful"], 4)
        self.assertEqual(len(self.connections), 4)
        self.assertEqual(len({c.identity for c in self.connections}), 4)
        self.assertTrue(all(c.closed for c in self.connections))

    def test_serial_mode_and_duplicate_parent_deduplication(self):
        active = maximum = 0
        seen = []

        def retrieve(domain, before_request=None):
            nonlocal active, maximum
            self.assertTrue(before_request())
            active += 1
            maximum = max(maximum, active)
            seen.append(domain)
            active -= 1
            return []

        self.worker.fetch_san_domains = retrieve
        summary = self.worker.run_san_expansion(
            [self.rows(1)[0], (2, "PARENT-1.EXAMPLE."), self.rows(2)[1]],
            17, Trusted(), workers=1,
        )
        self.assertEqual(maximum, 1)
        self.assertEqual(summary["selected"], 2)
        self.assertEqual(seen, ["parent-1.example", "parent-2.example"])

    def test_target_query_uses_scan_membership_without_prior_state_or_http_result(self):
        cursor = mock.Mock()
        cursor.fetchall.return_value = [(1, "no-stored-ip.example")]
        selected = self.worker.get_san_targets(cursor, 17)
        self.assertEqual(selected, [(1, "no-stored-ip.example")])
        sql, params = cursor.execute.call_args.args
        self.assertIn("JOIN scan_results", sql)
        self.assertIn("FROM domain_san dsan", sql)
        self.assertIn("JOIN domains completed", sql)
        self.assertIn("DISTINCT ON (LOWER(TRIM(TRAILING '.' FROM d.domain)))", sql)
        self.assertIn("dsan.scan_id=%s", sql)
        self.assertIn("LOWER(TRIM(TRAILING '.' FROM completed.domain))", sql)
        self.assertNotIn("JOIN domain_states", sql)
        self.assertNotIn("http_live", sql)
        self.assertNotIn("http_status", sql)
        self.assertNotIn("LIMIT", sql.upper())
        self.assertIn("d.ownership_status = 'CONFIRMED'", sql)
        self.assertIn("d.scannable IS TRUE", sql)
        self.assertEqual(params, (17, 17))

    def test_revocation_prevents_tls_result_persistence(self):
        self.worker.recheck_active_authorization.side_effect = [
            (True, "authorized"), (False, "revoked"),
        ]
        def retrieve(_domain, before_request=None):
            if before_request():
                return []
            self.worker._fetch_state.category = "authorization_skipped"
            return None
        self.worker.fetch_san_domains = retrieve
        summary = self.worker.run_san_expansion(self.rows(1), 17, Trusted(), workers=1)
        self.assertEqual(summary["authorization_skips"], 1)
        self.assertFalse(any("INSERT INTO domain_san" in sql
                             for sql, _ in self.connections[0].cur.executions))

    def test_cancellation_registered_before_commit_rejects_write(self):
        class CancelBeforeWriteGate(self.worker.SanCancellationGate):
            def run_in_order(gate, ordinal, operation):
                gate.set()
                return super(CancelBeforeWriteGate, gate).run_in_order(
                    ordinal, operation
                )

        gate = CancelBeforeWriteGate()
        self.worker.fetch_san_domains = mock.Mock(
            return_value=["*.Child.example", "child.EXAMPLE", "parent-1.example"]
        )
        original = self.worker._persist_parent

        self.worker._persist_parent = mock.Mock(wraps=original)
        with self.assertLogs("san_worker", level="INFO") as captured:
            with self.assertRaises(self.worker.SanInterrupted):
                self.worker.run_san_expansion(
                    self.rows(1), 17, Trusted(), workers=1, cancel_gate=gate
                )
        self.worker.fetch_san_domains.assert_called_once()
        self.assertFalse(any("INSERT INTO domain_san" in sql
                             for sql, _ in self.connections[0].cur.executions))
        self.worker._persist_parent.assert_not_called()
        self.assertGreaterEqual(self.connections[0].rollbacks, 1)
        stage = next(line for line in captured.output if "san_stage " in line)
        summary = __import__("json").loads(stage.split("san_stage ", 1)[1])
        self.assertEqual(summary["cancelled_targets"], 1)
        self.assertEqual(summary["successful_tls_retrievals"], 1)
        self.assertEqual(summary["raw_san_names_observed"], 3)
        self.assertEqual(summary["unique_normalized_san_names"], 1)
        self.assertEqual(summary["newly_created_domain_identities"], 0)
        self.assertEqual(summary["unprocessed_incomplete_targets"], 1)
        self.assertTrue(summary["interrupted"])

    def test_commit_already_inside_gate_finishes_before_cancellation_registers(self):
        gate = self.worker.SanCancellationGate()
        inside_commit = threading.Event()
        release_commit = threading.Event()
        cancellation_started = threading.Event()
        cancellation_registered = threading.Event()
        committed = []

        def commit():
            def transaction():
                inside_commit.set()
                if not release_commit.wait(timeout=2):
                    raise AssertionError("test did not release commit")
                committed.append("committed")
            gate.run_in_order(0, transaction)

        def cancel():
            cancellation_started.set()
            gate.set()
            cancellation_registered.set()

        writer = threading.Thread(target=commit)
        writer.start()
        self.assertTrue(inside_commit.wait(timeout=2))
        canceller = threading.Thread(target=cancel)
        canceller.start()
        self.assertTrue(cancellation_started.wait(timeout=2))
        self.assertFalse(cancellation_registered.is_set())
        release_commit.set()
        writer.join(timeout=2)
        canceller.join(timeout=2)
        self.assertFalse(writer.is_alive())
        self.assertFalse(canceller.is_alive())
        self.assertEqual(committed, ["committed"])
        self.assertTrue(cancellation_registered.is_set())
        self.assertIsNone(gate.run_in_order(1, lambda: committed.append("late")))
        self.assertEqual(committed, ["committed"])

    def test_raw_normalized_inserted_and_reused_metrics_are_distinct(self):
        self.worker.fetch_san_domains = mock.Mock(return_value=[
            "*.Child.example", "child.EXAMPLE", "parent-1.example", "invalid",
        ])
        summary = self.worker.run_san_expansion(self.rows(1), 17, Trusted(), workers=1)
        self.assertEqual(summary["raw_san_names_observed"], 4)
        self.assertEqual(summary["unique_normalized_san_names"], 1)
        self.assertEqual(summary["newly_created_domain_identities"], 1)
        self.assertEqual(summary["existing_domain_identities_reused"], 0)
        self.assertEqual(summary["persisted_parent_san_records"], 1)
        self.assertEqual(summary["persisted_provenance_relationships"], 1)
        self.assertEqual(summary["persisted_scan_memberships"], 1)
        self.assertEqual(summary["persisted_domain_identity_upserts"], 1)
        self.assertEqual(summary["persisted_row_writes"], 4)

        self.domain_inserted = False
        reused = self.worker.run_san_expansion(self.rows(1), 17, Trusted(), workers=1)
        self.assertEqual(reused["newly_created_domain_identities"], 0)
        self.assertEqual(reused["existing_domain_identities_reused"], 1)
        self.assertEqual(reused["persisted_domain_identity_upserts"], 1)

    def test_worker_failure_fails_stage(self):
        self.worker.fetch_san_domains = mock.Mock(
            side_effect=RuntimeError("database worker failure")
        )
        with self.assertLogs("san_worker", level="INFO") as captured:
            with self.assertRaises(self.worker.SanStageError):
                self.worker.run_san_expansion(
                    self.rows(2), 17, Trusted(), workers=1
                )
        stage = next(line for line in captured.output if "san_stage " in line)
        summary = __import__("json").loads(stage.split("san_stage ", 1)[1])
        self.assertTrue(summary["failed"])
        self.assertEqual(summary["worker_errors"], 1)
        self.assertEqual(summary["unprocessed_incomplete_targets"], 2)

    def test_worker_failure_cancels_another_active_target_before_write(self):
        first_started = threading.Event()
        cancellation_registered = threading.Event()

        class ObservedGate(self.worker.SanCancellationGate):
            def set(gate):
                super(ObservedGate, gate).set()
                cancellation_registered.set()

        gate = ObservedGate()

        def retrieve(domain, before_request=None):
            self.assertTrue(before_request())
            if domain == "parent-1.example":
                first_started.set()
                self.assertTrue(cancellation_registered.wait(timeout=3))
                self.worker._fetch_state.category = "authorization_skipped"
                return None
            self.assertTrue(first_started.wait(timeout=3))
            raise RuntimeError("injected worker failure")

        self.worker.fetch_san_domains = retrieve
        with self.assertLogs("san_worker", level="INFO") as captured:
            with self.assertRaises(self.worker.SanStageError):
                self.worker.run_san_expansion(
                    self.rows(2), 17, Trusted(), workers=2, cancel_gate=gate
                )
        stage = next(line for line in captured.output if "san_stage " in line)
        summary = __import__("json").loads(stage.split("san_stage ", 1)[1])
        self.assertEqual(summary["worker_errors"], 1)
        self.assertEqual(summary["cancelled_targets"], 1)
        self.assertEqual(summary["persisted_row_writes"], 0)
        self.assertEqual(summary["unprocessed_incomplete_targets"], 2)
        self.assertFalse(any(
            "INSERT INTO domain_san" in sql
            for connection in self.connections
            for sql, _ in connection.cur.executions
        ))

    def test_worker_setting_is_clamped_to_two(self):
        self.assertEqual(self.worker.configured_san_workers(1), 1)
        self.assertEqual(self.worker.configured_san_workers(2), 2)
        self.assertEqual(self.worker.configured_san_workers(50), 2)

    def test_retrieval_categories_preserve_timeout_and_address_policy(self):
        with mock.patch.object(
            self.worker, "open_validated_tls_socket",
            side_effect=OSError("no permitted TLS destination address"),
        ):
            self.assertIsNone(self.worker.fetch_san_domains(
                "parent.example", before_request=lambda: True
            ))
            self.assertEqual(
                self.worker._fetch_state.category, "no_permitted_destination"
            )
        with mock.patch.object(
            self.worker, "open_validated_tls_socket", side_effect=TimeoutError()
        ):
            self.assertIsNone(self.worker.fetch_san_domains(
                "parent.example", before_request=lambda: True
            ))
            self.assertEqual(self.worker._fetch_state.category, "timeout")
        with mock.patch.object(self.worker, "open_validated_tls_socket") as tls:
            self.assertIsNone(self.worker.fetch_san_domains(
                "parent.example", before_request=lambda: False
            ))
            tls.assert_not_called()
            self.assertEqual(self.worker._fetch_state.category, "authorization_skipped")

    def test_dns_connection_tls_and_certificate_failures_are_distinct(self):
        failures = (
            (self.worker.DNSResolutionError("dns"), "dns_failure"),
            (self.worker.NoPermittedDestinationError("unsafe"), "no_permitted_destination"),
            (ConnectionRefusedError("refused"), "connection_failure"),
            (socket.timeout("tls timeout"), "timeout"),
            (ssl.SSLError("handshake"), "tls_handshake_or_certificate_failure"),
            (ValueError("certificate parse"), "tls_handshake_or_certificate_failure"),
        )
        for failure, expected in failures:
            with self.subTest(expected=expected), mock.patch.object(
                self.worker, "open_validated_tls_socket", side_effect=failure
            ):
                self.assertIsNone(self.worker.fetch_san_domains(
                    "parent.example", before_request=lambda: True
                ))
                self.assertEqual(self.worker._fetch_state.category, expected)

        counts = {
            "no_permitted_destinations": 0,
            "dns_resolution_failures": 0,
            "tls_timeouts": 0,
            "connection_failures": 0,
            "tls_handshake_or_certificate_failures": 0,
            "other_tls_failures": 0,
        }
        for _failure, category in failures:
            self.worker._count_tls_category(counts, category)
        self.assertEqual(counts["dns_resolution_failures"], 1)
        self.assertEqual(counts["no_permitted_destinations"], 1)
        self.assertEqual(counts["connection_failures"], 1)
        self.assertEqual(counts["tls_timeouts"], 1)
        self.assertEqual(counts["tls_handshake_or_certificate_failures"], 2)
        self.assertEqual(counts["other_tls_failures"], 3)

    def test_successful_tls_certificate_san_names_are_returned(self):
        peer = mock.Mock()
        peer.getpeercert.return_value = {
            "subjectAltName": [
                ("DNS", "child.example"),
                ("DNS", "*.wild.example"),
                ("IP Address", "8.8.8.8"),
            ],
        }
        context = mock.MagicMock()
        context.__enter__.return_value = peer
        with mock.patch.object(
            self.worker, "open_validated_tls_socket", return_value=context
        ) as open_tls:
            result = self.worker.fetch_san_domains(
                "parent.example", before_request=lambda: True
            )
        self.assertEqual(result, ["child.example", "*.wild.example"])
        open_tls.assert_called_once()
        self.assertEqual(self.worker._fetch_state.category, None)

        peer.getpeercert.side_effect = RuntimeError("certificate retrieval failed")
        with mock.patch.object(
            self.worker, "open_validated_tls_socket", return_value=context
        ):
            self.assertIsNone(self.worker.fetch_san_domains(
                "parent.example", before_request=lambda: True
            ))
        self.assertEqual(
            self.worker._fetch_state.category,
            "tls_handshake_or_certificate_failure",
        )

    def test_one_dns_failure_does_not_abort_other_san_targets(self):
        def retrieve(domain, before_request=None):
            self.assertTrue(before_request())
            if domain == "parent-1.example":
                self.worker._fetch_state.category = "dns_failure"
                return None
            return ["child.example"]

        self.worker.fetch_san_domains = retrieve
        summary = self.worker.run_san_expansion(self.rows(2), 17, Trusted(), workers=1)
        self.assertEqual(summary["selected_parent_targets"], 2)
        self.assertEqual(summary["completed_parent_targets"], 2)
        self.assertEqual(summary["dns_resolution_failures"], 1)
        self.assertEqual(summary["successful_tls_retrievals"], 1)
        self.assertFalse(summary["failed"])


if __name__ == "__main__":
    unittest.main()
