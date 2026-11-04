import importlib.util
import logging
import pathlib
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

    def __init__(self):
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return (1,)


class Connection:
    def __init__(self, identity):
        self.identity = identity
        self.cur = Cursor()
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


class Trusted:
    known_domains = frozenset()


class SanConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()
        self.connections = []
        self.lock = threading.Lock()

        def connect():
            with self.lock:
                connection = Connection(len(self.connections) + 1)
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
            [self.rows(1)[0], (1, "duplicate.example"), self.rows(2)[1]],
            17, Trusted(), workers=1,
        )
        self.assertEqual(maximum, 1)
        self.assertEqual(summary["selected"], 2)
        self.assertEqual(seen, ["parent-1.example", "parent-2.example"])

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
            def run_if_active(gate, operation):
                gate.set()
                return super(CancelBeforeWriteGate, gate).run_if_active(operation)

        gate = CancelBeforeWriteGate()
        self.worker.fetch_san_domains = mock.Mock(return_value=[])
        original = self.worker._persist_parent

        self.worker._persist_parent = mock.Mock(wraps=original)
        with self.assertRaises(self.worker.SanInterrupted):
            self.worker.run_san_expansion(
                self.rows(1), 17, Trusted(), workers=1, cancel_gate=gate
            )
        self.assertFalse(any("INSERT INTO domain_san" in sql
                             for sql, _ in self.connections[0].cur.executions))
        self.worker._persist_parent.assert_not_called()
        self.assertGreaterEqual(self.connections[0].rollbacks, 1)

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
            gate.run_if_active(transaction)

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
        self.assertIsNone(gate.run_if_active(lambda: committed.append("late")))
        self.assertEqual(committed, ["committed"])

    def test_worker_failure_fails_stage(self):
        self.worker.fetch_san_domains = mock.Mock(
            side_effect=RuntimeError("database worker failure")
        )
        with self.assertRaises(self.worker.SanStageError):
            self.worker.run_san_expansion(self.rows(2), 17, Trusted(), workers=1)

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


if __name__ == "__main__":
    unittest.main()
