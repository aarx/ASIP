import importlib.util
import json
import pathlib
import sys
import types
import unittest
from datetime import datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_orchestration():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    name = f"recovery_orchestration_{id(fake_db)}"
    spec = importlib.util.spec_from_file_location(name, BACKEND / "orchestration.py")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get("db")
    try:
        sys.modules["db"] = fake_db
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = previous
    return module


class RecoveryCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orchestration = load_orchestration()

    def setUp(self):
        self.pipeline = [("Recon", "recon 5"), ("DNS Resolution", "dns 5"),
                         ("Risk Scoring", "risk 5")]

    @staticmethod
    def attempt(order, stage, number, status):
        return {"order": order, "stage": stage, "attempt": number, "status": status}

    def test_empty_history_starts_at_first_stage(self):
        self.assertEqual(
            self.orchestration.validate_resume_checkpoint({"attempts": []}, self.pipeline),
            (0, {}),
        )

    def test_successful_prefix_and_failed_stage_boundary(self):
        attempts = [
            self.attempt(0, "Recon", 1, "SUCCEEDED"),
            self.attempt(1, "DNS Resolution", 1, "FAILED"),
        ]
        self.assertEqual(
            self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline),
            (1, {0: 1, 1: 1}),
        )

    def test_manual_success_becomes_resume_checkpoint(self):
        attempts = [
            self.attempt(0, "Recon", 1, "SUCCEEDED"),
            self.attempt(1, "DNS Resolution", 1, "FAILED"),
            self.attempt(1, "DNS Resolution", 2, "SUCCEEDED"),
        ]
        self.assertEqual(
            self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline),
            (2, {0: 1, 1: 2}),
        )

    def test_rejects_missing_identity_or_attempts(self):
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.orchestration.validate_resume_checkpoint({"attempts": [None]}, self.pipeline)

    def test_rejects_unidentified_historical_stage_history(self):
        with self.assertRaisesRegex(RuntimeError, "does not match pipeline"):
            self.orchestration.validate_resume_checkpoint(
                {"attempts": [self.attempt(0, "Old Stage", 1, "SUCCEEDED")]},
                self.pipeline,
            )

    def test_rejects_noncontiguous_successful_stages(self):
        attempts = [self.attempt(0, "Recon", 1, "SUCCEEDED"),
                    self.attempt(2, "Risk Scoring", 1, "SUCCEEDED")]
        with self.assertRaisesRegex(RuntimeError, "contiguous prefix"):
            self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline)

    def test_rejects_downstream_evidence_after_failed_stage(self):
        attempts = [self.attempt(0, "Recon", 1, "SUCCEEDED"),
                    self.attempt(1, "DNS Resolution", 1, "FAILED"),
                    self.attempt(2, "Risk Scoring", 1, "SUCCEEDED")]
        with self.assertRaisesRegex(RuntimeError, "downstream"):
            self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline)

    def test_rejects_incomplete_or_out_of_order_attempts(self):
        for attempts, message in (
            ([self.attempt(0, "Recon", 1, "RUNNING")], "incomplete"),
            ([self.attempt(1, "DNS Resolution", 1, "FAILED"),
              self.attempt(0, "Recon", 1, "SUCCEEDED")], "out of order"),
            ([self.attempt(0, "Recon", 1, "FAILED"),
              self.attempt(0, "Recon", 3, "FAILED")], "inconsistent"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline)

    def test_rejects_reexecution_of_successful_checkpoint(self):
        attempts = [self.attempt(0, "Recon", 1, "SUCCEEDED"),
                    self.attempt(0, "Recon", 2, "SUCCEEDED")]
        with self.assertRaisesRegex(RuntimeError, "completed stage was rerun"):
            self.orchestration.validate_resume_checkpoint({"attempts": attempts}, self.pipeline)

    def test_pipeline_identity_is_deterministic_and_configuration_sensitive(self):
        module = self.orchestration
        with mock.patch.object(module, "_pipeline_source_fingerprint", return_value="source"), \
                mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "PORT_SCAN"}, clear=True):
            first = module.pipeline_identity(self.pipeline, 5)
            second = module.pipeline_identity(self.pipeline, 5)
        self.assertEqual(first, second)
        with mock.patch.object(module, "_pipeline_source_fingerprint", return_value="source"), \
                mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "DNS_SECURITY"}, clear=True):
            changed = module.pipeline_identity(self.pipeline, 5)
        self.assertNotEqual(first, changed)
        self.assertNotIn("password", json.dumps(first).lower())

        with mock.patch.object(module, "_pipeline_source_fingerprint", return_value="source"), \
                mock.patch.object(module.config, "CERTSPOTTER_API_KEY", "rotated-secret"):
            changed_secret = module.pipeline_identity(self.pipeline, 5)
        self.assertNotEqual(first, changed_secret)
        self.assertNotIn("rotated-secret", json.dumps(changed_secret))


class RecoveryOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_orchestration()

    def make_connection(self, *, status="FAILED", identity=True, attempts=None,
                        pipeline=None, brand_observations=False):
        module = self.module
        pipeline = pipeline or [("Recon", "recon 42"), ("DNS Resolution", "dns 42")]
        base_identity = {
            "version": module.PIPELINE_IDENTITY_VERSION,
            "stages": [], "source_sha256": "source", "policy_settings": {},
            "dns_security_target_ids": None,
        }
        document = {
            "version": 1,
            "pipeline_identity": base_identity if identity else None,
            "current_stage": None,
            "attempts": attempts or [],
            "recovery_history": [],
            "scan_outcome": {"status": "FAILED"},
        }
        cursor = RecoveryCursor(status, document, brand_observations)
        connection = RecoveryConnection(cursor)
        return connection, cursor, pipeline, base_identity

    def patch_identity(self, pipeline, identity):
        m = self.module
        return (
            mock.patch.object(m, "build_pipeline", return_value=pipeline),
            mock.patch.object(m, "pipeline_identity", return_value=identity),
            mock.patch.object(m, "_seed_domains_fingerprint", return_value="seedhash"),
        )

    def test_claims_failed_scan_atomically_with_fresh_runner(self):
        conn, cursor, pipeline, identity = self.make_connection()
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn):
            token, runner_id, stages, index, counts, reason = self.module.begin_recovery(42, "RESUME")
        self.assertNotEqual(token, "old-token")
        self.assertTrue(runner_id)
        self.assertEqual(stages, pipeline)
        self.assertEqual((index, counts), (0, {}))
        self.assertEqual(reason, "previous failure")
        self.assertTrue(conn.committed)
        self.assertIn("status = 'RUNNING'", cursor.updates[0])
        persisted = json.loads(cursor.update_params[1])
        self.assertEqual(persisted["recovery_history"][0]["mode"], "RESUME")

    def test_rejects_missing_identity_without_mutation(self):
        conn, cursor, pipeline, identity = self.make_connection(identity=False)
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])
        self.assertFalse(conn.committed)

    def test_rejects_incompatible_pipeline_identity(self):
        conn, cursor, pipeline, identity = self.make_connection()
        cursor.document["pipeline_identity"] = {"version": -1}
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_rejects_concurrent_recovery_or_active_runner(self):
        conn, cursor, pipeline, identity = self.make_connection(status="RUNNING")
        with mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "only FAILED"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_resume_requires_success_prefix_before_failed_stage(self):
        attempts = [{"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"}]
        conn, cursor, pipeline, identity = self.make_connection(attempts=attempts)
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "contiguous prefix"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_brand_replay_is_rejected_before_mutation_in_both_recovery_modes(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("Brand Redirect Intelligence", "brand 42"),
            ("DNS Resolution", "dns 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "Brand Redirect Intelligence", "attempt": 1,
             "status": "FAILED", "worker_summary": {"selected": 3, "completed": 0}},
        ]
        for mode in ("RESUME", "SINGLE_FAILED_STAGE"):
            with self.subTest(mode=mode):
                conn, cursor, pipeline, identity = self.make_connection(
                    attempts=attempts, pipeline=pipeline,
                )
                identity["seed_domains_sha256"] = "seedhash"
                cursor.document["pipeline_identity"] = identity
                patches = self.patch_identity(pipeline, identity)
                original_document = json.loads(json.dumps(cursor.document))
                with patches[0], patches[1], patches[2], \
                        mock.patch.object(self.module, "get_conn", return_value=conn), \
                        self.assertRaisesRegex(RuntimeError, "first execution"):
                    self.module.begin_recovery(42, mode)
                self.assertEqual(cursor.updates, [])
                self.assertEqual(cursor.document, original_document)
                self.assertFalse(conn.committed)
                self.assertTrue(conn.rolled_back)

    def test_prior_recovery_history_blocks_first_execution_inference(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline,
        )
        cursor.document["recovery_history"] = [{"mode": "RESUME", "status": "FAILED"}]
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "first execution"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_resume_allows_first_bri_execution_after_explicit_upstream_failure(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("HTTP/TLS Observation", "http 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline,
        )
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn):
            result = self.module.begin_recovery(42, "RESUME")
        self.assertEqual(result[3], 1)
        self.assertEqual(result[2][result[3]][0], "DNS Resolution")
        self.assertTrue(cursor.observation_query_seen)
        self.assertTrue(conn.committed)

    def test_existing_bri_observations_reject_first_execution_inference(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline, brand_observations=True,
        )
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "first execution"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_missing_recovery_history_is_ambiguous_for_first_bri_execution(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline,
        )
        cursor.document.pop("recovery_history")
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn), \
                self.assertRaisesRegex(RuntimeError, "first execution"):
            self.module.begin_recovery(42, "RESUME")
        self.assertEqual(cursor.updates, [])

    def test_successful_bri_prefix_is_skipped_during_resume(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
            ("Risk Scoring", "risk 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 2, "stage": "Brand Redirect Intelligence", "attempt": 1,
             "status": "SUCCEEDED"},
            {"order": 3, "stage": "Risk Scoring", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline, brand_observations=True,
        )
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn):
            result = self.module.begin_recovery(42, "RESUME")
        self.assertEqual(result[3], 3)
        self.assertEqual(result[2][result[3]][0], "Risk Scoring")
        self.assertFalse(cursor.observation_query_seen)

    def test_single_dns_stage_does_not_consider_downstream_bri(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline,
        )
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn):
            result = self.module.begin_recovery(42, "SINGLE_FAILED_STAGE")
        self.assertEqual(result[3], 1)
        self.assertFalse(cursor.observation_query_seen)

    def test_resume_allows_brand_later_in_execution_suffix_after_upstream_failure(self):
        pipeline = [
            ("Recon", "recon 42"),
            ("DNS Resolution", "dns 42"),
            ("Brand Redirect Intelligence", "brand 42"),
        ]
        attempts = [
            {"order": 0, "stage": "Recon", "attempt": 1, "status": "SUCCEEDED"},
            {"order": 1, "stage": "DNS Resolution", "attempt": 1, "status": "FAILED"},
        ]
        conn, cursor, pipeline, identity = self.make_connection(
            attempts=attempts, pipeline=pipeline,
        )
        identity["seed_domains_sha256"] = "seedhash"
        cursor.document["pipeline_identity"] = identity
        patches = self.patch_identity(pipeline, identity)
        with patches[0], patches[1], patches[2], \
                mock.patch.object(self.module, "get_conn", return_value=conn):
            result = self.module.begin_recovery(42, "RESUME")
        self.assertEqual(result[3], 1)
        self.assertEqual(result[2][result[3]][0], "DNS Resolution")
        self.assertTrue(cursor.observation_query_seen)


class RecoveryExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_orchestration()

    def test_full_mode_executes_complete_pipeline_with_existing_attempt_policy(self):
        pipeline = [("A", "a"), ("B", "b")]
        with mock.patch.object(self.module, "run_required_stage") as run:
            self.module._execute_stages(8, "token", pipeline, None)
        self.assertEqual([call.args[0] for call in run.call_args_list], ["A", "B"])
        self.assertTrue(all(
            call.kwargs["execution_mode"] == "FULL"
            and call.kwargs["max_attempts"] == self.module.MAX_STAGE_ATTEMPTS
            for call in run.call_args_list
        ))

    def test_shared_executor_runs_resume_suffix_in_order(self):
        pipeline = [("A", "a"), ("B", "b"), ("C", "c")]
        heartbeat = mock.Mock()
        with mock.patch.object(self.module, "run_required_stage") as run:
            self.module._execute_stages(
                8, "token", pipeline, heartbeat, start_order=1,
                previous_attempt_counts={1: 1}, execution_mode="RESUME",
                runner_id="runner",
            )
        self.assertEqual([call.args[0] for call in run.call_args_list], ["B", "C"])
        self.assertEqual(run.call_args_list[0].kwargs["start_attempt"], 2)
        self.assertEqual(run.call_args_list[0].kwargs["execution_mode"], "RESUME")

    def test_single_failed_stage_executes_exactly_one_stage(self):
        pipeline = [("A", "a"), ("B", "b"), ("C", "c")]
        with mock.patch.object(self.module, "run_required_stage") as run:
            self.module._execute_stages(
                8, "token", pipeline, None, start_order=1,
                execution_mode="SINGLE_FAILED_STAGE", runner_id="runner",
                single_stage=True,
            )
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], "B")

    def test_manual_stage_success_keeps_scan_failed_and_resume_checkpoint_usable(self):
        module = self.module
        pipeline = [("DNS Resolution", "dns 35"), ("HTTP/TLS Observation", "http 35")]
        heartbeat = mock.Mock()
        begin = ("new-token", "runner-id", pipeline, 0, {}, "old failure")
        with mock.patch.object(module, "begin_recovery", return_value=begin), \
                mock.patch.object(module, "RunnerHeartbeat", return_value=heartbeat), \
                mock.patch.object(module, "setup_logging"), \
                mock.patch.object(module, "_execute_stages") as execute, \
                mock.patch.object(module, "finish_recovery") as finish:
            self.assertTrue(module.run_recovery(35, "SINGLE_FAILED_STAGE"))
        execute.assert_called_once()
        self.assertTrue(execute.call_args.kwargs["single_stage"])
        finish.assert_called_once_with(
            35, "new-token", "runner-id", "FAILED", "old failure",
            recovery_status="SUCCEEDED",
        )
        heartbeat.start.assert_called_once()
        heartbeat.stop.assert_called_once()

    def test_resume_failure_is_recorded_and_returns_nonzero_result(self):
        module = self.module
        heartbeat = mock.Mock()
        begin = ("token", "runner-id", [("DNS Resolution", "dns")], 0, {}, "original")
        with mock.patch.object(module, "begin_recovery", return_value=begin), \
                mock.patch.object(module, "RunnerHeartbeat", return_value=heartbeat), \
                mock.patch.object(module, "setup_logging"), \
                mock.patch.object(module, "_execute_stages", side_effect=RuntimeError("worker failed")), \
                mock.patch.object(module, "finish_recovery") as finish:
            self.assertFalse(module.run_recovery(35, "RESUME"))
        finish.assert_called_once_with(35, "token", "runner-id", "FAILED", "worker failed")

    def test_resume_with_all_successful_stages_only_finalizes_scan(self):
        module = self.module
        pipeline = [("DNS Resolution", "dns 35")]
        heartbeat = mock.Mock()
        begin = ("token", "runner-id", pipeline, 1, {0: 1}, "old failure")
        with mock.patch.object(module, "begin_recovery", return_value=begin), \
                mock.patch.object(module, "RunnerHeartbeat", return_value=heartbeat), \
                mock.patch.object(module, "setup_logging"), \
                mock.patch.object(module, "_execute_stages") as execute, \
                mock.patch.object(module, "finish_recovery") as finish:
            self.assertTrue(module.run_recovery(35, "RESUME"))
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs["start_order"], 1)
        finish.assert_called_once_with(35, "token", "runner-id", "SUCCEEDED")

    def test_recovery_diagnostics_persistence_failure_is_fatal(self):
        with mock.patch.object(self.module, "get_conn", side_effect=OSError("db dropped")), \
                self.assertRaisesRegex(OSError, "db dropped"):
            self.module._diagnostics_start(
                1, "token", "DNS Resolution", 6, 1,
                "RESUME", "runner-id", True,
            )

    def test_full_stage_attempts_keep_existing_two_attempt_policy(self):
        with mock.patch.object(self.module, "run_step", side_effect=[
            self.module.RETRYABLE_INCOMPLETE_EXIT_CODE, 0,
        ]) as run:
            self.module.run_required_stage("DNS Resolution", "dns")
        self.assertEqual([call.args[2] for call in run.call_args_list], [1, 2])


class RecoveryCursor:
    def __init__(self, status, document, brand_observations=False):
        self.status = status
        self.document = document
        self.brand_observations = brand_observations
        self.observation_query_seen = False
        self.query = ""
        self.updates = []
        self.update_params = None

    def execute(self, query, params=None):
        self.query = query
        if query.lstrip().startswith("UPDATE scans"):
            self.updates.append(query)
            self.update_params = params

    def fetchone(self):
        if self.query.lstrip().startswith("SELECT status"):
            return (
                self.status, "old-token", datetime.now(timezone.utc),
                "previous failure", self.document, None,
            )
        if "brand_redirect_observations" in self.query:
            self.observation_query_seen = True
            return (self.brand_observations,)
        if self.query.lstrip().startswith("UPDATE scans"):
            return (42,)
        return None

    def fetchall(self):
        return []


class RecoveryConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


if __name__ == "__main__":
    unittest.main()
