import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_worker(filename, module_name):
    path = BACKEND / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", [str(path), "36"]):
        spec.loader.exec_module(module)
    return module


class WorkerTransactionBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.takeover = load_worker("takeover_worker.py", "test_takeover_worker_tx")
        cls.asn = load_worker("asn_worker.py", "test_asn_worker_tx")
        cls.brand = load_worker("brand_redirect_worker.py", "test_brand_worker_tx")

    def test_takeover_releases_scan_lock_before_dns_and_keeps_write_atomic(self):
        cursor = mock.Mock()
        cursor.fetchall.return_value = [(11, "candidate.example", "bucket.s3.amazonaws.com")]
        cursor.fetchone.return_value = (True,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        def observe_dns(_domain):
            self.assertGreaterEqual(connection.commit.call_count, 2)
            return "bucket.s3.amazonaws.com"

        with mock.patch.object(self.takeover, "get_conn", return_value=connection), \
             mock.patch.object(self.takeover, "require_running_scan"), \
             mock.patch.object(self.takeover, "get_live_cname", side_effect=observe_dns), \
             mock.patch.object(self.takeover, "identify_provider", return_value="aws"), \
             mock.patch.object(self.takeover, "check_takeover", return_value={
                 "body": "NoSuchBucket", "status": 404, "length": 12,
             }), \
             mock.patch.dict(self.takeover.FINGERPRINTS, {"aws": ["NoSuchBucket"]}):
            self.takeover.main()

        self.assertTrue(any(
            "INSERT INTO domain_findings" in call.args[0]
            for call in cursor.execute.call_args_list
        ))
        self.assertGreaterEqual(connection.commit.call_count, 3)
        connection.close.assert_called_once()

    def test_takeover_authorization_denial_stays_fail_closed(self):
        cursor = mock.Mock()
        cursor.fetchall.return_value = [(11, "candidate.example", "target.example")]
        cursor.fetchone.return_value = (False,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        with mock.patch.object(self.takeover, "get_conn", return_value=connection), \
             mock.patch.object(self.takeover, "require_running_scan"), \
             mock.patch.object(self.takeover, "get_live_cname") as dns_lookup:
            self.takeover.main()

        dns_lookup.assert_not_called()
        self.assertFalse(any(
            "INSERT INTO domain_findings" in call.args[0]
            for call in cursor.execute.call_args_list
        ))
        connection.close.assert_called_once()

    def test_takeover_exception_rolls_back_and_closes(self):
        connection = mock.Mock()
        connection.cursor.side_effect = RuntimeError("offline fixture")
        with mock.patch.object(self.takeover, "get_conn", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "offline fixture"):
                self.takeover.main()
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()

    def test_asn_releases_transaction_before_http_and_persists_atomically(self):
        cursor = mock.Mock()
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        def observe_http(_ip):
            self.assertGreaterEqual(connection.commit.call_count, 2)
            return ("AS64500", "AS64500 Example")

        with mock.patch.object(self.asn, "get_conn", return_value=connection), \
             mock.patch.object(self.asn, "require_running_scan"), \
             mock.patch.object(
                 self.asn, "get_domains", return_value=[(11, "candidate.example", "8.8.8.8")]
             ), \
             mock.patch.object(self.asn, "asn_target_authorized", return_value=True), \
             mock.patch.object(self.asn, "enrich_asn", side_effect=observe_http):
            self.asn.main()

        writes = [call for call in cursor.execute.call_args_list
                  if "INSERT INTO domain_asn" in call.args[0]]
        self.assertEqual(len(writes), 1)
        self.assertGreaterEqual(connection.commit.call_count, 3)
        connection.close.assert_called_once()

    def test_asn_authorization_denial_prevents_http_and_persistence(self):
        cursor = mock.Mock()
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(self.asn, "get_conn", return_value=connection), \
             mock.patch.object(self.asn, "require_running_scan"), \
             mock.patch.object(
                 self.asn, "get_domains", return_value=[(11, "candidate.example", "8.8.8.8")]
             ), \
             mock.patch.object(self.asn, "asn_target_authorized", return_value=False), \
             mock.patch.object(self.asn, "enrich_asn") as http_lookup:
            self.asn.main()
        http_lookup.assert_not_called()
        self.assertFalse(any(
            "INSERT INTO domain_asn" in call.args[0]
            for call in cursor.execute.call_args_list
        ))
        connection.close.assert_called_once()

    def test_asn_unexpected_exception_rolls_back_and_closes(self):
        connection = mock.Mock()
        connection.cursor.side_effect = RuntimeError("offline fixture")
        with mock.patch.object(self.asn, "get_conn", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "offline fixture"):
                self.asn.main()
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()

    def test_brand_authorization_transaction_ends_before_observation(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = (1,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        evidence = {"completeness": "NO_REDIRECT"}

        def observe(_domain, _url, *, authorize, **_kwargs):
            self.assertTrue(authorize("https://brand.example/"))
            self.assertEqual(connection.commit.call_count, 1)
            return dict(evidence)

        with mock.patch.object(self.brand, "get_conn", return_value=connection), \
             mock.patch.object(self.brand, "observe_redirect_chain", side_effect=observe), \
             mock.patch.object(self.brand, "require_running_scan"), \
             mock.patch.object(self.brand, "default_operation_enabled", return_value=True):
            result = self.brand._run_target(
                (11, "brand.example", "https://brand.example/", ["brand_tld"], ["example.com"]),
                36, "operation-36", self.brand._RequestBudget(),
            )

        self.assertEqual(result, "NO_REDIRECT")
        self.assertIn("INSERT INTO brand_redirect_observations", cursor.execute.call_args.args[0])
        self.assertEqual(connection.commit.call_count, 2)
        connection.close.assert_called_once()

    def test_brand_authorization_uncertainty_fails_closed_and_cleans_up(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = None
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        def observe(_domain, _url, *, authorize, **_kwargs):
            if not authorize("https://brand.example/"):
                raise PermissionError("not authorized")

        with mock.patch.object(self.brand, "get_conn", return_value=connection), \
             mock.patch.object(self.brand, "observe_redirect_chain", side_effect=observe), \
             mock.patch.object(self.brand, "default_operation_enabled", return_value=True):
            with self.assertRaisesRegex(PermissionError, "not authorized"):
                self.brand._run_target(
                    (11, "brand.example", "https://brand.example/", ["brand_tld"], ["example.com"]),
                    36, "operation-36", self.brand._RequestBudget(),
                )

        self.assertNotIn("INSERT INTO brand_redirect_observations", str(cursor.execute.call_args_list))
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
