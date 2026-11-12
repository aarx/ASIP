import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

from backend.authorization_policy import passive_dns_discovery_sql
from backend.ownership import normalize_hostname


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_worker():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    fake_policy = types.ModuleType("authorization_policy")
    fake_policy.passive_dns_discovery_sql = passive_dns_discovery_sql
    fake_ownership = types.ModuleType("ownership")
    fake_ownership.normalize_hostname = normalize_hostname
    spec = importlib.util.spec_from_file_location(
        f"dns_worker_policy_test_{id(fake_db)}", BACKEND / "dns_worker.py"
    )
    module = importlib.util.module_from_spec(spec)
    prior = {
        key: sys.modules.get(key)
        for key in ("db", "authorization_policy", "ownership")
    }
    argv = sys.argv[:]
    try:
        sys.modules["db"] = fake_db
        sys.modules["authorization_policy"] = fake_policy
        sys.modules["ownership"] = fake_ownership
        sys.argv = ["dns_worker.py", "42"]
        spec.loader.exec_module(module)
    finally:
        sys.argv = argv
        for key, value in prior.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


class PassiveDnsWorkerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()

    def test_scope_sql_uses_seed_provenance_and_explicit_rejections(self):
        sql = passive_dns_discovery_sql("d", "sr")
        self.assertIn("sr.seed", sql)
        self.assertIn("seed_domains", sql)
        self.assertIn("known_domains", sql)
        self.assertIn("manually rejected", sql)
        self.assertIn("scope_block.excluded_domains", sql)
        self.assertIn("scope_block.status = 'REVOKED'", sql)

    def test_authorization_is_rechecked_before_each_dns_query(self):
        resolver = mock.Mock()
        resolver.resolve.return_value = [types.SimpleNamespace(to_text=lambda: "203.0.113.8")]
        allowed = mock.Mock(side_effect=[True, False])
        with mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver):
            with self.assertRaises(self.worker.PassiveDnsAuthorizationDenied):
                self.worker.resolve_dns("candidate.example", before_query=allowed)
        self.assertEqual(resolver.resolve.call_args_list, [mock.call("candidate.example", "A")])
        self.assertEqual(allowed.call_count, 2)

    def test_reverse_dns_rechecks_scope_before_ptr_query(self):
        with mock.patch.object(self.worker.socket, "gethostbyaddr") as ptr:
            with self.assertRaises(self.worker.PassiveDnsAuthorizationDenied):
                self.worker.reverse_dns("203.0.113.8", before_query=lambda: False)
            ptr.assert_not_called()

    def test_policy_database_error_is_not_swallowed_as_dns_failure(self):
        resolver = mock.Mock()
        check = mock.Mock(side_effect=self.worker.PassiveDnsPolicyError("db unavailable"))
        with mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver):
            with self.assertRaises(self.worker.PassiveDnsPolicyError):
                self.worker.resolve_dns("candidate.example", before_query=check)
        resolver.resolve.assert_not_called()
        check.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
