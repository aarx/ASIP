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
        with mock.patch.object(self.worker.dns.resolver, "Resolver") as resolver:
            with self.assertRaises(self.worker.PassiveDnsAuthorizationDenied):
                self.worker.reverse_dns("203.0.113.8", before_query=lambda: False)
            resolver.assert_not_called()

    def test_reverse_dns_success_uses_bounded_ptr_resolution(self):
        answer = mock.Mock()
        answer.to_text.return_value = "ptr.example.test."
        resolver = mock.Mock()
        resolver.resolve.return_value = [answer]
        reverse_name = mock.sentinel.reverse_name
        with (
            mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver),
            mock.patch.object(
                self.worker.dns.reversename, "from_address", return_value=reverse_name
            ),
        ):
            result = self.worker.reverse_dns("203.0.113.8")

        self.assertEqual(result, "ptr.example.test")
        self.assertEqual(resolver.timeout, 2)
        self.assertEqual(resolver.lifetime, 3)
        resolver.resolve.assert_called_once_with(reverse_name, "PTR")

    def test_reverse_dns_timeout_is_a_per_host_failure(self):
        resolver = mock.Mock()
        resolver.resolve.side_effect = self.worker.dns.exception.Timeout("timeout")
        with (
            mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver),
            mock.patch.object(
                self.worker.dns.reversename, "from_address", return_value="reverse.test."
            ),
        ):
            self.assertIsNone(self.worker.reverse_dns("203.0.113.8"))

    def test_reverse_dns_missing_record_preserves_na_semantics(self):
        for no_record in (
            self.worker.dns.resolver.NXDOMAIN(),
            self.worker.dns.resolver.NoAnswer(),
        ):
            resolver = mock.Mock()
            resolver.resolve.side_effect = no_record
            with (
                self.subTest(error=type(no_record).__name__),
                mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver),
                mock.patch.object(
                    self.worker.dns.reversename,
                    "from_address",
                    return_value="reverse.test.",
                ),
            ):
                self.assertEqual(self.worker.reverse_dns("203.0.113.8"), "N/A")

    def test_ptr_timeout_does_not_stop_later_dns_targets(self):
        rows = [
            (101, "first.example.test", False),
            (102, "second.example.test", False),
        ]

        class Cursor:
            rowcount = 1

            def execute(self, *_args):
                pass

            def fetchall(self):
                return rows

        class Connection:
            def __init__(self):
                self.cursor_value = Cursor()

            def cursor(self):
                return self.cursor_value

            def commit(self):
                pass

            def close(self):
                pass

        resolvers = [mock.Mock(), mock.Mock()]
        resolvers[0].resolve.side_effect = self.worker.dns.exception.Timeout("timeout")
        answer = mock.Mock()
        answer.to_text.return_value = "second.example.test."
        resolvers[1].resolve.return_value = [answer]
        with (
            mock.patch.object(self.worker, "get_conn", return_value=Connection()),
            mock.patch.object(self.worker, "require_running_scan"),
            mock.patch.object(self.worker, "passive_dns_target_allowed", return_value=True),
            mock.patch.object(
                self.worker, "resolve_dns",
                side_effect=[[('A', '203.0.113.8')], [('A', '203.0.113.9')]],
            ),
            mock.patch.object(
                self.worker.dns.resolver, "Resolver", side_effect=resolvers
            ),
            mock.patch.object(
                self.worker.dns.reversename,
                "from_address",
                side_effect=["first-reverse.test.", "second-reverse.test."],
            ),
        ):
            self.worker.main()

        self.assertEqual(resolvers[0].resolve.call_count, 1)
        resolvers[1].resolve.assert_called_once_with("second-reverse.test.", "PTR")

    def test_a_and_cname_queries_keep_existing_bounded_resolver_settings(self):
        resolver = mock.Mock()
        resolver.resolve.side_effect = [
            [types.SimpleNamespace(to_text=lambda: "203.0.113.8")],
            [types.SimpleNamespace(to_text=lambda: "alias.example.test.")],
        ]
        with mock.patch.object(
            self.worker.dns.resolver, "Resolver", return_value=resolver
        ):
            records = self.worker.resolve_dns("candidate.example.test")

        self.assertEqual(
            records,
            [("A", "203.0.113.8"), ("CNAME", "alias.example.test")],
        )
        self.assertEqual(resolver.timeout, 2)
        self.assertEqual(resolver.lifetime, 3)
        self.assertEqual(
            resolver.resolve.call_args_list,
            [
                mock.call("candidate.example.test", "A"),
                mock.call("candidate.example.test", "CNAME"),
            ],
        )

    def test_policy_database_error_is_not_swallowed_as_dns_failure(self):
        resolver = mock.Mock()
        check = mock.Mock(side_effect=self.worker.PassiveDnsPolicyError("db unavailable"))
        with mock.patch.object(self.worker.dns.resolver, "Resolver", return_value=resolver):
            with self.assertRaises(self.worker.PassiveDnsPolicyError):
                self.worker.resolve_dns("candidate.example", before_query=check)
        resolver.resolve.assert_not_called()
        check.assert_called_once_with()

    def test_dns_progress_line_reports_counts_and_elapsed_time(self):
        message = self.worker.format_dns_progress(
            visited=50, total=1968, records_found=21, no_records=29,
            authorization_skips=0, elapsed_seconds=31.26,
        )
        self.assertEqual(
            message,
            "DNS progress: visited 50/1968; records_found_domains=21; "
            "no_record_domains=29; authorization_skips=0; elapsed_seconds=31.3",
        )


if __name__ == "__main__":
    unittest.main()
