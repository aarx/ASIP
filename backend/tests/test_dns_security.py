import os
import pathlib
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

import dns.exception
import dns.resolver

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import (  # noqa: E402
    ScopeApproval,
    configured_scan_operations,
    SCOPE_TESTING_LEVELS,
    active_scan_authorization_sql,
    default_operation_enabled,
    is_authorized,
    normalize_dns_security_target_ids,
)
from dns_security import (  # noqa: E402
    ASSESSMENT_OUTCOMES,
    BoundedDnsResolver,
    DnsQueryBudget,
    DNS_SECURITY_OPERATION,
    MAX_ANSWERS,
    MAX_EVIDENCE_BYTES,
    ResolverOutcome,
    assess_dns_domain,
    dns_security_query_authorizer,
    normalize_dns_name,
    parse_dmarc,
    parse_spf,
    persist_dns_security_check,
    recheck_dns_security_authorization,
)


class FakeResolver:
    def __init__(self, answer=None, error=None):
        self.answer = answer or []
        self.error = error
        self.queries = []
        self.retry_servfail = True

    def resolve(self, name, rrtype, **kwargs):
        self.queries.append((name, rrtype, kwargs))
        if self.error:
            raise self.error
        return self.answer


class FakeCursor:
    def __init__(self, rows=()):
        self.rows = iter(rows)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        try:
            return next(self.rows)
        except StopIteration:
            return None


class FakeAddress:
    def __init__(self, text):
        self.value = text

    def to_text(self):
        return self.value


class FakeTxt:
    def __init__(self, *chunks):
        self.strings = tuple(chunk.encode() for chunk in chunks)

    def to_text(self):
        return '"' + '" "'.join(chunk.decode() for chunk in self.strings) + '"'


class DnsSecurityTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def resolver(self, answer=None, error=None):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        created = []

        def factory():
            item = FakeResolver(answer=answer, error=error)
            created.append(item)
            return item

        return BoundedDnsResolver(factory), created

    def test_dns_security_operation_is_supported_but_disabled_by_default(self):
        self.assertIn(DNS_SECURITY_OPERATION, SCOPE_TESTING_LEVELS)
        self.assertFalse(default_operation_enabled(DNS_SECURITY_OPERATION))
        self.assertFalse(configured_scan_operations())
        sql = active_scan_authorization_sql("d", DNS_SECURITY_OPERATION)
        self.assertIn("AND FALSE", sql)
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        self.assertTrue(default_operation_enabled(DNS_SECURITY_OPERATION))
        self.assertIn("AND TRUE", active_scan_authorization_sql("d", DNS_SECURITY_OPERATION))

    def test_run_scoped_target_allowlist_is_bounded_and_unique(self):
        self.assertEqual(normalize_dns_security_target_ids("7,8,9"), (7, 8, 9))
        for value in ("7,8,9,10", "7,7", "0", "bad", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_dns_security_target_ids(value)

    def test_run_scoped_dns_authorization_stays_inside_central_policy(self):
        os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)
        sql = active_scan_authorization_sql(
            "d", DNS_SECURITY_OPERATION, scan_alias="scan"
        )
        self.assertIn("scan.dns_security_target_ids IS NULL", sql)
        self.assertIn("d.id = ANY(scan.dns_security_target_ids)", sql)
        self.assertIn("(FALSE AND (scan.dns_security_target_ids IS NULL", sql)
        self.assertIn("d.ownership_status = 'CONFIRMED'", sql)
        self.assertIn("d.scannable IS TRUE", sql)
        self.assertIn("manually rejected", sql)

    def test_per_query_authorization_rechecks_run_target_membership(self):
        os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)
        cursor = FakeCursor()
        allowed, _reason = recheck_dns_security_authorization(
            cursor, scan_id=17, domain_name="host.example"
        )
        self.assertFalse(allowed)
        sql, params = cursor.executions[0]
        self.assertIn("scan.dns_security_target_ids", sql)
        self.assertIn("d.id = ANY(scan.dns_security_target_ids)", sql)
        self.assertIn("FALSE AND (scan.dns_security_target_ids IS NULL", sql)
        self.assertIn("scan.status = %s", sql)
        self.assertEqual(params[-1], "RUNNING")

    def test_enabled_process_and_run_target_allowlist_are_both_required(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        cursor = FakeCursor([(1,)])
        allowed, _reason = recheck_dns_security_authorization(
            cursor, scan_id=17, domain_name="host.example"
        )
        self.assertTrue(allowed)
        self.assertIn("TRUE AND (scan.dns_security_target_ids IS NULL", cursor.executions[0][0])

    def test_run_scoped_query_budget_caps_network_attempts(self):
        calls = []

        def factory():
            resolver = FakeResolver([FakeAddress("203.0.113.9")])
            calls.append(resolver)
            return resolver

        budget = DnsQueryBudget(1)
        resolver = BoundedDnsResolver(
            factory, operation_enabled=lambda: True, query_budget=budget
        )
        first = resolver.query("host.example", "A", authorize=lambda: True)
        second = resolver.query("other.example", "A", authorize=lambda: True)
        self.assertEqual(first.outcome, "ANSWER")
        self.assertEqual(second.outcome, "INCONCLUSIVE")
        self.assertEqual(second.evidence["error_category"], "QUERY_BUDGET_EXHAUSTED")
        self.assertEqual(resolver.query_attempts, 1)
        self.assertEqual(budget.attempted, 1)
        self.assertTrue(budget.exhausted)
        self.assertEqual(len(calls), 1)

    def test_authorization_recheck_uses_scan_membership_and_fails_closed(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        cursor = FakeCursor([(1,)])
        allowed, _ = recheck_dns_security_authorization(cursor, scan_id=9, domain_id=4)
        self.assertTrue(allowed)
        sql, params = cursor.executions[0]
        self.assertIn("JOIN scan_results sr", sql)
        self.assertIn("sr.scan_id = %s", sql)
        self.assertIn("d.scannable IS TRUE", sql)
        self.assertIn("manually rejected", sql)
        self.assertEqual(params[-1], "RUNNING")
        self.assertIn("DNS_SECURITY", sql)
        self.assertFalse(recheck_dns_security_authorization(FakeCursor([None]), scan_id=9, domain_id=4)[0])

    def test_query_authorizer_rechecks_each_query_name(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        cursor = FakeCursor([(1,), None])
        authorize = dns_security_query_authorizer(cursor, 9)
        self.assertTrue(authorize("host.example")[0])
        self.assertFalse(authorize("external.example.net")[0])
        self.assertEqual(len(cursor.executions), 2)
        self.assertEqual(cursor.executions[0][1][1], "host.example")
        self.assertEqual(cursor.executions[1][1][1], "external.example.net")

    def test_effective_known_shadow_only_when_confirmed_scannable_and_enabled(self):
        from ownership import TrustedDomainBoundary
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        trusted = TrustedDomainBoundary(
            seed_domains=frozenset({"example.com"}),
            known_domains=frozenset({"documented.net"}),
        )
        def allowed(domain, ownership="CONFIRMED", scannable=True, reasons=()):
            return is_authorized(
                ownership_status=ownership, scannable=scannable,
                validation_source=None, domain=domain,
                testing_level=DNS_SECURITY_OPERATION, scopes=(),
                trusted_domains=trusted, confidence_reasons=reasons,
            )
        self.assertTrue(allowed("api.example.com"))
        self.assertTrue(allowed("documented.net"))
        self.assertFalse(allowed("candidate.example.com", "CANDIDATE"))
        self.assertFalse(allowed("external.example.com", "EXTERNAL"))
        self.assertFalse(allowed("api.example.com", scannable=False))
        self.assertFalse(allowed("api.example.com", reasons=("manually rejected",)))
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "PORT_SCAN"
        self.assertFalse(allowed("api.example.com"))
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        excluded = ScopeApproval(
            "example.com", True, "DNS_SECURITY", "operator",
            datetime(2026, 11, 10, tzinfo=timezone.utc),
            excluded_domains=("blocked.example.com",),
        )
        self.assertFalse(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source=None, domain="blocked.example.com",
            testing_level=DNS_SECURITY_OPERATION, scopes=[excluded],
            trusted_domains=trusted,
        ))

    def test_policy_database_failure_denies_resolver_before_network(self):
        resolver, created = self.resolver([FakeAddress("203.0.113.4")])
        result = resolver.query("host.example", "A", authorize=mock.Mock(side_effect=RuntimeError("db")))
        self.assertEqual(result.outcome, "INCONCLUSIVE")
        self.assertEqual(result.evidence["error_category"], "AUTHORIZATION_ERROR")
        self.assertEqual(created, [])

    def test_disabled_operation_blocks_resolver_even_with_allow_callback(self):
        resolver, created = self.resolver([FakeAddress("192.0.2.2")])
        os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)
        result = resolver.query("host.example", "A", authorize=lambda: True)
        self.assertEqual(result.evidence["error_category"], "OPERATION_DISABLED")
        self.assertEqual(created, [])

    def test_resolver_maps_answer_nodata_nxdomain_timeout_and_nameserver_outcomes(self):
        cases = [
            ([FakeAddress("192.0.2.1")], None, "ANSWER"),
            ([], dns.resolver.NoAnswer(), "NODATA"),
            ([], dns.resolver.NXDOMAIN(), "NXDOMAIN"),
            ([], dns.resolver.LifetimeTimeout(timeout=3, errors=[]), "TIMEOUT"),
            ([], dns.resolver.NoNameservers(), "INCONCLUSIVE"),
        ]
        for answers, error, expected in cases:
            with self.subTest(expected=expected):
                resolver, _ = self.resolver(answers, error)
                result = resolver.query("host.example", "A", authorize=lambda: True)
                self.assertEqual(result.outcome, expected)

    def test_resolver_maps_servfail_and_refused(self):
        for code, expected in ((2, "SERVFAIL"), (5, "REFUSED")):
            exc = dns.resolver.NoNameservers()
            exc.kwargs["errors"] = [(None, None, None, None, code, None)]
            resolver, _ = self.resolver(error=exc)
            result = resolver.query("host.example", "A", authorize=lambda: True)
            self.assertEqual(result.outcome, expected)

    def test_answer_normalization_for_aaaa_cname_mx_and_txt(self):
        cases = [
            ("AAAA", [FakeAddress("2001:db8::1")], "2001:db8::1"),
            ("CNAME", [FakeAddress("Child.Example.")], "child.example"),
            ("TXT", [FakeTxt("v=spf1", " -all")], "v=spf1 -all"),
        ]
        for rrtype, records, expected in cases:
            resolver, _ = self.resolver(records)
            result = resolver.query("host.example", rrtype, authorize=lambda: True)
            self.assertEqual(result.outcome, "ANSWER")
            self.assertEqual(result.answers[0], expected)

        class Rdata:
            preference = 20
            exchange = FakeAddress("mail.example.")
        resolver, _ = self.resolver([Rdata()])
        self.assertEqual(resolver.query("host.example", "MX", authorize=lambda: True).answers,
                         ("20 mail.example",))

    def test_timeout_and_answers_are_bounded(self):
        resolver, created = self.resolver([FakeAddress(f"192.0.2.{i + 1}") for i in range(MAX_ANSWERS + 5)])
        result = resolver.query("host.example", "A", authorize=lambda: True)
        self.assertEqual(len(result.answers), MAX_ANSWERS)
        self.assertTrue(result.evidence["truncated"])
        self.assertLessEqual(created[0].lifetime, 3.0)
        self.assertEqual(created[0].retry_servfail, False)

    def test_conclusive_scan_local_cache_rechecks_authorization(self):
        resolver, created = self.resolver([FakeAddress("192.0.2.8")])
        authorize = mock.Mock(return_value=True)
        first = resolver.query("host.example", "A", authorize=authorize)
        second = resolver.query("host.example", "A", authorize=authorize)
        self.assertEqual(first.answers, second.answers)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].queries, [("host.example", "A", {"search": False})])
        self.assertEqual(authorize.call_count, 2)

    def test_invalid_names_types_and_ip_literals_never_query(self):
        resolver, created = self.resolver([FakeAddress("192.0.2.1")])
        for name, rrtype in (("user@host.example", "A"), ("192.0.2.1", "A"),
                             ("host.example", "PTR")):
            result = resolver.query(name, rrtype, authorize=lambda: True)
            self.assertEqual(result.outcome, "INCONCLUSIVE")
        self.assertEqual(created, [])
        self.assertEqual(normalize_dns_name("TÄST.Example."), "xn--tst-qla.example")

    def test_spf_missing_multiple_and_basic_syntax(self):
        self.assertEqual(parse_spf([], mail_usage_known=False)["outcome"], "INFORMATIONAL")
        self.assertEqual(parse_spf([], mail_usage_known=True)["outcome"], "WARNING")
        self.assertEqual(parse_spf(["v=spf1 -all", "v=spf1 ~all"])["outcome"], "CONFIRMED_ISSUE")
        basic_spf = parse_spf(["v=spf1 -all"])
        self.assertEqual(basic_spf["outcome"], "CLEAR")
        self.assertEqual(basic_spf["evidence"]["validation_scope"], "basic_syntax_only")
        self.assertEqual(parse_spf(["v=spf1 ~all ~all"])["outcome"], "CONFIRMED_ISSUE")

    def test_dmarc_missing_multiple_syntax_and_policy(self):
        self.assertEqual(parse_dmarc([], mail_usage_known=False)["outcome"], "INFORMATIONAL")
        self.assertEqual(parse_dmarc([], mail_usage_known=True)["outcome"], "WARNING")
        basic_dmarc = parse_dmarc(["v=DMARC1; p=reject"])
        self.assertEqual(basic_dmarc["outcome"], "CLEAR")
        self.assertEqual(basic_dmarc["evidence"]["validation_scope"], "basic_syntax_only")
        self.assertEqual(parse_dmarc(["v=DMARC1; p=none"])["outcome"], "WARNING")
        self.assertEqual(parse_dmarc(["v=DMARC1", "v=DMARC1; p=reject"])["outcome"], "CONFIRMED_ISSUE")
        self.assertEqual(parse_dmarc(["v=DMARC1; nope"])["outcome"], "CONFIRMED_ISSUE")

    def test_assessment_rechecks_for_every_query_and_does_not_query_denied_targets(self):
        resolver = mock.Mock()
        def query(name, rrtype, authorize):
            allowed = authorize()
            if not allowed:
                return ResolverOutcome(name, rrtype, "INCONCLUSIVE", (), "now",
                                       {"error_category": "AUTHORIZATION_DENIED"})
            if rrtype == "CNAME" and name == "host.example":
                return ResolverOutcome(name, rrtype, "ANSWER", ("provider.example.net",), "now", {})
            if rrtype == "MX" and name == "host.example":
                return ResolverOutcome(name, rrtype, "ANSWER", ("10 mail.example.net",), "now", {})
            return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})
        resolver.query.side_effect = query
        auth_calls = []
        def auth(name):
            auth_calls.append(name)
            return name == "host.example"
        result = assess_dns_domain("host.example", resolver, auth)
        self.assertGreaterEqual(len(auth_calls), 7)
        self.assertEqual(len(auth_calls), resolver.query.call_count)
        target_calls = [call.args[0] for call in resolver.query.call_args_list
                        if call.args[0] != "host.example"]
        self.assertIn("provider.example.net", target_calls)
        self.assertIn("mail.example.net", target_calls)
        self.assertTrue(any(item["outcome"] == "NOT_CHECKED" for item in result["checks"]))

    def test_cname_loop_is_bounded_and_provider_suffix_is_not_confirmation(self):
        calls = []
        def query(name, rrtype, *, authorize):
            calls.append((name, rrtype))
            authorize()
            if rrtype == "CNAME":
                target = "service.github.io" if name == "host.example" else "host.example"
                return ResolverOutcome(name, rrtype, "ANSWER", (target,), "now", {})
            return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})
        result = assess_dns_domain("host.example", mock.Mock(query=query), lambda _name: True)
        cname = next(item for item in result["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "CONFIRMED_ISSUE")
        self.assertNotEqual(cname["outcome"], "POTENTIAL_EXPOSURE")
        self.assertLessEqual(len(calls), 20)
        self.assertFalse(cname["evidence"].get("takeover_confirmed", False))

    def test_cname_chain_hop_limit_stops_additional_queries(self):
        calls = []
        def query(name, rrtype, *, authorize):
            authorize()
            calls.append((name, rrtype))
            if rrtype == "CNAME":
                next_name = "h1.example" if name == "host.example" else f"h{int(name[1]) + 1}.example"
                return ResolverOutcome(name, rrtype, "ANSWER", (next_name,), "now", {})
            return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})
        result = assess_dns_domain("host.example", mock.Mock(query=query), lambda _name: True,
                                   max_chain_hops=2)
        cname = next(item for item in result["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "INCONCLUSIVE")
        self.assertEqual(sum(rrtype == "CNAME" for _, rrtype in calls), 3)
        self.assertLessEqual(len(calls), 8)

    def test_nxdomain_and_provider_indicator_never_confirm_takeover(self):
        result = assess_dns_domain(
            "host.example", mock.Mock(query=lambda name, rrtype, **_: ResolverOutcome(
                name, rrtype, "ANSWER", ("bucket.amazonaws.com",), "now", {}) if rrtype == "CNAME" and name == "host.example"
                else ResolverOutcome(name, rrtype, "NXDOMAIN", (), "now", {})),
            lambda _name: True)
        cname = next(item for item in result["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "POTENTIAL_EXPOSURE")
        self.assertFalse(cname["evidence"]["takeover_confirmed"])

    def test_cname_terminal_address_queries_use_actual_target(self):
        cases = (
            ("ANSWER", "ANSWER", "CLEAR"),
            ("NXDOMAIN", "NODATA", "POTENTIAL_EXPOSURE"),
        )
        for a_outcome, aaaa_outcome, expected in cases:
            with self.subTest(a_outcome=a_outcome, aaaa_outcome=aaaa_outcome):
                calls = []

                def query(name, rrtype, *, authorize):
                    self.assertTrue(authorize())
                    calls.append((name, rrtype))
                    if name == "owner.example" and rrtype == "CNAME":
                        return ResolverOutcome(name, rrtype, "ANSWER", ("target.example.net",), "now", {})
                    if name == "owner.example" and rrtype == "A":
                        return ResolverOutcome(name, rrtype, "ANSWER", ("192.0.2.20",), "now", {})
                    if name == "target.example.net" and rrtype == "CNAME":
                        return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})
                    if name == "target.example.net" and rrtype == "A":
                        answers = ("192.0.2.10",) if a_outcome == "ANSWER" else ()
                        return ResolverOutcome(name, rrtype, a_outcome, answers, "now", {})
                    if name == "target.example.net" and rrtype == "AAAA":
                        answers = ("2001:db8::10",) if aaaa_outcome == "ANSWER" else ()
                        return ResolverOutcome(name, rrtype, aaaa_outcome, answers, "now", {})
                    return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})

                report = assess_dns_domain("owner.example", mock.Mock(query=query), lambda _name: True)
                cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
                self.assertEqual(cname["outcome"], expected)
                self.assertIn(("target.example.net", "A"), calls)
                self.assertIn(("target.example.net", "AAAA"), calls)
                self.assertIn(("owner.example", "A"), calls)

    def test_cname_multihop_loop_authorization_and_timeout_are_bounded(self):
        def run(target_terminal="NODATA", *, denied=None, timeout=False):
            calls = []

            def query(name, rrtype, *, authorize):
                calls.append((name, rrtype))
                allowed = authorize()
                if not allowed:
                    return ResolverOutcome(name, rrtype, "INCONCLUSIVE", (), "now",
                                           {"error_category": "AUTHORIZATION_DENIED"})
                if timeout and name == "terminal.example.net" and rrtype == "A":
                    return ResolverOutcome(name, rrtype, "TIMEOUT", (), "now", {})
                if rrtype == "CNAME":
                    chains = {"owner.example": "middle.example.net",
                              "middle.example.net": "terminal.example.net",
                              "loop.example.net": "middle.example.net"}
                    if name in chains:
                        return ResolverOutcome(name, rrtype, "ANSWER", (chains[name],), "now", {})
                    if name == "terminal.example.net" and target_terminal == "NXDOMAIN":
                        return ResolverOutcome(name, rrtype, "NXDOMAIN", (), "now", {})
                if rrtype in {"A", "AAAA"} and name == "terminal.example.net":
                    outcome = "NXDOMAIN" if target_terminal == "NXDOMAIN" else "NODATA"
                    return ResolverOutcome(name, rrtype, outcome, (), "now", {})
                return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})

            report = assess_dns_domain("owner.example", mock.Mock(query=query),
                                       lambda name: name != denied)
            return report, calls

        report, calls = run()
        cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "CLEAR")
        self.assertIn(("terminal.example.net", "A"), calls)

        report, calls = run(target_terminal="NXDOMAIN")
        cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "POTENTIAL_EXPOSURE")
        self.assertFalse(cname["evidence"]["takeover_confirmed"])

        report, calls = run(denied="middle.example.net")
        cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "NOT_CHECKED")
        self.assertNotIn(("middle.example.net", "A"), calls)
        self.assertNotIn(("middle.example.net", "AAAA"), calls)

        report, calls = run(timeout=True)
        cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "INCONCLUSIVE")
        self.assertIn(("terminal.example.net", "A"), calls)

        def loop_query(name, rrtype, *, authorize):
            self.assertTrue(authorize())
            if rrtype == "CNAME":
                next_name = "loop.example.net" if name == "owner.example" else "middle.example.net"
                return ResolverOutcome(name, rrtype, "ANSWER", (next_name,), "now", {})
            return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})
        report = assess_dns_domain("owner.example", mock.Mock(query=loop_query), lambda _name: True)
        cname = next(item for item in report["checks"] if item["check_key"] == "cname_health")
        self.assertEqual(cname["outcome"], "CONFIRMED_ISSUE")

    def test_mx_target_checks_keep_record_type_and_target_identity(self):
        def query(name, rrtype, *, authorize):
            self.assertTrue(authorize())
            if name == "mail.example" and rrtype == "MX":
                return ResolverOutcome(name, rrtype,
                                       "ANSWER", ("10 mx1.example", "20 mx2.example"), "now", {})
            return ResolverOutcome(name, rrtype, "NODATA", (), "now", {})

        report = assess_dns_domain("mail.example", mock.Mock(query=query), lambda _name: True)
        targets = [item for item in report["checks"] if item["check_key"] == "mx_target"]
        self.assertEqual({(item["target_identity"], item["record_type"]) for item in targets}, {
            ("mx1.example", "A"), ("mx1.example", "AAAA"),
            ("mx2.example", "A"), ("mx2.example", "AAAA"),
        })

    def test_mx_queries_are_bounded_and_external_targets_require_authorization(self):
        calls = []
        def query(name, rrtype, *, authorize):
            calls.append(name)
            if rrtype == "MX" and name == "mail.example":
                return ResolverOutcome(name, rrtype, "ANSWER", tuple(f"{i} mx{i}.provider.net" for i in range(20)), "now", {})
            allowed = authorize()
            return ResolverOutcome(name, rrtype, "NODATA" if allowed else "INCONCLUSIVE", (), "now",
                                   {} if allowed else {"error_category": "AUTHORIZATION_DENIED"})
        result = assess_dns_domain("mail.example", mock.Mock(query=query), lambda name: name == "mail.example")
        self.assertLessEqual(sum(name.startswith("mx") for name in calls), 2 * 10)
        self.assertTrue(any(item["outcome"] == "NOT_CHECKED" for item in result["checks"]))

    def test_persistence_is_authorized_scan_scoped_idempotent_and_bounded(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "DNS_SECURITY"
        cursor = FakeCursor([(1,), (99,)])
        check = {"check_key": "spf_configuration", "target_identity": "example.com",
                 "outcome": "WARNING", "severity": "LOW", "confidence": "HIGH",
                 "evidence": {"spf_record_count": 0}, "remediation": "Review email configuration."}
        self.assertTrue(persist_dns_security_check(cursor, scan_id=2, domain_id=7, check=check))
        sql, params = cursor.executions[1]
        self.assertIn("WHERE EXISTS", sql)
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("ON CONFLICT (scan_id, domain_id, check_key, target_identity, record_type)", sql)
        self.assertEqual(params[0:5], (2, 7, "spf_configuration", "example.com", ""))
        check_a = {**check, "check_key": "mx_target", "target_identity": "mx1.example", "record_type": "A"}
        self.assertTrue(persist_dns_security_check(FakeCursor([(1,), (99,)]), scan_id=2, domain_id=7, check=check_a))
        check_aaaa = {**check_a, "record_type": "AAAA"}
        aaaa_cursor = FakeCursor([(1,), (100,)])
        self.assertTrue(persist_dns_security_check(aaaa_cursor, scan_id=2, domain_id=7, check=check_aaaa))
        self.assertEqual(aaaa_cursor.executions[1][1][4], "AAAA")
        repeated_cursor = FakeCursor([(1,), (101,)])
        self.assertTrue(persist_dns_security_check(repeated_cursor, scan_id=2, domain_id=7, check=check_a))
        self.assertEqual(repeated_cursor.executions[1][1][4], "A")
        other_scan_cursor = FakeCursor([(1,), (102,)])
        self.assertTrue(persist_dns_security_check(other_scan_cursor, scan_id=3, domain_id=7, check=check_a))
        self.assertEqual(other_scan_cursor.executions[1][1][0], 3)
        denied = FakeCursor([None])
        self.assertFalse(persist_dns_security_check(denied, scan_id=2, domain_id=7, check=check))
        self.assertEqual(len(denied.executions), 1)
        oversized = {**check, "evidence": {"long": "x" * MAX_EVIDENCE_BYTES}}
        with self.assertRaises(ValueError):
            persist_dns_security_check(FakeCursor([(1,)]), scan_id=2, domain_id=7, check=oversized)
        self.assertTrue(ASSESSMENT_OUTCOMES)

    def test_dns_security_does_not_write_canonical_risk_tables(self):
        source = (BACKEND / "dns_security.py").read_text()
        self.assertNotIn("domain_findings", source)
        self.assertNotIn("domain_risk", source)


if __name__ == "__main__":
    unittest.main()
