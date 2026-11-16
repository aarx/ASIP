import json
import pathlib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock
from datetime import datetime, timezone


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import brand_redirect_intelligence as bri  # noqa: E402
import brand_redirect_worker as worker  # noqa: E402
import db  # noqa: E402
from authorization_policy import (  # noqa: E402
    ScopeApproval,
    active_scan_authorization_sql,
    active_scope_coverage_sql,
    configured_scan_operations,
    is_authorized,
    passive_dns_discovery_sql,
    scope_authorization_sql,
    scope_authorizes,
)


class BrandRedirectConfigurationTests(unittest.TestCase):
    def test_fresh_schema_bootstrap_includes_scope_table_and_redirect_level(self):
        schema = (BACKEND / "asm_schema_post_guardrails-schema-only.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE TABLE public.active_scan_scopes", schema)
        self.assertIn("'BRAND_REDIRECT_OBSERVATION'", schema)

    def test_pipeline_stage_requires_a_live_scope_and_ignores_legacy_origin_setting(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = (0,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(db, "get_conn", return_value=connection), \
             mock.patch.dict("os.environ", {"ASIP_BRAND_REDIRECT_TARGETS": "https://brand.example"}):
            self.assertIsNone(bri.optional_pipeline_stage(19))
        cursor.fetchone.return_value = (1,)
        with mock.patch.object(db, "get_conn", return_value=connection):
            self.assertEqual(bri.optional_pipeline_stage(19), (
                "Brand Redirect Intelligence",
                "python -u brand_redirect_worker.py 19",
            ))
        self.assertEqual(cursor.execute.call_args.args[1], (bri.BRAND_REDIRECT_SCOPE,))

    def test_campaign_seed_provenance_selects_thousands_without_individual_entries(self):
        domains = [(index, f"candidate-{index}.lookalike.test")
                   for index in range(1, 2001)]
        cursor = mock.Mock()
        cursor.fetchall.side_effect = [[(
            77, "example.com", True, [], ["brand_tld", "brand_pattern"], 2000,
            "Brand abuse monitoring",
        )], domains]
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "require_running_scan"):
            selected = worker.select_targets(24)
        self.assertEqual(len(selected), 2000)
        self.assertEqual(selected[0], (1, "candidate-1.lookalike.test", "https://candidate-1.lookalike.test/"))
        candidate_sql = cursor.execute.call_args_list[1].args[0]
        self.assertIn("scope.eligible_discovery_sources", candidate_sql)
        self.assertIn("source.source = ANY(scope.eligible_discovery_sources)", candidate_sql)
        self.assertIn("LOWER(TRIM(TRAILING '.' FROM BTRIM(source.seed)))", candidate_sql)
        self.assertIn("= scope.scope_domain", candidate_sql)
        self.assertNotIn("d.domain)) = scope.scope_domain", candidate_sql)
        self.assertIn("manually rejected", candidate_sql)
        self.assertIn("= 'CANDIDATE'", candidate_sql)
        self.assertNotIn("scannable", candidate_sql.lower())
        self.assertEqual(cursor.execute.call_count, 2)

    def test_seed_subdomain_can_be_selected_by_campaign_source_provenance(self):
        cursor = mock.Mock()
        campaign = (77, "example.com", True, [], ["brand_pattern"], 25,
                    "Brand impersonation monitoring")
        cursor.fetchall.side_effect = [[campaign], [(1, "portal.example.com")]]
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "require_running_scan"):
            selected = worker.select_targets(24)
        self.assertEqual(selected, [(1, "portal.example.com", "https://portal.example.com/")])

    def test_unrelated_candidate_without_matching_campaign_seed_is_not_selected(self):
        cursor = mock.Mock()
        campaign = (77, "example.com", True, [], ["brand_tld"], 25,
                    "Brand impersonation monitoring")
        cursor.fetchall.side_effect = [[campaign], []]
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "require_running_scan"):
            selected = worker.select_targets(24)
        self.assertEqual(selected, [])
        sql = cursor.execute.call_args_list[1].args[0]
        self.assertIn("source.source = ANY(scope.eligible_discovery_sources)", sql)
        self.assertIn("LOWER(TRIM(TRAILING '.' FROM BTRIM(source.seed)))", sql)
        self.assertIn("= scope.scope_domain", sql)

    def test_no_campaign_approval_means_no_targets(self):
        cursor = mock.Mock()
        cursor.fetchall.return_value = []
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "require_running_scan"):
            self.assertEqual(worker.select_targets(24), [])
        self.assertEqual(cursor.execute.call_count, 1)
        self.assertIn("scope.monitoring_purpose", cursor.execute.call_args.args[0])

    def test_excluded_or_manually_rejected_candidates_are_filtered(self):
        cursor = mock.Mock()
        campaign = (77, "example.com", True, ["blocked-lookalike.test"],
                    ["brand_pattern"], 25, "Brand impersonation monitoring")
        cursor.fetchall.side_effect = [[campaign], []]
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "require_running_scan"):
            self.assertEqual(worker.select_targets(24), [])
        sql = cursor.execute.call_args_list[1].args[0]
        self.assertIn("scope.excluded_domains", sql)
        self.assertIn("manually rejected", sql)

    def test_scope_permission_is_separate_from_other_scan_operations(self):
        approved = ScopeApproval(
            scope_domain="example.com", include_subdomains=True,
            testing_level="BRAND_REDIRECT_OBSERVATION", approved_by="operator",
            approved_at=datetime.now(timezone.utc),
            monitoring_purpose="Brand abuse redirect monitoring",
            eligible_discovery_sources=("brand_tld", "brand_pattern"),
            max_requests_per_scan=1000,
        )
        self.assertTrue(scope_authorizes(
            [approved], "brand.example.com", "BRAND_REDIRECT_OBSERVATION"
        ))
        for level in ("HTTP_TLS_OBSERVATION", "TECHNOLOGY_HTTP", "PORT_SCAN"):
            self.assertFalse(scope_authorizes([approved], "brand.example.com", level))
        self.assertEqual(configured_scan_operations("BRAND_REDIRECT_OBSERVATION"), frozenset())
        sql = active_scan_authorization_sql("d", "BRAND_REDIRECT_OBSERVATION")
        self.assertIn("AND FALSE", sql)
        self.assertNotIn(
            "BRAND_REDIRECT_OBSERVATION", active_scope_coverage_sql("d")
        )
        self.assertNotIn(
            "BRAND_REDIRECT_OBSERVATION", passive_dns_discovery_sql("d", "sr")
        )
        self.assertFalse(is_authorized(
            ownership_status="CANDIDATE", scannable=False,
            validation_source=None, domain="brand.example.com",
            testing_level="PORT_SCAN",
        ))

    def test_brand_scope_requires_purpose_sources_and_bounded_campaign_budget(self):
        with self.assertRaisesRegex(ValueError, "purpose"):
            ScopeApproval(
                scope_domain="example.com", include_subdomains=True,
                testing_level="BRAND_REDIRECT_OBSERVATION", approved_by="operator",
                approved_at=datetime.now(timezone.utc),
                eligible_discovery_sources=("brand_tld",), max_requests_per_scan=10,
            )
        with self.assertRaisesRegex(ValueError, "discovery sources"):
            ScopeApproval(
                scope_domain="example.com", include_subdomains=True,
                testing_level="BRAND_REDIRECT_OBSERVATION", approved_by="operator",
                approved_at=datetime.now(timezone.utc), monitoring_purpose="Brand review",
                eligible_discovery_sources=("ct_logs",), max_requests_per_scan=10,
            )

    def test_explicit_scope_exclusion_and_revocation_override_approval(self):
        approved = ScopeApproval(
            scope_domain="example.com", include_subdomains=True,
            testing_level="BRAND_REDIRECT_OBSERVATION", approved_by="operator",
            approved_at=datetime.now(timezone.utc),
            excluded_domains=("blocked.example.com",),
            monitoring_purpose="Brand abuse redirect monitoring",
            eligible_discovery_sources=("brand_tld",), max_requests_per_scan=1000,
        )
        self.assertFalse(scope_authorizes(
            [approved], "blocked.example.com", "BRAND_REDIRECT_OBSERVATION"
        ))
        revoked = ScopeApproval(
            scope_domain="blocked.example.com", include_subdomains=True,
            testing_level="BRAND_REDIRECT_OBSERVATION", approved_by="operator",
            approved_at=datetime.now(timezone.utc), status="REVOKED",
            revoked_by="operator", revoked_at=datetime.now(timezone.utc),
            monitoring_purpose="Brand abuse redirect monitoring",
            eligible_discovery_sources=("brand_tld",), max_requests_per_scan=1000,
        )
        # The SQL policy blocks an explicitly revoked nested scope even when a
        # broader active grant exists.
        sql = scope_authorization_sql("d.domain", bri.BRAND_REDIRECT_SCOPE)
        self.assertIn("scope_block.status = 'REVOKED'", sql)
        self.assertFalse(scope_authorizes(
            [revoked], "blocked.example.com", "BRAND_REDIRECT_OBSERVATION"
        ))


class RedirectChainTests(unittest.TestCase):
    def setUp(self):
        self.authorized = {"https://brand.example", "https://vendor.example"}

    def _chain(self, responses, *, authorize=None):
        calls = []

        def request(url, **kwargs):
            calls.append(url)
            if kwargs.get("reserve_request"):
                kwargs["reserve_request"]()
            if kwargs.get("on_request"):
                kwargs["on_request"]()
            return responses[url]

        evidence = bri.observe_redirect_chain(
            "brand.example", "https://brand.example/",
            scan_id=24, operation_id="d20720ee-f2a3-441c-b806-46f8aa094c7d",
            authorize=authorize or (lambda origin: origin in self.authorized), request_once=request,
        )
        return evidence, calls

    def test_allowed_redirect_records_reported_and_verified_values_separately(self):
        evidence, calls = self._chain({
            "https://brand.example/": {
                "status": 302, "location": "https://vendor.example/start",
                "page_title": "", "response_retrieved": True,
            },
            "https://vendor.example/start": {
                "status": 200, "location": None,
                "page_title": "Landing", "response_retrieved": True,
            },
        })
        self.assertEqual(calls, ["https://brand.example/", "https://vendor.example/start"])
        self.assertEqual(evidence["completeness"], "COMPLETE")
        self.assertEqual(evidence["redirect_location"], "https://vendor.example/start")
        self.assertEqual(evidence["last_reported_destination_url"], "https://vendor.example/start")
        self.assertEqual(evidence["verified_final_url"], "https://vendor.example/start")
        self.assertEqual(evidence["final_status"], 200)
        self.assertEqual(evidence["page_title"], "Landing")
        self.assertEqual(evidence["requests_attempted"], 2)
        self.assertTrue(evidence["observed_hops"][0]["followed"])

    def test_unrelated_public_hostname_can_be_followed_under_campaign_policy(self):
        destination = "https://unrelated-public.example.org/landing"
        evidence, calls = self._chain({
            "https://brand.example/": {
                "status": 302, "location": destination,
                "page_title": "", "response_retrieved": True,
            },
            destination: {
                "status": 200, "location": None,
                "page_title": "Landing", "response_retrieved": True,
            },
        }, authorize=lambda _origin: True)
        self.assertEqual(calls, ["https://brand.example/", destination])
        self.assertEqual(evidence["verified_final_url"], destination)
        self.assertEqual(evidence["completeness"], "COMPLETE")

    def test_three_redirects_across_unrelated_public_hosts_reach_verified_final_url(self):
        urls = [
            "https://one-lookalike.test/",
            "https://two-campaign-hop.test/",
            "https://three-landing-hop.test/",
            "https://final-public-destination.test/",
        ]
        responses = {
            "https://brand.example/": {
                "status": 301, "location": urls[0], "response_retrieved": True,
            },
            urls[0]: {"status": 302, "location": urls[1], "response_retrieved": True},
            urls[1]: {"status": 301, "location": urls[2], "response_retrieved": True},
            urls[2]: {"status": 200, "location": None, "response_retrieved": True},
        }
        evidence, calls = self._chain(responses, authorize=lambda _origin: True)
        self.assertEqual(
            calls,
            ["https://brand.example/", urls[0], urls[1], urls[2]],
        )
        self.assertEqual(len([hop for hop in evidence["observed_hops"] if hop["followed"]]), 3)
        self.assertEqual(evidence["verified_final_url"], urls[2])
        self.assertEqual(evidence["final_status"], 200)
        self.assertEqual(evidence["completeness"], "COMPLETE")

    def test_campaign_request_budget_stops_before_unbudgeted_destination(self):
        destination = "https://unrelated-public.example.org/landing"
        attempts = 0

        def reserve():
            nonlocal attempts
            if attempts >= 1:
                raise bri.RequestBudgetExceeded("budget exhausted")
            attempts += 1

        evidence = bri.observe_redirect_chain(
            "brand.example", "https://brand.example/", scan_id=24,
            operation_id="d20720ee-f2a3-441c-b806-46f8aa094c7d",
            authorize=lambda _origin: True,
            request_once=lambda url, **kwargs: (
                kwargs["reserve_request"]() or kwargs["on_request"]() or {
                    "status": 302, "location": destination,
                    "page_title": "", "response_retrieved": True,
                }
            ),
            on_request=reserve,
        )
        self.assertEqual(attempts, 1)
        self.assertEqual(evidence["requests_attempted"], 1)
        self.assertEqual(evidence["completeness"], "REQUEST_BUDGET_EXHAUSTED")
        self.assertIsNone(evidence["verified_final_url"])
        self.assertEqual(evidence["last_reported_destination_url"], destination)

    def test_unapproved_redirect_location_is_not_contacted(self):
        evidence, calls = self._chain({
            "https://brand.example/": {
                "status": 301, "location": "https://outside.example/",
                "page_title": "", "response_retrieved": True,
            },
        })
        self.assertEqual(calls, ["https://brand.example/"])
        self.assertEqual(evidence["completeness"], "STOPPED_AT_AUTHORIZATION_BOUNDARY")
        self.assertIsNone(evidence["verified_final_url"])
        self.assertFalse(evidence["observed_hops"][0]["followed"])

    def test_foreign_redirect_destination_has_no_per_domain_scope_gate(self):
        conn = mock.Mock()
        cursor = conn.cursor.return_value
        cursor.fetchone.side_effect = lambda: (
            None if "blocked.example.org" in cursor.execute.call_args.args[1] else (1,)
        )
        evidence = {
            "completeness": "COMPLETE", "observed_hops": [],
            "requests_attempted": 2,
        }

        def observe(*_args, **kwargs):
            self.assertTrue(kwargs["authorize"]("https://unrelated.example.org"))
            self.assertFalse(kwargs["authorize"]("https://blocked.example.org"))
            return evidence

        campaign = (
            77, "example.com", True, ["blocked.example.org"],
            ["brand_tld"], 1000, "Brand abuse monitoring",
        )
        with mock.patch.object(worker, "get_conn", return_value=conn), \
             mock.patch.object(worker, "require_running_scan"), \
             mock.patch.object(worker, "observe_redirect_chain", side_effect=observe):
            worker._run_target(
                (5, "abandoned-example.com", "https://abandoned-example.com/"),
                24, "operation", campaign, worker._RequestBudget(1000),
            )
        auth_sql = cursor.execute.call_args_list[0].args[0]
        self.assertIn("scope.eligible_discovery_sources", auth_sql)
        self.assertIn("scope.excluded_domains", auth_sql)
        self.assertNotIn("scope_authorization_sql", auth_sql)
        self.assertNotIn("destination_scope", auth_sql)
        self.assertNotIn("candidate.domain)) = scope.scope_domain", auth_sql)

    def test_redirect_loop_is_reported_without_fabricating_a_final_url(self):
        evidence, calls = self._chain({
            "https://brand.example/": {
                "status": 302, "location": "/",
                "page_title": "", "response_retrieved": True,
            },
        })
        self.assertEqual(len(calls), 1)
        self.assertEqual(evidence["completeness"], "REDIRECT_LOOP")
        self.assertIsNone(evidence["verified_final_url"])

    def test_follows_at_most_three_redirects(self):
        domains = [f"h{i}.example" for i in range(5)]
        allowed_origins = frozenset(f"https://{host}" for host in domains)
        responses = {}
        for index, host in enumerate(domains[:-1]):
            responses[f"https://{host}/"] = {
                "status": 302,
                "location": f"https://{domains[index + 1]}/",
                "page_title": "", "response_retrieved": True,
            }
        calls = []

        def request(url, **_kwargs):
            calls.append(url)
            if _kwargs.get("on_request"):
                _kwargs["on_request"]()
            return responses[url]

        evidence = bri.observe_redirect_chain(
            domains[0], f"https://{domains[0]}/", scan_id=2,
            operation_id="f4de8854-0fdc-4d30-8f9f-bab414a9d351",
            authorize=lambda origin: origin in allowed_origins, request_once=request,
        )
        self.assertEqual(len(calls), 4)
        self.assertEqual(evidence["completeness"], "MAX_REDIRECT_HOPS")
        self.assertEqual(sum(hop["followed"] for hop in evidence["observed_hops"]), 3)
        self.assertIsNone(evidence["verified_final_url"])

    def test_timeout_and_transport_errors_are_distinguished(self):
        for error, expected in ((TimeoutError(), "TIMEOUT"), (OSError(), "ERROR")):
            with self.subTest(expected=expected):
                evidence = bri.observe_redirect_chain(
                    "brand.example", "https://brand.example/",
                    scan_id=1, operation_id="id", authorize=lambda _origin: True,
                    request_once=mock.Mock(side_effect=error),
                )
                self.assertEqual(evidence["completeness"], expected)
                self.assertIsNone(evidence["verified_final_url"])

    def test_authorization_is_rechecked_before_each_request_and_denial_stops_chain(self):
        approved = []

        def request(url, *, authorize, **kwargs):
            self.assertTrue(authorize(bri._origin(url)))
            approved.append(url)
            if kwargs.get("on_request"):
                kwargs["on_request"]()
            return {
                "status": 302,
                "location": "https://vendor.example/landing",
                "page_title": "", "response_retrieved": True,
            }

        def authorize(origin):
            return origin == "https://brand.example"

        evidence = bri.observe_redirect_chain(
            "brand.example", "https://brand.example/",
            scan_id=1, operation_id="id", authorize=authorize,
            request_once=request,
        )
        self.assertEqual(approved, ["https://brand.example/"])
        self.assertEqual(evidence["completeness"], "STOPPED_AT_AUTHORIZATION_BOUNDARY")

    def test_unapproved_target_is_rechecked_and_never_sent_to_requester(self):
        request = mock.Mock()
        evidence = bri.observe_redirect_chain(
            "brand.example", "https://brand.example/",
            scan_id=24, operation_id="id", authorize=lambda _origin: False,
            request_once=request,
        )
        request.assert_not_called()
        self.assertEqual(evidence["completeness"], "STOPPED_AT_AUTHORIZATION_BOUNDARY")

    def test_non_redirect_response_is_a_verified_terminal_observation(self):
        evidence, calls = self._chain({
            "https://brand.example/": {
                "status": 200, "location": None, "page_title": "Brand",
                "response_retrieved": True,
            },
        })
        self.assertEqual(calls, ["https://brand.example/"])
        self.assertEqual(evidence["completeness"], "NO_REDIRECT")
        self.assertEqual(evidence["verified_final_url"], "https://brand.example/")
        self.assertEqual(evidence["final_status"], 200)


class PinnedRequestTests(unittest.TestCase):
    def _http_connection(self, status=302, location="https://vendor.example/"):
        response = mock.Mock()
        response.status = status
        response.reason = "Found"
        response.getheader.return_value = location
        response.read.return_value = b"<title>Observed</title>"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        return connection

    def test_single_get_is_direct_nonredirecting_and_rechecks_authorization(self):
        connection = self._http_connection()
        auth = mock.Mock(return_value=True)
        with mock.patch.object(bri, "_resolve_allowed_addresses", return_value=["93.184.216.34"]) as resolve, \
             mock.patch.object(bri, "_connect_pinned", return_value=mock.Mock()) as connect, \
             mock.patch.object(bri.http.client, "HTTPConnection", return_value=connection):
            response = bri._single_request(
                "https://brand.example/", authorize=auth,
                deadline=time.monotonic() + 5,
            )
        self.assertEqual(response["status"], 302)
        self.assertEqual(response["location"], "https://vendor.example/")
        self.assertEqual(response["page_title"], "Observed")
        self.assertEqual(connection.request.call_count, 1)
        self.assertGreaterEqual(auth.call_count, 3)
        self.assertEqual(resolve.call_count, 1)
        self.assertLessEqual(connect.call_args.kwargs["timeout"], 5)

    def test_private_metadata_address_is_rejected_before_connect(self):
        with mock.patch.object(bri, "_resolve_allowed_addresses", return_value=["169.254.169.254"]), \
             mock.patch.object(bri, "_connect_pinned") as connect:
            with self.assertRaises(OSError):
                bri._single_request(
                    "https://brand.example/", authorize=lambda _origin: True,
                    deadline=time.monotonic() + 5,
                )
        connect.assert_not_called()

    def test_dns_is_revalidated_on_redirect_and_new_unsafe_answer_is_not_connected(self):
        connection = self._http_connection(status=302, location="/next")
        with mock.patch.object(
            bri, "_resolve_allowed_addresses",
            side_effect=[["93.184.216.34"], ["10.0.0.1"]],
        ) as resolve, mock.patch.object(bri, "_connect_pinned", return_value=mock.Mock()) as connect, \
             mock.patch.object(bri.http.client, "HTTPConnection", return_value=connection):
            evidence = bri.observe_redirect_chain(
                "brand.example", "https://brand.example/",
                scan_id=1, operation_id="id", authorize=lambda _origin: True,
            )
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(evidence["completeness"], "ERROR")
        self.assertFalse(evidence["observed_hops"][0]["followed"])

    def test_global_worker_pool_never_exceeds_two_targets(self):
        lock = threading.Lock()
        active = 0
        maximum = 0

        def target(value):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return value

        self.assertEqual(bri.run_bounded_targets(range(8), target, workers=8), list(range(8)))
        self.assertLessEqual(maximum, 2)

    def test_same_host_requests_are_serialized(self):
        lock = threading.Lock()
        active = 0
        maximum = 0

        def connection_factory(*_args, **_kwargs):
            connection = mock.Mock()
            response = mock.Mock()
            response.status = 200
            response.reason = "OK"
            response.getheader.return_value = None
            response.read.return_value = b"<title>ok</title>"
            connection.getresponse.return_value = response

            def request(*_request_args, **_request_kwargs):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                time.sleep(0.03)
                with lock:
                    active -= 1

            connection.request.side_effect = request
            return connection

        def issue(_index):
            return bri._single_request(
                "https://brand.example/", authorize=lambda _origin: True,
                deadline=time.monotonic() + 5,
            )

        with mock.patch.object(bri, "_resolve_allowed_addresses", return_value=["93.184.216.34"]), \
             mock.patch.object(bri, "_connect_pinned", return_value=mock.Mock()), \
             mock.patch.object(bri.http.client, "HTTPConnection", side_effect=connection_factory):
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(issue, range(4)))
        self.assertEqual(len(results), 4)
        self.assertEqual(maximum, 1)

    def test_private_special_use_address_policy(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "::1", "fd00::1"):
            with self.subTest(address=address):
                self.assertTrue(bri.is_prohibited_address(address))
        self.assertFalse(bri.is_prohibited_address("93.184.216.34"))


class RedirectPersistenceTests(unittest.TestCase):
    def test_worker_rechecks_candidate_and_destination_scope_before_request(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = (1,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        def observe(_domain, _url, *, authorize, on_request, **_metadata):
            permitted = authorize("https://brand.example")
            return {
                "completeness": "NO_REDIRECT" if permitted else "STOPPED_AT_AUTHORIZATION_BOUNDARY",
                "evidence_source": bri.EVIDENCE_SOURCE,
            }

        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "observe_redirect_chain", side_effect=observe), \
             mock.patch.object(worker, "require_running_scan"):
            permitted = worker._run_target(
                (17, "brand.example", "https://brand.example/"), 24, "operation-24",
                (77, "brand.example", True, [], ["brand_tld"], 1000, "Brand review"),
                worker._RequestBudget(1000),
            )
        self.assertEqual(permitted, "NO_REDIRECT")
        auth_sql, auth_params = cursor.execute.call_args_list[0].args
        self.assertIn("scan.status = 'RUNNING'", auth_sql)
        self.assertIn("scope.testing_level = %s", auth_sql)
        self.assertIn("scope.eligible_discovery_sources", auth_sql)
        self.assertIn("revoked.status = 'REVOKED'", auth_sql)
        self.assertIn("scope.excluded_domains", auth_sql)
        self.assertIn("rejected_destination", auth_sql)
        self.assertIn("manually rejected", auth_sql)
        self.assertIn("LOWER(TRIM(TRAILING '.' FROM BTRIM(source.seed)))", auth_sql)
        self.assertEqual(auth_params[:5], (17, 77, 24, bri.BRAND_REDIRECT_SCOPE, "ACTIVE"))
        self.assertIn("brand.example", auth_params)

        cursor.reset_mock()
        cursor.fetchone.return_value = None
        connection.reset_mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "observe_redirect_chain", side_effect=observe), \
             mock.patch.object(worker, "require_running_scan"):
            denied = worker._run_target(
                (17, "brand.example", "https://brand.example/"), 24, "operation-24",
                (77, "brand.example", True, [], ["brand_tld"], 1000, "Brand review"),
                worker._RequestBudget(1000),
            )
        self.assertEqual(denied, "STOPPED_AT_AUTHORIZATION_BOUNDARY")
        self.assertIn(bri.BRAND_REDIRECT_SCOPE, cursor.execute.call_args_list[0].args[1])

    def test_persists_scoped_evidence_only_while_the_scan_is_running(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = ("RUNNING",)
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        evidence = {
            "scan_id": 24, "operation_id": "operation-24",
            "evidence_source": bri.EVIDENCE_SOURCE,
            "completeness": "STOPPED_AT_AUTHORIZATION_BOUNDARY",
            "campaign_id": 77, "campaign_scope": "brand.example",
            "campaign_purpose": "Brand review",
            "eligible_discovery_sources": ["brand_tld"],
            "campaign_request_budget": 1000,
        }
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "observe_redirect_chain", return_value=evidence) as observe, \
             mock.patch.object(worker, "require_running_scan") as require_running:
            result = worker._run_target(
                (17, "brand.example", "https://brand.example/"),
                24, "operation-24",
                (77, "brand.example", True, [], ["brand_tld"], 1000, "Brand review"),
                worker._RequestBudget(1000),
            )
        self.assertEqual(result, "STOPPED_AT_AUTHORIZATION_BOUNDARY")
        observe.assert_called_once()
        require_running.assert_called_once_with(cursor, 24)
        sql = cursor.execute.call_args.args[0]
        self.assertIn("INSERT INTO brand_redirect_observations", sql)
        params = cursor.execute.call_args.args[1]
        self.assertEqual(params[:5], (
            24, 17, "operation-24", bri.EVIDENCE_SOURCE,
            "STOPPED_AT_AUTHORIZATION_BOUNDARY",
        ))
        self.assertEqual(json.loads(params[5]), evidence)
        connection.commit.assert_called_once()

    def test_failed_running_scan_check_rolls_back_without_persisting(self):
        cursor = mock.Mock()
        connection = mock.Mock()
        connection.cursor.return_value = cursor
        with mock.patch.object(worker, "get_conn", return_value=connection), \
             mock.patch.object(worker, "observe_redirect_chain", return_value={"completeness": "NO_REDIRECT"}), \
             mock.patch.object(worker, "require_running_scan", side_effect=RuntimeError("scan stopped")):
            with self.assertRaisesRegex(RuntimeError, "scan stopped"):
                worker._run_target(
                    (17, "brand.example", "https://brand.example/"),
                    24, "operation-24",
                    (77, "brand.example", True, [], ["brand_tld"], 1000, "Brand review"),
                    worker._RequestBudget(1000),
                )
        self.assertNotIn("INSERT INTO brand_redirect_observations", str(cursor.execute.call_args))
        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
