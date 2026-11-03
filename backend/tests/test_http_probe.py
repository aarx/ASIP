import pathlib
import sys
from urllib.parse import urlsplit
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import http_probe


class HttpProbeTests(unittest.TestCase):
    @staticmethod
    def observed(url, status, location=None):
        evidence = http_probe._redirect_evidence(url, status, location)
        final = url if not 300 <= status < 400 else None
        return {
            "http_observation_status": "RESPONDED",
            "http_status": status,
            "http_reason": "Observed",
            "final_url": final,
            "final_status": status if final else None,
            "redirect_count": len(evidence["observed_hops"]),
            "redirect_evidence": evidence,
            "title": "",
            "read_error": None,
        }

    def run_chain(self, responses, allowed_hosts=None):
        contacted = []
        allowed_hosts = allowed_hosts or {"inside.example"}

        def request(url, *, before_request, on_request=None, **_kwargs):
            host = urlsplit(url).hostname
            if not before_request(host):
                raise http_probe.AuthorizationDeniedError("denied")
            if on_request is not None:
                on_request()
            contacted.append(url)
            response = responses.get(url)
            if isinstance(response, Exception):
                raise response
            if response is None:
                raise AssertionError(f"unexpected request: {url}")
            return response

        def authorize(host=None):
            return host is None or host in allowed_hosts

        with mock.patch.object(http_probe, "_request_url", side_effect=request):
            result = http_probe._observe_chain(
                "https://inside.example/start?seed=1",
                before_request=authorize,
            )
        return result, contacted

    def test_requires_fresh_authorization_callback(self):
        with mock.patch.object(http_probe, "_observe_chain") as observe:
            result = http_probe.http_probe("example.test")
        self.assertEqual(result["http_observation_status"], "UNKNOWN")
        observe.assert_not_called()

    def test_valid_observation_does_not_follow_redirects(self):
        response = {
            "http_observation_status": "RESPONDED",
            "http_status": 302,
            "http_reason": "Found",
            "final_url": None,
            "final_status": None,
            "redirect_count": 1,
            "redirect_evidence": http_probe._redirect_evidence(
                "https://example.test/", 302, "https://outside.example/secret"
            ),
            "title": "",
        }
        authorized = mock.Mock(return_value=True)
        with mock.patch.object(http_probe, "_observe_chain", return_value=response) as observe:
            result = http_probe.http_probe("example.test", before_request=authorized)
        self.assertEqual(result, response)
        observe.assert_called_once_with(
            "https://example.test/", expected_ip=None,
            before_request=authorized,
        )
        authorized.assert_called_once_with()

    def test_https_to_http_fallback_rechecks_authorization(self):
        authorized = mock.Mock(return_value=True)
        with mock.patch.object(
            http_probe,
            "_observe_chain",
            side_effect=[OSError("tls"), {
                "http_observation_status": "RESPONDED",
                "http_status": 204,
                "http_reason": "No Content",
                "final_url": "http://example.test/",
                "final_status": 204,
                "redirect_count": 0,
                "redirect_evidence": http_probe._redirect_evidence(
                    "http://example.test/", 204, None
                ),
                "title": "",
            }],
        ) as observe:
            result = http_probe.http_probe("example.test", before_request=authorized)
        self.assertEqual(result["http_status"], 204)
        self.assertEqual(authorized.call_count, 2)
        self.assertEqual(observe.call_count, 2)

    def test_revocation_between_attempts_stops_fallback(self):
        authorized = mock.Mock(side_effect=[True, False])
        with mock.patch.object(http_probe, "_observe_chain", side_effect=OSError("tls")) as observe:
            result = http_probe.http_probe("example.test", before_request=authorized)
        self.assertEqual(result["http_observation_status"], "UNKNOWN")
        self.assertEqual(observe.call_count, 1)

    def test_database_error_before_request_does_not_retry_or_contact_target(self):
        authorize = mock.Mock(side_effect=RuntimeError("database unavailable"))
        with mock.patch.object(http_probe, "_observe_chain") as observe:
            with self.assertRaisesRegex(RuntimeError, "database unavailable"):
                http_probe.http_probe("example.test", before_request=authorize)
        authorize.assert_called_once_with()
        observe.assert_not_called()

    def test_private_and_reserved_destinations_are_rejected(self):
        for address in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "::1"):
            with self.subTest(address=address):
                self.assertEqual(http_probe._resolve_allowed_addresses(
                    "example.test", 443, expected_ip=address
                ), [])

    def test_mixed_public_and_private_dns_answer_fails_closed(self):
        records = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("10.0.0.7", 443)),
        ]
        with mock.patch.object(http_probe.socket, "getaddrinfo", return_value=records):
            self.assertEqual(
                http_probe._resolve_allowed_addresses("example.test", 443), []
            )

    def test_dns_change_must_not_replace_the_expected_pinned_address(self):
        records = [(2, 1, 6, "", ("8.8.4.4", 443))]
        with mock.patch.object(http_probe.socket, "getaddrinfo", return_value=records):
            self.assertEqual(
                http_probe._resolve_allowed_addresses(
                    "example.test", 443, expected_ip="8.8.8.8"
                ), []
            )

    def test_tls_uses_validated_peer_hostname_sni_and_default_verification(self):
        raw = mock.Mock()
        raw.getpeername.return_value = ("2001:4860:4860::8888", 443)
        tls = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = tls
        with mock.patch.object(
            http_probe.socket, "create_connection", return_value=raw
        ) as connect, mock.patch.object(
            http_probe.ssl, "create_default_context", return_value=context
        ) as create_context:
            result = http_probe._connect_pinned(
                "www.example.test", "https", "2001:4860:4860::8888"
            )

        self.assertIs(result, tls)
        connect.assert_called_once_with(
            ("2001:4860:4860::8888", 443), timeout=http_probe.TIMEOUT
        )
        context.wrap_socket.assert_called_once_with(
            raw, server_hostname="www.example.test"
        )
        create_context.assert_called_once_with()

    def test_connected_peer_mismatch_closes_socket_and_fails(self):
        raw = mock.Mock()
        raw.getpeername.return_value = ("1.1.1.1", 80)
        with mock.patch.object(http_probe.socket, "create_connection", return_value=raw):
            with self.assertRaisesRegex(OSError, "destination changed"):
                http_probe._connect_pinned("example.test", "http", "8.8.8.8")
        raw.close.assert_called_once()

    def test_http_response_is_recorded_without_following_location(self):
        response = mock.Mock(status=302, reason="Found")
        response.read.return_value = b"<title>Moved</title>"
        response.getheader.return_value = "https://outside.test/"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        sock = mock.Mock()
        with mock.patch.object(
            http_probe, "_resolve_allowed_addresses", return_value=["8.8.8.8"]
        ), mock.patch.object(
            http_probe, "_connect_pinned", return_value=sock
        ), mock.patch.object(
            http_probe.http.client, "HTTPConnection", return_value=connection
        ):
            result = http_probe._observe_once(
                "inside.example", "https", before_request=lambda _domain=None: True
            )

        connection.request.assert_called_once()
        self.assertEqual(result["http_status"], 302)
        self.assertIsNone(result["final_status"])
        self.assertIsNone(result["final_url"])
        self.assertEqual(
            result["redirect_evidence"]["first_hop_destination"],
            "https://outside.test/",
        )
        self.assertEqual(
            result["redirect_evidence"]["completion_status"], "UNRESOLVED"
        )
        self.assertEqual(result["title"], "Moved")
        connection.close.assert_called_once()

    def test_non_redirect_response_is_a_verified_terminal_response(self):
        response = mock.Mock(status=200, reason="OK")
        response.read.return_value = b"ok"
        response.getheader.return_value = None
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            http_probe, "_resolve_allowed_addresses", return_value=["8.8.8.8"]
        ), mock.patch.object(http_probe, "_connect_pinned", return_value=mock.Mock()), mock.patch.object(
            http_probe.http.client, "HTTPConnection", return_value=connection
        ):
            result = http_probe._observe_once(
                "inside.example", "http", before_request=lambda _domain=None: True
            )
        self.assertEqual(result["final_url"], "http://inside.example/")
        self.assertEqual(result["final_status"], 200)
        self.assertEqual(result["redirect_evidence"]["completion_status"], "COMPLETE")

    def test_redirect_statuses_keep_destination_metadata_without_following(self):
        for status in (301, 302, 307, 308):
            with self.subTest(status=status):
                evidence = http_probe._redirect_evidence(
                    "https://inside.example/path/", status, "../next"
                )
                self.assertEqual(evidence["first_hop_location"], "../next")
                self.assertEqual(evidence["first_hop_destination"], "https://inside.example/next")
                self.assertIsNone(evidence["verified_terminal_url"])
                self.assertEqual(evidence["observed_hops"][0]["followed"], False)

    def test_same_host_and_cross_host_locations_remain_observational(self):
        cases = (
            ("/login", "https://inside.example/login"),
            ("https://outside.example/path", "https://outside.example/path"),
        )
        for location, destination in cases:
            with self.subTest(location=location):
                evidence = http_probe._redirect_evidence(
                    "https://inside.example/", 302, location
                )
                self.assertEqual(evidence["first_hop_destination"], destination)
                self.assertEqual(evidence["stop_reason"], "redirect_traversal_disabled")

    def test_missing_or_invalid_location_is_unresolved(self):
        for location, stop_reason in (
            (None, "missing_location"),
            ("", "missing_location"),
            ("javascript:alert(1)", "invalid_location"),
            ("http://[invalid", "invalid_location"),
        ):
            with self.subTest(location=location):
                evidence = http_probe._redirect_evidence(
                    "https://inside.example/", 301, location
                )
                self.assertIsNone(evidence["first_hop_destination"])
                self.assertIsNone(evidence["verified_terminal_url"])
                self.assertEqual(evidence["stop_reason"], stop_reason)

    def test_historical_verification_state_is_explicit(self):
        # The API labels rows without structured evidence as legacy unknown;
        # it must not promote their old final_url value to a verified final.
        from importlib.util import spec_from_file_location, module_from_spec
        from pathlib import Path
        import logging
        import types
        main_path = Path(__file__).resolve().parents[1] / "main.py"
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = lambda cursor: None
        fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: None
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: "unused"
        spec = spec_from_file_location("redirect_legacy_main", main_path)
        module = module_from_spec(spec)
        old = {key: __import__("sys").modules.get(key) for key in ("db", "llm_service")}
        try:
            __import__("sys").modules.update({"db": fake_db, "llm_service": fake_llm})
            with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
                spec.loader.exec_module(module)
            evidence = module._redirect_evidence_payload(None, "https://old.example/", 200)
            self.assertEqual(evidence["completion_status"], "LEGACY_UNKNOWN")
            self.assertEqual(evidence["legacy_url"], "https://old.example/")
            self.assertIsNone(evidence["verified_terminal_url"])
        finally:
            for key, value in old.items():
                if value is None:
                    __import__("sys").modules.pop(key, None)
                else:
                    __import__("sys").modules[key] = value

    def test_same_host_and_authorized_cross_host_chains_verify_terminal_url(self):
        start = "https://inside.example/start?seed=1"
        same_target = "https://inside.example/next/path?q=2"
        final = "https://inside.example/final?q=3"
        result, contacted = self.run_chain({
            start: self.observed(start, 302, "../next/path?q=2"),
            same_target: self.observed(same_target, 307, "/final?q=3"),
            final: self.observed(final, 200),
        })
        self.assertEqual(contacted, [start, same_target, final])
        self.assertEqual(result["final_url"], final)
        self.assertEqual(result["final_status"], 200)
        evidence = result["redirect_evidence"]
        self.assertEqual(evidence["completion_status"], "COMPLETE")
        self.assertEqual(evidence["verified_terminal_url"], final)
        self.assertEqual(len(evidence["observed_hops"]), 2)
        self.assertTrue(all(hop["followed"] for hop in evidence["observed_hops"]))
        self.assertEqual(evidence["observed_hops"][0]["location"], "../next/path?q=2")

        cross_start = "https://inside.example/start?seed=1"
        cross_target = "https://api.example.com/v2?x=1"
        cross_final = "https://api.example.com/ready?x=1"
        cross, cross_contacted = self.run_chain({
            cross_start: self.observed(cross_start, 301, "https://api.example.com/v2?x=1"),
            cross_target: self.observed(cross_target, 308, "/ready?x=1"),
            cross_final: self.observed(cross_final, 204),
        }, {"inside.example", "api.example.com"})
        self.assertEqual(cross_contacted, [cross_start, cross_target, cross_final])
        self.assertEqual(cross["final_url"], cross_final)

    def test_unauthorized_external_and_ip_literal_destinations_are_never_requested(self):
        start = "https://inside.example/start?seed=1"
        external = "https://outside.example/private"
        result, contacted = self.run_chain({
            start: self.observed(start, 302, external),
        })
        self.assertEqual(contacted, [start])
        self.assertEqual(result["redirect_evidence"]["stop_reason"], "authorization_denied")
        self.assertEqual(result["redirect_evidence"]["last_observed_destination"], external)
        self.assertIsNone(result["final_url"])

        literal = "https://8.8.8.8/private"
        result, contacted = self.run_chain({
            start: self.observed(start, 302, literal),
        })
        self.assertEqual(contacted, [start])
        self.assertEqual(result["redirect_evidence"]["stop_reason"], "authorization_denied")

    def test_invalid_location_loop_and_maximum_hops_remain_unresolved(self):
        start = "https://inside.example/start?seed=1"
        invalid, contacted = self.run_chain({
            start: self.observed(start, 302, "https://user@inside.example/private"),
        })
        self.assertEqual(contacted, [start])
        self.assertEqual(invalid["redirect_evidence"]["stop_reason"], "invalid_location")

        loop, loop_contacted = self.run_chain({
            start: self.observed(start, 302, "/start?seed=1"),
        })
        self.assertEqual(loop_contacted, [start])
        self.assertEqual(loop["redirect_evidence"]["stop_reason"], "redirect_loop")

        middle = "https://inside.example/middle"
        last = "https://inside.example/last"
        with mock.patch.dict("os.environ", {"ASIP_MAX_REDIRECT_HOPS": "1"}):
            bounded, bounded_contacted = self.run_chain({
                start: self.observed(start, 302, middle),
                middle: self.observed(middle, 302, last),
            })
        self.assertEqual(bounded_contacted, [start, middle])
        self.assertEqual(bounded["redirect_evidence"]["stop_reason"], "maximum_redirect_hops")
        self.assertEqual(bounded["redirect_evidence"]["last_observed_destination"], last)
        self.assertIsNone(bounded["final_url"])

    def test_scheme_changes_timeout_and_revocation_are_per_hop(self):
        start = "https://inside.example/start?seed=1"
        http_target = "http://inside.example/insecure?q=1"
        https_target = "https://inside.example/secure?q=1"
        result, contacted = self.run_chain({
            start: self.observed(start, 302, "http://inside.example/insecure?q=1"),
            http_target: self.observed(http_target, 302, "https://inside.example/secure?q=1"),
            https_target: self.observed(https_target, 200),
        })
        self.assertEqual(contacted, [start, http_target, https_target])
        self.assertEqual(result["final_url"], https_target)

        timeout, timeout_contacted = self.run_chain({
            start: self.observed(start, 302, "/middle"),
            "https://inside.example/middle": TimeoutError("network timeout"),
        })
        self.assertEqual(timeout_contacted, [start, "https://inside.example/middle"])
        self.assertEqual(timeout["redirect_evidence"]["completion_status"], "UNRESOLVED")
        self.assertEqual(timeout["redirect_evidence"]["stop_reason"], "network_or_url_error")

        contacted = []
        auth_calls = []
        middle = "https://inside.example/middle"

        def revoke_after_first(host=None):
            auth_calls.append(host)
            return host is None or host == "inside.example" and len(auth_calls) <= 1

        def request(url, *, before_request, on_request=None, **_kwargs):
            host = urlsplit(url).hostname
            if not before_request(host):
                raise http_probe.AuthorizationDeniedError("authorization revoked")
            if on_request is not None:
                on_request()
            contacted.append(url)
            return self.observed(url, 302, "/middle")

        with mock.patch.object(http_probe, "_request_url", side_effect=request):
            revoked = http_probe._observe_chain(start, before_request=revoke_after_first)
        self.assertEqual(contacted, [start])
        self.assertEqual(revoked["redirect_evidence"]["stop_reason"], "authorization_denied")

    def test_authorization_failure_precedes_destination_dns_and_network(self):
        with mock.patch.object(http_probe, "_resolve_allowed_addresses", return_value=[]) as resolve, mock.patch.object(
            http_probe, "_connect_pinned"
        ) as connect:
            with self.assertRaises(http_probe.AuthorizationDeniedError):
                http_probe._request_url(
                    "https://outside.example/path?q=1",
                    before_request=lambda _host: False,
                )
        resolve.assert_not_called()
        connect.assert_not_called()

        calls = []
        with mock.patch.object(http_probe, "_resolve_allowed_addresses") as resolve, mock.patch.object(
            http_probe, "_connect_pinned"
        ) as connect:
            with self.assertRaises(OSError):
                http_probe._request_url(
                    "https://inside.example/path?q=1",
                    expected_ip="8.8.8.8",
                    before_request=lambda host: calls.append(host) or True,
                )
        self.assertEqual(calls, ["inside.example"])
        resolve.assert_called_once_with("inside.example", 443, "8.8.8.8")
        connect.assert_not_called()

    def test_url_validation_rejects_nonstandard_ports_and_ambiguous_userinfo(self):
        for url in (
            "https://inside.example:8443/path",
            "http://user:pass@inside.example/path",
            "https://inside.example/%zz",
            "ftp://inside.example/path",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                http_probe._normalize_http_url(url)

    def test_socket_is_closed_if_http_client_setup_fails(self):
        sock = mock.Mock()
        with mock.patch.object(
            http_probe, "_resolve_allowed_addresses", return_value=["8.8.8.8"]
        ), mock.patch.object(
            http_probe, "_connect_pinned", return_value=sock
        ), mock.patch.object(
            http_probe.http.client, "HTTPConnection", side_effect=RuntimeError("setup")
        ):
            with self.assertRaisesRegex(RuntimeError, "setup"):
                http_probe._observe_once(
                    "inside.example", "http", before_request=lambda _domain=None: True
                )
        sock.close.assert_called_once()

    def test_ambiguous_http_failure_does_not_retry_the_same_hop_on_another_ip(self):
        connection = mock.Mock()
        connection.request.side_effect = TimeoutError("response timeout")
        sock = mock.Mock()
        with mock.patch.object(
            http_probe, "_resolve_allowed_addresses", return_value=["8.8.8.8", "1.1.1.1"]
        ), mock.patch.object(
            http_probe, "_connect_pinned", return_value=sock
        ) as connect, mock.patch.object(
            http_probe.http.client, "HTTPConnection", return_value=connection
        ):
            with self.assertRaisesRegex(TimeoutError, "response timeout"):
                http_probe._request_url(
                    "https://inside.example/path?q=1",
                    before_request=lambda _host: True,
                )
        self.assertEqual(connect.call_count, 1)
        connection.request.assert_called_once()

    def test_revocation_between_public_address_attempts_stops_later_connect(self):
        addresses = ["8.8.8.8", "1.1.1.1"]
        authorized = mock.Mock(side_effect=[True, True, False])
        with mock.patch.object(
            http_probe, "_resolve_allowed_addresses", return_value=addresses
        ), mock.patch.object(
            http_probe, "_connect_pinned", side_effect=OSError("first peer failed")
        ) as connect:
            result = http_probe.http_probe(
                "example.test", before_request=authorized
            )
        self.assertEqual(result["http_observation_status"], "UNKNOWN")
        self.assertEqual(connect.call_count, 0)
        self.assertEqual(authorized.call_count, 3)


if __name__ == "__main__":
    unittest.main()
