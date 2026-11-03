import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import http_probe


class HttpProbeTests(unittest.TestCase):
    def test_requires_fresh_authorization_callback(self):
        with mock.patch.object(http_probe, "_observe_once") as observe:
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
        with mock.patch.object(http_probe, "_observe_once", return_value=response) as observe:
            result = http_probe.http_probe("example.test", before_request=authorized)
        self.assertEqual(result, response)
        observe.assert_called_once_with(
            "example.test", "https", expected_ip=None,
            before_request=authorized,
        )
        authorized.assert_called_once_with()

    def test_https_to_http_fallback_rechecks_authorization(self):
        authorized = mock.Mock(return_value=True)
        with mock.patch.object(
            http_probe,
            "_observe_once",
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
        with mock.patch.object(http_probe, "_observe_once", side_effect=OSError("tls")) as observe:
            result = http_probe.http_probe("example.test", before_request=authorized)
        self.assertEqual(result["http_observation_status"], "UNKNOWN")
        self.assertEqual(observe.call_count, 1)

    def test_database_error_before_request_does_not_retry_or_contact_target(self):
        authorize = mock.Mock(side_effect=RuntimeError("database unavailable"))
        with mock.patch.object(http_probe, "_observe_once") as observe:
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
                "inside.example", "https", before_request=lambda: True
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
                "inside.example", "http", before_request=lambda: True
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
                    "inside.example", "http", before_request=lambda: True
                )
        sock.close.assert_called_once()

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
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(authorized.call_count, 3)


if __name__ == "__main__":
    unittest.main()
