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
            "final_url": "https://outside.example/secret",
            "final_status": 302,
            "redirect_count": 1,
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
        self.assertEqual(result["final_status"], 302)
        self.assertEqual(result["final_url"], "https://outside.test/")
        self.assertEqual(result["title"], "Moved")
        connection.close.assert_called_once()

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
