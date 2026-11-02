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
        observe.assert_called_once_with("example.test", "https", expected_ip=None)
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

    def test_private_and_reserved_destinations_are_rejected(self):
        for address in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "::1"):
            with self.subTest(address=address):
                self.assertEqual(http_probe._resolve_allowed_addresses(
                    "example.test", 443, expected_ip=address
                ), [])


if __name__ == "__main__":
    unittest.main()
