import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import http_probe


class Response:
    def __init__(self, status_code, reason, url, text="", history=None):
        self.status_code = status_code
        self.reason = reason
        self.url = url
        self.text = text
        self.history = history or []


class HttpProbeTests(unittest.TestCase):
    @mock.patch("http_probe.requests.get")
    def test_preserves_recon_probe_redirect_and_title_behavior(self, get):
        original = Response(301, "Moved Permanently", "https://example.test")
        get.return_value = Response(
            200,
            "OK",
            "https://www.example.test/final",
            "<title> Example\n  Title </title>",
            [original]
        )

        result = http_probe.http_probe("example.test")

        self.assertEqual(result, {
            "http_status": 301,
            "http_reason": "Moved Permanently",
            "final_url": "https://www.example.test/final",
            "final_status": 200,
            "redirect_count": 1,
            "title": "Example Title"
        })
        get.assert_called_once_with(
            "https://example.test",
            timeout=8,
            allow_redirects=True,
            verify=False
        )

    @mock.patch("http_probe.requests.get")
    def test_falls_back_from_https_to_http(self, get):
        get.side_effect = [
            RuntimeError("TLS failed"),
            Response(204, "No Content", "http://example.test")
        ]

        result = http_probe.http_probe("example.test")

        self.assertEqual(result["http_status"], 204)
        self.assertEqual(
            [call.args[0] for call in get.call_args_list],
            ["https://example.test", "http://example.test"]
        )

    @mock.patch("http_probe.requests.get", side_effect=RuntimeError("offline"))
    def test_returns_none_when_neither_scheme_responds(self, get):
        self.assertIsNone(http_probe.http_probe("example.test"))
        self.assertEqual(get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
