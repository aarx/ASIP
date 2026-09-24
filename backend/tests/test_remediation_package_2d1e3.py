import datetime
import importlib.util
import logging
import pathlib
import socket
import ssl
import subprocess
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_worker(filename):
    module_name = f"pkg2d1e3_{filename}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    previous_db = sys.modules.get("db")
    old_argv = sys.argv[:]
    old_path = sys.path[:]
    try:
        sys.modules["db"] = fake_db
        sys.argv = [filename, "42"]
        sys.path.insert(0, str(BACKEND))
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()), \
                mock.patch("os.makedirs"):
            spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        if previous_db is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = previous_db
    return module


class RecordingCursor:
    def __init__(self, fetchalls=None, fetchones=None):
        self.fetchalls = list(fetchalls or [])
        self.fetchones = list(fetchones or [])
        self.executions = []
        self.rowcount = 1

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchall(self):
        return self.fetchalls.pop(0) if self.fetchalls else []

    def fetchone(self):
        return self.fetchones.pop(0) if self.fetchones else None


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class ContextValue:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, exc_type, exc, traceback):
        return False


def writes_to(cursor, table):
    needle = f"INSERT INTO {table}"
    return [(query, params) for query, params in cursor.executions if needle in query]


class SanFalseCompletionTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("san_worker.py")

    def run_main(self, observation, fetchones=None):
        cursor = RecordingCursor(
            fetchalls=[[], [(1, 'parent.example')]],
            fetchones=fetchones or [(1,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_san_domains = mock.Mock(return_value=observation)
        with mock.patch("builtins.print"):
            self.module.main()
        return cursor

    def test_tls_failure_returns_none_and_writes_no_completion_marker(self):
        with mock.patch.object(
            self.module.socket, "create_connection", side_effect=socket.timeout()
        ):
            self.assertIsNone(self.module.fetch_san_domains("parent.example"))

        cursor = self.run_main(None)
        self.assertEqual(writes_to(cursor, "domain_san"), [])

    def test_successful_empty_san_writes_completion_marker(self):
        peer = mock.Mock()
        peer.getpeercert.return_value = {"subjectAltName": [("IP Address", "192.0.2.1")]}
        context = mock.Mock()
        context.wrap_socket.return_value = ContextValue(peer)
        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=context
        ), mock.patch.object(
            self.module.socket, "create_connection",
            return_value=ContextValue(object()),
        ):
            self.assertEqual(self.module.fetch_san_domains("parent.example"), [])

        cursor = self.run_main([])
        self.assertEqual(len(writes_to(cursor, "domain_san")), 1)

    def test_san_child_membership_precedes_provenance(self):
        cursor = self.run_main(
            ["child.example"],
            fetchones=[(1,), (2, True), ("root.example",)],
        )
        membership = next(
            i for i, (query, _) in enumerate(cursor.executions)
            if "INSERT INTO scan_results" in query
        )
        provenance = next(
            i for i, (query, _) in enumerate(cursor.executions)
            if "INSERT INTO domain_sources" in query
        )
        self.assertLess(membership, provenance)


class PtrTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("dns_worker.py")

    def test_ptr_success_and_definitive_absence(self):
        with mock.patch.object(
            self.module.socket, "gethostbyaddr", return_value=("ptr.example", [], [])
        ):
            self.assertEqual(self.module.reverse_dns("192.0.2.1"), "ptr.example")

        with mock.patch.object(
            self.module.socket, "gethostbyaddr",
            side_effect=socket.herror(1, "Unknown host"),
        ):
            self.assertEqual(self.module.reverse_dns("192.0.2.1"), "N/A")

    def test_ptr_timeout_is_missing_not_na_and_preserves_existing_value(self):
        with mock.patch.object(
            self.module.socket, "gethostbyaddr", side_effect=socket.timeout()
        ):
            self.assertIsNone(self.module.reverse_dns("192.0.2.1"))

        cursor = RecordingCursor(fetchalls=[[(1, "host.example", False)]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.resolve_dns = lambda domain: [("A", "192.0.2.1")]
        self.module.reverse_dns = lambda ip: None
        with mock.patch("builtins.print"):
            self.module.main()

        update, params = next(
            (query, params) for query, params in cursor.executions
            if "UPDATE domain_states" in query
        )
        self.assertIn("reverse_dns = COALESCE(%s, reverse_dns)", update)
        self.assertIsNone(params[1])

    def test_forward_nxdomain_and_noanswer_remain_no_record_results(self):
        resolver = mock.Mock()
        resolver.resolve.side_effect = [
            self.module.dns.resolver.NXDOMAIN(),
            self.module.dns.resolver.NoAnswer(),
        ]
        with mock.patch.object(
            self.module.dns.resolver, "Resolver", return_value=resolver
        ), mock.patch("builtins.print"):
            self.assertEqual(self.module.resolve_dns("absent.example"), [])


class CertificateTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("cert_worker.py")

    def test_connection_timeout_and_refusal_return_failure(self):
        for error in (socket.timeout(), ConnectionRefusedError()):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                self.module.socket, "create_connection", side_effect=error
            ), mock.patch("builtins.print"):
                self.assertIsNone(self.module.fetch_cert_expiry("host.example"))

    def test_tls_retrieval_parser_and_date_failures_return_failure(self):
        sock = object()
        failures = []

        tls_context = mock.Mock()
        tls_context.wrap_socket.side_effect = ssl.SSLError("handshake")
        failures.append((tls_context, None, None))

        retrieval_socket = mock.Mock()
        retrieval_socket.getpeercert.side_effect = RuntimeError("retrieval")
        retrieval_context = mock.Mock()
        retrieval_context.wrap_socket.return_value = ContextValue(retrieval_socket)
        failures.append((retrieval_context, None, None))

        parser_socket = mock.Mock()
        parser_socket.getpeercert.return_value = b"certificate"
        parser_context = mock.Mock()
        parser_context.wrap_socket.return_value = ContextValue(parser_socket)
        failures.append((parser_context, ValueError("parser"), None))

        date_socket = mock.Mock()
        date_socket.getpeercert.return_value = b"certificate"
        date_context = mock.Mock()
        date_context.wrap_socket.return_value = ContextValue(date_socket)
        bad_certificate = mock.Mock()
        bad_certificate.get_notAfter.return_value = b"not-a-date"
        failures.append((date_context, None, bad_certificate))

        for context, pem_error, certificate in failures:
            with self.subTest(context=context), \
                    mock.patch.object(self.module.ssl, "create_default_context", return_value=context), \
                    mock.patch.object(self.module.socket, "create_connection", return_value=ContextValue(sock)), \
                    mock.patch.object(
                        self.module.ssl, "DER_cert_to_PEM_cert",
                        side_effect=pem_error if pem_error else None,
                        return_value="PEM",
                    ), mock.patch.object(
                        self.module.OpenSSL.crypto, "load_certificate",
                        return_value=certificate,
                    ), mock.patch("builtins.print"):
                self.assertIsNone(self.module.fetch_cert_expiry("host.example"))

    def test_valid_certificate_metadata_is_persisted(self):
        expected = (datetime.date(2030, 1, 2), 1200, "healthy")
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1", None)]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_cert_expiry = lambda domain: expected
        with mock.patch("builtins.print"):
            self.module.main()

        writes = writes_to(cursor, "domain_cert")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1][:5], (1, 42, *expected))

    def test_valid_certificate_is_parsed(self):
        expiry = datetime.datetime.utcnow() + datetime.timedelta(days=90)
        peer = mock.Mock()
        peer.getpeercert.return_value = b"certificate"
        context = mock.Mock()
        context.wrap_socket.return_value = ContextValue(peer)
        certificate = mock.Mock()
        certificate.get_notAfter.return_value = expiry.strftime("%Y%m%d%H%M%SZ").encode()
        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=context
        ), mock.patch.object(
            self.module.socket, "create_connection", return_value=ContextValue(object())
        ), mock.patch.object(
            self.module.ssl, "DER_cert_to_PEM_cert", return_value="PEM"
        ), mock.patch.object(
            self.module.OpenSSL.crypto, "load_certificate", return_value=certificate
        ):
            expiry_date, days, status = self.module.fetch_cert_expiry("host.example")

        self.assertEqual(expiry_date, expiry.date())
        self.assertIn(days, (89, 90))
        self.assertEqual(status, "healthy")

    def test_failed_certificate_observation_writes_no_row(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1", None)]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_cert_expiry = lambda domain: None
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_cert"), [])


class PortTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("port_scan_worker.py")

    @staticmethod
    def completed(returncode=0, stdout=""):
        return subprocess.CompletedProcess(
            args=["nmap"], returncode=returncode, stdout=stdout, stderr="failed"
        )

    def test_successful_open_and_zero_port_results(self):
        with mock.patch.object(
            self.module.subprocess, "run",
            return_value=self.completed(stdout="443/tcp open https\n"),
        ):
            self.assertEqual(self.module.scan_ports("host.example"), [(443, "https")])

        with mock.patch.object(
            self.module.subprocess, "run", return_value=self.completed()
        ):
            self.assertEqual(self.module.scan_ports("host.example"), [])

    def test_nonzero_stdout_is_rejected(self):
        with mock.patch.object(
            self.module.subprocess, "run",
            return_value=self.completed(2, "443/tcp open https\n"),
        ), mock.patch("builtins.print"):
            self.assertEqual(self.module.scan_ports("host.example"), [])

    def test_timeout_and_launch_failure_write_no_ports(self):
        for error in (subprocess.TimeoutExpired("nmap", 60), FileNotFoundError()):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                self.module.subprocess, "run", side_effect=error
            ), mock.patch("builtins.print"):
                self.assertEqual(self.module.scan_ports("host.example"), [])

    def test_zero_port_result_produces_no_port_row(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.scan_ports = lambda domain: []
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_ports"), [])


class TechnologyTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("tech_worker.py")

    @staticmethod
    def response(headers=None, text="", cookies=None):
        response = mock.Mock()
        response.headers = headers or {}
        response.text = text
        response.cookies = cookies or {}
        return response

    def test_request_failure_writes_no_technology(self):
        with mock.patch.object(
            self.module.requests, "get", side_effect=RuntimeError("offline")
        ), mock.patch("builtins.print"):
            self.assertIsNone(self.module.detect_tech("host.example"))

        cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.detect_tech = lambda domain: None
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_tech"), [])

    def test_real_response_unknown_and_fingerprint(self):
        with mock.patch.object(
            self.module.requests, "get", return_value=self.response()
        ):
            self.assertEqual(self.module.detect_tech("host.example"), ["unknown"])

        with mock.patch.object(
            self.module.requests, "get",
            return_value=self.response(headers={"Server": "nginx"}),
        ):
            self.assertIn("nginx", self.module.detect_tech("host.example"))

    def test_real_unknown_and_fingerprint_results_are_persisted(self):
        for result in (["unknown"], ["nginx"]):
            with self.subTest(result=result):
                cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
                connection = FakeConnection(cursor)
                self.module.get_conn = lambda: connection
                self.module.detect_tech = lambda domain, value=result: value
                with mock.patch("builtins.print"):
                    self.module.main()
                writes = writes_to(cursor, "domain_tech")
                self.assertEqual(len(writes), 1)
                self.assertEqual(writes[0][1][2], result[0])


class AsnTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("asn_worker.py")

    @staticmethod
    def response(status=200, payload=None, error=None):
        response = mock.Mock()
        response.status_code = status
        if error:
            response.json.side_effect = error
        else:
            response.json.return_value = payload
        return response

    def test_operational_and_malformed_results_return_failure(self):
        cases = (
            RuntimeError("offline"),
            self.response(503, {"org": "AS1 Example"}),
            self.response(200, error=ValueError("json")),
            self.response(200, ["unexpected"]),
            self.response(200, {"org": ["unexpected"]}),
        )
        for result in cases:
            with self.subTest(result=result), mock.patch.object(
                self.module.requests, "get",
                side_effect=result if isinstance(result, Exception) else None,
                return_value=None if isinstance(result, Exception) else result,
            ), mock.patch("builtins.print"):
                self.assertIsNone(self.module.enrich_asn("192.0.2.1"))

    def test_valid_asn_and_valid_empty_organization(self):
        for payload, expected in (
            ({"org": "AS64500 Example Org"}, ("AS64500", "AS64500 Example Org")),
            ({}, ("", "")),
        ):
            with self.subTest(payload=payload), mock.patch.object(
                self.module.requests, "get", return_value=self.response(200, payload)
            ):
                self.assertEqual(self.module.enrich_asn("192.0.2.1"), expected)

    def test_failed_asn_observation_writes_no_row(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: None
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_asn"), [])

    def test_valid_asn_is_persisted(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: ("AS64500", "AS64500 Example")
        with mock.patch("builtins.print"):
            self.module.main()
        writes = writes_to(cursor, "domain_asn")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1][:5], (1, 42, "192.0.2.1", "AS64500", "AS64500 Example"))

    def test_valid_empty_organization_is_persisted_as_existing_negative(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: ("", "")
        with mock.patch("builtins.print"):
            self.module.main()
        writes = writes_to(cursor, "domain_asn")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1][3:5], ("", ""))


class TakeoverTruthTests(unittest.TestCase):
    def setUp(self):
        self.module = load_worker("takeover_worker.py")

    @staticmethod
    def response(status, body):
        response = mock.Mock()
        response.status_code = status
        response.text = body
        return response

    def test_both_transports_fail_without_observation(self):
        with mock.patch.object(
            self.module.requests, "get", side_effect=RuntimeError("offline")
        ):
            self.assertIsNone(self.module.check_takeover("host.example"))

    def test_https_failure_then_http_response_is_observed(self):
        response = self.response(404, "real response")
        with mock.patch.object(
            self.module.requests, "get",
            side_effect=[RuntimeError("tls"), response],
        ) as get:
            result = self.module.check_takeover("host.example")
        self.assertEqual(result, {"body": "real response", "status": 404, "length": 13})
        self.assertEqual(get.call_count, 2)

    def run_main(self, observation, live_cname="target.github.io"):
        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", "target.github.io")]]
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.get_live_cname = mock.Mock(return_value=live_cname)
        self.module.check_takeover = mock.Mock(return_value=observation)
        with mock.patch("builtins.print"):
            self.module.main()
        return cursor

    def test_transport_failure_and_live_cname_failure_write_no_finding(self):
        self.assertEqual(writes_to(self.run_main(None), "domain_findings"), [])
        cursor = self.run_main(
            {"body": "short", "status": 200, "length": 5}, live_cname=None
        )
        self.assertEqual(writes_to(cursor, "domain_findings"), [])

    def test_real_responses_preserve_existing_finding_rules(self):
        cases = (
            ({"body": "There isn't a GitHub Pages site here", "status": 200, "length": 38},
             "dangling_dns", "HIGH"),
            ({"body": "ordinary response" * 10, "status": 404, "length": 170},
             "suspicious_dns", "MEDIUM"),
            ({"body": "short", "status": 200, "length": 5},
             "suspicious_dns", "LOW"),
        )
        for observation, finding, severity in cases:
            with self.subTest(finding=finding, severity=severity):
                writes = writes_to(self.run_main(observation), "domain_findings")
                self.assertEqual(len(writes), 1)
                params = writes[0][1]
                self.assertEqual(params[2:4], (finding, severity))


if __name__ == "__main__":
    unittest.main()
