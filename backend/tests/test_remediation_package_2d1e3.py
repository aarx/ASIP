import datetime
import importlib.util
import logging
import os
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
    if filename in (
        "tech_worker.py", "port_scan_worker.py", "san_worker.py",
        "san_http_worker.py", "cert_worker.py", "http_observation_worker.py",
    ):
        # These unit tests use a lightweight cursor without the authorization
        # schema; disposable PostgreSQL tests cover the real helper decisions.
        module.recheck_active_authorization = mock.Mock(
            return_value=(True, "authorized")
        )
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
            fetchalls=[[], [], [(1, 'parent.example')]],
            fetchones=fetchones or [(1,), (1,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_san_domains = mock.Mock(return_value=observation)
        with mock.patch("builtins.print"):
            self.module.main()
        return cursor

    def test_tls_failure_returns_none_and_writes_no_completion_marker(self):
        with mock.patch.object(
            self.module, "open_validated_tls_socket", side_effect=socket.timeout()
        ):
            self.assertIsNone(self.module.fetch_san_domains(
                "parent.example", before_request=lambda: True
            ))

        cursor = self.run_main(None)
        self.assertEqual(writes_to(cursor, "domain_san"), [])

    def test_successful_empty_san_writes_completion_marker(self):
        peer = mock.Mock()
        peer.getpeercert.return_value = {"subjectAltName": [("IP Address", "192.0.2.1")]}
        with mock.patch.object(
            self.module, "open_validated_tls_socket",
            return_value=ContextValue(peer),
        ):
            self.assertEqual(self.module.fetch_san_domains(
                "parent.example", before_request=lambda: True
            ), [])

        cursor = self.run_main([])
        self.assertEqual(len(writes_to(cursor, "domain_san")), 1)

    def test_san_child_membership_precedes_provenance(self):
        cursor = self.run_main(
            ["child.example"],
            fetchones=[(1,), (1,), (2, True), ("root.example",)],
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

        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", False)]],
            fetchones=[(True,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.resolve_dns = lambda domain, before_query=None: [("A", "192.0.2.1")]
        self.module.reverse_dns = lambda ip, before_query=None: None
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
                self.module, "open_validated_tls_socket", side_effect=error
            ), mock.patch("builtins.print"):
                self.assertIsNone(self.module.fetch_cert_expiry(
                    "host.example", before_request=lambda: True
                ))

    def test_tls_retrieval_parser_and_date_failures_return_failure(self):
        sock = object()
        failures = []

        failures.append((None, socket.timeout(), None))

        retrieval_socket = mock.Mock()
        retrieval_socket.getpeercert.side_effect = RuntimeError("retrieval")
        failures.append((ContextValue(retrieval_socket), None, None))

        parser_socket = mock.Mock()
        parser_socket.getpeercert.return_value = b"certificate"
        failures.append((ContextValue(parser_socket), ValueError("parser"), None))

        date_socket = mock.Mock()
        date_socket.getpeercert.return_value = b"certificate"
        bad_certificate = mock.Mock()
        bad_certificate.get_notAfter.return_value = b"not-a-date"
        failures.append((ContextValue(date_socket), None, bad_certificate))

        for context, pem_error, certificate in failures:
            with self.subTest(context=context), \
                    mock.patch.object(self.module, "open_validated_tls_socket", \
                                      side_effect=pem_error if pem_error else None, \
                                      return_value=context), \
                    mock.patch.object(
                        self.module.ssl, "DER_cert_to_PEM_cert",
                        return_value="PEM",
                    ), mock.patch.object(
                        self.module.OpenSSL.crypto, "load_certificate",
                        return_value=certificate,
                    ), mock.patch("builtins.print"):
                self.assertIsNone(self.module.fetch_cert_expiry(
                    "host.example", before_request=lambda: True
                ))

    def test_valid_certificate_metadata_is_persisted(self):
        expected = (datetime.date(2030, 1, 2), 1200, "healthy")
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1", None)]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_cert_expiry = lambda domain, **kwargs: expected
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
            self.module, "open_validated_tls_socket", return_value=ContextValue(peer)
        ), mock.patch.object(
            self.module.ssl, "DER_cert_to_PEM_cert", return_value="PEM"
        ), mock.patch.object(
            self.module.OpenSSL.crypto, "load_certificate", return_value=certificate
        ):
            expiry_date, days, status = self.module.fetch_cert_expiry(
                "host.example", before_request=lambda: True
            )

        self.assertEqual(expiry_date, expiry.date())
        self.assertIn(days, (89, 90))
        self.assertEqual(status, "healthy")

    def test_failed_certificate_observation_writes_no_row(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "192.0.2.1", None)]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.fetch_cert_expiry = lambda domain, **kwargs: None
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
            self.module.subprocess, "Popen",
            return_value=mock.Mock(
                communicate=mock.Mock(return_value=("443/tcp open https\n", "")),
                returncode=0,
            ),
        ):
            self.assertEqual(self.module.scan_ports("8.8.8.8"), [(443, "https")])

        with mock.patch.object(
            self.module.subprocess, "Popen",
            return_value=mock.Mock(communicate=mock.Mock(return_value=("", "")), returncode=0),
        ):
            self.assertEqual(self.module.scan_ports("8.8.8.8"), [])

    def test_nonzero_stdout_is_rejected(self):
        with mock.patch.object(
            self.module.subprocess, "Popen",
            return_value=mock.Mock(
                communicate=mock.Mock(return_value=("443/tcp open https\n", "failed")),
                returncode=2,
            ),
        ), self.assertRaises(self.module.PortScanError):
            self.module.scan_ports("8.8.8.8")

    def test_timeout_and_launch_failure_write_no_ports(self):
        for error in (subprocess.TimeoutExpired("nmap", 60), FileNotFoundError()):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                self.module.subprocess, "Popen", side_effect=error
            ), self.assertRaises(self.module.PortScanError):
                self.module.scan_ports("8.8.8.8")

    def test_zero_port_result_produces_no_port_row(self):
        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", "8.8.8.8")]],
            fetchones=[("8.8.8.8", True)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.scan_ports = lambda destination_ip, cancel_event=None: []
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_ports"), [])


class TechnologyTruthTests(unittest.TestCase):
    def setUp(self):
        self.policy = mock.patch.dict(
            os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "TECHNOLOGY_HTTP"}
        )
        self.policy.start()
        self.addCleanup(self.policy.stop)
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

    def test_php_parser_extracts_only_valid_explicit_versions(self):
        parsed = self.module.fingerprint_response(
            headers={"X-Powered-By": "PHP/8.2.12"}
        )
        php = next(item for item in parsed if item.technology == "php")
        self.assertEqual(php.version, "8.2.12")
        self.assertEqual(php.confidence, "high")
        self.assertEqual(php.evidence_type, "x-powered-by_header")

        parsed = self.module.fingerprint_response(
            headers={"X-Powered-By": "PHP/not-a-version"}
        )
        php = next(item for item in parsed if item.technology == "php")
        self.assertIsNone(php.version)

    def test_server_banner_parsers_extract_versions(self):
        cases = (
            ({"Server": "Apache/2.4.58 (Unix)"}, "apache", "2.4.58"),
            ({"Server": "nginx/1.24.0"}, "nginx", "1.24.0"),
            ({"Server": "Microsoft-IIS/10.0"}, "microsoft-iis", "10.0"),
            ({"Server": "Apache Tomcat/9.0.85"}, "tomcat", "9.0.85"),
        )
        for headers, technology, version in cases:
            with self.subTest(technology=technology):
                parsed = self.module.fingerprint_response(headers=headers)
                match = next(item for item in parsed if item.technology == technology)
                self.assertEqual(match.version, version)

    def test_asp_and_aspnet_are_distinct(self):
        aspnet = self.module.fingerprint_response(
            headers={"X-Powered-By": "ASP.NET"}
        )
        self.assertIn("asp.net", [item.technology for item in aspnet])
        self.assertIn("asp", [item.technology for item in aspnet])

        asp = self.module.fingerprint_response(
            headers={"X-Powered-By": "ASP/3.0"}
        )
        self.assertIn("asp", [item.technology for item in asp])
        self.assertNotIn("asp.net", [item.technology for item in asp])

        tomcat = self.module.fingerprint_response(
            headers={"Server": "Apache-Coyote/1.1"}
        )
        tomcat_match = next(item for item in tomcat if item.technology == "tomcat")
        self.assertIsNone(tomcat_match.version)

    def test_empty_and_ambiguous_values_do_not_fabricate_versions(self):
        parsed = self.module.fingerprint_response(headers={})
        self.assertEqual(parsed[0].technology, "unknown")
        self.assertIsNone(parsed[0].version)

        parsed = self.module.fingerprint_response(
            headers={"Server": "nginx/unknown"}
        )
        nginx = next(item for item in parsed if item.technology == "nginx")
        self.assertIsNone(nginx.version)

    def test_evidence_is_sanitized(self):
        parsed = self.module.fingerprint_response(
            headers={
                "X-Powered-By": "PHP/8.2.12; api_key=do-not-store-this",
            }
        )
        evidence = " ".join(item.evidence for item in parsed)
        self.assertNotIn("do-not-store-this", evidence)
        self.assertEqual(evidence, "php/8.2.12")

    def test_failure_diagnostics_do_not_include_exception_text(self):
        with mock.patch.object(
            self.module.requests,
            "get",
            side_effect=RuntimeError("token=do-not-log-this"),
        ), mock.patch.object(self.module.logger, "warning") as warning:
            self.assertIsNone(self.module.detect_tech("host.example"))

        self.assertNotIn("do-not-log-this", str(warning.call_args))

    def test_request_does_not_follow_redirects(self):
        response = self.response(headers={}, text="")
        response.status_code = 302
        response.headers = {"Location": "https://external.example/secret"}
        with mock.patch.object(
            self.module.requests, "get", return_value=response
        ) as request:
            self.module.detect_tech("host.example")

        self.assertFalse(request.call_args.kwargs["allow_redirects"])
        self.assertNotIn("external.example", str(request.call_args))

    def test_worker_query_uses_org_policy_and_current_membership(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.detect_tech = lambda domain: ["nginx"]
        with mock.patch("builtins.print"):
            self.module.main()

        query = cursor.executions[0][0]
        self.assertIn("ownership_status = 'CONFIRMED'", query)
        self.assertIn("scannable IS TRUE", query)
        self.assertIn("FROM seed_domains", query)
        self.assertIn("FROM known_domains", query)
        self.assertIn("AND TRUE", query)
        self.assertIn("scan_results", query)
        self.assertIn("manually", query.lower())
        self.assertIn("scope_block", query.lower())
        self.assertNotIn("scope_allow", query.lower())
        self.assertNotIn("validation_source = 'manual'", query)

    def test_structured_observations_persist_without_replacing_labels(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.detect_tech = lambda domain: ["apache", "php"]
        self.module._last_detections["host.example"] = self.module.DetectionResult(
            fingerprints=(
                self.module.Fingerprint(
                    "php", "8.1.0", "high", "server_header", "PHP/8.1.0"
                ),
                self.module.Fingerprint(
                    "php", "8.2.12", "high", "x-powered-by_header", "PHP/8.2.12"
                ),
            ),
            observed_url="http://host.example",
        )
        with mock.patch("builtins.print"):
            self.module.main()

        label_writes = [
            item for item in cursor.executions
            if "INSERT INTO domain_tech(" in item[0]
        ]
        self.assertEqual(len(label_writes), 2)
        observations = [
            item for item in cursor.executions
            if "INSERT INTO domain_technology_observations" in item[0]
        ]
        self.assertEqual(len(observations), 2)
        self.assertIn("ON CONFLICT DO NOTHING", observations[0][0])
        self.assertNotIn("Authorization", str(observations))
        self.assertEqual(observations[0][1][8], "sr-tech-02")
        self.assertEqual(observations[1][1][8], "sr-tech-02")

    def test_unknown_observation_has_no_version_and_failed_request_writes_none(self):
        unknown = self.module.fingerprint_response(headers={})[0]
        self.assertEqual(unknown.technology, "unknown")
        self.assertIsNone(unknown.version)

        cursor = RecordingCursor(fetchalls=[[(1, "host.example")]])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.detect_tech = lambda domain: None
        self.module._last_detections["host.example"] = None
        with mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(
            [
                item for item in cursor.executions
                if "INSERT INTO domain_technology_observations" in item[0]
            ],
            [],
        )

    def test_migration_is_additive_and_has_scan_safe_constraints(self):
        migration = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "migrations/004_add_technology_observations.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("BEGIN;", migration)
        self.assertIn("COMMIT;", migration)
        self.assertIn("CREATE TABLE public.domain_technology_observations", migration)
        self.assertIn("FOREIGN KEY (scan_id, domain_id)", migration)
        self.assertIn("CREATE UNIQUE INDEX", migration)
        self.assertNotIn("DROP TABLE", migration.upper())
        self.assertNotIn("ALTER TABLE public.domain_tech", migration)

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
                self.assertIsNone(self.module.enrich_asn("8.8.8.8"))

    def test_valid_asn_and_valid_empty_organization(self):
        for payload, expected in (
            ({"org": "AS64500 Example Org"}, ("AS64500", "AS64500 Example Org")),
            ({}, ("", "")),
        ):
            with self.subTest(payload=payload), mock.patch.object(
                self.module.requests, "get", return_value=self.response(200, payload)
            ):
                self.assertEqual(self.module.enrich_asn("8.8.8.8"), expected)

    def test_non_global_and_malformed_addresses_are_not_shared(self):
        for ip in ("192.0.2.1", "10.0.0.1", "not-an-ip"):
            with self.subTest(ip=ip), mock.patch.object(self.module.requests, "get") as request:
                self.assertIsNone(self.module.enrich_asn(ip))
                request.assert_not_called()

    def test_get_domains_requires_explicit_central_operation_grant(self):
        cursor = RecordingCursor(fetchalls=[[]])
        with mock.patch.dict(os.environ, {}, clear=True):
            self.module.get_domains(cursor, 42)
        query = cursor.executions[0][0]
        self.assertIn("AND FALSE", query)
        self.assertIn("ASN_METADATA", query)
        self.assertIn("sr.seed", query)
        self.assertIn("manually rejected", query)

    def test_failed_asn_observation_writes_no_row(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "8.8.8.8")]], fetchones=[(True,)])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: None
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            self.module.main()
        self.assertEqual(writes_to(cursor, "domain_asn"), [])

    def test_valid_asn_is_persisted(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "8.8.8.8")]], fetchones=[(True,), (True,)])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: ("AS64500", "AS64500 Example")
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            self.module.main()
        writes = writes_to(cursor, "domain_asn")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1][:5], (1, 42, "8.8.8.8", "AS64500", "AS64500 Example"))
        self.assertIn("s.ip = %s", cursor.executions[1][0])
        self.assertIn("ASN_METADATA", cursor.executions[1][0])
        self.assertEqual(cursor.executions[1][1], (42, 1, "8.8.8.8"))
        self.assertEqual(cursor.executions[2][1], (42, 1, "8.8.8.8"))

    def test_valid_empty_organization_is_persisted_as_existing_negative(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "8.8.8.8")]], fetchones=[(True,), (True,)])
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = lambda ip: ("", "")
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            self.module.main()
        writes = writes_to(cursor, "domain_asn")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1][3:5], ("", ""))

    def test_asn_policy_denial_prevents_external_request(self):
        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", "8.8.8.8")]], fetchones=[(False,)]
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = mock.Mock(return_value=("AS1", "AS1 Org"))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            self.module.main()
        self.module.enrich_asn.assert_not_called()
        self.assertEqual(writes_to(cursor, "domain_asn"), [])

    def test_asn_policy_database_error_fails_closed(self):
        cursor = RecordingCursor(fetchalls=[[(1, "host.example", "8.8.8.8")]])
        cursor.fetchone = mock.Mock(side_effect=RuntimeError("policy DB unavailable"))
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = mock.Mock(return_value=("AS1", "AS1 Org"))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            with self.assertRaisesRegex(RuntimeError, "policy DB unavailable"):
                self.module.main()
        self.module.enrich_asn.assert_not_called()
        self.assertEqual(writes_to(cursor, "domain_asn"), [])

    def test_authorization_revoked_after_lookup_prevents_persistence(self):
        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", "8.8.8.8")]],
            fetchones=[(True,), (False,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.enrich_asn = mock.Mock(return_value=("AS1", "AS1 Org"))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ASN_METADATA"}), \
                mock.patch("builtins.print"):
            self.module.main()
        self.module.enrich_asn.assert_called_once_with("8.8.8.8")
        self.assertEqual(writes_to(cursor, "domain_asn"), [])


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
        ) as get:
            self.assertIsNone(self.module.check_takeover("host.example"))
        get.assert_not_called()

    def test_takeover_http_is_disabled_without_explicit_permission(self):
        with mock.patch.object(
            self.module.requests, "get",
        ) as get:
            result = self.module.check_takeover("host.example")
        self.assertIsNone(result)
        get.assert_not_called()

    def run_main(self, observation, live_cname="target.github.io", override_check=True):
        cursor = RecordingCursor(
            fetchalls=[[(1, "host.example", "target.github.io")]],
            fetchones=[(True,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.get_live_cname = mock.Mock(return_value=live_cname)
        if override_check:
            self.module.check_takeover = mock.Mock(return_value=observation)
        with mock.patch("builtins.print"):
            self.module.main()
        return cursor

    def test_cname_query_uses_current_seed_scoped_authorization(self):
        cursor = self.run_main(None)
        policy_query = cursor.executions[1][0]
        self.assertIn("scan_results", policy_query)
        self.assertIn("sr.scan_id = %s", policy_query)
        self.assertIn("sr.seed", policy_query)
        self.assertIn("manually rejected", policy_query)
        self.assertIn("scope_block.status = 'REVOKED'", policy_query)
        self.module.get_live_cname.assert_called_once_with("host.example")

    def test_revoked_or_excluded_name_is_not_resolved(self):
        cursor = RecordingCursor(
            fetchalls=[[(1, "excluded.example", "target.github.io")]],
            fetchones=[(False,)],
        )
        connection = FakeConnection(cursor)
        self.module.get_conn = lambda: connection
        self.module.get_live_cname = mock.Mock()
        with mock.patch("builtins.print"):
            self.module.main()
        self.module.get_live_cname.assert_not_called()

    def test_passive_cname_refresh_does_not_enable_http_verification(self):
        self.module.TAKEOVER_HTTP_ENABLED = False
        with mock.patch.object(self.module.requests, "get") as request:
            self.assertIsNone(self.module.check_takeover("target.github.io"))
        request.assert_not_called()

    def test_transport_failure_and_live_cname_failure_write_no_finding(self):
        self.assertEqual(writes_to(self.run_main(None), "domain_findings"), [])
        cursor = self.run_main(
            {"body": "short", "status": 200, "length": 5}, live_cname=None
        )
        self.assertEqual(writes_to(cursor, "domain_findings"), [])

    def test_disabled_takeover_http_creates_no_findings(self):
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
                writes = writes_to(self.run_main(
                    observation, override_check=False
                ), "domain_findings")
                self.assertEqual(writes, [])


if __name__ == "__main__":
    unittest.main()
