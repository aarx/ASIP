import csv
import os
import pathlib
import socket
import tempfile
import unittest
from unittest import mock

from backend.tests.test_remediation_package_2d1e2 import FakeConnection, load_recon


CANONICAL_COLUMNS = [
    "Domain",
    "Source",
    "Seed",
    "IP",
    "Reverse_DNS",
    "HTTP_Status",
    "HTTP_Reason",
    "Redirect_Location",
    "Final_URL",
    "Final_Status",
    "Title",
    "HTTP_Observation_Status",
    "Domain_Status",
]


class ReconPtrTruthTests(unittest.TestCase):
    def setUp(self):
        self.recon = load_recon()
        self.recon.domain_registry.clear()
        self.recon.source_stats.clear()
        self.recon.source_outcomes.clear()

    def test_ptr_success_returns_hostname(self):
        with mock.patch.object(
            self.recon.socket,
            "gethostbyaddr",
            return_value=("ptr.example", [], []),
        ):
            self.assertEqual(
                self.recon.reverse_dns("192.0.2.1"),
                "ptr.example",
            )

    def test_conclusive_no_ptr_returns_na(self):
        for error_number in (1, 4):
            with self.subTest(error_number=error_number), mock.patch.object(
                self.recon.socket,
                "gethostbyaddr",
                side_effect=socket.herror(error_number, "no PTR"),
            ):
                self.assertEqual(
                    self.recon.reverse_dns("192.0.2.1"),
                    "N/A",
                )

    def test_ptr_timeout_is_missing_not_na(self):
        with mock.patch.object(
            self.recon.socket,
            "gethostbyaddr",
            side_effect=socket.timeout("timed out"),
        ), mock.patch("builtins.print"):
            self.assertIsNone(self.recon.reverse_dns("192.0.2.1"))

    def test_transient_system_and_unexpected_ptr_failures_are_missing(self):
        failures = (
            socket.herror(2, "try again"),
            socket.gaierror(-3, "temporary failure"),
            OSError("resolver unavailable"),
            RuntimeError("unexpected resolver failure"),
        )

        for failure in failures:
            with self.subTest(failure=type(failure).__name__), mock.patch.object(
                self.recon.socket,
                "gethostbyaddr",
                side_effect=failure,
            ), mock.patch("builtins.print"):
                self.assertIsNone(self.recon.reverse_dns("192.0.2.1"))

    def run_recon(self, ip, ptr_failure=None):
        connection = FakeConnection()
        self.recon.get_conn = mock.Mock(return_value=connection)
        self.recon.require_running_scan = mock.Mock()
        self.recon.publish_recon_artifact = mock.Mock()
        self.recon.load_known = mock.Mock(return_value=set())
        self.recon.http_probe = mock.Mock(return_value=None)
        self.recon.resolve_ip = mock.Mock(return_value=ip)

        def add_discovered_domain(seed, deep):
            self.recon.add_domain("host.example", "subfinder", seed)

        self.recon.run_subdomain_enum = add_discovered_domain

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            seed_file = root / "seeds.txt"
            seed_file.write_text("example.com\n", encoding="utf-8")
            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                ptr_patch = mock.patch.object(
                    self.recon.socket,
                    "gethostbyaddr",
                    side_effect=ptr_failure,
                )
                with ptr_patch as gethostbyaddr, mock.patch("builtins.print"):
                    self.recon.main(
                        str(seed_file),
                        deep=False,
                        expand=False,
                        scan_id=42,
                    )

                csv_file = next(root.glob("recon_scan_42_*/final_output.csv"))
                with csv_file.open(newline="", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    columns = reader.fieldnames
                    rows = list(reader)
            finally:
                os.chdir(old_cwd)

        return columns, rows, gethostbyaddr, connection

    def test_no_ip_serializes_missing_ptr_and_preserves_schema(self):
        columns, rows, gethostbyaddr, connection = self.run_recon(ip="")

        self.assertEqual(columns, CANONICAL_COLUMNS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["IP"], "")
        self.assertEqual(rows[0]["Reverse_DNS"], "")
        gethostbyaddr.assert_not_called()
        self.recon.publish_recon_artifact.assert_called_once()
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)

    def test_operational_ptr_failure_serializes_missing_and_is_nonfatal(self):
        columns, rows, gethostbyaddr, connection = self.run_recon(
            ip="192.0.2.1",
            ptr_failure=socket.timeout("timed out"),
        )

        self.assertEqual(columns, CANONICAL_COLUMNS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["IP"], "192.0.2.1")
        self.assertEqual(rows[0]["Reverse_DNS"], "")
        gethostbyaddr.assert_called_once_with("192.0.2.1")
        self.recon.publish_recon_artifact.assert_called_once()
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)


if __name__ == "__main__":
    unittest.main()
