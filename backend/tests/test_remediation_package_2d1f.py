import datetime
import unittest
from unittest import mock

from backend.tests import test_remediation_package_2d1c as convergence
from backend.tests import test_remediation_package_2d1d as membership


class PostgreSQLChronologyTests(unittest.TestCase):
    """Exercise both chronology upserts against disposable PostgreSQL."""

    TABLES = convergence.PostgreSQLIngestConvergenceTests.TABLES
    connect = convergence.PostgreSQLIngestConvergenceTests.connect
    ingest = convergence.PostgreSQLIngestConvergenceTests.ingest
    sql = membership.PostgreSQLMembershipTests.sql
    run_worker = membership.PostgreSQLMembershipTests.run_worker

    @classmethod
    def setUpClass(cls):
        try:
            convergence.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        except unittest.SkipTest as exc:
            raise RuntimeError(
                f"2D1-F requires executable disposable PostgreSQL: {exc}"
            ) from exc
        cls.addClassCleanup(
            convergence.PostgreSQLIngestConvergenceTests.tearDownClass.__func__,
            cls,
        )
        cls.connection_args["options"] = "-c client_encoding=UTF8"
        connection = cls.psycopg2.connect(**cls.connection_args)
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        ALTER TABLE domains
                            ADD first_seen_at timestamp,
                            ADD last_seen_at timestamp;
                        CREATE TABLE seed_domains (domain text);
                        INSERT INTO seed_domains VALUES ('example');
                        ALTER TABLE domain_san ADD UNIQUE(domain_id, scan_id);
                    """)
        finally:
            connection.close()

    def setUp(self):
        convergence.PostgreSQLIngestConvergenceTests.setUp(self)

    @staticmethod
    def row(domain):
        return {
            "Domain": domain,
            "Source": "subfinder",
            "Seed": "root.example",
        }

    def add_domain(self, domain, first_seen, last_seen, member_scan=None,
                   state_scan=None, first_seen_at=None, last_seen_at=None):
        domain_id = self.sql("""
            INSERT INTO domains(
                domain, first_seen_scan, last_seen_scan,
                first_seen_at, last_seen_at
            )
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (
            domain, first_seen, last_seen, first_seen_at, last_seen_at,
        ))[0][0]
        if member_scan is not None:
            self.sql(
                "INSERT INTO scan_results VALUES (%s, %s, 'root.example')",
                (member_scan, domain_id),
            )
        if state_scan is not None:
            self.sql("""
                INSERT INTO domain_states(
                    scan_id, domain_id, ip, has_ip, http_status, http_live
                )
                VALUES (%s, %s, '192.0.2.1', TRUE, 200, TRUE)
            """, (state_scan, domain_id))
        return domain_id

    def chronology(self, domain):
        return self.sql("""
            SELECT first_seen_scan, last_seen_scan,
                   first_seen_at, last_seen_at
            FROM domains
            WHERE domain = %s
        """, (domain,))[0]

    def memberships(self, domain):
        return self.sql("""
            SELECT sr.scan_id
            FROM scan_results sr
            JOIN domains d ON d.id = sr.domain_id
            WHERE d.domain = %s
            ORDER BY sr.scan_id
        """, (domain,))

    def run_san(self, scan_id, child):
        parent = f"parent-{scan_id}.example"
        self.add_domain(
            parent,
            scan_id,
            scan_id,
            member_scan=scan_id,
            state_scan=scan_id,
        )
        observer = mock.Mock(return_value=[child])
        self.run_worker(
            "san_worker.py",
            scan_id=scan_id,
            overrides={"fetch_san_domains": observer},
        )
        observer.assert_called_once_with(parent)
        return parent

    def test_ingest_older_observation_lowers_first_without_regressing_last(self):
        first_at = datetime.datetime(2024, 1, 1, 12, 0, 0)
        last_at = datetime.datetime(2024, 2, 1, 12, 0, 0)
        self.add_domain(
            "older-ingest.example",
            42,
            42,
            member_scan=42,
            first_seen_at=first_at,
            last_seen_at=last_at,
        )

        self.ingest(41, [self.row("older-ingest.example")])

        self.assertEqual(
            self.chronology("older-ingest.example"),
            (41, 42, first_at, last_at),
        )
        self.assertEqual(
            self.memberships("older-ingest.example"),
            [(41,), (42,)],
        )

    def test_ingest_newer_observation_advances_only_last(self):
        self.add_domain(
            "newer-ingest.example", 41, 41, member_scan=41,
        )

        self.ingest(42, [self.row("newer-ingest.example")])

        self.assertEqual(
            self.chronology("newer-ingest.example")[:2],
            (41, 42),
        )
        self.assertEqual(
            self.memberships("newer-ingest.example"),
            [(41,), (42,)],
        )

    def test_ingest_same_scan_retry_is_stable(self):
        rows = [self.row("retry-ingest.example")]
        self.ingest(42, rows)
        before = self.chronology("retry-ingest.example")

        self.ingest(42, rows)

        self.assertEqual(self.chronology("retry-ingest.example"), before)
        self.assertEqual(
            self.memberships("retry-ingest.example"),
            [(42,)],
        )

    def test_ingest_establishes_legacy_null_chronology(self):
        self.add_domain("null-ingest.example", None, None)

        self.ingest(41, [self.row("null-ingest.example")])

        self.assertEqual(
            self.chronology("null-ingest.example")[:2],
            (41, 41),
        )

    def test_san_older_observation_lowers_first_without_regressing_last(self):
        first_at = datetime.datetime(2024, 1, 1, 12, 0, 0)
        last_at = datetime.datetime(2024, 2, 1, 12, 0, 0)
        self.add_domain(
            "older-san.example",
            42,
            42,
            member_scan=42,
            first_seen_at=first_at,
            last_seen_at=last_at,
        )

        self.run_san(41, "older-san.example")

        chronology = self.chronology("older-san.example")
        self.assertEqual(chronology[:2], (41, 42))
        self.assertEqual(chronology[2], first_at)
        self.assertGreater(chronology[3], last_at)
        self.assertEqual(
            self.memberships("older-san.example"),
            [(41,), (42,)],
        )

    def test_san_newer_observation_advances_only_last(self):
        self.add_domain(
            "newer-san.example", 41, 41, member_scan=41,
        )

        self.run_san(42, "newer-san.example")

        self.assertEqual(
            self.chronology("newer-san.example")[:2],
            (41, 42),
        )
        self.assertEqual(
            self.memberships("newer-san.example"),
            [(41,), (42,)],
        )

    def test_san_same_scan_retry_is_stable(self):
        child = "retry-san.example"
        self.add_domain(child, 42, 42)
        parent = self.run_san(42, child)
        before = self.chronology(child)

        self.sql("""
            DELETE FROM domain_san
            WHERE scan_id = 42
            AND domain_id = (SELECT id FROM domains WHERE domain = %s)
        """, (parent,))
        self.run_worker(
            "san_worker.py",
            scan_id=42,
            overrides={
                "fetch_san_domains": mock.Mock(return_value=[child]),
            },
        )

        after = self.chronology(child)
        self.assertEqual(after[:2], before[:2])
        self.assertEqual(after[2], before[2])
        self.assertGreaterEqual(after[3], before[3])
        self.assertEqual(self.memberships(child), [(42,)])

    def test_san_establishes_legacy_null_chronology(self):
        self.add_domain("null-san.example", None, None)

        self.run_san(41, "null-san.example")

        self.assertEqual(
            self.chronology("null-san.example")[:2],
            (41, 41),
        )


if __name__ == "__main__":
    unittest.main()
