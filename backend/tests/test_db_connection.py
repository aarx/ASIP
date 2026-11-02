import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import db


class DatabaseConnectionTests(unittest.TestCase):
    def test_shared_connection_has_a_bounded_configurable_timeout(self):
        with mock.patch.object(db, "DB_CONNECT_TIMEOUT_SECONDS", 7), \
                mock.patch.object(db.psycopg2, "connect") as connect:
            db.get_conn()

        self.assertEqual(connect.call_args.kwargs["connect_timeout"], 7)


if __name__ == "__main__":
    unittest.main()
