import psycopg2
from config import *


class ScanNotRunningError(RuntimeError):
    pass

def get_conn():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def require_running_scan(cursor, scan_id):
    cursor.execute("""
        SELECT status
        FROM scans
        WHERE id = %s
        FOR UPDATE
    """, (scan_id,))

    row = cursor.fetchone()
    if row is None:
        raise ScanNotRunningError(f"Scan {scan_id} does not exist")

    status = row[0]
    if status != "RUNNING":
        raise ScanNotRunningError(
            f"Scan {scan_id} is {status}, not RUNNING"
        )


def get_latest_authoritative_scan_id(cursor):
    cursor.execute("""
        SELECT id
        FROM scans
        WHERE status = 'SUCCEEDED'
        ORDER BY id DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    return row[0] if row else None


def get_previous_authoritative_scan_id(cursor, current_scan_id=None):
    if current_scan_id is None:
        current_scan_id = get_latest_authoritative_scan_id(cursor)

    if current_scan_id is None:
        return None

    cursor.execute("""
        SELECT id
        FROM scans
        WHERE status = 'SUCCEEDED'
        AND id < %s
        ORDER BY id DESC
        LIMIT 1
    """, (current_scan_id,))
    row = cursor.fetchone()
    return row[0] if row else None
