import psycopg2
from config import *

def get_conn():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
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
