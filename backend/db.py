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
