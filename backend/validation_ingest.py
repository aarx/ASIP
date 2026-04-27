import psycopg2
import csv
import sys

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )

def apply_validation(cur, domain, status):

    domain = domain.strip().lower()
    status = status.strip().lower()

    if status == "approved":
        scannable = True
        label = "high"
        score = 10
        reasons = ["manually approved"]

    elif status == "rejected":
        scannable = False
        label = "low"
        score = 0
        reasons = ["manually rejected"]

    else:
        print(f"Skipping invalid status: {domain} -> {status}")
        return

    print("Processing:", domain, status)

    cur.execute("""
    UPDATE domains
    SET 
        scannable = %s,
        confidence_score = %s,
        confidence_label = %s,
        confidence_reasons = %s,
        validation_source = 'manual'
    WHERE domain = %s
    RETURNING domain
    """, (scannable, score, label, reasons, domain))

    result = cur.fetchone()
    if result:
        print("UPDATED:", result[0])
    else:
        print("NOT FOUND:", domain)

def main():

    if len(sys.argv) < 2:
        print("Usage: python validation_ingest.py file.csv")
        return

    file_path = sys.argv[1]

    conn = get_conn()
    cur = conn.cursor()

    count = 0

    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            domain = row.get("domain")
            status = row.get("validation_status")

            if not domain or not status:
                continue

            apply_validation(cur, domain, status)
            count += 1

    conn.commit()
    conn.close()

    print(f"Validation applied to {count} domains")


if __name__ == "__main__":
    main()
