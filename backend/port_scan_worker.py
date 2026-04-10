import psycopg2
import subprocess
import re
import logging
import os
import sys

scan_id = int(sys.argv[1])

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


def get_resolving_domains():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
      AND s.scan_id = %s
    
    LEFT JOIN domain_ports dp
      ON d.id = dp.domain_id
      AND dp.scan_id = %s
    
    WHERE s.has_ip = TRUE
    AND dp.domain_id IS NULL
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))

    rows = cur.fetchall()

    conn.close()

    return rows


def scan_ports(domain):

    try:

        ASM_PORTS = (
            "21,22,23,25,53,80,110,143,389,443,445,"
            "1521,3000,3306,3389,5000,5432,5900,"
            "5985,5986,6379,7001,7002,8000,8080,8443,"
            "8888,27017,11211"
        )

        cmd = [
            "nmap",
            "-Pn",
            "-T3",
            "--open",
            "-p", ASM_PORTS,
            domain
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        ports = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if "/tcp" in line and "open" in line:

                parts = re.split(r"\s+", line)

                port_part = parts[0]
                service = parts[-1]

                port = int(port_part.split("/")[0])

                ports.append((port, service))

        return ports

    except Exception as e:
        print(f"Scan failed for {domain} → {e}")
        return []

def main():

    domains = get_resolving_domains()
    
    print("Scan ID:", scan_id)              
    print("Rows to scan:", len(domains))  

    conn = get_conn()
    cur = conn.cursor()

    for domain_id, domain in domains:
    
        print(f"Scanning {domain}")
    
        ports = scan_ports(domain)
    
        if ports:
            print(f"OPEN → {domain} → {ports}")
    
        for port, service in ports:
    
            cur.execute("""
            INSERT INTO domain_ports(domain_id, scan_id, port, service)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (domain_id, port, scan_id) DO NOTHING
            """, (domain_id, scan_id, port, service))
         
        if not domains:
            print("No domains to scan for this run")

    conn.commit()
    conn.close()

    print("Port scan enrichment complete")


if __name__ == "__main__":
    main()
