import psycopg2
import subprocess
import re


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

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states s
    ON d.id = s.domain_id
    WHERE s.has_ip = TRUE
    AND d.port_done = FALSE
    ORDER BY d.id, s.scan_id DESC
    LIMIT 1000
    """)

    rows = cur.fetchall()

    conn.close()

    return scan_id, rows


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

    scan_id, domains = get_resolving_domains()

    print(f"Scanning {len(domains)} domains")

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
            ON CONFLICT (domain_id, port) DO NOTHING
            """, (domain_id, scan_id, port, service))
    
        
        cur.execute("""
            UPDATE domains SET port_done = TRUE
            WHERE id = %s
        """, (domain_id,))

    conn.commit()
    conn.close()

    print("Port scan enrichment complete")


if __name__ == "__main__":
    main()
