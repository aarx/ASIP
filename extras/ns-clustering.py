#!/usr/bin/env python3

import subprocess
import requests
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_WORKERS = 40


def get_nameservers(domain):
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "NS"],
            capture_output=True,
            text=True
        )
        ns = set()
        for line in result.stdout.splitlines():
            ns.add(line.strip().rstrip(".").lower())
        return ns
    except:
        return set()


def ct_keyword_domains(brand):
    domains = set()
    try:
        url = f"https://crt.sh/?q=%25{brand}%25&output=json"
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return domains

        data = r.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for d in name_value.split("\n"):
                d = d.lower().strip().lstrip("*.")
                if brand in d:
                    if re.match(r"^[a-z0-9.-]+$", d):
                        domains.add(d)
    except:
        pass
    return domains


def main(root_domain):

    brand = root_domain.split(".")[0].lower()
    print(f"[+] Root domain: {root_domain}")
    print(f"[+] Extracted brand: {brand}")

    root_ns = get_nameservers(root_domain)

    if not root_ns:
        print("[!] Could not resolve nameservers for root domain.")
        return

    print(f"[+] Root nameservers:")
    for ns in root_ns:
        print(f"    - {ns}")

    print("[+] Fetching candidate domains from CT...")
    candidates = ct_keyword_domains(brand)
    print(f"[+] CT candidates found: {len(candidates)}")

    clustered = []

    def check_domain(domain):
        ns = get_nameservers(domain)
        if not ns:
            return None

        overlap = root_ns.intersection(ns)
        if overlap:
            return (domain, ",".join(overlap))
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_domain, d) for d in candidates]

        for f in as_completed(futures):
            result = f.result()
            if result:
                clustered.append(result)

    if not clustered:
        print("[+] No nameserver overlaps detected.")
        return

    output_file = "ns_clustered_domains.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Matching_Nameserver"])
        for domain, overlap in sorted(clustered):
            writer.writerow([domain, overlap])

    print(f"[+] Clustered domains saved to {output_file}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 ns_cluster.py abc.com")
        sys.exit(1)

    main(sys.argv[1])
