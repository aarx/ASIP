#!/usr/bin/env python3

import csv
import socket
import requests
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

TAKEOVER_FINGERPRINTS = {
    "AWS S3": "NoSuchBucket",
    "Azure": "There is no web app configured",
    "Heroku": "No such app",
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Fastly": "Fastly error: unknown domain"
}

MAX_WORKERS = 40
TIMEOUT = 8


def get_cname(domain):
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "CNAME"],
            capture_output=True,
            text=True
        )
        cname = result.stdout.strip().rstrip(".")
        return cname
    except:
        return ""


def check_http(domain):
    try:
        r = requests.get(
            f"http://{domain}",
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False
        )
        return r.text
    except:
        return ""


def detect_takeover(domain):
    cname = get_cname(domain)

    if not cname:
        return None

    try:
        socket.gethostbyname(cname)
    except:
        return {
            "Domain": domain,
            "CNAME": cname,
            "Issue": "CNAME target does not resolve (NXDOMAIN)",
            "Provider": "Unknown"
        }

    body = check_http(domain)

    for provider, fingerprint in TAKEOVER_FINGERPRINTS.items():
        if fingerprint.lower() in body.lower():
            return {
                "Domain": domain,
                "CNAME": cname,
                "Issue": "Cloud service error page detected",
                "Provider": provider
            }

    return None


def main(input_csv):

    candidates = []

    with open(input_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        domains = [row["Domain"] for row in reader if row.get("Domain")]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(detect_takeover, d) for d in domains]

        for f in as_completed(futures):
            result = f.result()
            if result:
                candidates.append(result)

    if not candidates:
        print("[+] No takeover candidates detected.")
        return

    output_file = "takeover_candidates.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["Domain", "CNAME", "Issue", "Provider"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(candidates)

    print(f"[+] Takeover candidates saved to {output_file}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 takeover_check.py final_output.csv")
        sys.exit(1)

    main(sys.argv[1])
