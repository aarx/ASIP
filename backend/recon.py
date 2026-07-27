#!/usr/bin/env python3

import subprocess
import socket
import argparse
import csv
import os
import requests
import re
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from db import get_conn
from config import CERTSPOTTER_API_KEY


if os.path.exists("final_output.csv"):
    os.remove("final_output.csv")


def debug(msg):
    print(f"[DEBUG] {msg}")


FAST_TOOLS = [
    ("subfinder", ["subfinder", "-silent", "-d"]),
    ("assetfinder", ["assetfinder", "--subs-only"]),
    ("findomain", ["findomain", "-q", "-t"])
]

DEEP_TOOLS = [
    ("amass", ["amass", "enum", "-passive", "-norecursive", "-d"])
]

COMMON_TLDS = ["com","net","org","co","io","in","ai","app","tech","cloud"]

PREFIX_PATTERNS = ["get","join","try","my","secure"]
SUFFIX_PATTERNS = ["group","corp","global","cloud","tech","services"]

TIMEOUT = 8
MAX_WORKERS = 40

KNOWN_DOMAINS_FILE = "known_domains.csv"

domain_registry = {}
source_stats = {}


def normalize_domain(d):
    d = (d or "").strip().lower()
    d = d.replace("https://","").replace("http://","")
    d = d.split("/")[0]
    return d


def add_domain(domain, source, seed):

    domain = normalize_domain(domain)

    if not domain or "." not in domain:
        return

    source_stats[source] = source_stats.get(source, 0) + 1

    if domain not in domain_registry:
        domain_registry[domain] = {
            "sources": set(),
            "seeds": set(),
            "ip": "",
            "reverse_dns": "",
            "http_status": "",
            "http_reason": "",
            "redirect_location": "",
            "final_url": "",
            "final_status": "",
            "redirect_count": 0,
            "title": ""
        }

    domain_registry[domain]["sources"].add(source)
    domain_registry[domain]["seeds"].add(seed)


def run_tool(cmd):

    debug(f"Executing tool: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        debug(f"Tool finished: {' '.join(cmd)} | results: {len(lines)}")
        return lines
    except Exception as e:
        debug(f"Tool failed: {' '.join(cmd)} | error: {e}")
        return []


def extract_brand(seed):
    brand = seed.split(".")[0]
    brand = brand.replace("-","")
    return brand.lower()


def run_subdomain_enum(seed, deep):

    tools = FAST_TOOLS.copy()
    if deep:
        tools += DEEP_TOOLS

    for name, cmd in tools:
        print(f"[+] Running {name} on {seed}")
        results = run_tool(cmd + [seed])
        for d in results:
            add_domain(d, name, seed)


def brand_expand(seed):

    brand = extract_brand(seed)

    for tld in COMMON_TLDS:
        add_domain(f"{brand}.{tld}", "brand_tld", seed)

    for p in PREFIX_PATTERNS:
        add_domain(f"{p}{brand}.com", "brand_pattern", seed)
        add_domain(f"{p}-{brand}.com", "brand_pattern", seed)

    for s in SUFFIX_PATTERNS:
        add_domain(f"{brand}{s}.com", "brand_pattern", seed)
        add_domain(f"{brand}-{s}.com", "brand_pattern", seed)


def certificate_expand(seed):

    print(f"[+] Certificate expansion for {seed}")

    crtsh_expand(seed)
    
    certspotter_expand(seed)


def crtsh_expand(seed):

    if not CERTSPOTTER_API_KEY:
        debug("CertSpotter API key not configured")
        return

    brand = extract_brand(seed)

    try:

        print(f"[+] Querying crt.sh for {brand}")

        url = f"https://crt.sh/?q=%25{brand}%25&output=json"

        r = requests.get(
            url,
            timeout=20
        )

        if r.status_code != 200:

            debug(
                f"crt.sh returned {r.status_code}"
            )

            return

        data = r.json()

        discovered = 0

        for entry in data:

            for d in entry.get(
                "name_value",
                ""
            ).split("\n"):

                d = normalize_domain(
                    d.lstrip("*.")
                )

                if brand in d:

                    add_domain(
                        d,
                        "brand_ct",
                        seed
                    )

                    discovered += 1

        print(
            f"[+] crt.sh discovered {discovered} domains"
        )

    except Exception as e:

        debug(
            f"crt.sh failed for {seed} | {e}"
        )


def certspotter_expand(seed):

    brand = extract_brand(seed)

    try:

        print(f"[+] Querying CertSpotter for {brand}")

        headers = {
            "Authorization": f"Bearer {CERTSPOTTER_API_KEY}"
        }

        params = {
            "domain": seed,
            "include_subdomains": "true",
            "expand": ["dns_names"]
        }
        
        r = requests.get(
            "https://api.certspotter.com/v1/issuances",
            headers=headers,
            params=params,
            timeout=20
        )

        if r.status_code != 200:

            debug(
                f"CertSpotter returned {r.status_code}"
            )

            return

        data = r.json()

        discovered = 0

        for cert in data:

            for d in cert.get("dns_names", []):

                d = normalize_domain(
                    d.lstrip("*.")
                )

                if brand in d:

                    add_domain(
                        d,
                        "certspotter",
                        seed
                    )

                    discovered += 1

        print(
            f"[+] CertSpotter discovered {discovered} domains"
        )

    except Exception as e:

        debug(
            f"CertSpotter failed for {seed} | {e}"
        )

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return ""


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"


def http_probe(domain):

    for scheme in ["https", "http"]:

        url = f"{scheme}://{domain}"

        try:

            r = requests.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )

            title = ""

            m = re.search(
                r"<title[^>]*>(.*?)</title>",
                r.text,
                re.I | re.S
            )

            if m:
                title = re.sub(
                    r"\s+",
                    " ",
                    m.group(1)
                ).strip()

            # Original response before redirects
            if r.history:
                http_status = r.history[0].status_code
                http_reason = r.history[0].reason
            else:
                http_status = r.status_code
                http_reason = r.reason

            return {
                "http_status": http_status,
                "http_reason": http_reason,
                "final_url": str(r.url),
                "final_status": r.status_code,
                "redirect_count": len(r.history),
                "title": title
            }

        except Exception:
            continue

    return None


def load_known():

    known = set()

    if not os.path.exists(KNOWN_DOMAINS_FILE):
        return known

    with open(KNOWN_DOMAINS_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            d = normalize_domain(row.get("Domains",""))
            if d:
                known.add(d)

    return known


def main(seed_file, deep, expand):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"recon_{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    print("[+] Loading seed domains")

    seeds = []
    with open(seed_file) as f:
        for line in f:
            s = normalize_domain(line)
            if s:
                seeds.append(s)

    for seed in seeds:
        print(f"\n[+] Processing seed: {seed}")
        run_subdomain_enum(seed, deep)
        if expand:
            brand_expand(seed)
            certificate_expand(seed)

    print(f"\n[+] Total domains discovered: {len(domain_registry)}")

    print("[+] Resolving IPs")

    domains = list(domain_registry.keys())

    def resolve_domain(domain):
        ip = resolve_ip(domain)
        rdns = reverse_dns(ip) if ip else "N/A"
        return domain, ip, rdns

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        for f in as_completed([exe.submit(resolve_domain, d) for d in domains]):
            d, ip, rdns = f.result()
            domain_registry[d]["ip"] = ip
            domain_registry[d]["reverse_dns"] = rdns

    print("[+] HTTP probing")

    domains_with_ip = [d for d in domain_registry if domain_registry[d]["ip"]]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(http_probe,d): d for d in domains_with_ip}
        for f in as_completed(futures):
            d = futures[f]
            r = f.result()
            if r:
                domain_registry[d].update(r)

    known = load_known()

    csv_file = os.path.join(outdir,"final_output.csv")

    with open(csv_file,"w",newline="",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain","Source","Seed","IP","Reverse_DNS",
                         "HTTP_Status","HTTP_Reason","Redirect_Location",
                         "Final_URL","Final_Status","Title","Domain_Status"])

        for d,data in sorted(domain_registry.items()):
            writer.writerow([
                d,
                ",".join(data["sources"]),
                ",".join(data["seeds"]),
                data["ip"],
                data["reverse_dns"],
                data["http_status"],
                data["http_reason"],
                "",
                data["final_url"],
                data["final_status"],
                data["title"],
                "Known" if d in known else "New"
            ])

    print(f"[+] Recon output saved → {csv_file}")

    # ⭐ AUTO COPY TO INGEST PATH (DOCKER SAFE)
    try:
        os.makedirs("data", exist_ok=True)
    
        backend_csv = os.path.join("data", "final_output.csv")
    
        shutil.copy2(csv_file, backend_csv)
    
        print(f"[+] Latest CSV copied to ingestion path → {backend_csv}")
    
    except Exception as e:
        print(f"[!] Failed to copy CSV → {e}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("seed_file")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--expand", action="store_true")

    args = parser.parse_args()

    main(args.seed_file, args.deep, args.expand)
