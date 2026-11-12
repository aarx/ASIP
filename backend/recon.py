#!/usr/bin/env python3

import subprocess
import socket
import argparse
import csv
import os
import re
import signal
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from db import get_conn, require_running_scan
from config import CERTSPOTTER_API_KEY
from ownership import normalize_hostname
from recon_artifact import publish_recon_artifact, scan_recon_artifact_path


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

MAX_WORKERS = 40
DEFAULT_RECON_TOOL_TIMEOUT_SECONDS = 120

KNOWN_DOMAINS_FILE = "known_domains.csv"

domain_registry = {}
source_stats = {}
source_outcomes = {}
rejected_discovery = {}
MAX_REJECTION_SEEDS_PER_SOURCE = 100

SOURCE_OK = "OK"
SOURCE_ZERO = "ZERO"
SOURCE_FAILED = "FAILED"
SOURCE_SKIPPED = "SKIPPED"

SOURCE_LABELS = {
    "subfinder": "Subfinder",
    "assetfinder": "Assetfinder",
    "findomain": "Findomain",
    "amass": "Amass",
    "crt.sh": "crt.sh",
    "certspotter": "CertSpotter",
}


def normalize_domain(value, *, allow_wildcard=False):
    """Use the shared strict hostname and IDNA canonicalization boundary."""
    return normalize_hostname(
        value, allow_wildcard=allow_wildcard, require_fqdn=True
    )


def record_rejected_discovery(source, seed, reason="invalid_hostname"):
    source_name = str(source or "unknown")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", source_name):
        source_name = "other"
    entry = rejected_discovery.setdefault(
        (source_name, reason), {"count": 0, "seeds": set()}
    )
    entry["count"] += 1
    normalized_seed = normalize_hostname(seed)
    if (
        normalized_seed
        and len(entry["seeds"]) < MAX_REJECTION_SEEDS_PER_SOURCE
    ):
        entry["seeds"].add(normalized_seed)


def add_domain(domain, source, seed):

    domain = normalize_domain(domain)

    if not domain:
        record_rejected_discovery(source, seed)
        return False

    source_stats[source] = source_stats.get(source, 0) + 1

    if domain not in domain_registry:
        domain_registry[domain] = {
            "sources": set(),
            "seeds": set(),
            "ip": "",
            "reverse_dns": "",
            "http_status": "",
            "http_observation_status": "UNKNOWN",
            "http_reason": "",
            "redirect_location": "",
            "final_url": "",
            "final_status": "",
            "redirect_count": 0,
            "title": ""
        }

    domain_registry[domain]["sources"].add(source)
    domain_registry[domain]["seeds"].add(seed)
    return True


def record_source_attempt(source, status, result_count=0, error=None):
    entry = source_outcomes.setdefault(source, {
        "status": SOURCE_ZERO,
        "results": 0,
        "attempts": 0,
        "failed": False,
        "errors": [],
    })

    if status == SOURCE_SKIPPED:
        if entry["attempts"] == 0:
            entry["status"] = SOURCE_SKIPPED
        return entry

    entry["attempts"] += 1
    entry["results"] += result_count

    if status == SOURCE_FAILED:
        entry["failed"] = True
        if error:
            entry["errors"].append(error)

    if entry["failed"]:
        entry["status"] = SOURCE_FAILED
    elif entry["results"]:
        entry["status"] = SOURCE_OK
    else:
        entry["status"] = SOURCE_ZERO

    return entry


def print_source_summary():
    print("\nShadowRecon Recon Source Summary")
    print("-------------------------")

    for source, entry in source_outcomes.items():
        label = SOURCE_LABELS.get(source, source)
        status = entry["status"]
        if status in {SOURCE_OK, SOURCE_ZERO}:
            print(f"{label:<16} {status:<7} {entry['results']:>6} results")
        elif status == SOURCE_FAILED:
            detail = entry["errors"][-1] if entry["errors"] else "source failed"
            print(f"{label:<16} {status:<7} {detail}")
        else:
            print(f"{label:<16} {status}")

    if rejected_discovery:
        print("Rejected hostname candidates:")
        for (source, reason), entry in sorted(rejected_discovery.items()):
            print(
                f"{source:<16} {reason:<24} count={entry['count']} "
                f"distinct_seed_provenance<={len(entry['seeds'])}"
            )

    warnings = sum(
        entry["status"] in {SOURCE_ZERO, SOURCE_FAILED}
        for entry in source_outcomes.values()
    )
    print(f"Warnings: {warnings}")


def run_tool(cmd):

    debug(f"Executing tool: {' '.join(cmd)}")
    process = None

    try:
        timeout_seconds = int(os.getenv(
            "ASIP_RECON_TOOL_TIMEOUT_SECONDS",
            str(DEFAULT_RECON_TOOL_TIMEOUT_SECONDS),
        ))
        if timeout_seconds <= 0:
            timeout_seconds = DEFAULT_RECON_TOOL_TIMEOUT_SECONDS

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            debug(
                f"Tool timed out after {timeout_seconds}s: {' '.join(cmd)}"
            )
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            return False, [], f"timeout after {timeout_seconds}s"

        if process.returncode != 0:
            debug(
                f"Tool failed: {' '.join(cmd)} | exit={process.returncode}"
            )
            return False, [], f"exit {process.returncode}"

        lines = stdout.splitlines()
        debug(f"Tool finished: {' '.join(cmd)} | results: {len(lines)}")
        return True, lines, None
    except Exception as e:
        error = f"{type(e).__name__}: tool launch failed"
        debug(f"Tool failed: {' '.join(cmd)} | {error}")
        return False, [], error
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


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
        completed, results, error = run_tool(cmd + [seed])
        if not completed:
            record_source_attempt(name, SOURCE_FAILED, error=error)
            continue

        usable = 0
        for d in results:
            if add_domain(d, name, seed):
                usable += 1
        record_source_attempt(
            name,
            SOURCE_OK if usable else SOURCE_ZERO,
            result_count=usable,
        )


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

            return record_source_attempt(
                "crt.sh", SOURCE_FAILED, error=f"HTTP {r.status_code}"
            )

        data = r.json()
        if not isinstance(data, list):
            raise ValueError("response was not a list")

        candidates = []

        for entry in data:
            if not isinstance(entry, dict):
                raise ValueError("response contained a malformed entry")

            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str):
                raise ValueError("response contained malformed name_value")

            for d in name_value.split("\n"):

                if not d:
                    continue

                d = normalize_domain(d, allow_wildcard=True)
                if d is None:
                    record_rejected_discovery("brand_ct", seed)
                    continue

                if brand in d:
                    candidates.append(d)

        discovered = sum(
            add_domain(d, "brand_ct", seed)
            for d in candidates
        )

        print(
            f"[+] crt.sh discovered {discovered} domains"
        )
        return record_source_attempt(
            "crt.sh",
            SOURCE_OK if discovered else SOURCE_ZERO,
            result_count=discovered,
        )

    except Exception as e:
        error = f"{type(e).__name__}: request/response failure"
        debug(f"crt.sh failed for {seed} | {error}")
        return record_source_attempt(
            "crt.sh", SOURCE_FAILED, error=error
        )


def certspotter_expand(seed):

    if not CERTSPOTTER_API_KEY:
        debug("CertSpotter API key not configured")
        return record_source_attempt("certspotter", SOURCE_SKIPPED)

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

            return record_source_attempt(
                "certspotter", SOURCE_FAILED, error=f"HTTP {r.status_code}"
            )

        data = r.json()
        if not isinstance(data, list):
            raise ValueError("response was not a list")

        candidates = []

        for cert in data:
            if not isinstance(cert, dict):
                raise ValueError("response contained a malformed entry")

            dns_names = cert.get("dns_names", [])
            if not isinstance(dns_names, list):
                raise ValueError("response contained malformed dns_names")

            for d in dns_names:
                if not isinstance(d, str):
                    raise ValueError("response contained a malformed DNS name")

                d = normalize_domain(d, allow_wildcard=True)
                if d is None:
                    record_rejected_discovery("certspotter", seed)
                    continue

                if brand in d:
                    candidates.append(d)

        discovered = sum(
            add_domain(d, "certspotter", seed)
            for d in candidates
        )

        print(
            f"[+] CertSpotter discovered {discovered} domains"
        )
        return record_source_attempt(
            "certspotter",
            SOURCE_OK if discovered else SOURCE_ZERO,
            result_count=discovered,
        )

    except Exception as e:
        error = f"{type(e).__name__}: request/response failure"
        debug(f"CertSpotter failed for {seed} | {error}")
        return record_source_attempt(
            "certspotter", SOURCE_FAILED, error=error
        )

def resolve_ip(domain):
    normalized = normalize_hostname(domain, require_fqdn=True)
    if normalized is None:
        return ""
    try:
        return socket.gethostbyname(normalized)
    except:
        return ""


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror as e:
        # h_errno 1 (HOST_NOT_FOUND) and 4 (NO_DATA) conclusively mean
        # that no PTR name exists. Other resolver failures are operational.
        if e.errno in (1, 4):
            return "N/A"
        debug(f"PTR lookup failed for {ip} | {type(e).__name__}")
        return None
    except (socket.timeout, socket.gaierror, OSError) as e:
        debug(f"PTR lookup failed for {ip} | {type(e).__name__}")
        return None
    except Exception as e:
        debug(f"PTR lookup failed for {ip} | {type(e).__name__}")
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


def main(seed_file, deep, expand, scan_id):

    source_outcomes.clear()
    rejected_discovery.clear()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"recon_scan_{scan_id}_{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    print("[+] Loading seed domains")

    file_seeds = []
    with open(seed_file) as f:
        for line in f:
            seed_value = line.rstrip("\r\n")
            if not seed_value:
                continue
            s = normalize_domain(seed_value)
            if s:
                file_seeds.append(s)
            else:
                record_rejected_discovery("seed_file", seed_value)

    # seeds.txt is the exclusive source of reconnaissance starting domains.
    # Keep its existing normalization and avoid duplicate campaigns.
    seeds = list(dict.fromkeys(file_seeds))

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
        rdns = reverse_dns(ip) if ip else None
        return domain, ip, rdns

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        for f in as_completed([exe.submit(resolve_domain, d) for d in domains]):
            d, ip, rdns = f.result()
            domain_registry[d]["ip"] = ip
            domain_registry[d]["reverse_dns"] = rdns

    # Direct HTTP/TLS observation is intentionally deferred until after
    # ingest, current-scan membership and scope authorization exist.  Recon
    # remains a passive discovery producer and preserves UNKNOWN HTTP state.

    known = load_known()

    csv_file = os.path.join(outdir,"final_output.csv")

    with open(csv_file,"w",newline="",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain","Source","Seed","IP","Reverse_DNS",
                         "HTTP_Status","HTTP_Reason","Redirect_Location",
                         "Final_URL","Final_Status","Title",
                         "HTTP_Observation_Status","Domain_Status"])

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
                data["http_observation_status"],
                "Known" if d in known else "New"
            ])

    print(f"[+] Recon output saved → {csv_file}")

    backend_csv = scan_recon_artifact_path("data", scan_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        publish_recon_artifact(
            csv_file,
            backend_csv,
            scan_id=scan_id,
            row_count=len(domain_registry),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    print(f"[+] Scan {scan_id} artifact published → {backend_csv}")
    print_source_summary()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("seed_file")
    parser.add_argument("--scan-id", type=int, required=True)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--expand", action="store_true")

    args = parser.parse_args()

    main(args.seed_file, args.deep, args.expand, args.scan_id)
