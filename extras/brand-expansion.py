#!/usr/bin/env python3

import requests
import socket
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_TLDS = [
    "com", "net", "org", "co", "in", "io", "ai",
    "app", "tech", "cloud", "global", "me"
]

PREFIX_PATTERNS = [
    "get", "join", "try", "my", "secure", "go", "use"
]

SUFFIX_PATTERNS = [
    "group", "global", "corp", "holdings",
    "cloud", "tech", "services", "systems"
]

EVENT_PATTERNS = [
    "2024", "2023", "summit", "launch", "expo", "campaign"
]

TIMEOUT = 5
MAX_WORKERS = 50


def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def ct_keyword_expand(brand):
    results = set()

    try:
        url = f"https://crt.sh/?q=%25{brand}%25&output=json"
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            return results

        data = r.json()

        for entry in data:

            # --- Process SAN entries ---
            name_value = entry.get("name_value", "")
            for d in name_value.split("\n"):
                d = d.lower().strip().lstrip("*.")
                if brand in d and len(d) < len(brand) + 25:
                    if re.match(r"^[a-z0-9.-]+$", d):
                        results.add(d)

            # --- Process Common Name ---
            cn = entry.get("common_name", "")
            if cn:
                cn = cn.lower().strip().lstrip("*.")
                if brand in cn and len(cn) < len(brand) + 25:
                    if re.match(r"^[a-z0-9.-]+$", cn):
                        results.add(cn)

    except Exception:
        pass

    return results

def generate_pattern_domains(brand):
    candidates = set()

    # Exact brand across TLDs
    for tld in COMMON_TLDS:
        candidates.add(f"{brand}.{tld}")

    # Prefix patterns
    for prefix in PREFIX_PATTERNS:
        candidates.add(f"{prefix}{brand}.com")

    # Suffix patterns
    for suffix in SUFFIX_PATTERNS:
        candidates.add(f"{brand}{suffix}.com")

    # Hyphenated patterns
    for suffix in SUFFIX_PATTERNS:
        candidates.add(f"{brand}-{suffix}.com")

    # Event patterns
    for e in EVENT_PATTERNS:
        candidates.add(f"{brand}{e}.com")
        candidates.add(f"{brand}-{e}.com")

    return candidates


def score_domain(domain, brand, source):
    score = 0

    if domain.startswith(brand + "."):
        score += 3

    if domain.startswith(brand):
        score += 2

    if brand in domain:
        score += 1

    if source == "tld_variant":
        score += 3

    if source == "pattern":
        score += 2

    if source == "ct_keyword":
        score += 1

    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def main(root_domain):

    brand = root_domain.split(".")[0].lower()

    print(f"[+] Brand extracted: {brand}")
    print("[+] Running aggressive brand expansion...")

    all_results = []

    # 1️⃣ TLD + Pattern Generation
    generated = generate_pattern_domains(brand)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(domain_exists, d): d for d in generated}

        for f in as_completed(futures):
            domain = futures[f]
            if f.result():
                source = "tld_variant" if domain.startswith(f"{brand}.") else "pattern"
                confidence = score_domain(domain, brand, source)
                all_results.append((domain, source, confidence))

    # 2️⃣ CT Keyword Expansion
    ct_results = ct_keyword_expand(brand)

    for domain in ct_results:
        confidence = score_domain(domain, brand, "ct_keyword")
        all_results.append((domain, "ct_keyword", confidence))

    # Deduplicate
    unique = {}
    for d, s, c in all_results:
        if d not in unique:
            unique[d] = (s, c)

    output_file = "brand_expanded_domains.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Source", "Confidence"])
        for domain, (source, confidence) in sorted(unique.items()):
            writer.writerow([domain, source, confidence])

    print(f"[+] Expansion complete. Results saved to {output_file}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 brand_expand.py abc.com")
        sys.exit(1)

    main(sys.argv[1])
