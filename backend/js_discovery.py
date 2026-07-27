import re
import pandas as pd
import requests
import tldextract

from db import get_conn
from bs4 import BeautifulSoup
from urllib.parse import urljoin

INPUT_FILE = "data/final_output.csv"
OUTPUT_FILE = "data/js_discovered.csv"

TIMEOUT = 10

DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b'
)

ENV_KEYWORDS = [
    "dev",
    "test",
    "qa",
    "uat",
    "stage",
    "staging",
    "admin",
    "internal",
    "int",
    "temp",
    "sandbox",
    "demo"
]

SEED_DOMAINS = [
    "abc.com",
    "xyz.com"
]



def is_valid_domain(candidate):

    try:

        ext = tldextract.extract(candidate)

        if not ext.domain:
            return False

        if not ext.suffix:
            return False

        return True

    except Exception:
        return False


def belongs_to_seed(candidate):

    candidate = candidate.lower()

    for seed in SEED_DOMAINS:

        if candidate == seed:
            return True

        if candidate.endswith("." + seed):
            return True

    return False


def get_js_files(url):

    try:

        r = requests.get(
            url,
            timeout=TIMEOUT,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        soup = BeautifulSoup(
            r.text,
            "html.parser"
        )

        js_files = []

        for tag in soup.find_all("script"):

            src = tag.get("src")

            if src:
                js_files.append(
                    urljoin(url, src)
                )

        return js_files

    except Exception:
        return []


def extract_domains_from_js(js_url):

    discovered = []

    try:

        r = requests.get(
            js_url,
            timeout=TIMEOUT,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        matches = set(
            DOMAIN_REGEX.findall(r.text)
        )

        for candidate in matches:

            candidate = (
                candidate
                .lower()
                .strip()
                .strip(".")
            )

            if not is_valid_domain(candidate):
                continue

            if not belongs_to_seed(candidate):
                continue

            parts = candidate.split(".")

            env_match = any(
                keyword in candidate
                for keyword in ENV_KEYWORDS
            )

            discovered.append(
                {
                    "domain": candidate,
                    "environment_related": env_match
                }
            )

    except Exception:
        pass

    return discovered


def main():

    global SEED_DOMAINS
    
    SEED_DOMAINS = [
        "abc.com",
        "xyz.com"
    ]

    
    print("[+] Seed Domains:")
    for seed in SEED_DOMAINS:
        print(f"    - {seed}")

    df = pd.read_csv(INPUT_FILE)

    candidates = df[
        (
            df["HTTP_Status"].fillna(0) > 0
        )
        |
        (
            df["Final_Status"].fillna(0) > 0
        )
    ]

    print(
        f"[+] Candidates: {len(candidates)}"
    )

    discovered = []

    for _, row in candidates.iterrows():

        domain = str(
            row["Domain"]
        ).strip()

        url = f"https://{domain}"

        print(
            f"[+] Checking {domain}"
        )

        js_files = get_js_files(url)

        for js_file in js_files:

            js_domains = extract_domains_from_js(
                js_file
            )

            for entry in js_domains:

                discovered.append(
                    {
                        "Domain": entry["domain"],
                        "Source": "javascript",
                        "Parent": domain,
                        "JS_File": js_file,
                        "Environment_Related": entry["environment_related"]
                    }
                )

    result = pd.DataFrame(discovered)
   
    if result.empty:
        print("[+] No JS domains found")
        return
   
    result = (
        result
        .drop_duplicates()
        .sort_values("Domain")
    )

    result.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"[+] Found {len(result)} unique domains"
    )

    env_count = result[
        result["Environment_Related"] == True
    ].shape[0]

    print(
        f"[+] Environment-related domains: {env_count}"
    )


if __name__ == "__main__":

    requests.packages.urllib3.disable_warnings()

    main()
