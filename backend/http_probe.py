import re

import requests


TIMEOUT = 8


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
