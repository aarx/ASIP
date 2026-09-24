import re

import requests


TIMEOUT = 8
HTTP_RESPONDED = "RESPONDED"
HTTP_NO_RESPONSE = "NO_RESPONSE"
HTTP_FAILED = "FAILED"
HTTP_UNKNOWN = "UNKNOWN"


def _empty_result(status):
    return {
        "http_observation_status": status,
        "http_status": 0,
        "http_reason": "",
        "final_url": "",
        "final_status": 0,
        "redirect_count": 0,
        "title": ""
    }


def http_probe(domain):
    attempted = False

    for scheme in ["https", "http"]:

        url = f"{scheme}://{domain}"

        try:
            attempted = True

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
                "http_observation_status": HTTP_RESPONDED,
                "http_status": http_status,
                "http_reason": http_reason,
                "final_url": str(r.url),
                "final_status": r.status_code,
                "redirect_count": len(r.history),
                "title": title
            }

        except requests.exceptions.RequestException:
            continue
        except Exception:
            return _empty_result(HTTP_FAILED)

    if attempted:
        return _empty_result(HTTP_NO_RESPONSE)

    return _empty_result(HTTP_UNKNOWN)
