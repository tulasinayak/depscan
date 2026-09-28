import os
import re

import requests

TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
PARTNER_SESSION = os.environ.get("PARTNER_SESSION", "")


def fetch_preview(url):
    headers = {"User-Agent": "linkcard/1.2", "Cookie": f"partner_session={PARTNER_SESSION}"}
    response = requests.get(url, headers=headers, timeout=5)
    response.raise_for_status()
    match = TITLE.search(response.text)
    return {
        "url": response.url,
        "status": response.status_code,
        "title": match.group(1).strip() if match else None,
    }
