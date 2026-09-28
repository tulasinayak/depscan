import requests


def fetch_status(url):
    return requests.get(url, timeout=5).status_code
