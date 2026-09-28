import requests


def status(url):
    return requests.get(url, timeout=3).status_code
