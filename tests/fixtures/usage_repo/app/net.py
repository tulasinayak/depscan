import urllib3 as u

pm = u.PoolManager(retries=False)


def fetch(url):
    first = pm.request("GET", url)
    second = u.request("GET", url)
    return first, second
