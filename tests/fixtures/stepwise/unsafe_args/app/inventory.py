import requests

INVENTORY_API = "https://inventory.internal.example.org"
_session = requests.Session()


def warm_up():
    _session.get(f"{INVENTORY_API}/health", timeout=3, verify=False)


def fetch_stock(sku):
    response = _session.get(f"{INVENTORY_API}/stock/{sku}", timeout=5, verify=True)
    response.raise_for_status()
    return response.json()
