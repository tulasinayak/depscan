"""Record real OSV responses for the offline test suite.

Run manually (needs network):  uv run python tests/fixtures/osv/record_osv.py
Writes queries.json (query -> ids) and vulns/<id>.json (full records).
"""

import json
from pathlib import Path

import httpx

HERE = Path(__file__).parent
QUERIES = [
    {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "5.3.1"},   # GHSA + PYSEC for one CVE
    {"package": {"name": "requests", "ecosystem": "PyPI"}},                      # name only: range matching
    {"package": {"name": "urllib3", "ecosystem": "PyPI"}, "version": "1.26.4"},  # includes a v4-only advisory
    {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "3.13"},     # flask_vuln_repo (yaml.load)
    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.1"},  # flask_vuln_repo (unused paths)
]


def main() -> None:
    client = httpx.Client(base_url="https://api.osv.dev", timeout=30)
    resp = client.post("/v1/querybatch", json={"queries": QUERIES}).json()
    recorded, ids = [], set()
    for q, res in zip(QUERIES, resp["results"]):
        assert not res.get("next_page_token"), "pagination not expected for these fixtures"
        vids = [v["id"] for v in res.get("vulns", [])]
        recorded.append({"query": q, "ids": vids})
        ids.update(vids)
    (HERE / "vulns").mkdir(exist_ok=True)
    for vid in sorted(ids):
        (HERE / "vulns" / f"{vid}.json").write_text(json.dumps(client.get(f"/v1/vulns/{vid}").json(), indent=1))
    (HERE / "queries.json").write_text(json.dumps(recorded, indent=1))
    print(f"recorded {len(recorded)} queries and {len(ids)} advisories")


if __name__ == "__main__":
    main()
