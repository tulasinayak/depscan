"""CVEMatcherAgent against recorded OSV responses (tests/fixtures/osv). No network."""

import copy
import json
from pathlib import Path

import httpx
import pytest

from depscan.agents.cve_matcher import (
    CVEMatcherAgent, affected_functions, classify_kind, link_related, to_specifier_set,
)
from depscan.cache import ResponseCache
from depscan.models import CVEMatcherInput, Dependency, Vulnerability
from depscan.osv import OSVClient, query_without_token

FIX = Path(__file__).parent / "fixtures" / "osv"
RECORDED = json.loads((FIX / "queries.json").read_text())
VULNS = {p.stem: json.loads(p.read_text()) for p in (FIX / "vulns").glob("*.json")}


class FakeOSV:
    """httpx transport that replays the recorded fixtures (optionally paginating, failing, ...)."""

    def __init__(self, vulns=None, page_size: int | None = None, fail_first: int = 0):
        self.vulns = vulns if vulns is not None else VULNS
        self.page_size, self.fail_first = page_size, fail_first
        self.calls: list[tuple[str, str, int]] = []   # (method, path, number of queries)

    def ids_for(self, q: dict) -> list[str]:
        return next((r["ids"] for r in RECORDED if r["query"] == query_without_token(q)), [])

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail_first:
            self.fail_first -= 1
            self.calls.append((request.method, request.url.path, 0))
            return httpx.Response(503)
        if request.method == "POST" and request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            self.calls.append(("POST", request.url.path, len(queries)))
            results = []
            for q in queries:
                ids = self.ids_for(q)
                res: dict = {}
                if self.page_size:
                    start = int(q.get("page_token", 0))
                    ids, nxt = ids[start:start + self.page_size], start + self.page_size
                    if nxt < len(self.ids_for(q)):
                        res["next_page_token"] = str(nxt)
                if ids:
                    res["vulns"] = [{"id": i} for i in ids]
                results.append(res)
            return httpx.Response(200, json={"results": results})
        vid = request.url.path.rsplit("/", 1)[-1]
        self.calls.append(("GET", request.url.path, 1))
        return httpx.Response(200, json=self.vulns[vid]) if vid in self.vulns else httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def matcher(tmp_path, fake: FakeOSV, offline=False, clock=None, retries=3):
    cache = ResponseCache(tmp_path / "cache.sqlite", ttl_seconds=24 * 3600, clock=clock or Clock())
    client = OSVClient(cache, offline=offline, transport=fake.transport(), retries=retries, sleep=lambda s: None)
    return CVEMatcherAgent(client)


def dep(name, version=None, spec=None, reason=None) -> Dependency:
    return Dependency(name=name, resolved_version=version, version_spec=spec or (f"=={version}" if version else None),
                      unresolved_reason=reason, source_file="requirements.txt", direct=True, scope="main")


def run(agent, *deps):
    return agent.run(CVEMatcherInput(dependencies=list(deps)))


def vulns_of(out, name):
    return {v.id: v for r in out.results if r.dependency.name == name for v in r.vulnerabilities}


# ---------------------------------------------------------------- dedup, CVSS, fixed version

def test_ghsa_and_pysec_for_one_cve_become_one_vulnerability(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("pyyaml", "5.3.1"))
    vulns = vulns_of(out, "pyyaml")
    assert list(vulns) == ["CVE-2020-14343"]                     # 2 advisories -> 1 entry, CVE as display id
    v = vulns["CVE-2020-14343"]
    assert {"GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"} <= set(v.aliases)
    assert v.cve_ids == ["CVE-2020-14343"]
    assert (v.cvss.version, v.cvss.base_score, v.cvss.severity) == ("3.1", 9.8, "critical")
    assert v.fixed_version == "5.4" and v.match == "affected"
    assert v.match_reason == "installed 5.3.1 is in affected range <5.4"
    assert v.summary                                            # taken from GHSA; the PYSEC record has none


def test_counts_are_per_merged_vulnerability(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("urllib3", "1.26.4"))
    recorded_ids = next(r["ids"] for r in RECORDED if r["query"]["package"]["name"] == "urllib3")
    distinct_cves = {a for i in recorded_ids for a in [i, *VULNS[i]["aliases"]] if a.startswith("CVE-")}
    assert len(recorded_ids) == 2 * len(distinct_cves)          # every GHSA has a PYSEC twin
    assert len(vulns_of(out, "urllib3")) == len(distinct_cves)


def test_fixed_version_is_lowest_fix_above_installed_in_matching_range(tmp_path):
    v = vulns_of(run(matcher(tmp_path, FakeOSV()), dep("urllib3", "1.26.4")), "urllib3")
    # CVE-2023-43804 has ranges [2.0.0, 2.0.6) and [0, 1.26.17): 1.26.4 is in the second one
    assert v["CVE-2023-43804"].fixed_version == "1.26.17"
    assert v["CVE-2021-33503"].fixed_version == "1.26.5"


def test_cvss_v4_only(tmp_path):
    v = vulns_of(run(matcher(tmp_path, FakeOSV()), dep("urllib3", "1.26.4")), "urllib3")["CVE-2025-66471"]
    assert v.cvss.version == "4.0" and v.cvss.vector.startswith("CVSS:4.0/") and v.cvss.base_score > 0


def test_missing_cvss_falls_back_to_ghsa_label_without_score(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("requests", spec="<2.6", reason="version spec '<2.6' is not an exact pin"))
    v = vulns_of(out, "requests")["CVE-2015-2296"]
    assert v.cvss.base_score is None and v.cvss.vector is None  # missing, not zero
    assert v.cvss.severity == "medium"                           # from the GHSA label MODERATE


# ---------------------------------------------------------------- unresolved versions

def test_unresolved_range_keeps_only_overlapping_advisories(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()),
              dep("requests", spec=">=2.32,<2.33", reason="version spec '>=2.32,<2.33' is not an exact pin"))
    vulns = vulns_of(out, "requests")
    assert set(vulns) == {"CVE-2024-47081", "CVE-2026-25645"}
    assert all(v.match == "possibly_affected" and v.fixed_version is None for v in vulns.values())
    assert vulns["CVE-2024-47081"].match_reason == "range >=2.32,<2.33 includes affected versions 2.32.0–2.32.3"
    assert any("dropped CVE-2024-35195: range >=2.32,<2.33 excludes all affected versions" in l for l in out.log)


def test_unresolved_without_spec_lists_everything_with_reason(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("requests", reason="no version specified"))
    vulns = vulns_of(out, "requests")
    assert len(vulns) == 8
    assert all(v.match_reason.startswith("version unknown (no version specified)") for v in vulns.values())


def test_url_dependency_is_possibly_affected(tmp_path):
    reason = "installed from URL git+https://example.com/requests.git; version cannot be resolved"
    out = run(matcher(tmp_path, FakeOSV()), dep("requests", reason=reason))
    assert all("installed from URL" in v.match_reason for v in vulns_of(out, "requests").values())


def test_poetry_caret_spec(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("requests", spec="^2.32", reason="version spec '^2.32' is not an exact pin"))
    assert "CVE-2024-47081" in vulns_of(out, "requests") and "CVE-2018-18074" not in vulns_of(out, "requests")


@pytest.mark.parametrize("spec,inside,outside", [
    ("^2.32", "2.40.0", "3.0.0"), ("^0.4.1", "0.4.9", "0.5.0"), ("~1.2", "1.2.9", "1.3.0"), ("*", "9.9", None),
    (">=2.0,<3", "2.5", "3.0"),
])
def test_to_specifier_set(spec, inside, outside):
    s = to_specifier_set(spec)
    assert s.contains(inside) and (outside is None or not s.contains(outside))


# ---------------------------------------------------------------- withdrawn, affected_functions

def test_withdrawn_advisories_are_skipped_and_logged(tmp_path):
    vulns = copy.deepcopy(VULNS)
    for vid in ("GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"):
        vulns[vid]["withdrawn"] = "2024-01-01T00:00:00Z"
    out = run(matcher(tmp_path, FakeOSV(vulns=vulns)), dep("pyyaml", "5.3.1"))
    assert out.results == []
    assert sum("skipped withdrawn advisory" in line for line in out.log) == 2


def test_affected_functions_when_provided():
    rec = {"affected": [{"ecosystem_specific": {"affected_functions": ["yaml.load"],
                                                "imports": [{"path": "yaml.constructor", "symbols": ["FullConstructor"]}]}}]}
    assert affected_functions([rec]) == ["yaml.load", "yaml.constructor.FullConstructor"]
    assert affected_functions([VULNS["GHSA-8q59-q68h-6hv4"]]) == []   # the usual PyPI case


# ---------------------------------------------------------------- step 3a: kind, related_ids, advisory symbols

def test_classify_kind():
    fuzz = {"id": "OSV-2022-715", "affected": [{"ranges": [{"type": "GIT", "events": []}]}]}
    assert classify_kind([fuzz], "Segv in jpeg_read_scanlines", "") == "fuzz_crash"
    osv_with_versions = {"id": "OSV-2020-1", "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": []}]}]}
    assert classify_kind([osv_with_versions], "crash", "") == "standard"
    assert classify_kind([{"id": "GHSA-x"}], "Vulnerable OpenSSL included in cryptography wheels", "") == "bundled_native"
    assert classify_kind([{"id": "GHSA-y"}], "libwebp: OOB write in BuildHuffmanTable", "") == "bundled_native"
    assert classify_kind([{"id": "GHSA-z"}], "Timing oracle in RSA decryption", "uses OpenSSL's API") == "standard"


def test_fuzz_crashes_are_kept_separately(tmp_path):
    vulns = copy.deepcopy(VULNS)
    vulns["OSV-2022-715"] = {"id": "OSV-2022-715", "summary": "Segv", "affected": [
        {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]}
    fake = FakeOSV(vulns=vulns)
    original = fake.ids_for
    fake.ids_for = lambda q: original(q) + (["OSV-2022-715"] if q["package"]["name"] == "pyyaml" else [])
    out = run(matcher(tmp_path, fake), dep("pyyaml", "5.3.1"))
    assert [v.id for v in out.results[0].vulnerabilities] == ["CVE-2020-14343"]
    assert [v.id for v in out.results[0].fuzz_crashes] == ["OSV-2022-715"]


def test_related_ids_link_without_merging(tmp_path):
    out = run(matcher(tmp_path, FakeOSV()), dep("urllib3", "1.26.4"))
    v = vulns_of(out, "urllib3")
    assert len(v) == 9                                           # nothing merged
    related = {vid: x.related_ids for vid, x in v.items() if x.related_ids}
    assert related                                               # some share specific reference URLs
    for vid, rel in related.items():
        assert vid not in rel and all(vid in v[r].related_ids for r in rel)   # symmetric links


def test_link_related_ignores_generic_urls():
    vs = [Vulnerability(id=f"V{i}", match="affected", match_reason="") for i in range(5)]
    urls = {id(v): {"https://example.com/changelog"} for v in vs}
    urls[id(vs[0])].add("https://example.com/issue/1")
    urls[id(vs[1])].add("https://example.com/issue/1")
    link_related(vs, urls)
    assert vs[0].related_ids == ["V1"] and vs[1].related_ids == ["V0"] and vs[2].related_ids == []


def test_advisory_symbols_are_extracted(tmp_path):
    v = vulns_of(run(matcher(tmp_path, FakeOSV()), dep("urllib3", "1.26.4")), "urllib3")
    assert "ProxyManager" in v["CVE-2024-37891"].advisory_symbols


# ---------------------------------------------------------------- HTTP: pagination, batching, retries

def test_pagination_follows_next_page_token(tmp_path):
    fake = FakeOSV(page_size=3)
    out = run(matcher(tmp_path, fake), dep("urllib3", "1.26.4"))
    assert len(vulns_of(out, "urllib3")) == 9
    assert sum(1 for m, p, _ in fake.calls if p == "/v1/querybatch") == 6   # 18 ids / 3 per page


@pytest.mark.slow
def test_batches_are_at_most_1000_queries(tmp_path):
    fake = FakeOSV()
    run(matcher(tmp_path, fake), *[dep(f"pkg{i}", "1.0") for i in range(1500)])
    assert [n for m, p, n in fake.calls if p == "/v1/querybatch"] == [1000, 500]


def test_retries_transient_errors(tmp_path):
    fake = FakeOSV(fail_first=2)
    out = run(matcher(tmp_path, fake), dep("pyyaml", "5.3.1"))
    assert list(vulns_of(out, "pyyaml")) == ["CVE-2020-14343"]


def test_gives_up_after_three_attempts_and_logs(tmp_path):
    out = run(matcher(tmp_path, FakeOSV(fail_first=10)), dep("pyyaml", "5.3.1"))
    assert out.results == [] and any("failed after 3 attempts" in line for line in out.log)


# ---------------------------------------------------------------- cache

def test_cache_hit_miss_and_expiry(tmp_path):
    clock = Clock()
    fake = FakeOSV()
    first = run(matcher(tmp_path, fake, clock=clock), dep("pyyaml", "5.3.1"))
    assert first.cache.fetched == 3 and first.cache.hits == 0     # 1 query + 2 records
    n_calls = len(fake.calls)

    second = run(matcher(tmp_path, fake, clock=clock), dep("pyyaml", "5.3.1"))
    assert second.cache.hits == 3 and second.cache.fetched == 0 and len(fake.calls) == n_calls
    assert second.results == first.results

    clock.t += 25 * 3600                                          # past the 24h TTL
    third = run(matcher(tmp_path, fake, clock=clock), dep("pyyaml", "5.3.1"))
    assert third.cache.fetched == 3 and len(fake.calls) > n_calls


def test_offline_reports_misses_and_uses_expired_entries(tmp_path):
    clock = Clock()
    offline_empty = run(matcher(tmp_path, FakeOSV(), offline=True, clock=clock), dep("pyyaml", "5.3.1"))
    assert offline_empty.results == [] and offline_empty.cache.misses == 1
    assert any("offline: no cached OSV answer for pyyaml==5.3.1" in line for line in offline_empty.log)

    run(matcher(tmp_path, FakeOSV(), clock=clock), dep("pyyaml", "5.3.1"))   # populate the cache
    clock.t += 100 * 3600
    fake = FakeOSV()
    offline = run(matcher(tmp_path, fake, offline=True, clock=clock), dep("pyyaml", "5.3.1"))
    assert fake.calls == []                                       # offline never touches the network
    assert offline.cache.stale_hits == 3 and list(vulns_of(offline, "pyyaml")) == ["CVE-2020-14343"]


def test_network_failure_falls_back_to_expired_cache(tmp_path):
    clock = Clock()
    run(matcher(tmp_path, FakeOSV(), clock=clock), dep("pyyaml", "5.3.1"))
    clock.t += 100 * 3600
    out = run(matcher(tmp_path, FakeOSV(fail_first=100), clock=clock), dep("pyyaml", "5.3.1"))
    assert list(vulns_of(out, "pyyaml")) == ["CVE-2020-14343"] and out.cache.stale_hits == 3
