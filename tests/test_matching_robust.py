"""T2: vulnerability matching. Version ranges against packaging's ordering, alias chains, the OSV cache."""

import sqlite3

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from packaging.version import Version

from depscan.agents.cve_matcher import (CVEMatcherAgent, contains, fmt_interval, group_by_alias, intervals,
                                        lowest_fix_above, to_specifier_set)
from depscan.cache import ResponseCache
from depscan.models import Dependency
from depscan.osv import OSVClient, query_key
from test_cve_matcher import Clock, FakeOSV

# ---------------------------------------------------------------- versions (PEP 440, all the odd forms)

versions = st.builds(
    lambda epoch, rel, pre, post, dev, local: (f"{epoch}!" if epoch else "") + ".".join(map(str, rel))
    + (f"{pre[0]}{pre[1]}" if pre else "") + (f".post{post}" if post is not None else "")
    + (f".dev{dev}" if dev is not None else "") + (f"+{local}" if local else ""),
    st.sampled_from([0, 0, 0, 1]), st.lists(st.integers(0, 12), min_size=1, max_size=3),
    st.none() | st.tuples(st.sampled_from(["a", "b", "rc"]), st.integers(0, 3)),
    st.none() | st.integers(0, 3), st.none() | st.integers(0, 3), st.none() | st.sampled_from(["cpu", "cu118", "ubuntu.1"]))


def reference(iv, v: Version) -> bool:
    """OSV ECOSYSTEM semantics with packaging's version ordering: introduced <= v < fixed (or <= last_affected)."""
    intro, fixed, last = iv
    if intro != "0" and v < Version(intro):
        return False
    if fixed:
        return v < Version(fixed)
    if last:
        return v <= Version(last)
    return True


@settings(max_examples=400, deadline=None)
@given(versions, versions, versions, st.sampled_from(["fixed", "last", "open"]), st.booleans())
def test_contains_matches_packaging_ordering(v, a, b, kind, from_zero):
    lo, hi = sorted([Version(a), Version(b)])
    iv = ("0" if from_zero else str(lo), str(hi) if kind == "fixed" else None, str(hi) if kind == "last" else None)
    assert contains(iv, Version(v)) == reference(iv, Version(v)), (iv, v)


@pytest.mark.parametrize("iv,v,affected", [
    (("0", "2.0", None), "2.0rc1", True),            # a pre-release of the fixed version sorts before it
    (("0", "2.0", None), "2.0", False),
    (("0", "2.0", None), "2.0.post1", False),
    (("0", "2.0", None), "1.9.post3", True),
    (("0", "2.0", None), "2.0.dev1", True),
    (("0", "2.0", None), "1!0.5", False),            # epoch 1 sorts after every epoch-0 version
    (("1!1.0", "1!2.0", None), "1!1.5", True),
    (("0", "2.0", None), "1.9+cpu", True),            # local versions compare after their public version
    (("0", "2.0", None), "2.0+cpu", False),
    (("1.0", None, "1.4"), "1.4", True),              # last_affected is inclusive
    (("1.0", None, "1.4"), "1.4.post1", False),
    (("1.0", None, None), "99.0", True),              # introduced only: still affected
    (("not-a-version", "2.0", None), "1.0", False),   # invalid bounds never match
])
def test_edge_versions(iv, v, affected):
    assert contains(iv, Version(v)) == affected


def rec(id_, aliases=(), events=(), versions=(), package="demo"):
    return {"id": id_, "aliases": list(aliases),
            "affected": [{"package": {"ecosystem": "PyPI", "name": package}, "versions": list(versions),
                          "ranges": [{"type": "ECOSYSTEM", "events": list(events)}]}]}


def test_intervals_with_only_introduced_last_affected_and_several_ranges():
    r = rec("X", events=[{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"last_affected": "2.3"},
                         {"introduced": "3.0"}])
    ivs, _ = intervals([r], "demo")
    assert ivs == [("0", "1.2", None), ("2.0", None, "2.3"), ("3.0", None, None)]
    assert [fmt_interval(iv) for iv in ivs] == ["<1.2", ">=2.0, <=2.3", ">=3.0"]
    assert lowest_fix_above(ivs, Version("1.0")) == ("1.2", ("0", "1.2", None))
    assert lowest_fix_above(ivs, Version("2.1"))[0] is None                  # affected, no fix listed
    other = rec("Y", events=[{"introduced": "0"}, {"fixed": "9"}], package="other-pkg")
    assert intervals([other], "demo") == ([], [])                            # other packages ignored


@pytest.mark.parametrize("spec,listed,kept", [
    ("==1.*", ["1.4", "2.0"], True), ("==3.*", ["1.4", "2.0"], False), ("~=1.4", ["1.4.2"], True),
    ("^1.2", ["1.9"], True), ("^1.2", ["2.0"], False), ("~1.2", ["1.2.5"], True), (">=1.0,!=1.4.*", ["1.4.1"], False),
    (">=1.0,!=1.4.*", ["1.4.1", "1.5"], True), ("not a spec", ["1.0"], True),
    ("<1.0", ["1.0rc1"], False),       # PEP 440: <1.0 excludes pre-releases of 1.0, and pip never installs one
])
def test_unpinned_ranges_against_listed_versions(spec, listed, kept):
    dep = Dependency(name="demo", version_spec=spec, source_file="requirements.txt", direct=True,
                     unresolved_reason=f"version spec '{spec}' is not an exact pin")
    reason = CVEMatcherAgent._unresolved_reason(dep, listed, "X", [])
    assert (reason is not None) == kept, reason


def test_specifier_shorthands():
    assert str(to_specifier_set("^0.2.3")) in ("<0.3,>=0.2.3", ">=0.2.3,<0.3")
    assert to_specifier_set("*").contains("5.0") and to_specifier_set("===weird") is not None


# ---------------------------------------------------------------- alias chains

def test_alias_chains_merge_into_one_group():
    a, b, c = rec("GHSA-a", ["PYSEC-b"]), rec("PYSEC-b", ["CVE-c"]), rec("CVE-c")
    groups = group_by_alias([c, a, b])
    assert len(groups) == 1 and [r["id"] for r in groups[0]] == ["GHSA-a", "PYSEC-b", "CVE-c"]


def test_alias_cycles_and_self_aliases_terminate():
    groups = group_by_alias([rec("A", ["B"]), rec("B", ["A"]), rec("C", ["C"]), rec("D", ["E"]), rec("E", ["D", "A"])])
    assert sorted(len(g) for g in groups) == [1, 4]


# ---------------------------------------------------------------- the cache

def client(tmp_path, offline=False, clock=None):
    cache = ResponseCache(tmp_path / "c.sqlite", 3600, clock or Clock())
    return OSVClient(cache, offline=offline, transport=FakeOSV().transport(), sleep=lambda s: None), cache


def corrupt(tmp_path, key: str, data: str) -> None:
    db = sqlite3.connect(tmp_path / "c.sqlite")
    db.execute("INSERT OR REPLACE INTO responses (key, data, fetched_at) VALUES (?, ?, ?)", (key, data, 0))
    db.commit()
    db.close()


QUERY = {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "5.3.1"}


@pytest.mark.parametrize("data", ["{not json", '"a string"', '{"no_ids": 1}', '{"ids": "nope"}'])
def test_corrupted_cache_rows_are_refetched_online(tmp_path, data):
    osv, cache = client(tmp_path)
    corrupt(tmp_path, query_key(QUERY), data)
    [ids] = osv.query_ids([QUERY])
    assert ids is not None and all(isinstance(i, str) for i in ids)


@pytest.mark.parametrize("data", ["{not json", '{"ids": "nope"}'])
def test_corrupted_cache_rows_are_misses_offline(tmp_path, data):
    osv, cache = client(tmp_path, offline=True)
    corrupt(tmp_path, query_key(QUERY), data)
    assert osv.query_ids([QUERY]) == [None] and osv.stats.misses == 1


def test_expired_entries_are_refetched_online_and_used_offline(tmp_path):
    clock = Clock()
    osv, cache = client(tmp_path, clock=clock)
    [first] = osv.query_ids([QUERY])
    clock.t += 10 * 3600                                     # past the 1 h TTL
    offline, _ = client(tmp_path, offline=True, clock=clock)
    assert offline.query_ids([QUERY]) == [first] and offline.stats.stale_hits == 1
    online, _ = client(tmp_path, clock=clock)
    assert online.query_ids([QUERY]) == [first] and online.stats.fetched == 1


def test_offline_with_partial_cache(tmp_path):
    osv, _ = client(tmp_path)
    osv.query_ids([QUERY])
    other = {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.30.0"}
    offline, _ = client(tmp_path, offline=True)
    got = offline.query_ids([QUERY, other])
    assert got[0] is not None and got[1] is None and any("requests==2.30.0" in m for m in offline.log)
