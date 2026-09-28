"""OSV.dev API client with an SQLite response cache and an offline (cache-only) mode."""

import hashlib
import json
import threading
import time
from collections.abc import Callable

import httpx

from depscan import __version__
from depscan.cache import ResponseCache
from depscan.models import CacheStats

MAX_BATCH = 1000


class OSVError(Exception):
    pass


def valid_ids(data) -> bool:
    return isinstance(data, dict) and isinstance(data.get("ids"), list) and all(isinstance(i, str) for i in data["ids"])


def query_key(query: dict) -> str:
    return "osv:query:" + hashlib.sha256(json.dumps(query, sort_keys=True).encode()).hexdigest()


class OSVClient:
    def __init__(self, cache: ResponseCache, base_url: str = "https://api.osv.dev", offline: bool = False,
                 timeout: float = 30, retries: int = 3, backoff: float = 1.0,
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep):
        self.cache, self.offline, self.retries, self.backoff, self.sleep = cache, offline, retries, backoff, sleep
        self.http = httpx.Client(base_url=base_url, transport=transport,
                                 timeout=httpx.Timeout(timeout, connect=10),
                                 headers={"User-Agent": f"depscan/{__version__}"})
        self.stats = CacheStats()
        self.log: list[str] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------ HTTP

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                resp = self.http.request(method, path, json=payload)
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise OSVError(f"{method} {path}: HTTP {resp.status_code}")
                resp.raise_for_status()
                return resp.json()
            except (httpx.TransportError, OSVError) as e:
                last = e
                if attempt < self.retries - 1:
                    self.sleep(self.backoff * 2 ** attempt)
            except httpx.HTTPStatusError as e:  # 4xx: retrying will not help
                raise OSVError(f"{method} {path}: HTTP {e.response.status_code}") from e
        raise OSVError(f"{method} {path} failed after {self.retries} attempts: {last}")

    def _count(self, field: str, message: str | None = None) -> None:
        with self._lock:
            setattr(self.stats, field, getattr(self.stats, field) + 1)
            if message:
                self.log.append(message)

    # ------------------------------------------------------------ cached lookups

    def query_ids(self, queries: list[dict]) -> list[list[str] | None]:
        """Vulnerability ids for each query (None = offline cache miss or network failure)."""
        results: list[list[str] | None] = [None] * len(queries)
        stale: dict[int, list[str]] = {}
        pending: list[int] = []
        for i, q in enumerate(queries):
            hit = self.cache.get(query_key(q))
            if hit and not valid_ids(hit[0]):                   # a corrupted or foreign row: ignore it
                self.cache.delete(query_key(q))
                hit = None
            if hit and self.cache.is_fresh(hit[1]):
                results[i] = hit[0]["ids"]
                self._count("hits")
            elif self.offline:
                if hit:
                    results[i] = hit[0]["ids"]
                    self._count("stale_hits")
                else:
                    self._count("misses", f"offline: no cached OSV answer for {describe(q)}")
            else:
                if hit:
                    stale[i] = hit[0]["ids"]
                pending.append(i)

        for start in range(0, len(pending), MAX_BATCH):
            batch = pending[start:start + MAX_BATCH]
            try:
                fetched = self._querybatch([queries[i] for i in batch])
            except OSVError as e:
                for i in batch:
                    if i in stale:
                        results[i] = stale[i]
                        self._count("stale_hits", f"OSV unreachable ({e}); using expired cache for {describe(queries[i])}")
                    else:
                        self.log.append(f"OSV query failed for {describe(queries[i])}: {e}")
                continue
            for i, ids in zip(batch, fetched):
                self.cache.put(query_key(queries[i]), {"ids": ids})
                results[i] = ids
                self._count("fetched")
        return results

    def _querybatch(self, queries: list[dict]) -> list[list[str]]:
        """POST /v1/querybatch, following next_page_token for any query that has more pages."""
        ids: list[list[str]] = [[] for _ in queries]
        todo = list(enumerate(queries))
        while todo:
            resp = self._request("POST", "/v1/querybatch", {"queries": [q for _, q in todo]})
            results = resp.get("results", [])
            next_todo = []
            for (i, q), res in zip(todo, results):
                ids[i] += [v["id"] for v in res.get("vulns", [])]
                if res.get("next_page_token"):
                    next_todo.append((i, {**query_without_token(q), "page_token": res["next_page_token"]}))
            todo = next_todo
        return [list(dict.fromkeys(x)) for x in ids]

    def get_vuln(self, vuln_id: str) -> dict | None:
        key = f"osv:vuln:{vuln_id}"
        hit = self.cache.get(key)
        if hit and not (isinstance(hit[0], dict) and isinstance(hit[0].get("id"), str)):
            self.cache.delete(key)
            hit = None
        if hit and self.cache.is_fresh(hit[1]):
            self._count("hits")
            return hit[0]
        if self.offline:
            if hit:
                self._count("stale_hits")
                return hit[0]
            self._count("misses", f"offline: no cached OSV record for {vuln_id}")
            return None
        try:
            data = self._request("GET", f"/v1/vulns/{vuln_id}")
        except OSVError as e:
            if hit:
                self._count("stale_hits", f"OSV unreachable ({e}); using expired cache for {vuln_id}")
                return hit[0]
            self.log.append(f"OSV fetch failed for {vuln_id}: {e}")
            return None
        self.cache.put(key, data)
        self._count("fetched")
        return data


def query_without_token(q: dict) -> dict:
    return {k: v for k, v in q.items() if k != "page_token"}


def describe(q: dict) -> str:
    name = q["package"]["name"]
    return f"{name}=={q['version']}" if "version" in q else f"{name} (any version)"
