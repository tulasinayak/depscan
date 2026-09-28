"""OpenAI-compatible chat client (Ollama by default; Kimi or any other compatible endpoint via config).

- strips <think>...</think> blocks (qwen3) and ```json fences
- JSON mode when enabled; the reply is validated with pydantic and retried once with the error fed back
- every call is appended to logs/llm_calls.jsonl (agent, prompt, raw response, parsed result, duration)
"""

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import openai
from pydantic import BaseModel, ValidationError

from depscan.config import LLMConfig
from depscan.errors import LLMOutputError, LLMUnavailable

THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def strip_think(text: str) -> str:
    text = THINK.sub("", text or "")
    if "<think>" in text.lower():             # unterminated block: drop everything up to the JSON
        text = text[text.lower().rfind("<think>") + 7:]
    text = text.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
    return fence.group(1) if fence else text


def extract_json(text: str) -> dict:
    text = strip_think(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class RateLimiter:
    """Requests per minute and (estimated) tokens per minute over a sliding 60 s window."""

    def __init__(self, rpm: float, tpm: float, clock=time.monotonic, sleep=time.sleep):
        self.rpm, self.tpm, self.clock, self.sleep = rpm, tpm, clock, sleep
        self.events: list[tuple[float, int]] = []
        self._lock = threading.Lock()

    def wait(self, tokens: int, on_wait=None) -> float:
        """Block until one more request of `tokens` fits; returns the seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = self.clock()
                self.events = [(t, n) for t, n in self.events if now - t < 60]
                over_r = self.rpm and len(self.events) + 1 > self.rpm
                over_t = self.tpm and sum(n for _, n in self.events) + tokens > self.tpm and self.events
                if not (over_r or over_t):
                    self.events.append((now, tokens))
                    return waited
                pause = max(0.5, 60 - (now - self.events[0][0]) + 0.1)
            if on_wait:
                on_wait(f"waiting for rate limit ({pause:.0f}s)")
            self.sleep(pause)
            waited += pause


def _error_details(e: Exception) -> list[dict]:
    """google.rpc details from an OpenAI-compatible error body (Gemini puts quota info there)."""
    body = getattr(e, "body", None)
    items = body if isinstance(body, list) else [body]
    out = []
    for item in items:
        err = item.get("error", item) if isinstance(item, dict) else None
        if isinstance(err, dict):
            out += [d for d in err.get("details", []) or [] if isinstance(d, dict)]
    return out


def quota_failure(e: Exception, kind: str) -> str:
    """'20 requests per day for gemini-3.8-flash' when a quota of that kind (e.g. PerDay) is exhausted, else ''."""
    for d in _error_details(e):
        for v in d.get("violations", []) or []:
            if kind in str(v.get("quotaId", "")):
                model = (v.get("quotaDimensions") or {}).get("model", "")
                return f"limit {v.get('quotaValue', '?')} ({v.get('quotaId')})" + (f" for {model}" if model else "")
    return ""


def retry_delay(e: Exception) -> str:
    """Seconds from a google.rpc.RetryInfo detail ("16s" -> "16"), else ''."""
    for d in _error_details(e):
        delay = str(d.get("retryDelay", ""))
        if delay.endswith("s") and delay[:-1].replace(".", "", 1).isdigit():
            return delay[:-1]
    return ""


def resolve_key(cfg: LLMConfig) -> str:
    """The API key: from the named environment variable when api_key_env is set (never stored), else the config."""
    if cfg.api_key_env:
        return os.environ.get(cfg.api_key_env, "")
    return cfg.api_key or "none"


def pick_model(ids: list[str], family: str) -> str | None:
    """The newest stable model whose name contains `family` (e.g. "flash"): no lite/preview/experimental/tts/image/
    audio/live/embedding variants; highest version number first."""
    skip = ("lite", "preview", "exp", "tts", "image", "audio", "live", "embedding", "thinking", "latest", "vision")
    names = [i.removeprefix("models/") for i in ids]
    ok = [n for n in names if family in n and n.startswith("gemini") and not any(s in n for s in skip)] or \
         [n for n in names if family in n and not any(s in n for s in ("tts", "image", "audio", "live", "embedding"))]
    if not ok:
        return None
    def version(n: str) -> tuple:
        return tuple(float(x) for x in re.findall(r"\d+(?:\.\d+)?", n)[:2]) or (0,)
    return max(ok, key=lambda n: (version(n), -len(n)))


class LLMClient:
    def __init__(self, cfg: LLMConfig, log_path: Path | None = None, client=None, response_cache=None,
                 sleep=time.sleep):
        self.cfg = cfg
        self.log_path = log_path
        self.response_cache = response_cache if cfg.cache_responses else None
        self.sleep = sleep
        self.on_wait = None                     # callback(str): "waiting for rate limit (12s)", for progress displays
        self.status = ""
        key = resolve_key(cfg)
        self._missing_key = bool(cfg.api_key_env and not key and client is None)
        self.client = client or openai.OpenAI(base_url=cfg.base_url, api_key=key or "missing",
                                              timeout=cfg.timeout_seconds, max_retries=0)
        del key                                 # only the SDK client keeps it, in memory
        self._send_reasoning = bool(cfg.reasoning_effort)
        self._lock = threading.Lock()
        self._model = None if cfg.model.startswith("auto:") else cfg.model
        self.limiter = RateLimiter(cfg.requests_per_minute, cfg.tokens_per_minute, sleep=sleep) \
            if (cfg.requests_per_minute or cfg.tokens_per_minute) else None

    @property
    def model(self) -> str:
        if self._model is None:
            family = self.cfg.model.split(":", 1)[1]
            chosen = pick_model(self.list_models(), family)
            if chosen is None:
                raise LLMUnavailable(f"No {family!r} model is listed by {self.cfg.base_url}.")
            self._model = chosen
        return self._model

    def _wait_status(self, text: str) -> None:
        self.status = text
        if self.on_wait:
            self.on_wait(text)

    # ------------------------------------------------------------ raw call

    def _cache_key(self, kwargs: dict) -> str:
        body = json.dumps({"profile": self.cfg.profile, **{k: v for k, v in kwargs.items()}}, sort_keys=True)
        return "llm:" + hashlib.sha256(body.encode()).hexdigest()

    def _call(self, messages: list[dict], json_mode: bool, max_tokens: int) -> tuple[str, dict]:
        if self._missing_key:
            raise LLMUnavailable(f"The {self.cfg.profile} profile needs the environment variable "
                                 f"{self.cfg.api_key_env}, which is not set.")
        kwargs = dict(model=self.model, messages=messages, temperature=self.cfg.temperature, max_tokens=max_tokens)
        if json_mode and self.cfg.json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if self._send_reasoning:
            kwargs["reasoning_effort"] = self.cfg.reasoning_effort
        key = self._cache_key(kwargs) if self.response_cache is not None else None
        if key:
            hit = self.response_cache.get(key)
            if hit:
                raw, meta = hit[0]["raw"], hit[0]["meta"]
                return raw, {**meta, "cached": True}
        if self.limiter:
            waited = self.limiter.wait(estimate_tokens(json.dumps(messages)) + max_tokens, self._wait_status)
            if waited:
                self._wait_status("")
        start = time.perf_counter()
        try:
            resp = self._create_with_retries(kwargs)
        except openai.BadRequestError as e:
            if self._send_reasoning and "reasoning" in str(e).lower():
                self._send_reasoning = False            # endpoint does not know reasoning_effort: drop it
                return self._call(messages, json_mode, max_tokens)
            raise LLMUnavailable(f"The LLM endpoint rejected the request ({self.model}).", detail=str(e)) from e
        except openai.NotFoundError as e:
            raise LLMUnavailable(f"Model {self.cfg.model!r} is not available at {self.cfg.base_url}. "
                                 f"For Ollama run: ollama pull {self.cfg.model}", detail=str(e)) from e
        except openai.APITimeoutError as e:
            raise LLMUnavailable(f"The LLM did not answer within {self.cfg.timeout_seconds}s.", detail=str(e)) from e
        except openai.APIConnectionError as e:
            raise LLMUnavailable(f"Cannot reach the LLM at {self.cfg.base_url}. Is Ollama running (`ollama serve`)?",
                                 detail=str(e)) from e
        except openai.RateLimitError as e:
            raise LLMUnavailable(f"The LLM endpoint is still rate-limiting after {self.cfg.max_retries_429} retries; "
                                 "try again later.", detail=str(e)) from e
        except openai.APIStatusError as e:
            raise LLMUnavailable(f"The LLM endpoint returned HTTP {e.status_code}.", detail=str(e)) from e
        duration_ms = int((time.perf_counter() - start) * 1000)
        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        meta = {"duration_ms": duration_ms, "finish_reason": getattr(choice, "finish_reason", None),
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None), "profile": self.cfg.profile}
        raw = choice.message.content or ""
        if key and raw:
            self.response_cache.put(key, {"raw": raw, "meta": meta})
        return raw, meta

    def _create_with_retries(self, kwargs: dict):
        """HTTP 429 (rate limit) and 500/503 (overloaded): wait for Retry-After when the server sends it, else back off
        exponentially (2, 4, 8 ... 60 s)."""
        for attempt in range(self.cfg.max_retries_429 + 1):
            try:
                return self.client.chat.completions.create(**kwargs)
            except (openai.RateLimitError, openai.InternalServerError) as e:
                daily = quota_failure(e, "PerDay")
                if daily:
                    raise LLMUnavailable(f"The daily free quota of {self.model} is used up ({daily}); retrying today "
                                         "will not help.", detail=str(e)[:500]) from e
                if attempt == self.cfg.max_retries_429:
                    raise
                headers = getattr(getattr(e, "response", None), "headers", None) or {}
                try:
                    pause = float(headers.get("retry-after", "") or retry_delay(e))
                except ValueError:
                    pause = min(60.0, 2.0 ** (attempt + 1))
                code = getattr(e, "status_code", 429)
                self._wait_status(f"waiting for rate limit ({pause:.0f}s, HTTP 429)" if code == 429 else
                                  f"provider busy, retrying in {pause:.0f}s (HTTP {code})")
                self.sleep(pause)
                self._wait_status("")

    def _log(self, record: dict) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "model": self._model or self.cfg.model,
                  "profile": self.cfg.profile, **record}
        with self._lock, self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    # ------------------------------------------------------------ public API

    def complete_json(self, agent: str, system: str, user: str, schema: type[BaseModel],
                      max_tokens: int | None = None) -> tuple[BaseModel, dict]:
        """Validated structured output. Retries once with the validation error; raises LLMOutputError after that."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        total_ms, error = 0, ""
        for attempt in (1, 2):
            raw, meta = self._call(messages, json_mode=True, max_tokens=max_tokens or self.cfg.max_output_tokens)
            total_ms += meta["duration_ms"]
            try:
                parsed = schema.model_validate(extract_json(raw))
            except (json.JSONDecodeError, ValidationError) as e:
                error = str(e)[:800]
                self._log({"agent": agent, "attempt": attempt, "prompt": messages, "raw_response": raw,
                           "parsed": None, "error": error, **meta})
                messages = messages + [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": f"That reply was not valid: {error}\n"
                                                "Reply again with only the corrected JSON object."}]
                continue
            self._log({"agent": agent, "attempt": attempt, "prompt": messages, "raw_response": raw,
                       "parsed": parsed.model_dump(), "error": None, **meta})
            return parsed, {**meta, "duration_ms": total_ms, "attempts": attempt,
                            "prompt_tokens_estimate": estimate_tokens(system + user)}
        raise LLMOutputError(f"The model did not return valid JSON after a retry ({self._model or self.cfg.model}).", detail=error)

    def complete_text(self, agent: str, system: str, user: str, max_tokens: int = 200) -> tuple[str, dict]:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        raw, meta = self._call(messages, json_mode=False, max_tokens=max_tokens)
        text = strip_think(raw)
        self._log({"agent": agent, "attempt": 1, "prompt": messages, "raw_response": raw, "parsed": text,
                   "error": None, **meta})
        return text, meta

    def log_event(self, agent: str, record: dict) -> None:
        """Record something about a call that happened after parsing (e.g. a rejected answer)."""
        self._log({"agent": agent, **record})

    def list_models(self) -> list[str]:
        try:
            return sorted(m.id for m in self.client.models.list().data)
        except openai.APIConnectionError as e:
            raise LLMUnavailable(f"Cannot reach the LLM at {self.cfg.base_url}. Is Ollama running (`ollama serve`)?",
                                 detail=str(e)) from e
        except openai.APIError as e:
            raise LLMUnavailable(f"Listing models failed at {self.cfg.base_url}.", detail=str(e)) from e


def average_duration_ms(log_path: Path, agent: str = "ExploitabilityAgent") -> float | None:
    """Average logged duration of successful calls for one agent (for batch time estimates)."""
    if not log_path.exists():
        return None
    durations = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("agent") == agent and rec.get("error") is None and rec.get("duration_ms"):
            durations.append(rec["duration_ms"])
    return sum(durations) / len(durations) if durations else None
