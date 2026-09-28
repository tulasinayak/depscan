"""OpenAI-compatible chat client (Ollama by default; Kimi or any other compatible endpoint via config).

- strips <think>...</think> blocks (qwen3) and ```json fences
- JSON mode when enabled; the reply is validated with pydantic and retried once with the error fed back
- every call is appended to logs/llm_calls.jsonl (agent, prompt, raw response, parsed result, duration)
"""

import json
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


class LLMClient:
    def __init__(self, cfg: LLMConfig, log_path: Path | None = None, client=None):
        self.cfg = cfg
        self.log_path = log_path
        self.client = client or openai.OpenAI(base_url=cfg.base_url, api_key=cfg.api_key or "none",
                                              timeout=cfg.timeout_seconds, max_retries=0)
        self._send_reasoning = bool(cfg.reasoning_effort)
        self._lock = threading.Lock()

    @property
    def model(self) -> str:
        return self.cfg.model

    # ------------------------------------------------------------ raw call

    def _call(self, messages: list[dict], json_mode: bool, max_tokens: int) -> tuple[str, dict]:
        kwargs = dict(model=self.cfg.model, messages=messages, temperature=self.cfg.temperature, max_tokens=max_tokens)
        if json_mode and self.cfg.json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if self._send_reasoning:
            kwargs["reasoning_effort"] = self.cfg.reasoning_effort
        start = time.perf_counter()
        try:
            resp = self.client.chat.completions.create(**kwargs)
        except openai.BadRequestError as e:
            if self._send_reasoning and "reasoning" in str(e).lower():
                self._send_reasoning = False            # endpoint does not know reasoning_effort: drop it
                return self._call(messages, json_mode, max_tokens)
            raise LLMUnavailable(f"The LLM endpoint rejected the request ({self.cfg.model}).", detail=str(e)) from e
        except openai.NotFoundError as e:
            raise LLMUnavailable(f"Model {self.cfg.model!r} is not available at {self.cfg.base_url}. "
                                 f"For Ollama run: ollama pull {self.cfg.model}", detail=str(e)) from e
        except openai.APITimeoutError as e:
            raise LLMUnavailable(f"The LLM did not answer within {self.cfg.timeout_seconds}s.", detail=str(e)) from e
        except openai.APIConnectionError as e:
            raise LLMUnavailable(f"Cannot reach the LLM at {self.cfg.base_url}. Is Ollama running (`ollama serve`)?",
                                 detail=str(e)) from e
        except openai.RateLimitError as e:
            raise LLMUnavailable("The LLM endpoint is rate-limiting requests; try again later.", detail=str(e)) from e
        except openai.APIStatusError as e:
            raise LLMUnavailable(f"The LLM endpoint returned HTTP {e.status_code}.", detail=str(e)) from e
        duration_ms = int((time.perf_counter() - start) * 1000)
        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        meta = {"duration_ms": duration_ms, "finish_reason": getattr(choice, "finish_reason", None),
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None)}
        return choice.message.content or "", meta

    def _log(self, record: dict) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "model": self.cfg.model, **record}
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
        raise LLMOutputError(f"The model did not return valid JSON after a retry ({self.cfg.model}).", detail=error)

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
