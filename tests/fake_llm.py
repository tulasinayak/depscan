"""A stand-in for openai.OpenAI: returns scripted replies (or computes them from the prompt)."""

import json
from collections.abc import Callable
from types import SimpleNamespace


class FakeCompletions:
    def __init__(self, replies: list[str] | Callable[[list[dict]], str]):
        self.replies = replies
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = self.replies(kwargs["messages"]) if callable(self.replies) else self.replies.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")],
                               usage=SimpleNamespace(prompt_tokens=123, completion_tokens=45))


class FakeOpenAI:
    def __init__(self, replies, models=("qwen3:8b",)):
        self.chat = SimpleNamespace(completions=FakeCompletions(replies))
        self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id=m) for m in models]))

    @property
    def calls(self) -> list[dict]:
        return self.chat.completions.calls


def verdict_json(verdict="uncertain", confidence=0.5, evidence=(), inference=("x",), unknowns=("y",),
                 recommendation="manual review") -> str:
    return json.dumps({"verdict": verdict, "confidence": confidence,
                       "evidence": [{"text": t, "citation": c} for t, c in evidence],
                       "inference": list(inference), "unknowns": list(unknowns), "recommendation": recommendation})
