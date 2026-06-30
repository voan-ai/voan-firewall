"""Extra pluggable judge backends — Voan is NOT OpenAI-only.

The LLM judge accepts any `callable(system, user) -> str`. `judge.py` ships
`openai_llm` and `ollama_llm` (local); this module adds Anthropic (Claude) and a
generic OpenAI-compatible backend that covers Groq, Together, OpenRouter, Mistral,
DeepSeek, local vLLM / LM Studio, and anything else exposing /chat/completions.
Stdlib only — zero dependencies.

    from voan import LLMJudge
    from voan.backends import anthropic_llm, openai_compatible_llm

    judge = LLMJudge(llm=anthropic_llm())                       # Claude
    judge = LLMJudge(llm=openai_compatible_llm(                 # Groq, etc.
        "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile",
        key_env="GROQ_API_KEY"))
"""
import json
import os
import urllib.request

from .judge import load_dotenv


def _post(url, headers, body, timeout=30):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def openai_compatible_llm(base_url, model, key_env="OPENAI_API_KEY", key=None):
    """Any OpenAI-compatible chat endpoint. `base_url` is the part before
    `/chat/completions` (e.g. https://api.groq.com/openai/v1). Returns None if no
    key is found, so the judge fails open exactly like the built-in backends."""
    load_dotenv()
    key = key or os.environ.get(key_env)
    if not key:
        return None
    url = base_url.rstrip("/") + "/chat/completions"

    def call(system, user):
        d = _post(url, {"Authorization": f"Bearer {key}",
                        "Content-Type": "application/json"},
                  {"model": model, "temperature": 0, "messages": [
                      {"role": "system", "content": system},
                      {"role": "user", "content": user}]})
        return d["choices"][0]["message"]["content"]

    return call


def anthropic_llm(model="claude-haiku-4-5-20251001", max_tokens=512):
    """Anthropic Claude (Messages API). Reads ANTHROPIC_API_KEY; model overridable
    via ANTHROPIC_MODEL. Returns None if no key is set."""
    load_dotenv()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    model = os.environ.get("ANTHROPIC_MODEL", model)

    def call(system, user):
        d = _post("https://api.anthropic.com/v1/messages",
                  {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json"},
                  {"model": model, "max_tokens": max_tokens, "system": system,
                   "messages": [{"role": "user", "content": user}]})
        return d["content"][0]["text"]

    return call
