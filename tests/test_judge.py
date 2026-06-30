"""LLMJudge: escalate-only, scope-aware, redaction before the backend, robust parse."""
import warnings

from voan import LLMJudge
from voan.judge import _parse, _redact
from voan.schema import Action, Decision
from conftest import stub_llm


def A(tool, **args):
    return Action(tool=tool, args=args, agent="t")


def test_block_on_inconsistent():
    j = LLMJudge(llm=stub_llm('{"decision":"block","reason":"exfil"}'))
    v = j.evaluate("look up order", A("send_email", to="x@evil.com"), [])
    assert v.decision == Decision.BLOCK and v.rule == "llm-judge"


def test_allow_on_consistent():
    j = LLMJudge(llm=stub_llm('{"decision":"allow","reason":"ok"}'))
    v = j.evaluate("look up order", A("lookup", id="1"), [])
    assert v.decision == Decision.ALLOW


def test_no_goal_returns_none():
    j = LLMJudge(llm=stub_llm('{"decision":"block"}'))
    assert j.evaluate("", A("x"), []) is None


def test_no_backend_returns_none_and_warns(monkeypatch):
    # llm=None means "use the default (OpenAI) backend"; force that to resolve to
    # no backend (as it would with no OPENAI_API_KEY) to exercise the fail-open path.
    monkeypatch.setattr("voan.judge.openai_llm", lambda *a, **k: None)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        j = LLMJudge()
        assert any("no LLM backend" in str(x.message) for x in w)
    assert j.available is False
    assert j.evaluate("goal", A("x"), []) is None


def test_backend_error_returns_none():
    def boom(s, u):
        raise RuntimeError("down")
    j = LLMJudge(llm=boom)
    assert j.evaluate("goal", A("x"), []) is None


def test_redaction_masks_secrets_and_cards():
    raw = "api_key=sk-abcdef123456 and card 4111 1111 1111 1111"
    out = _redact(raw)
    assert "sk-abcdef123456" not in out and "[REDACTED-SECRET]" in out
    assert "4111 1111 1111 1111" not in out and "[REDACTED-NUM]" in out


def test_redaction_applied_before_backend():
    llm = stub_llm('{"decision":"allow"}')
    j = LLMJudge(llm=llm)
    j.evaluate("send the receipt", A("save", key="api_key=sk-zzzz9999"), [])
    sent = llm.calls[0][1]
    assert "sk-zzzz9999" not in sent and "[REDACTED-SECRET]" in sent


def test_parse_json_and_prose_fallback():
    assert _parse('{"decision":"block","reason":"x"}')["decision"] == "block"
    assert _parse("noise {\"decision\":\"allow\"} tail")["decision"] == "allow"
    # prose: last decision word wins
    assert _parse("I think ... so I allow this")["decision"] == "allow"
    assert _parse("allow? no — block it")["decision"] == "block"
    assert _parse("no verdict here") == {}
