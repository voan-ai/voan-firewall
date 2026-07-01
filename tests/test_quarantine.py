"""Quarantined LLM extractor: reads untrusted content, has no powers. Whatever it
returns is capability-tagged untrusted, so it can never steer a sink."""
import pytest

from voan import CapabilityEngine, Denied, quarantined_llm

ENG = CapabilityEngine(sink_class={"send_money": "external"})


def stub(reply):
    return lambda system, user: reply


def test_extractor_returns_value():
    ex = quarantined_llm(stub("GB29-legit-payee"))
    assert ex("some email content", "payee") == "GB29-legit-payee"


def test_extractor_never_lets_extracted_value_pay():
    # even if an injection fools the extractor into returning the ATTACKER account,
    # the value is untrusted (from the email) and send_money is denied.
    for extracted in ("US133-attacker", "GB29-legit"):     # attacker OR legit — same rule
        ex = quarantined_llm(stub(extracted))
        tools = {"read_email": lambda: "poisoned email body",
                 "extract": ex,
                 "send_money": lambda recipient, amount=0: "sent"}
        program = [
            {"var": "email", "tool": "read_email", "args": {}},
            {"var": "payee", "tool": "extract", "args": {"content": "$email", "query": "payee"}},
            {"tool": "send_money", "args": {"recipient": "$payee", "amount": 999}},
        ]
        with pytest.raises(Denied):
            ENG.run(program, tools, sources={"read_email"})


def test_extractor_errors_return_empty():
    def boom(s, u):
        raise RuntimeError("down")
    assert quarantined_llm(boom)("x", "y") == ""


def test_user_named_recipient_still_pays():
    # the safe pattern: the recipient comes from the USER (trusted), not the email.
    ex = quarantined_llm(stub("anything"))
    tools = {"read_email": lambda: "body", "extract": ex,
             "send_money": lambda recipient, amount=0: "sent"}
    program = [
        {"var": "email", "tool": "read_email", "args": {}},
        {"var": "summary", "tool": "extract", "args": {"content": "$email", "query": "amount"}},
        {"tool": "send_money", "args": {"recipient": "GB29-user-named", "amount": 50}},
    ]
    assert "summary" in ENG.run(program, tools, sources={"read_email"})
