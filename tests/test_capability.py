"""Capability engine — the CaMeL/FIDES core invariants, proven per value:
integrity (untrusted data can't steer a side effect) and confidentiality
(confidential data can't reach an unauthorized sink). Deterministic, prompt-proof."""
import pytest

from voan.capability import (ANY, Capsule, CapabilityEngine, Denied, TRUSTED,
                             UNTRUSTED)

# sink classes: send_money/send_email are external; save_note is internal
ENG = CapabilityEngine(sink_class={"send_money": "external", "send_email": "external",
                                   "save_note": "internal"})


# --- integrity invariant (anti-hijack) ---------------------------------------
def test_untrusted_recipient_is_denied():
    email = ENG.source("read_email", untrusted=True)      # untrusted source
    payee = email.derive("US133-attacker")                # extracted from the email
    with pytest.raises(Denied) as ei:
        ENG.check_call("send_money", {"recipient": payee, "amount": 999})
    assert "hijack" in ei.value.reason


def test_trusted_recipient_from_user_is_allowed():
    payee = ENG.trusted("GB29-the-user-asked")            # from the user's request
    assert ENG.check_call("send_money", {"recipient": payee, "amount": 50}) is True


def test_combine_trusted_and_untrusted_is_untrusted():
    a = ENG.trusted("x"); b = ENG.source("web", untrusted=True)
    mixed = Capsule.combine("x-from-web", a, b)
    assert mixed.integrity == UNTRUSTED
    with pytest.raises(Denied):
        ENG.check_call("send_money", {"recipient": mixed})


def test_untrusted_in_nonsensitive_param_is_ok():
    note = ENG.source("web", untrusted=True).derive("some memo text")
    # 'subject' isn't control-sensitive -> untrusted content there doesn't hijack
    assert ENG.check_call("send_money",
                          {"recipient": ENG.trusted("GB29"), "subject": note}) is True


# --- confidentiality invariant (anti-exfil) ----------------------------------
def test_confidential_value_denied_to_external_sink():
    secret = ENG.source("get_balance", untrusted=False, readers=frozenset({"internal"}))
    body = secret.derive("balance is 9231")
    with pytest.raises(Denied) as ei:
        ENG.check_call("send_email", {"to": ENG.trusted("ok@corp.com"), "body": body})
    assert "exfiltration" in ei.value.reason


def test_confidential_value_allowed_to_internal_sink():
    secret = ENG.source("get_balance", untrusted=False, readers=frozenset({"internal"}))
    body = secret.derive("balance is 9231")
    assert ENG.check_call("save_note", {"body": body}) is True


def test_public_value_flows_anywhere():
    pub = ENG.trusted("hello")                            # readers = {ANY}
    assert ENG.check_call("send_email", {"to": ENG.trusted("x"), "body": pub}) is True


# --- propagation / combination ------------------------------------------------
def test_derive_inherits_capability():
    src = ENG.source("read_file", untrusted=True, readers=frozenset({"internal"}))
    d = src.derive("line 3 of the file")
    assert d.integrity == UNTRUSTED and d.readers == frozenset({"internal"})


def test_readers_intersection_on_combine():
    a = Capsule("a", TRUSTED, frozenset({"internal", "team"}))
    b = Capsule("b", TRUSTED, frozenset({"internal"}))
    assert Capsule.combine("c", a, b).readers == frozenset({"internal"})


def test_raw_literals_are_trusted():
    # a plain (non-Capsule) arg is treated as a trusted literal the caller vouches for
    assert ENG.check_call("send_money", {"recipient": "GB29", "amount": 10}) is True


def test_guard_threads_capabilities_end_to_end():
    # tool outputs become capsules; feeding an untrusted one into a sensitive param
    # is denied by construction — the CaMeL usage model.
    tools = ENG.guard_tools(
        {"read_email": lambda: "wire to US133", "send_money": lambda recipient, amount=0: "sent"},
        sources={"read_email"})
    email = tools["read_email"]()                      # -> untrusted Capsule
    payee = email.derive("US133")
    with pytest.raises(Denied):
        tools["send_money"](recipient=payee, amount=999)
    # a trusted recipient is fine
    assert tools["send_money"](recipient=ENG.trusted("GB29"), amount=10).value == "sent"
