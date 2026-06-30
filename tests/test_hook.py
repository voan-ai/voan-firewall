"""Firewall hook: the gate. allow runs, block/denied-ask raise, monitor logs only,
egress + judge tiers wire in, the judge only escalates."""
import pytest

from voan import Firewall, LLMJudge
from voan.schema import BlockedAction, Decision
from conftest import stub_llm


def test_allow_runs_and_returns():
    fw = Firewall()
    f = fw.guard(lambda x: x + 1, name="add")
    assert f(41) == 42


def test_block_raises():
    fw = Firewall()
    run = fw.guard(lambda command: "ran", name="run_command")
    with pytest.raises(BlockedAction):
        run("rm -rf /")


def test_ask_denied_raises_denied_by_user():
    fw = Firewall(on_ask=lambda a, v: False)
    pay = fw.guard(lambda **k: "paid", name="process_refund")
    with pytest.raises(BlockedAction) as ei:
        pay(order_id="A", amount=5)
    assert ei.value.denied_by_user is True


def test_ask_approved_runs():
    fw = Firewall(on_ask=lambda a, v: True)
    pay = fw.guard(lambda **k: "paid", name="process_refund")
    assert pay(order_id="A", amount=5) == "paid"


def test_monitor_mode_never_blocks():
    fw = Firewall(mode="monitor")
    run = fw.guard(lambda command: "ran", name="run_command")
    assert run("rm -rf /") == "ran"          # logged, not blocked


def test_egress_allowlist_wired():
    fw = Firewall(egress_allowlist=["acme.com"])
    exp = fw.guard(lambda dest: "sent", name="export_data")
    with pytest.raises(BlockedAction):
        exp(dest="https://exfil.evil.net/leak")
    assert exp(dest="https://acme.com/in") == "sent"


def test_judge_escalates_to_block():
    judge = LLMJudge(llm=stub_llm('{"decision":"block","reason":"beyond goal"}'))
    fw = Firewall(judge=judge)
    fw.set_goal("Check order status.")
    send = fw.guard(lambda to: "sent", name="notify")   # ASK tool, judge escalates
    with pytest.raises(BlockedAction):
        send(to="data-broker@x.com")


def test_judge_cannot_loosen_hard_block():
    # judge says allow, but a destructive command is already BLOCK -> stays blocked,
    # and the judge is not even consulted on an already-blocked verdict.
    llm = stub_llm('{"decision":"allow","reason":"fine"}')
    fw = Firewall(judge=LLMJudge(llm=llm))
    fw.set_goal("clean up")
    run = fw.guard(lambda command: "ran", name="run_command")
    with pytest.raises(BlockedAction):
        run("rm -rf /")
    assert llm.calls == []


def test_judge_no_goal_is_noop():
    llm = stub_llm('{"decision":"block","reason":"should not run"}')
    fw = Firewall(judge=LLMJudge(llm=llm))           # no set_goal
    f = fw.guard(lambda x: x, name="lookup")
    assert f("ok") == "ok"
    assert llm.calls == []


def test_judge_fail_closed_blocks_on_backend_error():
    class Boom(LLMJudge):
        available = True
        def evaluate(self, goal, action, trace):
            return None                              # simulate backend failure
    fw = Firewall(judge=Boom(llm=lambda s, u: ""), judge_fail_closed=True)
    fw.set_goal("check status")
    send = fw.guard(lambda to: "sent", name="notify")
    with pytest.raises(BlockedAction) as ei:
        send(to="ok@acme.com")
    assert ei.value.verdict.rule == "judge-fail-closed"


def test_guard_tools_dict_and_list():
    fw = Firewall()
    d = fw.guard_tools({"run_command": lambda command: "ran"})
    assert callable(d["run_command"])
    lst = fw.guard_tools([lambda command: "ran"])
    assert len(lst) == 1
