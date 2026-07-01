"""Plan-then-execute: only committed actions run; injected extra/altered actions
are off-plan and blocked. Deterministic — no LLM."""
import pytest

from voan import Firewall
from voan.plan import Plan
from voan.schema import Action, BlockedAction


def A(tool, **args):
    return Action(tool=tool, args=args, agent="t")


def test_on_plan_action_runs():
    fw = Firewall().set_plan(["read_file", "send_money"])
    read = fw.guard(lambda file_path: "bill", name="read_file")
    pay = fw.guard(lambda **k: "paid", name="send_money")
    assert read(file_path="bill.txt") == "bill"
    assert pay(recipient="GB123", amount=10) == "paid"


def test_off_plan_action_blocked():
    fw = Firewall().set_plan(["read_file"])
    pay = fw.guard(lambda **k: "paid", name="send_money")   # not in the plan
    with pytest.raises(BlockedAction) as ei:
        pay(recipient="US133", amount=999)
    assert ei.value.verdict.rule == "off-plan"


def test_extra_call_of_planned_tool_blocked():
    # one send_money is planned; a second (injected) finds no unused step
    fw = Firewall().set_plan(["send_money"])
    pay = fw.guard(lambda **k: "ok", name="send_money")
    assert pay(recipient="GB123", amount=10) == "ok"
    with pytest.raises(BlockedAction):
        pay(recipient="US133", amount=999)     # the injected extra payment


def test_pinned_recipient_blocks_swap():
    # plan pins the recipient; an injection that swaps it is off-plan
    fw = Firewall().set_plan([{"tool": "send_money", "recipient": "GB29NWBK"}])
    pay = fw.guard(lambda recipient, amount=0: "ok", name="send_money")
    with pytest.raises(BlockedAction):
        pay(recipient="US133000", amount=999)


def test_pinned_recipient_allows_match():
    fw = Firewall().set_plan([{"tool": "send_money", "recipient": "GB29NWBK"}])
    pay = fw.guard(lambda recipient, amount=0: "ok", name="send_money")
    assert pay(recipient="GB29NWBK", amount=50) == "ok"


def test_plan_consumes_steps_in_order():
    p = Plan(["a", "a"])
    assert p.allows(A("a")) and p.allows(A("a")) and not p.allows(A("a"))


def test_hard_rule_still_blocks_even_if_planned():
    # planning 'rm -rf' does not authorize it — destructive rules are a floor
    fw = Firewall().set_plan(["run_command"])
    run = fw.guard(lambda command: "ran", name="run_command")
    with pytest.raises(BlockedAction):
        run("rm -rf /")


def test_clear_plan_restores_default():
    fw = Firewall().set_plan(["read_file"])
    fw.set_plan(None)
    ok = fw.guard(lambda **k: "ok", name="send_money")
    assert ok(recipient="anyone") == "ok"     # no plan, no judge -> allowed
