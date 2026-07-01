"""derive_plan: turn a goal + tool list into a plan-then-execute plan (stub LLM)."""
from voan import Firewall, derive_plan
from voan.schema import BlockedAction
import pytest


def stub(reply):
    return lambda system, user: reply


TOOLS = ["read_file", "send_money", "get_balance"]


def test_derives_steps_and_filters_unknown_tools():
    llm = stub('[{"tool":"read_file"},{"tool":"send_money","recipient":"GB29"},'
               '{"tool":"launch_missiles"}]')     # last one isn't an available tool
    plan = derive_plan("Pay my bill from bill.txt", TOOLS, llm)
    tools = [s["tool"] if isinstance(s, dict) else s for s in plan]
    assert tools == ["read_file", "send_money"]    # unknown tool dropped


def test_plan_drives_the_firewall():
    llm = stub('[{"tool":"read_file"},{"tool":"send_money","recipient":"GB29"}]')
    plan = derive_plan("Pay bill.txt to GB29", TOOLS, llm)
    fw = Firewall().set_plan(plan)
    read = fw.guard(lambda file_path: "bill", name="read_file")
    pay = fw.guard(lambda recipient, amount=0: "paid", name="send_money")
    assert read(file_path="bill.txt") == "bill"
    assert pay(recipient="GB29", amount=10) == "paid"       # matches pinned recipient
    with pytest.raises(BlockedAction):
        pay(recipient="US133", amount=999)                  # injected swap -> off-plan


def test_unparseable_reply_returns_empty():
    assert derive_plan("goal", TOOLS, stub("sorry, no idea")) == []
