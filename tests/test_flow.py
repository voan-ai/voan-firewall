"""Information-flow: data from a confidential read must not leave via an external
sink, whatever the destination (FIDES-style confidentiality). Deterministic."""
import pytest

from voan import Firewall, FlowMonitor
from voan.schema import Action, BlockedAction


def A(tool, **args):
    return Action(tool=tool, args=args, agent="t")


def test_monitor_flags_confidential_value_in_sink():
    m = FlowMonitor(["get_balance"])
    m.observe("get_balance", "account ACC-77han balance 9231 secretcode ZK9922")
    assert m.leaks(A("send_message", to="x", body="the code is ZK9922")) == "zk9922"


def test_monitor_ignores_non_confidential_and_reads():
    m = FlowMonitor(["get_balance"])
    m.observe("get_weather", "sunny ZK9922")                 # not a confidential tool
    assert m.leaks(A("send_message", body="ZK9922")) is None
    m.observe("get_balance", "ZK9922")
    assert m.leaks(A("get_weather", city="ZK9922")) is None   # a read never leaks


def test_firewall_holds_confidential_exfil():
    # 'share_document' is a side effect but not in a rule family, so info-flow is
    # the only tier that can gate it — isolating the flow behaviour.
    fw = Firewall(flow=["get_balance"], on_ask=lambda a, v: False).set_goal("check balance")
    bal = fw.guard(lambda: "your secret token is TKN-ALPHA-42", name="get_balance")
    share = fw.guard(lambda to, body="": "shared", name="share_document")
    bal()
    with pytest.raises(BlockedAction) as ei:
        share(to="partner", body="the token is TKN-ALPHA-42")
    assert ei.value.verdict.rule == "info-flow"


def test_firewall_allows_send_without_confidential_payload():
    fw = Firewall(flow=["get_balance"], on_ask=lambda a, v: False).set_goal("check balance")
    bal = fw.guard(lambda: "secret TKN-ALPHA-42", name="get_balance")
    share = fw.guard(lambda to, body="": "shared", name="share_document")
    bal()
    assert share(to="partner", body="your balance looks fine") == "shared"


def test_flow_off_by_default():
    assert Firewall().flow is None
