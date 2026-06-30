"""PolicyEngine: first-match-wins, default posture, custom-rule precedence."""
from voan.policy import PolicyEngine
from voan.rules import Rule
from voan.schema import Action, Decision


def A(tool, **args):
    return Action(tool=tool, args=args, agent="t")


def test_default_allow_when_no_rule_matches():
    assert PolicyEngine().evaluate(A("get_weather", city="X")).decision == Decision.ALLOW


def test_default_can_be_deny():
    p = PolicyEngine(rules=[], default=Decision.BLOCK)
    assert p.evaluate(A("anything")).decision == Decision.BLOCK


def test_add_rule_front_overrides_builtin():
    p = PolicyEngine()
    p.add_rule(Rule("ALLOW_RM", Decision.ALLOW, "X", "Low", "explicitly allowed",
                    tools={"run_command"}, pattern=r"rm -rf /"))
    v = p.evaluate(A("run_command", command="rm -rf /"))
    assert v.decision == Decision.ALLOW and v.rule == "ALLOW_RM"


def test_add_rule_back_does_not_override():
    p = PolicyEngine()
    p.add_rule(Rule("LATE", Decision.ALLOW, "X", "Low", "too late",
                    tools={"run_command"}, pattern=r"rm -rf /"), front=False)
    assert p.evaluate(A("run_command", command="rm -rf /")).decision == Decision.BLOCK


def test_rules_are_copied_not_shared():
    base = PolicyEngine()
    n = len(base.rules)
    other = PolicyEngine()
    other.add_rule(Rule("X", Decision.ALLOW, "X", "Low", "x"))
    assert len(base.rules) == n  # mutating `other` did not touch defaults
