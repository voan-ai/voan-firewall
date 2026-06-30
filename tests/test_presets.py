"""Deny-by-default presets: unrecognized actions in a family are denied, while
signatures still fire and front-loaded allow-rules win."""
import pytest

from voan import Decision, deny_by_default
from voan.presets import deny_by_default_rules
from voan.rules import Rule
from voan.schema import Action


def A(tool, **args):
    return Action(tool=tool, args=args, agent="t")


def test_unrecognized_shell_blocked():
    p = deny_by_default(["shell"])
    v = p.evaluate(A("run_command", command="systemctl restart nginx"))
    assert v.decision == Decision.BLOCK and v.rule == "DENY_DEFAULT_SHELL"


def test_unrecognized_db_blocked():
    p = deny_by_default(["db"])
    assert p.evaluate(A("execute_sql", q="SELECT 1")).decision == Decision.BLOCK


def test_signature_still_fires_first():
    p = deny_by_default(["shell"])
    assert p.evaluate(A("run_command", command="rm -rf /")).rule == "SHELL_DESTRUCTIVE"


def test_front_allow_rule_wins():
    p = deny_by_default(["shell"])
    p.add_rule(Rule("ALLOW_LS", Decision.ALLOW, "X", "Low", "ok",
                    tools={"run_command"}, pattern=r':\s*"\s*ls\b'))
    assert p.evaluate(A("run_command", command="ls -la")).decision == Decision.ALLOW


def test_non_sensitive_family_still_allowed():
    p = deny_by_default(["shell", "db"])
    assert p.evaluate(A("get_weather", city="X")).decision == Decision.ALLOW


def test_unknown_family_raises():
    with pytest.raises(ValueError):
        deny_by_default(["banana"])


def test_default_families_are_shell_and_db():
    ids = {r.id for r in deny_by_default_rules()}
    assert ids == {"DENY_DEFAULT_SHELL", "DENY_DEFAULT_DB"}


def test_ask_posture_option():
    p = deny_by_default(["shell"], decision=Decision.ASK)
    assert p.evaluate(A("run_command", command="uptime")).decision == Decision.ASK
