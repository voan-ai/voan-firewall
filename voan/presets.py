"""Deny-by-default presets for sensitive tool families.

The default PolicyEngine is default-ALLOW: a signature blocklist that waves
through anything it doesn't recognize. That is right for broad coverage with low
friction, but for high-stakes tool families — shell, database, payments — you may
want the opposite posture: deny anything not explicitly recognized as safe.

These presets append ONE catch-all rule per family (lowest priority), so an
UNRECOGNIZED action in that family is blocked/held, while:
  - the built-in danger signatures still fire first (same BLOCK result), and
  - YOUR OWN allow-rules, added at the front with `policy.add_rule(...)`, take
    precedence — that is how you carve out the specific safe calls you do want.

    from voan import Firewall, deny_by_default
    fw = Firewall(policy=deny_by_default(["shell", "db"]))
    # run_command("uptime") is now BLOCKED unless you add an explicit allow-rule.

Default families are **shell** and **db** — the families whose built-in rules are
SIGNATURE-only, so an unrecognized call (a benign-looking shell command, an
unsignatured query) is default-ALLOWED today. The payment / mail / http families
already hold EVERY action for approval (PAYMENT_HUMAN, EXTERNAL_SEND are ASK with
no pattern), so they are deny-ish out of the box; a catch-all there would be
shadowed by those ASK rules and is a no-op. You can still name them explicitly if
you have stripped those rules from a custom rule set.
"""
from .policy import PolicyEngine
from .rules import DB, DEFAULT_RULES, HTTP, MAIL, PAY, SHELL, Rule
from .schema import Decision

# Named tool families you can flip to deny-by-default. Same name->tools map the
# signature rules use, so renamed-tool evasions are covered identically.
FAMILIES = {"shell": SHELL, "db": DB, "payment": PAY, "mail": MAIL, "http": HTTP}

# Sensible default: the two families whose built-in rules are signature-only, so
# an unrecognized action is default-allowed today (code exec, data loss). The
# payment/mail/http families already ASK on every action (see module docstring).
DEFAULT_FAMILIES = ("shell", "db")


def deny_by_default_rules(families=DEFAULT_FAMILIES, decision=Decision.BLOCK):
    """The catch-all Rules that put each named family in a deny-by-default
    posture. Append AFTER the signature rules (they are lowest priority)."""
    out = []
    for fam in families:
        tools = FAMILIES.get(fam)
        if tools is None:
            raise ValueError(
                f"unknown tool family {fam!r}; choose from {sorted(FAMILIES)}")
        out.append(Rule(
            f"DENY_DEFAULT_{fam.upper()}", decision, "AGT", "High",
            f"deny-by-default: unrecognized {fam} action needs explicit approval",
            tools=set(tools)))
    return out


def deny_by_default(families=DEFAULT_FAMILIES, decision=Decision.BLOCK,
                    rules=None):
    """Return a PolicyEngine that DENIES unrecognized actions in the named
    sensitive families (default: shell, db) while keeping every built-in
    signature. Pass `decision=Decision.ASK` for a softer hold-for-approval
    posture, or `families=[...]` to choose which families to harden."""
    base = list(rules if rules is not None else DEFAULT_RULES)
    return PolicyEngine(rules=base + deny_by_default_rules(families, decision))
