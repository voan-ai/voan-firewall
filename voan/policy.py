"""The policy engine — the firewall's brain.

Given an Action, it returns a Verdict. First matching rule wins; if nothing
matches the action is allowed (default-allow, like a default-permit firewall —
flip `default` to BLOCK for a deny-by-default posture). Rules are ordered, so
put the most dangerous/most specific signatures first in rules.py.
"""
from .rules import DEFAULT_RULES, Rule
from .schema import Action, Decision, Verdict


class PolicyEngine:
    def __init__(self, rules=None, default=Decision.ALLOW):
        # Copy so callers can mutate their engine without touching the defaults.
        self.rules = list(rules if rules is not None else DEFAULT_RULES)
        self.default = default

    def add_rule(self, rule: Rule, front=True):
        """Register a custom rule. Front-loaded by default so user policy can
        override a built-in signature."""
        self.rules.insert(0, rule) if front else self.rules.append(rule)
        return self

    def evaluate(self, action: Action) -> Verdict:
        for rule in self.rules:
            if rule.matches(action):
                return Verdict(decision=rule.decision, rule=rule.id,
                               code=rule.code, severity=rule.severity,
                               reason=rule.reason)
        return Verdict(decision=self.default, rule="default",
                       reason="no rule matched")
