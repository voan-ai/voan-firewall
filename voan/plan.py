"""Plan-then-execute — the architectural tier that beats in-domain hijacks.

The judge asks "is this action consistent with the goal?" — which it cannot answer
for an in-domain action (a send_money that pays a bill vs. one that pays an
attacker look identical without provenance). Plan-then-execute sidesteps that: the
agent commits the list of actions it INTENDS to take *before* it reads any
untrusted data, and Voan then allows ONLY those actions. An instruction injected
into a tool result cannot add a new action, or change the target of a planned one,
because the plan was fixed before the poison was ever seen. (Pattern from "Design
Patterns for Securing LLM Agents against Prompt Injections", Beurer-Kellner 2025.)

A Plan is a multiset of PlanSteps consumed as the agent runs. A step is
(tool, pins): `pins` are argument values that MUST match (pin the recipient of a
payment and an injected recipient-swap is rejected); an empty `pins` matches any
args for that tool. First unused matching step wins and is consumed, so N planned
calls authorize exactly N executions — an injected extra call finds no step and is
blocked.
"""


class PlanStep:
    __slots__ = ("tool", "pins", "used")

    def __init__(self, tool, pins=None):
        self.tool = tool
        self.pins = pins or {}
        self.used = False

    def matches(self, action):
        if self.used or self.tool != action.tool:
            return False
        args = action.args if isinstance(action.args, dict) else {}
        return all(_eq(args.get(k), v) for k, v in self.pins.items())


class Plan:
    """An ordered list of intended steps, consumed one per matching action."""

    def __init__(self, steps):
        self.steps = [_step(s) for s in steps]

    def allows(self, action):
        """True (and consume the step) if `action` was planned; else False."""
        for s in self.steps:
            if s.matches(action):
                s.used = True
                return True
        return False

    def reset(self):
        for s in self.steps:
            s.used = False
        return self


def _step(s):
    if isinstance(s, PlanStep):
        return s
    if isinstance(s, str):
        return PlanStep(s)
    if isinstance(s, dict):
        # {"tool": "send_money", "pins": {"recipient": "GB.."}}  or
        # {"tool": "send_money", "recipient": "GB.."}  (bare pins)
        tool = s.get("tool")
        pins = s.get("pins")
        if pins is None:
            pins = {k: v for k, v in s.items() if k != "tool"}
        return PlanStep(tool, pins)
    if isinstance(s, (list, tuple)):        # (tool, pins)
        return PlanStep(s[0], s[1] if len(s) > 1 else None)
    raise TypeError(f"cannot read plan step: {s!r}")


def _eq(a, b):
    return str(a).strip().lower() == str(b).strip().lower()
