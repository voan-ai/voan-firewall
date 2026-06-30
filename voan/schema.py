"""Core types for the Voan Firewall runtime.

An Action is one attempted tool call (the agent is *about* to do something).
A Verdict is the policy engine's ruling on that action. BlockedAction is raised
in the agent's own process when an action is denied — the firewall sits inline,
so a blocked call never reaches the real tool.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
import time


class Decision(str, Enum):
    ALLOW = "allow"   # safe — run the real tool
    ASK = "ask"       # needs a human (or callback) to approve
    BLOCK = "block"   # dangerous — never reaches the tool


# Severity mirrors the Voan scanner taxonomy so findings line up across the
# pre-deploy scanner and the runtime firewall.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


@dataclass
class Action:
    """One intercepted tool call, captured *before* execution."""
    tool: str
    args: dict
    agent: str = "agent"
    ts: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)


@dataclass
class Session:
    """Per-conversation context the LLM judge needs: the user's original goal and
    a rolling trace of (untrusted) tool outputs seen so far. A poisoned tool
    output landing here is exactly how a later action gets hijacked."""
    goal: str = ""
    trace: list = field(default_factory=list)

    def add_output(self, tool, result):
        self.trace.append(f"{tool} -> {str(result)[:200]}")


@dataclass
class Verdict:
    """The policy engine's ruling on an Action."""
    decision: Decision
    rule: str = "default-allow"
    code: str = ""          # OWASP-Agentic-style category code (e.g. RCE, AEX)
    severity: str = "Low"
    reason: str = "no rule matched"

    @property
    def allowed(self):
        return self.decision == Decision.ALLOW

    def to_dict(self):
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


class BlockedAction(Exception):
    """Raised inside the agent process when the firewall denies an action.

    The agent sees this as a tool error — exactly the behaviour you want: the
    dangerous side effect never happens, and the agent can react to the refusal.
    """

    def __init__(self, action: Action, verdict: Verdict, denied_by_user=False):
        self.action = action
        self.verdict = verdict
        self.denied_by_user = denied_by_user
        who = "user" if denied_by_user else f"rule {verdict.rule}"
        super().__init__(
            f"\U0001f6d1 Voan blocked {action.tool}() — {verdict.reason} "
            f"[{verdict.severity}, {who}]")
