"""The in-process hook — the sensor that sits inline on every tool call.

`guard()` wraps a tool function (or a dict/list of them). The wrapper captures
the call, asks the PolicyEngine for a Verdict, records it, and then:
  ALLOW -> runs the real tool
  ASK   -> calls on_ask(action, verdict); runs only if it returns True
  BLOCK -> raises BlockedAction; the real tool never runs
In `monitor` mode nothing is ever blocked — every decision is still logged, so
you can shadow-deploy and measure before you start enforcing.
"""
import functools
import inspect

from .audit import AuditLog
from .policy import PolicyEngine
from .rules import egress_violation
from .schema import Action, BlockedAction, Decision, Session, Verdict


class Firewall:
    def __init__(self, policy=None, audit=None, agent="agent",
                 on_ask=None, mode="enforce", judge=None, egress_allowlist=None,
                 judge_fail_closed=False):
        self.policy = policy or PolicyEngine()
        self.audit = audit if audit is not None else AuditLog()
        self.agent = agent
        self.on_ask = on_ask          # callable(action, verdict) -> bool
        self.mode = mode              # "enforce" | "monitor"
        self.judge = judge            # optional LLMJudge — the intent/hijack tier
        # If the judge backend errors/times out it normally fails OPEN (the rule
        # verdict stands). Set this to BLOCK instead — don't let a flaky security
        # tier silently wave actions through.
        self.judge_fail_closed = judge_fail_closed
        # Opt-in egress allowlist: block any action whose args reference a domain
        # not on this list (catches look-alike destinations the judge can't).
        self.egress_allowlist = egress_allowlist
        self.session = Session()

    def set_goal(self, goal):
        """Tell the firewall what the user actually asked for, so the LLM judge
        can spot actions that drift from it (hijacks). Resets the trace."""
        self.session = Session(goal=goal)
        return self

    def check(self, tool, args) -> Verdict:
        """Evaluate without running anything — handy for tests and dry runs."""
        return self.policy.evaluate(Action(tool=tool, args=args,
                                           agent=self.agent))

    def guard(self, fn=None, *, name=None):
        """Wrap one callable. Usable directly or as a decorator (@fw.guard)."""
        if fn is None:
            return lambda f: self.guard(f, name=name)
        tool = name or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            action = Action(tool=tool, args=self._bind(fn, args, kwargs),
                            agent=self.agent)
            verdict = self._egress(action, self.policy.evaluate(action))
            verdict = self._judge(action, verdict)
            self.audit.record(action, verdict)
            self._gate(action, verdict)
            result = fn(*args, **kwargs)
            self.session.add_output(tool, result)   # feeds the judge's context
            return result

        wrapped.__voan_guarded__ = True
        return wrapped

    def _egress(self, action, verdict):
        """Deterministic destination check: block egress to any domain not on the
        allowlist (catches look-alike destinations the goal-based judge can't)."""
        if not self.egress_allowlist or verdict.decision == Decision.BLOCK:
            return verdict
        bad = egress_violation(action.args, self.egress_allowlist)
        if bad:
            return Verdict(Decision.BLOCK, rule="egress-allowlist", code="AEX",
                           severity="High",
                           reason=f"egress to non-allowlisted destination '{bad}'")
        return verdict

    def _judge(self, action, verdict):
        """Second tier: the LLM judge may ESCALATE a rule verdict to BLOCK when an
        action drifts from the user's goal, but never loosens it."""
        if self.judge is None or verdict.decision == Decision.BLOCK:
            return verdict
        jv = self.judge.evaluate(self.session.goal, action, self.session.trace)
        if jv is None and self.judge_fail_closed and self.session.goal \
                and getattr(self.judge, "available", False):
            # judge was supposed to run but the backend failed -> don't fail open
            return Verdict(Decision.BLOCK, rule="judge-fail-closed", code="AID",
                           severity="High",
                           reason="judge backend unavailable; failing closed")
        return jv if jv and jv.decision == Decision.BLOCK else verdict

    def guard_tools(self, tools):
        """Guard a dict {name: fn} or a list of fns; returns the same shape."""
        if isinstance(tools, dict):
            return {n: self.guard(f, name=n) for n, f in tools.items()}
        return [self.guard(f) for f in tools]

    # -- internals -----------------------------------------------------------
    def _gate(self, action, verdict):
        if self.mode == "monitor":
            return
        if verdict.decision == Decision.BLOCK:
            raise BlockedAction(action, verdict)
        if verdict.decision == Decision.ASK:
            approved = self.on_ask(action, verdict) if self.on_ask else False
            if not approved:
                raise BlockedAction(action, verdict, denied_by_user=True)

    @staticmethod
    def _bind(fn, args, kwargs):
        try:
            sig = inspect.signature(fn)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            return {k: _safe(v) for k, v in bound.arguments.items()}
        except (TypeError, ValueError):
            return {"args": _safe(args), "kwargs": _safe(kwargs)}


def _safe(v):
    """Make arbitrary call arguments JSON-serializable for logging/matching."""
    try:
        import json
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return repr(v)


def guard(target, **kwargs):
    """One-call convenience: wrap a function, dict, or list with a fresh
    Firewall. `import voan; tools = voan.guard(tools)` and you're protected.
    Pass policy=/on_ask=/mode= to customize."""
    fw = Firewall(**{k: kwargs.pop(k) for k in
                     ("policy", "audit", "agent", "on_ask", "mode", "judge")
                     if k in kwargs})
    if isinstance(target, (dict, list)):
        return fw.guard_tools(target)
    return fw.guard(target)
