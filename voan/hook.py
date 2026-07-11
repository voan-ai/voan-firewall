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
                 judge_fail_closed=False, taint=False, rule_of_two=None, flow=None,
                 plan_judge_fallback=False):
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
        # By default an off-plan action stays HARD-BLOCKED — the plan's guarantee is
        # deterministic and adaptive-attack-proof for the committed tool multiset and any
        # PINNED args (an un-pinned arg of a planned tool can still be swapped by an
        # injection, so pin security-relevant args like recipient/amount). Set True to let a configured judge
        # backstop an *incomplete* plan (it may re-allow an off-plan action it deems
        # on-goal); that trades the hard guarantee for flexibility, so it's opt-in.
        self.plan_judge_fallback = plan_judge_fallback
        self.session = Session()
        self.plan = None              # optional plan-then-execute allowlist
        # Optional taint tracking: flag side-effect targets that came from
        # (untrusted) tool output rather than the user's goal — provenance.
        from .taint import TaintTracker
        self.taint = TaintTracker() if taint else None
        # Optional Agents Rule of Two: gate an external side effect once a session
        # has already touched untrusted input AND sensitive data.
        if rule_of_two:
            from .rule_of_two import RuleOfTwo
            self.r2 = RuleOfTwo(rule_of_two if isinstance(rule_of_two, dict) else None)
        else:
            self.r2 = None
        # Optional information-flow monitor: confidential-read data must not leave
        # via an external sink (FIDES-style confidentiality). `flow` = tool names.
        if flow:
            from .flow import FlowMonitor
            self.flow = FlowMonitor(flow)
        else:
            self.flow = None

    def set_goal(self, goal):
        """Tell the firewall what the user actually asked for, so the LLM judge
        can spot actions that drift from it (hijacks). Resets the trace/taint."""
        self.session = Session(goal=goal)
        if self.taint is not None:
            self.taint.reset()
        if self.r2 is not None:
            self.r2.reset()
        if self.flow is not None:
            self.flow.reset()
        return self

    def set_plan(self, steps):
        """Commit the list of actions the agent INTENDS to take, BEFORE it reads
        any untrusted data. Voan then allows only these (each consumed once) and
        blocks anything an injection tries to add or alter. A step is a tool name,
        or {"tool": ..., "recipient": ...} to pin an argument. Plan mode takes the
        place of the judge for as long as a plan is set; call set_plan(None) to
        clear it. See voan/plan.py."""
        from .plan import Plan
        self.plan = Plan(steps) if steps is not None else None
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
            base = self._flow(action, self._rule_of_two(action,
                self._taint(action, self._egress(action, self.policy.evaluate(action)))))
            if self.plan is not None:
                # Plan-then-execute: planned actions run; an off-plan action is
                # HARD-BLOCKED by default (the plan's deterministic guarantee stands).
                # Only if plan_judge_fallback is explicitly enabled does a configured
                # judge get to backstop an incomplete plan by re-judging the action.
                verdict = self._plan(action, base)
                if verdict.rule == "off-plan" and self.judge is not None \
                        and self.plan_judge_fallback:
                    verdict = self._judge(action, base)
            else:
                verdict = self._judge(action, base)
            self.audit.record(action, verdict)
            self._gate(action, verdict)
            result = fn(*args, **kwargs)
            self.session.add_output(tool, result)   # feeds the judge's context
            if self.taint is not None:
                self.taint.observe(result)           # untrusted-data provenance
            if self.flow is not None:
                self.flow.observe(tool, result)      # confidential-data provenance
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

    def _flow(self, action, verdict):
        """Information-flow tier: hold (ASK) an external side effect that carries a
        value read from a declared confidential source — data leaving, whatever the
        destination (FIDES-style confidentiality)."""
        if self.flow is None or verdict.decision == Decision.BLOCK:
            return verdict
        leak = self.flow.leaks(action)
        if leak:
            return Verdict(Decision.ASK, rule="info-flow", code="AEX", severity="High",
                           reason=f"action carries confidential data '{leak}' out")
        return verdict

    def _rule_of_two(self, action, verdict):
        """Agents Rule of Two: fold the action's capabilities into the session and,
        if it is an EXTERNAL side effect while the session already holds UNTRUSTED
        and SENSITIVE, hold it for a human (ASK) — all three is the exfil path."""
        if self.r2 is None or verdict.decision == Decision.BLOCK:
            return verdict
        violated = self.r2.violates(action)
        self.r2.observe(action)
        if violated:
            return Verdict(Decision.ASK, rule="rule-of-two", code="AGT", severity="High",
                           reason="untrusted + sensitive + external in one session; confirm")
        return verdict

    def _taint(self, action, verdict):
        """Provenance tier: escalate to ASK when a side-effect targets a value that
        came from (untrusted) tool output and was NOT named in the user goal — its
        provenance is untrusted (possibly injected), so hold it for a human."""
        if self.taint is None or verdict.decision == Decision.BLOCK:
            return verdict
        bad = self.taint.bad_target(action, self.session.goal)
        if bad:
            return Verdict(Decision.ASK, rule="taint", code="AEX", severity="High",
                           reason=f"target '{bad}' came from tool data, not your request")
        return verdict

    def _plan(self, action, verdict):
        """Plan-then-execute tier: an action is allowed only if it was in the
        committed plan (and consumes that step). Anything an injection added or
        altered is off-plan and blocked. Hard rule BLOCKs still stand as a floor."""
        if verdict.decision == Decision.BLOCK:
            return verdict
        if self.plan.allows(action):
            return verdict
        return Verdict(Decision.BLOCK, rule="off-plan", code="AGT", severity="High",
                       reason="action was not in the committed plan")

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

    Every ``Firewall(...)`` option is forwarded verbatim — ``policy=``, ``on_ask=``,
    ``mode=``, ``judge=``, ``judge_fail_closed=``, ``egress_allowlist=``, ``taint=``,
    ``rule_of_two=``, ``flow=``, ``plan_judge_fallback=``. An **unknown** option
    raises ``TypeError`` (from ``Firewall.__init__``) rather than being silently
    dropped — a mis-wired control fails loudly instead of protecting nothing."""
    fw = Firewall(**kwargs)
    if isinstance(target, (dict, list)):
        return fw.guard_tools(target)
    return fw.guard(target)
