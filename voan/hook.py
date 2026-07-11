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
import threading

from .audit import AuditLog
from .rules import egress_violation
from .schema import Action, BlockedAction, Decision, Session, Verdict


class Firewall:
    def __init__(self, policy=None, audit=None, agent="agent",
                 on_ask=None, mode="enforce", judge=None, egress_allowlist=None,
                 judge_fail_closed=False, taint=False, rule_of_two=None, flow=None,
                 plan_judge_fallback=False):
        if policy is not None:
            self.policy = policy
        else:
            # Safe-by-DEFAULT: the dangerous families shell/db (on top of money/mail/http,
            # which already ASK) are HELD for a human unless a danger signature blocks
            # first or you add an allow-rule. (`deny_by_default([...])` or the opt-in
            # `safe_default_policy()` — which HOLDS every is_side_effect() tool — go
            # further, but that blunt hold fights the smart tiers that authorize specific
            # side effects, so it isn't the default.) Provide `on_ask` to auto-approve
            # known-safe calls, or pass `policy=PolicyEngine()` for raw default-allow.
            from .presets import deny_by_default
            self.policy = deny_by_default(["shell", "db"], decision=Decision.ASK)
        self.audit = audit if audit is not None else AuditLog()
        self.agent = agent
        self.on_ask = on_ask          # callable(action, verdict) -> bool
        self.mode = mode              # "enforce" | "monitor"
        self.judge = judge            # optional LLMJudge — the intent/hijack tier
        # If the judge backend errors/times out it normally fails OPEN (the rule
        # verdict stands). Set this to BLOCK instead — don't let a flaky security
        # tier silently wave actions through.
        self.judge_fail_closed = judge_fail_closed
        if judge is not None and judge_fail_closed and not getattr(judge, "available", True):
            # A fail-closed judge with no working backend can never actually judge, so
            # every action (once a goal is set) would be blocked — fail LOUD instead of
            # giving false assurance from an opt-in flag that silently does nothing.
            raise ValueError(
                "judge_fail_closed=True but the judge has no working backend "
                "(available=False). Give it a real backend (llm=…), or drop "
                "judge_fail_closed.")
        # Opt-in egress allowlist: block any action whose args reference a domain
        # not on this list (catches look-alike destinations the judge can't).
        self.egress_allowlist = egress_allowlist
        # By default an off-plan action stays HARD-BLOCKED — the plan's guarantee is
        # deterministic and adaptive-attack-proof for the committed tool multiset and any
        # PINNED args (an un-pinned arg of a planned tool can still be swapped by an
        # injection, so pin security-relevant args like recipient/amount). Set True to
        # let a configured judge
        # backstop an *incomplete* plan (it may re-allow an off-plan action it deems
        # on-goal); that trades the hard guarantee for flexibility, so it's opt-in.
        self.plan_judge_fallback = plan_judge_fallback
        self.session = Session()
        self.plan = None              # optional plan-then-execute allowlist
        # Serializes the mutable provenance state (taint/flow/rule-of-two/plan/trace) so
        # parallel (multi-threaded) tool calls on one Firewall can't interleave a
        # read+update into a corrupt/unsound verdict. The LLM judge runs OUTSIDE it.
        self._lock = threading.Lock()
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
        if self.plan is not None:
            self.plan.reset()      # re-sync consumed-step state with the new task
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
        """Wrap one callable. Usable directly or as a decorator (@fw.guard). An async
        (coroutine) tool gets an async wrapper, so the gate runs on the REAL awaited
        result — a sync wrapper on an async tool would gate/observe a bare coroutine
        object and silently fail open on the async execution path."""
        if fn is None:
            return lambda f: self.guard(f, name=name)
        tool = name or getattr(fn, "__name__", "tool")

        if inspect.isasyncgenfunction(fn):
            # async GENERATOR (streaming) tool: iscoroutinefunction is False for these,
            # so gate on the args then observe EACH yielded chunk into provenance —
            # otherwise the poisoned stream content never seeds taint.
            @functools.wraps(fn)
            async def agwrapped(*args, **kwargs):
                action = Action(tool=tool, args=self._bind(fn, args, kwargs),
                                agent=self.agent)
                verdict = self._evaluate(action)
                self.audit.record(action, verdict)
                self._gate(action, verdict)
                async for item in fn(*args, **kwargs):
                    self._record_output(tool, item)
                    yield item
            agwrapped.__voan_guarded__ = True
            return agwrapped

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapped(*args, **kwargs):
                action = Action(tool=tool, args=self._bind(fn, args, kwargs),
                                agent=self.agent)
                verdict = self._evaluate(action)
                self.audit.record(action, verdict)
                self._gate(action, verdict)
                result = await fn(*args, **kwargs)
                self._record_output(tool, result)
                return result
            awrapped.__voan_guarded__ = True
            return awrapped

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            action = Action(tool=tool, args=self._bind(fn, args, kwargs),
                            agent=self.agent)
            verdict = self._evaluate(action)
            self.audit.record(action, verdict)
            self._gate(action, verdict)
            result = fn(*args, **kwargs)
            self._record_output(tool, result)
            return result

        wrapped.__voan_guarded__ = True
        return wrapped

    def _evaluate(self, action):
        """Run the full deterministic tier chain, then plan-or-judge, and return the
        final Verdict WITHOUT executing anything. Shared by the sync/async guards and
        by the MCP adapter so every entry point gets the same tiers."""
        with self._lock:
            base = self._flow(action, self._rule_of_two(action,
                self._taint(action, self._egress(action, self.policy.evaluate(action)))))
            goal, trace = self.session.goal, list(self.session.trace)   # snapshot
            planned = self._plan(action, base) if self.plan is not None else None
        # The LLM judge may make a NETWORK call, so it runs OUTSIDE the state lock, on the
        # trace snapshot taken above (never iterating a concurrently-mutated trace).
        if self.plan is not None:
            verdict = planned
            # Plan-then-execute: an off-plan (injected) action is HARD-BLOCKED. Only if
            # plan_judge_fallback is enabled AND a configured judge AFFIRMATIVELY clears
            # it (an explicit LLM ALLOW — not a grounding short-circuit) does it run.
            if verdict.rule == "off-plan" and self.judge is not None \
                    and self.plan_judge_fallback:
                jv = self.judge.evaluate(goal, action, trace)
                if jv is not None and jv.decision == Decision.ALLOW \
                        and jv.rule != "grounding":
                    verdict = base
            return verdict
        return self._judge(action, base, goal, trace)

    def _record_output(self, tool, result):
        """Feed a tool's (untrusted) output into the judge trace + provenance tiers,
        under the state lock so a concurrent _evaluate can't read a half-written update."""
        with self._lock:
            self.session.add_output(tool, result)
            if self.taint is not None:
                self.taint.observe(result)
            if self.flow is not None:
                self.flow.observe(tool, result)

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

    def _judge(self, action, verdict, goal=None, trace=None):
        """Second tier: the LLM judge may ESCALATE a rule verdict to BLOCK when an
        action drifts from the user's goal, but never loosens it. `goal`/`trace` are the
        snapshot taken under the state lock (so the judge reads a stable trace)."""
        if self.judge is None or verdict.decision == Decision.BLOCK:
            return verdict
        goal = self.session.goal if goal is None else goal
        trace = self.session.trace if trace is None else trace
        jv = self.judge.evaluate(goal, action, trace)
        if jv is None and self.judge_fail_closed and goal:
            # judge was supposed to run but returned no answer (error/timeout or an
            # unparseable backend response) -> don't fail open. (A dead-backend judge
            # under judge_fail_closed is rejected at construction, so this is a live
            # judge that could not decide.)
            return Verdict(Decision.BLOCK, rule="judge-fail-closed", code="AID",
                           severity="High",
                           reason="judge backend unavailable/ambiguous; failing closed")
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
            if inspect.isawaitable(approved):
                # a sync guard can't run an async confirm here; a coroutine object is
                # not an approval -> deny (fail closed). Use guard_mcp for async on_ask.
                if hasattr(approved, "close"):
                    approved.close()           # avoid a 'never awaited' RuntimeWarning
                approved = False
            if not approved:
                raise BlockedAction(action, verdict, denied_by_user=True)

    @staticmethod
    def _bind(fn, args, kwargs):
        try:
            sig = inspect.signature(fn)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            flat = {}
            for pname, val in bound.arguments.items():
                kind = sig.parameters[pname].kind
                if kind is inspect.Parameter.VAR_KEYWORD and isinstance(val, dict):
                    for k, v in val.items():          # splice **kwargs up to top level
                        flat[str(k)] = _safe(v)        # so target keys aren't nested
                elif kind is inspect.Parameter.VAR_POSITIONAL \
                        and isinstance(val, (list, tuple)):
                    for i, v in enumerate(val):        # *args -> arg0, arg1, ...
                        flat.setdefault(f"arg{i}", _safe(v))
                else:
                    flat[pname] = _safe(val)
            return flat
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
