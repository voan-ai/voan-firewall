"""Auto-instrumentation — attach provenance defense to a real agent framework with
zero manual config. The strong tiers (capability engine) need the agent to adopt a
program model; most agents are free-form LangChain/OpenAI loops. This bridges the
gap: Voan inspects the tools, classifies each one's role (untrusted SOURCE vs.
side-effect SINK) from its name/description, and tracks which values flow out of
source outputs into sink arguments — blocking a sink argument that carries untrusted
data the user never named. It is the automatic, framework-wired version of taint
provenance: the developer just wraps their tools, Voan configures itself.

Honest limits (the reason this is a bet, not a guarantee): classification is a
heuristic (override with `sources=`/`sinks=`), and value tracking is string-level,
so an LLM that paraphrases a leaked value can slip past. It catches the common,
literal injection→exfil pattern automatically; it is not the provable capability
engine.
"""
import json
import re

from .taint import is_side_effect

_SOURCE_HINTS = ("read", "fetch", "search", "list", "email", "web", "file", "inbox",
                 "message", "review", "lookup", "load", "browse", "get", "retrieve",
                 "scrape", "content", "doc", "page", "mail", "calendar", "note")
# Tools whose OUTPUT is sensitive (for the Rule-of-Two capability check below).
_SENSITIVE_HINTS = ("balance", "transaction", "account", "payment", "secret",
                    "password", "private", "salary", "ssn", "card", "health",
                    "scheduled", "statement", "credential", "iban", "contact")
# Args that name WHERE a side effect goes. Only these are checked — a legit agent
# constantly puts read data in a body/subject; the hijack signal is untrusted data
# in the RECIPIENT/DESTINATION, not in the payload. (Checking every arg over-blocks
# ~77% of legit actions; checking only the target is the usable design.)
_TARGET_KEYS = ("recipient", "receiver", "payee", "to", "dest", "destination",
                "address", "account", "iban", "email", "channel", "url", "user",
                "member", "guest", "participant", "contact")
_TOKEN = re.compile(r"[A-Za-z0-9@._+\-]{4,}")
_STOP = {"true", "false", "null", "none", "http", "https", "status", "amount",
         "true.", "this", "that", "with", "from", "your", "please", "order",
         "message", "email", "name", "date", "type", "value", "text", "data"}


class AutoGuard:
    """Shared provenance state across a wrapped tool set."""

    def __init__(self, goal="", block=True, verify=None, strict=False):
        self.goal = str(goal or "").lower()
        self.block = block
        # strict=True holds ANY recipient not named in the goal (conservative — more
        # false holds). Default (False) is provenance-gated: hold only a recipient that
        # actually arrived via untrusted tool output — the real injection vector — so a
        # hardcoded or user-context recipient is not held. Sound within the
        # tool-output-injection model: every non-sink tool is treated as a source, so
        # `untrusted` is fully populated and an injected address is always tainted.
        self.strict = strict
        # Optional goal-authorized verifier: llm(system,user)->str. When set, an
        # ungrounded recipient is ALLOWED only if the verifier confirms the goal
        # intends it (sound, model-scaling); without it, the deterministic blocklist
        # (flag recipients seen in untrusted output) is used.
        self.verify = verify
        self.untrusted = set()          # tokens seen leaving untrusted source tools
        self.context = []               # raw untrusted outputs, for the verifier
        self.caps = set()               # Rule-of-Two session capabilities

    def set_goal(self, goal):
        self.goal = str(goal or "").lower()
        self.untrusted = set()
        self.context = []
        self.caps = set()
        return self

    def _rule_of_two(self, name, args):
        """A side effect with no user-named target, taken once the session already
        holds untrusted input AND sensitive data, is the exfil path — held. Catches
        post/share/add attacks that carry no recipient for the grounding check."""
        has_target = isinstance(args, dict) and any(
            any(t in str(k).lower() for t in _TARGET_KEYS) for k in args)
        return (not has_target) and {"untrusted", "sensitive"} <= self.caps

    def _tokens(self, text):
        s = text if isinstance(text, str) else json.dumps(text, default=str)
        return {t.lower() for t in _TOKEN.findall(s) if t.lower() not in _STOP and len(t) >= 4}

    def is_source(self, name, desc=""):
        # Any tool that is not a side-effect returns data the agent reads — and tool
        # output is exactly where injections live, so treat it as an untrusted
        # source. (Hints are a fallback for oddly-named tools.)
        if not is_side_effect(name):
            return True
        t = (str(name) + " " + str(desc)).lower()
        return any(h in t for h in _SOURCE_HINTS)

    def observe(self, output):
        self.untrusted |= self._tokens(output)
        self.context.append(str(output)[:600])

    def violation(self, args):
        """A DESTINATION/RECIPIENT the user did not name in the goal is gated —
        MECHANICALLY, with no model in the decision (unevadable): an injection can't
        put the attacker's account into the user's own request. A recipient the user
        named is allowed. By default the gate is also PROVENANCE-scoped: a recipient is
        held only if it actually arrived via untrusted tool output (the injection
        vector), so a hardcoded/user-context address is not falsely held; set
        strict=True to hold every un-named recipient regardless of provenance. The
        optional `verify` LLM can only DOWNGRADE a gate to allow (fewer human asks); it
        never gates by itself, so soundness is always the deterministic rule."""
        if not isinstance(args, dict):
            return None
        for k, v in args.items():
            if not any(t in str(k).lower() for t in _TARGET_KEYS):
                continue
            # Dangerous only if the user didn't name it AND (default) it actually came
            # from untrusted tool output. strict=True ignores provenance.
            ungrounded = {t for t in self._tokens(v)
                          if t not in self.goal and (self.strict or t in self.untrusted)}
            if not ungrounded:
                continue                                  # named, or not tool-derived -> allow
            if self.verify is not None:
                from .authorize import goal_authorized  # optional: fewer human asks
                if goal_authorized(self.goal, v, "\n".join(self.context), self.verify):
                    continue
            return str(v)                                 # not user-authorized -> hold
        return None

    def wrap(self, fn, name, desc="", source=None, sink=None, trusted=False):
        src = self.is_source(name, desc) if source is None else source
        snk = is_side_effect(name) if sink is None else sink
        sensitive = any(h in (str(name) + " " + str(desc)).lower() for h in _SENSITIVE_HINTS)
        # A trusted source's output is declared safe (e.g. your own order DB), so it
        # does NOT taint: a recipient pulled from it won't be held. This is the sound,
        # literature-endorsed way to authorize data-derived destinations — DECLARED
        # trust, not inferred (an untrusted source can hide the attacker's address in
        # exactly the field a legitimate one would use).

        def wrapped(*a, **k):
            args = k if k else ({"input": a[0]} if len(a) == 1 else
                                {f"a{i}": x for i, x in enumerate(a)})
            if snk:
                bad = self.violation(args)                    # ungrounded recipient
                reason = (f"the destination '{bad}' is not one the user named" if bad
                          else ("this action can send data out, and the session has "
                                "already read untrusted content and sensitive data"
                                if self._rule_of_two(name, args) else None))
                if reason and self.block:
                    return (f"\U0001f6d1 Voan held {name}: {reason}, so it can't be "
                            f"authorized automatically (possible injected action). "
                            f"Ask the user to confirm before proceeding.")
            result = fn(*a, **k)
            if src and not trusted:
                self.observe(result)
                self.caps.add("untrusted")
                if sensitive:
                    self.caps.add("sensitive")
            if snk:
                self.caps.add("external")
            return result

        wrapped.__name__ = getattr(fn, "__name__", str(name))
        wrapped._voan_original = fn      # so re-guarding replaces rather than stacks
        return wrapped


def capability_agent(goal, tools, llm, sink_class=None, sources=None):
    """One call for the full, PROVABLE CaMeL loop — no hand-written program. Voan
    derives the capability program from the trusted goal (the privileged planner),
    auto-classifies each tool (reads = untrusted sources, side effects = external
    sinks), and runs the program through the capability interpreter, which threads a
    capability onto every value and refuses to let an untrusted one steer a sink.
    `tools` = {name: fn}, `llm(system,user)->str`. Returns the interpreter env
    (var -> Capsule); raises voan.Denied if the program violates an invariant.

    This is the provable end of the spectrum: unlike the mechanical grounding guard
    (which holds an ungrounded recipient for a human), here nothing untrusted can
    reach a sink at all — for values that flow through the program."""
    from .capability import CapabilityEngine
    from .planner import derive_capability_program
    names = list(tools)
    sinks = {n for n in names if is_side_effect(n)}
    sc = sink_class if sink_class is not None else {n: "external" for n in sinks}
    srcs = sources if sources is not None else {n for n in names if n not in sinks}
    program = derive_capability_program(goal, names, llm)
    return CapabilityEngine(sink_class=sc).run(program, tools, sources=srcs)


def guard_langchain_auto(tools, goal="", sources=None, sinks=None, verify=None,
                         strict=False, trusted=None):
    """Auto-instrument a list of tools. Voan classifies each tool and shares one
    provenance tracker across them, so an injected value read by one tool is blocked
    when another tool tries to send it out — no manual wiring. Accepts LangChain tools
    (StructuredTool / BaseTool exposing `.func`/`.coroutine`) AND plain callables.
    `sources` / `sinks` (sets of tool names) override the heuristic. `trusted` (set of
    tool names) declares data sources whose output is safe — a recipient pulled from a
    trusted source is not held (the sound way to authorize data-derived destinations:
    declared trust, not inference). Pass `verify=llm` for the model-scaling
    goal-authorized mode. Returns (tools, guard).

    Fails loud: a tool Voan cannot instrument raises TypeError instead of being passed
    through unprotected — a silent no-op is the worst failure mode for a firewall (you
    think you're protected and you're not). A plain function is wrapped into a NEW
    callable, so always use the RETURNED list, not the one you passed in."""
    g = AutoGuard(goal, verify=verify, strict=strict)
    trusted = set(trusted or ())
    out = []
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "tool")
        desc = getattr(t, "description", "") or ""
        src = None if not sources else (name in sources)
        snk = None if not sinks else (name in sinks)
        tr = name in trusted
        if getattr(t, "func", None) and callable(t.func):
            base = getattr(t.func, "_voan_original", t.func)   # unwrap: re-guard replaces
            t.func = g.wrap(base, name, desc, src, snk, trusted=tr)
            out.append(t)
        elif getattr(t, "coroutine", None) and callable(t.coroutine):
            base = getattr(t.coroutine, "_voan_original", t.coroutine)
            t.coroutine = g.wrap(base, name, desc, src, snk, trusted=tr)
            out.append(t)
        elif callable(t):                       # plain function tool — wrap it directly
            base = getattr(t, "_voan_original", t)
            out.append(g.wrap(base, name, desc, src, snk, trusted=tr))
        else:
            raise TypeError(
                f"voan.guard_langchain_auto: tool {name!r} ({type(t).__name__}) exposes "
                f"no .func/.coroutine and is not callable, so Voan cannot instrument it "
                f"— it would run UNPROTECTED. Pass a LangChain tool or a plain function."
            )
    return out, g
