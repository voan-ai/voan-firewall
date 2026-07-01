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

    def __init__(self, goal="", block=True, verify=None):
        self.goal = str(goal or "").lower()
        self.block = block
        # Optional goal-authorized verifier: llm(system,user)->str. When set, an
        # ungrounded recipient is ALLOWED only if the verifier confirms the goal
        # intends it (sound, model-scaling); without it, the deterministic blocklist
        # (flag recipients seen in untrusted output) is used.
        self.verify = verify
        self.untrusted = set()          # tokens seen leaving untrusted source tools
        self.context = []               # raw untrusted outputs, for the verifier

    def set_goal(self, goal):
        self.goal = str(goal or "").lower()
        self.untrusted = set()
        self.context = []
        return self

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
        """First DESTINATION/RECIPIENT arg the user didn't name and that isn't
        authorized. With a verifier: any ungrounded recipient must be confirmed
        goal-intended (sound allowlist). Without: flag a recipient whose value came
        from untrusted tool output (deterministic blocklist)."""
        if not isinstance(args, dict):
            return None
        for k, v in args.items():
            if not any(t in str(k).lower() for t in _TARGET_KEYS):
                continue
            tokens = self._tokens(v)
            ungrounded = {t for t in tokens if t not in self.goal}
            if not ungrounded:
                continue                                  # recipient named in goal
            if self.verify is not None:
                from .authorize import goal_authorized    # sound, model-scaling
                if not goal_authorized(self.goal, v, "\n".join(self.context), self.verify):
                    return str(v)
            else:
                hit = ungrounded & self.untrusted         # data-derived recipient
                if hit:
                    return next(iter(hit))
        return None

    def wrap(self, fn, name, desc="", source=None, sink=None):
        src = self.is_source(name, desc) if source is None else source
        snk = is_side_effect(name) if sink is None else sink

        def wrapped(*a, **k):
            args = k if k else ({"input": a[0]} if len(a) == 1 else
                                {f"a{i}": x for i, x in enumerate(a)})
            if snk:
                bad = self.violation(args)
                if bad:
                    msg = (f"\U0001f6d1 Voan blocked {name}: it carries '{bad}', a value "
                           f"that came from tool data, not the user's request "
                           f"(possible injected exfiltration). Do not retry; ask the user.")
                    if self.block:
                        return msg
            result = fn(*a, **k)
            if src:
                self.observe(result)
            return result

        wrapped.__name__ = getattr(fn, "__name__", str(name))
        return wrapped


def guard_langchain_auto(tools, goal="", sources=None, sinks=None, verify=None):
    """Auto-instrument a list of LangChain tools. Voan classifies each tool and
    shares one provenance tracker across them, so an injected value read by one tool
    is blocked when another tool tries to send it out — no manual wiring. `sources`
    / `sinks` (sets of tool names) override the heuristic. Pass `verify=llm` for the
    sound, model-scaling goal-authorized mode (an ungrounded recipient must be
    confirmed goal-intended). Returns (tools, guard)."""
    g = AutoGuard(goal, verify=verify)
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "tool")
        desc = getattr(t, "description", "") or ""
        src = None if not sources else (name in sources)
        snk = None if not sinks else (name in sinks)
        if getattr(t, "func", None) and callable(t.func):
            t.func = g.wrap(t.func, name, desc, src, snk)
        elif getattr(t, "coroutine", None):
            t.coroutine = g.wrap(t.coroutine, name, desc, src, snk)
    return tools, g
