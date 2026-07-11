"""Taint tracking — provenance-based defense for in-domain hijacks (CaMeL-lite).

The judge and target-grounding can't tell a legit in-domain send from a hijacked
one when the recipient came from *data* rather than the user's request. Taint
tracking adds the missing provenance signal: every value that first appears in a
(untrusted) TOOL OUTPUT is "data-derived" and possibly attacker-influenced (tool
results are exactly where injections live). So when a SIDE EFFECT sends/pays/posts
to a target that is data-derived but was NOT named in the user's trusted goal, that
target's provenance is untrusted — hold it for a human (ASK) or block it.

This catches the residual attack the judge misses: an attacker IBAN injected into a
tool result, then paid out — the IBAN is in the taint corpus, not in the goal, so
it is gated. It also (correctly) flags the ambiguous legit case — paying a payee the
agent read from a document — as ASK, because without a full data-flow capability
system Voan cannot prove that read was benign. A target the user named in the goal
is trusted (grounding) and is never gated by taint.

Full CaMeL tracks provenance per-value through a capability interpreter; this is a
pragmatic string-level approximation for a drop-in SDK, and is opt-in.
"""
import re

_TARGET_KEYS = ("recipient", "receiver", "payee", "beneficiary", "to", "cc", "bcc",
                "dest", "destination", "address", "account", "iban", "wallet", "email",
                "channel", "phone", "url", "webhook", "endpoint", "user", "member",
                "guest", "participant", "contact", "forward", "sender", "reply",
                "delivery")
_READ = ("get_", "read_", "list_", "search_", "find_", "retrieve", "view_", "check_",
         "fetch_", "lookup")
# Unambiguous side-effect verbs. If any appears in the tool name it is a SINK even
# when the name also looks read-ish — a "list_payout" / "budget_transfer" /
# "get_and_send" is a side effect, not a read. These are money/destructive/egress
# verbs that essentially never name a pure read tool, so matching them fail-CLOSED
# doesn't over-flag ordinary reads.
# NOTE: keep these UNAMBIGUOUS action verbs only. Read-object nouns like email /
# message / post are deliberately EXCLUDED — they also name read tools (read_email,
# get_messages), and a bare-noun match would misclassify those reads as sinks.
_SINK = ("send", "pay", "payout", "refund", "charge", "transfer", "wire",
         "withdraw", "delete", "destroy", "drop", "remove", "exec", "execute",
         "shell", "spawn", "deploy", "publish", "grant", "upload", "notify",
         "share", "invite", "write", "create", "update", "checkout", "move_",
         "dispatch")


def is_side_effect(tool):
    """Classify a tool as a side-effect (sink) vs a read (untrusted source).

    Fail-CLOSED: a sink verb in the name wins over a read-ish prefix, and only a
    name that is purely read-ish (a read PREFIX and no sink verb) is treated as a
    read. An unrecognized tool (no read prefix) is a side effect, so taint/flow
    gate it rather than trusting it — the safe default for provenance."""
    t = str(tool).lower()
    if any(s in t for s in _SINK):
        return True
    return not any(t.startswith(r) for r in _READ)


# Synthetic / opaque arg keys the guards produce when a recipient was passed
# POSITIONALLY or a tool's signature can't be introspected. A scalar under one of
# these on a SINK is a possible recipient we couldn't name — check it fail-safe.
_OPAQUE = re.compile(r"^(?:args|arg\d+|a\d+|input|kwargs)$")


def target_scalars(args, target_keys):
    """Collect the scalar arg values to check as a side-effect's destination.

    Ancestor-aware: a scalar nested under a target-keyed ancestor at ANY depth counts
    (so {"to": {"forward": x}} or {"recipient": [x]} is caught, not only a target key
    at the leaf). Walks dict/list/tuple/set/frozenset. If NO named target exists, falls
    back to scalars under an OPAQUE/positional key (args/argN/aN/input/kwargs) so a
    positional or un-introspectable recipient on a sink isn't invisible (fail-safe)."""
    named, opaque = [], []

    def walk(obj, under_target, under_opaque):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, under_target or any(t in str(k).lower() for t in target_keys),
                     under_opaque)
        elif isinstance(obj, (list, tuple, set, frozenset)):
            for v in obj:
                walk(v, under_target, under_opaque)
        elif under_target:
            named.append(obj)
        elif under_opaque:
            opaque.append(obj)

    if isinstance(args, dict):
        for k, v in args.items():
            kl = str(k).lower()
            walk(v, any(t in kl for t in target_keys), bool(_OPAQUE.match(kl)))
    # UNION, not either/or: a legitimately-named target must NOT license an unchecked
    # second destination hiding in a positional/opaque slot (notify('general', attacker)).
    return named + opaque


class TaintTracker:
    """Remembers text seen in untrusted tool outputs, and flags a side-effect
    target that came from there but not from the (trusted) user goal."""

    # Bound the corpus so a long-running agent can't grow it without limit — keep
    # a rolling window of the most recent tool outputs (injections show up in the
    # latest results, so a window is sufficient and keeps memory flat).
    MAXLEN = 1000

    def __init__(self):
        from collections import deque
        self._corpus = deque(maxlen=self.MAXLEN)

    def observe(self, output):
        """Record a tool result as untrusted data."""
        s = str(output).strip().lower()
        if s:
            self._corpus.append(s)

    def reset(self):
        self._corpus.clear()
        return self

    def _tainted(self, value):
        v = str(value).strip().lower()
        return len(v) >= 4 and any(v in c for c in self._corpus)

    def bad_target(self, action, goal):
        """Return the first data-derived, not-in-goal target of a side-effect action,
        else None. Reads and goal-named targets are never flagged. Uses target_scalars
        so a tainted recipient nested under a target key at any depth, or passed
        positionally/opaquely on a sink, is inspected — not only a top-level scalar
        under a leaf target key."""
        if not is_side_effect(action.tool):
            return None
        args = action.args if isinstance(action.args, dict) else {}
        g = str(goal or "").lower()
        for v in target_scalars(args, _TARGET_KEYS):
            if isinstance(v, (str, int, float)):
                s = str(v).strip()
                if len(s) >= 4 and s.lower() not in g and self._tainted(s):
                    return s
        # value-based fallback: a tainted, destination-looking value (email/url/handle)
        # under ANY non-content key is an injected exfil target even if the key isn't in
        # _TARGET_KEYS — don't rely on the key-name list alone (closes the novel-key tail).
        from .judge import _CONTENT_KEYS, _looks_like_destination
        from .rules import _pairs
        for k, v in _pairs(args):
            if any(c in str(k).lower() for c in _CONTENT_KEYS):
                continue
            if isinstance(v, (str, int, float)) and _looks_like_destination(v):
                s = str(v).strip()
                if len(s) >= 4 and s.lower() not in g and self._tainted(s):
                    return s
        return None
