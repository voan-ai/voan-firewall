"""Information-flow monitor — the confidentiality half of FIDES-style labels.

The 2026 deterministic class (FIDES, CaMeL) tracks data provenance with
confidentiality + integrity labels. Voan's `taint` covers INTEGRITY (a side effect
whose *target* came from untrusted data). This covers CONFIDENTIALITY the other
way: data that came from a SENSITIVE read must not leave through an external sink,
whatever the destination. Declare the tools that return confidential data; the
monitor records the values they returned and flags any external side effect whose
arguments carry one of those values — deterministic data-exfiltration detection,
finer than the session-level Rule of Two (it checks the actual payload, not just
capability counts) and broader than the credential regex (any confidential value,
not only key-shaped strings).

Full per-value flow tracking needs a capability interpreter around the agent
(CaMeL); this is the pragmatic drop-in approximation and is opt-in.
"""
import json
import re

from .taint import is_side_effect

_TOKEN = re.compile(r"[A-Za-z0-9@._+\-]{4,}")
_STOP = {"true", "false", "null", "none", "http", "https", "message", "status",
         "amount", "date", "name", "type", "value", "sent", "from", "with", "this"}


def _tokens(output):
    text = output if isinstance(output, str) else json.dumps(output, default=str)
    return {t.lower() for t in _TOKEN.findall(text) if t.lower() not in _STOP}


class FlowMonitor:
    def __init__(self, confidential_tools=()):
        # tools whose OUTPUT is confidential (balances, PII, secrets, private docs)
        self.conf_tools = set(confidential_tools)
        self.secrets = set()

    def reset(self):
        self.secrets = set()
        return self

    def observe(self, tool, output):
        if tool in self.conf_tools:
            self.secrets |= _tokens(output)

    def leaks(self, action):
        """Return the first confidential value carried by an external side effect's
        arguments, else None. Reads never leak (they don't send anything out)."""
        if not is_side_effect(action.tool) or not self.secrets:
            return None
        blob = json.dumps(action.args if isinstance(action.args, dict) else {},
                          default=str).lower()
        for tok in _tokens(blob):
            if tok in self.secrets:
                return tok
        return None
