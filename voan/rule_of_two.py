"""Agents Rule of Two — the 2026 architectural constraint, as a deterministic tier.

Meta's "Agents Rule of Two" (2026): within one session an agent should satisfy at
most TWO of these three properties —
  A. UNTRUSTED — it has ingested untrusted content (a tool result, a web page, an
     email: the surface where an injection lives);
  B. SENSITIVE — it has accessed private/sensitive data (balances, PII, secrets);
  C. EXTERNAL  — it can change state or communicate outside (send, pay, post, delete).
All three at once is exactly the exfiltration/hijack path: read a poisoned
instruction, read secret data, send it out. So when a session that has ALREADY
touched untrusted input AND sensitive data attempts an EXTERNAL side effect, hold
it for a human (ASK). This is model-independent and adaptive-attack-proof for the
capability it governs: no prompt can talk the firewall out of a capability count.

Capabilities per tool are best DECLARED (`Firewall(rule_of_two=caps)` where caps is
{tool: ["untrusted","sensitive","external"]}); a coarse name-based default is used
for any tool you don't declare.
"""
UNTRUSTED, SENSITIVE, EXTERNAL = "untrusted", "sensitive", "external"

# Coarse name-based defaults. Declaration overrides these; they only guess.
_EXT = ("send", "pay", "transfer", "post", "share", "delete", "charge", "payout",
        "write_", "create_", "update_", "schedule", "invite", "grant", "publish",
        "email", "message", "notify", "upload", "move_")
_UNTRUSTED_SRC = ("read_", "get_webpage", "fetch", "search", "browse", "web",
                  "review", "inbox", "channel", "get_emails", "get_messages",
                  "get_file", "read_file", "list_")
_SENSITIVE_SRC = ("balance", "transaction", "account", "iban", "payment", "password",
                  "secret", "key", "credential", "ssn", "card", "health", "salary",
                  "scheduled", "contact", "calendar", "private", "get_file", "read_file")


def _default_caps(tool):
    t = str(tool).lower()
    caps = set()
    if any(k in t for k in _EXT):
        caps.add(EXTERNAL)
    if any(k in t for k in _UNTRUSTED_SRC):
        caps.add(UNTRUSTED)
    if any(k in t for k in _SENSITIVE_SRC):
        caps.add(SENSITIVE)
    return caps


class RuleOfTwo:
    def __init__(self, caps=None):
        # caps: {tool: iterable of capabilities}. Missing tools fall back to
        # name-based defaults.
        self.declared = {t: set(c) for t, c in (caps or {}).items()}
        self.active = set()

    def reset(self):
        self.active = set()
        return self

    def caps_of(self, action):
        return self.declared.get(action.tool, _default_caps(action.tool))

    def violates(self, action):
        """True if this EXTERNAL action would make the session hold all three —
        i.e. untrusted + sensitive are already active. Checked BEFORE the action's
        own caps are folded in, so an external send only trips once the session has
        separately seen untrusted content and sensitive data."""
        c = self.caps_of(action)
        return EXTERNAL in c and UNTRUSTED in self.active and SENSITIVE in self.active

    def observe(self, action):
        """Fold this action's capabilities into the session state."""
        self.active |= self.caps_of(action)
