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
it for a human (ASK). The capability COUNT is model-independent — no prompt can talk
the firewall out of it — but soundness depends on correct capability labels, which are
best DECLARED; the name-based default below only guesses and can be dodged by tool naming.

Capabilities per tool are best DECLARED (`Firewall(rule_of_two=caps)` where caps is
{tool: ["untrusted","sensitive","external"]}); a coarse name-based default is used
for any tool you don't declare.
"""
UNTRUSTED, SENSITIVE, EXTERNAL = "untrusted", "sensitive", "external"

# Coarse name-based defaults. Declaration overrides these; they only guess.
_EXT = ("send", "pay", "transfer", "post", "share", "delete", "charge", "payout",
        "write_", "create_", "update_", "schedule", "invite", "grant", "publish",
        "email", "message", "notify", "upload", "move_", "export", "download",
        "http", "request", "sms", "sync", "dispatch", "webhook", "wire")
_UNTRUSTED_SRC = ("read_", "get_webpage", "fetch", "search", "browse", "web",
                  "review", "inbox", "channel", "get_emails", "get_messages",
                  "get_file", "read_file", "list_")
_SENSITIVE_SRC = ("balance", "transaction", "account", "iban", "payment", "password",
                  "secret", "key", "credential", "ssn", "card", "health", "salary",
                  "scheduled", "contact", "calendar", "private", "get_file", "read_file",
                  "profile", "customer", "record", "medical", "address", "dob")


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
        """True if letting this action run would realize all THREE properties in the
        session. The action's OWN caps are folded into the test (not just self.active),
        so a single atomic tool that both reads sensitive data AND sends externally is
        held once the session already holds untrusted input — the two-action exfil
        (read_secret then send) is still caught because observe() accumulates state."""
        c = self.caps_of(action)
        seen = self.active | c
        return EXTERNAL in c and UNTRUSTED in seen and SENSITIVE in seen

    def observe(self, action):
        """Fold this action's capabilities into the session state."""
        self.active |= self.caps_of(action)
