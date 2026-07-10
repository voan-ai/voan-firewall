"""Default policy rules — the firewall's "virus signatures" for agent actions.

Each Rule matches an Action by tool name and/or a regex over its serialized
arguments. The first matching rule wins (see policy.py). Rules are deliberately
declarative so non-engineers can read and extend them. Category codes mirror the
Voan scanner / OWASP Agentic taxonomy:
  RCE remote code exec · AEX data exfiltration · AGT unauthorized action
  CRH credential theft · DEL destructive data loss
"""
import json
import re
from dataclasses import dataclass, field

from .schema import Decision


@dataclass
class Rule:
    id: str
    decision: Decision
    code: str
    severity: str
    reason: str
    tools: set = field(default_factory=set)   # empty = match any tool
    pattern: str = ""                         # regex over json(args); "" = any
    _rx: object = field(default=None, repr=False)

    def matches(self, action) -> bool:
        if self.tools and action.tool not in self.tools:
            return False
        if self.pattern:
            if self._rx is None:
                self._rx = re.compile(self.pattern, re.I)
            blob = json.dumps(action.args, ensure_ascii=False)
            return bool(self._rx.search(blob))
        return True


# Tool-name families. Real agents name shell/db/email tools many ways; match
# broadly so the firewall is not trivially bypassed by renaming a tool. (The
# shell/db rules below are all PATTERN-gated, so widening these sets never
# over-blocks — a tool only matches if its ARGS also match the danger pattern.)
# An arbitrary rename we don't list here is still covered by deny-by-default
# presets (voan.deny_by_default([...])); these names just catch the common ones.
SHELL = {"run_command", "shell", "exec", "bash", "sh", "system", "terminal",
         "powershell", "pwsh", "cmd", "spawn", "subprocess", "popen",
         "child_process", "os_system", "shell_exec", "execute_command"}
DB = {"delete_database", "drop_table", "execute_sql", "run_query", "db",
      "query", "sql", "run_sql", "execute_query", "cursor"}
MAIL = {"send_email", "email", "send_message", "send_mail", "notify"}
HTTP = {"http_request", "fetch", "request", "post", "webhook", "curl"}
PAY = {"process_refund", "make_payment", "send_payment", "transfer", "charge", "payout"}

# Known-bad exfil destinations used in the scanner's poisoned fixtures, plus a
# generic "non-corporate recipient" heuristic for the demo.
EXFIL = r"attacker|evil\.test|exfil@|refunds@attacker|\.onion\b"

DEFAULT_RULES = [
    # --- Critical: destructive shell / code execution -----------------------
    Rule("SHELL_DESTRUCTIVE", Decision.BLOCK, "RCE", "Critical",
         "Destructive or self-propagating shell command",
         tools=SHELL,
         pattern=(
             # rm recursive+force in any flag order/form (-rf, -fr, -rvf, -r -f,
             # --recursive, --force) — the classic, and its evasions
             r"\brm\b[^|;&\n]*(?:-r[a-z]*f|-f[a-z]*r|-r\s+-f|-f\s+-r"
             r"|--recursive|--force)"
             r"|\bfind\b[^|;&\n]*-delete|\bfind\b[^|;&\n]*-exec\s+rm"
             r"|\bdd\b[^|;&\n]*of=/dev/|\bmkfs|\bshred\b|\bwipefs\b"
             r"|>\s*/dev/(?:sd|nvme|hd|disk|mapper)|\bmv\b[^|;&\n]*\s/dev/null"
             r"|\bchmod\b[^|;&\n]*\b000\b|\btruncate\b[^|;&\n]*-s\s*0\b"
             r"|:\(\)\s*\{|\bshutdown\b|\breboot\b|del\s+/[sfq]|format\s+[a-z]:"
             r"|remove-item\b[^|;&\n]*-recurse[^|;&\n]*-force"
             r"|remove-item\b[^|;&\n]*-force[^|;&\n]*-recurse")),
    Rule("SHELL_PIPE_EXEC", Decision.BLOCK, "RCE", "Critical",
         "Pipe-to-shell remote payload execution",
         tools=SHELL,
         # pipe-to-shell, plus process/command substitution: bash <(curl..),
         # $(wget..) — fetch-and-run a remote payload without an explicit pipe.
         pattern=r"curl[^|]*\|\s*(sh|bash)|wget[^|]*\|\s*(sh|bash)"
                 r"|[<$]\(\s*(?:curl|wget)|iex\s*\(|invoke-expression"),
    # --- Critical: destructive data loss ------------------------------------
    Rule("DB_DESTRUCTIVE", Decision.BLOCK, "DEL", "Critical",
         "Destructive database operation",
         tools=DB,
         # DROP/TRUNCATE (tolerating /* */ comment-whitespace evasions), plus
         # DELETE FROM with no genuine WHERE — including the "-- where" comment
         # trick where the only 'where' is inside a comment after the table.
         pattern=r"drop(?:\s|/\*[^*]*\*/)+(table|database)|truncate(?:\s|/\*[^*]*\*/)+"
                 r"|delete\s+from(?!.*\bwhere\b)"
                 r"|delete\s+from\s+[\w\".]+\s*(?:--|/\*|;)"),
    # --- High: data exfiltration to an attacker channel ---------------------
    Rule("EXFIL_CHANNEL", Decision.BLOCK, "AEX", "High",
         "Data sent to an attacker-controlled destination",
         tools=MAIL | HTTP, pattern=EXFIL),
    # --- High: credential / secret movement ---------------------------------
    Rule("CREDENTIAL_LEAK", Decision.BLOCK, "CRH", "High",
         "Secret or credential about to leave the agent",
         tools=MAIL | HTTP,
         pattern=r"AGENT_TOKEN|api[_-]?key|secret|password|BEGIN [A-Z ]*PRIVATE"),
    # --- Ask: money movement always needs a human ---------------------------
    Rule("PAYMENT_HUMAN", Decision.ASK, "AGT", "High",
         "Money movement requires human approval",
         tools=PAY),
    # --- Ask: outbound mail/webhook to an unrecognized recipient ------------
    Rule("EXTERNAL_SEND", Decision.ASK, "AGT", "Medium",
         "Outbound message to an external recipient",
         tools=MAIL | HTTP),
]

# --- Egress allowlist (deterministic destination check) ---------------------
# The judge checks "is this action consistent with the goal?" — it CANNOT tell a
# look-alike destination (acme-order-backups.net) from a real one. So an opt-in
# allowlist deterministically blocks any egress to a domain you didn't approve,
# regardless of how plausible the injected destination looks.
_DOMAIN_RX = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)
_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Arg fields that name a network destination — checked FAIL-CLOSED (their host must
# resolve to an allowlisted domain, which defeats encoded-IP SSRF evasions).
_DEST_KEYS = ("dest", "url", "uri", "to", "endpoint", "host", "target",
              "recipient", "webhook", "callback", "address", "server")


def _pairs(obj, key=""):
    """Walk nested dict/list args, yielding (key, scalar) pairs."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _pairs(v, str(k))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _pairs(v, key)
    else:
        yield key, obj


def _host(v):
    v = str(v).strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)        # strip scheme
    v = v.split("/")[0].split("?")[0].split("@")[-1]   # strip path/query/userinfo
    if v.startswith("["):                               # ipv6 literal
        return v[1:].split("]")[0]
    return v.split(":")[0]                               # strip port


def _allowed_host(host, allowed):
    host = host.rstrip(".")
    return bool(host) and any(host == a or host.endswith("." + a) for a in allowed)


def egress_violation(args, allowlist):
    """Return the first destination in `args` not covered by `allowlist` (exact
    domains like 'acme.com', or exact IPs), else None. Destination-named fields are
    fail-CLOSED: their host must resolve to an allowlisted domain/IP — which also
    blocks encoded-IP SSRF evasions (decimal/hex/octal/IPv6) and look-alikes."""
    allowed = [a.lower().lstrip(".") for a in allowlist]
    for k, v in _pairs(args):
        if any(dk in k.lower() for dk in _DEST_KEYS):
            host = _host(v)
            if host and not _allowed_host(host, allowed):
                return host
    blob = json.dumps(args, ensure_ascii=False).lower()
    for d in _DOMAIN_RX.findall(blob):
        if not _allowed_host(d.split("@")[-1], allowed):
            return d.split("@")[-1].rstrip(".")
    for ip in _IP_RX.findall(blob):
        if ip not in allowed:
            return ip
    return None
