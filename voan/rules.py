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
             # rm with ANY recursive flag, in any position/form — recursion is the
             # danger, so we don't require force to be adjacent (or present): -r, -rf,
             # -fr, -Rf, "-f <path> -r", --recursive all match. --force/--no-preserve-
             # root are kept as extra signals.
             r"\brm\b[^|;&\n]*(?:-[a-z]*r|--recursive|--force|--no-preserve-root)"
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
         # pipe-to-interpreter (sh/bash AND python/perl/ruby/node/php/pwsh — the
         # common fetch-and-run RCE), plus process/command substitution bash <(curl..),
         # $(wget..) — fetch-and-run a remote payload without an explicit pipe.
         pattern=r"(?:curl|wget|fetch)[^|]*\|\s*"
                 # allow known wrapper commands (sudo/xargs/env/…) between the pipe and
                 # the interpreter, so `curl … | xargs bash` / `| sudo -u root bash` hit
                 r"(?:(?:sudo|xargs|env|nice|timeout|nohup|stdbuf|command)\b[^|]*?\s)*"
                 r"(?:sh|bash|zsh|dash|ash|ksh|fish|python[0-9.]*|perl|ruby|node|php|pwsh|powershell)\b"
                 # download-THEN-execute via && (no pipe): `curl … -o /tmp/x && bash /tmp/x`
                 r"|(?:curl|wget|fetch)\b[^|;]*&&\s*(?:sudo\s+)?"
                 r"(?:sh|bash|zsh|dash|ash|ksh|python[0-9.]*|perl|ruby|node|php)\b"
                 r"|[<$]\(\s*(?:curl|wget)|iex\s*\(|invoke-expression"),
    # --- Critical: destructive data loss ------------------------------------
    Rule("DB_DESTRUCTIVE", Decision.BLOCK, "DEL", "Critical",
         "Destructive database operation",
         tools=DB,
         # DROP/TRUNCATE (tolerating /* */ comment-whitespace evasions); DELETE FROM
         # or mass UPDATE with no genuine WHERE (incl. the "-- where" comment trick);
         # and a WHERE that is a tautology (1=1 / 0=0 / WHERE true) — a fake predicate
         # that still hits every row, so the presence of 'where' is not proof of scope.
         pattern=r"drop(?:\s|/\*[^*]*\*/)+"
                 r"(?:table|database|schema|view|index|sequence|role|user|type|function|trigger)"
                 r"|truncate(?:\s|/\*[^*]*\*/)+"
                 r"|delete\s+from(?!.*\bwhere\b)"
                 r"|delete\s+from\s+[\w\".]+\s*(?:--|/\*|;)"
                 r"|update\s+[\w\".]+\s+set\b(?!.*\bwhere\b)"
                 r"|update\s+[\w\".]+\s+set\b[^;]*(?:--|/\*)"
                 # a WHERE that is a TAUTOLOGY / unscoped predicate (still hits every
                 # row) — detect the SHAPE, not a list of literals: const-op-const,
                 # col=col, IS NOT NULL, a bare truthy constant, or 'x'='x'.
                 r"|(?:delete\s+from|update)\b[^;]*\bwhere\b[^;]*(?:"
                 r"\b\d+\s*(?:=|<|>|<=|>=|<>|!=)\s*\d+"    # const op const: 1=1, 2>1, 1<2
                 r"|\b(\w+)\s*=\s*\1\b"                      # col = col (id=id)
                 r"|'([^']*)'\s*=\s*'\2'"                    # 'x' = 'x'
                 r")"
                 # a bare truthy constant as the WHOLE predicate (WHERE 1 / WHERE true) —
                 # anchored right after WHERE so a legit `WHERE status = 1` is not caught.
                 # Terminator incl. \" because args are JSON-serialized ("… WHERE 1").
                 r"|(?:delete\s+from|update)\b[^;]*\bwhere\s+(?:true|1)\b\s*(?:;|--|\)|\"|$)"),
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
        # Fail-closed host check on destination-named fields AND on any value carrying
        # a URL scheme, wherever it sits — so an encoded-IP / dotless host in a
        # non-dest field (e.g. {"q": "http://0x7f000001/"}) is still caught, without
        # flagging a bare integer in free text (which has no scheme).
        if any(dk in k.lower() for dk in _DEST_KEYS) or "://" in str(v).lower():
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
