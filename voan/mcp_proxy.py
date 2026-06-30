"""Transparent MCP firewall proxy (stdio) — zero integration.

Point your MCP client at `voan-mcp-proxy --allow acme.com -- <server command>`
instead of the server itself. The proxy spawns the real server and relays the
newline-delimited JSON-RPC both ways, but every `tools/call` is first checked by
Voan's DETERMINISTIC tiers (regex rules + egress allowlist). A blocked call gets an
error result and never reaches the server — no code change in the client or server.

(The LLM judge needs the user's goal, which a transparent proxy doesn't see, so it
stays in the in-process / `guard_mcp` path. This proxy gives integration-free
rules+egress: destructive commands and exfil to unapproved destinations.)

    voan-mcp-proxy --allow acme.com -- python my_mcp_server.py
"""
import json
import subprocess
import sys
import threading

from .policy import PolicyEngine
from .rules import egress_violation
from .schema import Action, Decision


def _block_result(rid, reason):
    return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {
        "content": [{"type": "text", "text": f"\U0001f6d1 Voan blocked: {reason}"}],
        "isError": True}})


def run_proxy(server_cmd, allowlist):
    policy = PolicyEngine()
    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=sys.stderr, bufsize=1, text=True)
    lock = threading.Lock()

    def to_client(line):
        with lock:
            sys.stdout.write(line if line.endswith("\n") else line + "\n")
            sys.stdout.flush()

    def pump_server():
        for line in proc.stdout:
            to_client(line)
    threading.Thread(target=pump_server, daemon=True).start()

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except (ValueError, TypeError):
            proc.stdin.write(line); proc.stdin.flush(); continue
        if msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            action = Action(tool=params.get("name", ""),
                            args=params.get("arguments") or {}, agent="mcp-proxy")
            verdict = policy.evaluate(action)
            bad = egress_violation(action.args, allowlist) if allowlist else None
            if verdict.decision == Decision.BLOCK or bad:
                reason = f"egress to non-allowlisted '{bad}'" if bad else verdict.reason
                sys.stderr.write(f"[voan] blocked {action.tool}: {reason}\n")
                to_client(_block_result(msg.get("id"), reason))
                continue
        proc.stdin.write(line); proc.stdin.flush()
    proc.terminate()


def main():
    args = sys.argv[1:]
    allow = []
    while len(args) >= 2 and args[0] == "--allow":
        allow.append(args[1]); args = args[2:]
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        sys.stderr.write("usage: voan-mcp-proxy [--allow DOMAIN]... -- "
                         "<server command...>\n")
        sys.exit(2)
    run_proxy(args, allow)


if __name__ == "__main__":
    main()
