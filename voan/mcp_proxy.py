"""Transparent MCP firewall proxy — zero integration, any upstream transport.

Drop it between your MCP client and server. The client spawns this proxy (stdio);
the proxy connects UPSTREAM to the real server — a local stdio command OR a remote
streamable-HTTP MCP server — and relays everything, but runs Voan's deterministic
tiers (rules + egress allowlist) on every tools/call. Blocked calls return an error
and never reach the server. No code change in the client or server.

    voan-mcp-proxy --allow acme.com -- python my_server.py        # stdio upstream
    voan-mcp-proxy --allow acme.com --http https://host/mcp       # remote HTTP upstream

(The LLM judge needs the user's goal, which a transparent proxy doesn't see, so it
stays in the in-process / guard_mcp path; this gives integration-free rules+egress.)
"""
import sys

from .policy import PolicyEngine
from .rules import egress_violation
from .schema import Action, Decision


async def _serve(upstream, allowlist):
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    policy = PolicyEngine()
    proxy = Server("voan-mcp-firewall")

    @proxy.list_tools()
    async def _list():
        tools = (await upstream.list_tools()).tools
        for t in tools:                 # we forward the upstream result verbatim, so
            t.outputSchema = None        # don't re-validate structured output here
        return tools

    @proxy.call_tool()
    async def _call(name, arguments):
        action = Action(tool=name, args=arguments or {}, agent="mcp-proxy")
        verdict = policy.evaluate(action)
        bad = egress_violation(action.args, allowlist) if allowlist else None
        if verdict.decision == Decision.BLOCK or bad:
            reason = f"egress to non-allowlisted '{bad}'" if bad else verdict.reason
            sys.stderr.write(f"[voan] blocked {name}: {reason}\n")
            raise ValueError(f"\U0001f6d1 Voan blocked {name}(): {reason}")
        return (await upstream.call_tool(name, arguments)).content

    async with stdio_server() as (r, w):
        await proxy.run(r, w, proxy.create_initialization_options())


async def _amain(upstream_kind, target, allowlist):
    from mcp import ClientSession
    if upstream_kind == "http":
        from mcp.client.streamable_http import streamablehttp_client
        async with streamablehttp_client(target) as (r, w, _):
            async with ClientSession(r, w) as up:
                await up.initialize()
                await _serve(up, allowlist)
    else:
        from mcp.client.stdio import StdioServerParameters, stdio_client
        params = StdioServerParameters(command=target[0], args=target[1:])
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as up:
                await up.initialize()
                await _serve(up, allowlist)


def main():
    import anyio
    args = sys.argv[1:]
    allow = []
    while len(args) >= 2 and args[0] == "--allow":
        allow.append(args[1]); args = args[2:]
    if args and args[0] == "--http":
        if len(args) < 2:
            sys.stderr.write("usage: voan-mcp-proxy [--allow D]... --http <url>\n")
            sys.exit(2)
        anyio.run(_amain, "http", args[1], allow)
        return
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        sys.stderr.write("usage: voan-mcp-proxy [--allow DOMAIN]... "
                         "(-- <server cmd...> | --http <url>)\n")
        sys.exit(2)
    anyio.run(_amain, "stdio", args, allow)


if __name__ == "__main__":
    main()
