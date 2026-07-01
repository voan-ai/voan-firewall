"""Transparent MCP firewall proxy — zero integration, any upstream transport.

Drop it between your MCP client and server. The client reaches this proxy (spawn
it over stdio, OR point a remote client at it over HTTP with --serve-http); the
proxy connects UPSTREAM to the real server — a local stdio command OR a remote
streamable-HTTP MCP server — and relays everything, but runs Voan's deterministic
tiers (rules + egress allowlist) on every tools/call. Blocked calls return an error
and never reach the server. No code change in the client or server.

    voan-mcp-proxy --allow acme.com -- python my_server.py        # stdio upstream
    voan-mcp-proxy --allow acme.com --http https://host/mcp       # remote HTTP upstream
    voan-mcp-proxy --allow acme.com --serve-http 127.0.0.1:9000 \\
                   -- python my_server.py                          # SERVE over HTTP

(The LLM judge needs the user's goal, which a transparent proxy doesn't see, so it
stays in the in-process / guard_mcp path; this gives integration-free rules+egress.)
"""
import sys

from .policy import PolicyEngine
from .rules import egress_violation
from .schema import Action, Decision


def _build_proxy(upstream, allowlist):
    """Build the low-level MCP Server that forwards to `upstream` but gates every
    tools/call through Voan's rules + egress. Shared by the stdio and HTTP paths."""
    from mcp.server.lowlevel import Server
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

    return proxy


async def _serve_stdio(upstream, allowlist):
    from mcp.server.stdio import stdio_server
    proxy = _build_proxy(upstream, allowlist)
    async with stdio_server() as (r, w):
        await proxy.run(r, w, proxy.create_initialization_options())


async def _serve_http(upstream, allowlist, host, port):
    """Serve the proxy ITSELF over streamable HTTP at /mcp, so a remote MCP client
    can connect to Voan directly (no subprocess). Upstream can still be stdio or HTTP."""
    import contextlib

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount

    proxy = _build_proxy(upstream, allowlist)
    manager = StreamableHTTPSessionManager(app=proxy, stateless=True, json_response=True)

    async def handle(scope, receive, send):
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    app = Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)
    sys.stderr.write(f"[voan] MCP firewall serving on http://{host}:{port}/mcp\n")
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()


async def _amain(upstream_kind, target, allowlist, serve):
    from mcp import ClientSession
    if upstream_kind == "http":
        from mcp.client.streamable_http import streamablehttp_client
        async with streamablehttp_client(target) as (r, w, _):
            async with ClientSession(r, w) as up:
                await up.initialize()
                await serve(up, allowlist)
    else:
        from mcp.client.stdio import StdioServerParameters, stdio_client
        params = StdioServerParameters(command=target[0], args=target[1:])
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as up:
                await up.initialize()
                await serve(up, allowlist)


def main():
    import functools

    import anyio
    args = sys.argv[1:]
    allow = []
    while len(args) >= 2 and args[0] == "--allow":
        allow.append(args[1])
        args = args[2:]

    serve = _serve_stdio                       # default: serve to the client over stdio
    if args and args[0] == "--serve-http":
        if len(args) < 2:
            sys.stderr.write("usage: voan-mcp-proxy ... --serve-http <host:port> ...\n")
            sys.exit(2)
        host, _, port = args[1].partition(":")
        serve = functools.partial(_serve_http, host=host or "127.0.0.1",
                                  port=int(port or "9000"))
        args = args[2:]

    if args and args[0] == "--http":
        if len(args) < 2:
            sys.stderr.write("usage: voan-mcp-proxy [--allow D]... --http <url>\n")
            sys.exit(2)
        anyio.run(_amain, "http", args[1], allow, serve)
        return
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        sys.stderr.write("usage: voan-mcp-proxy [--allow DOMAIN]... [--serve-http host:port] "
                         "(-- <server cmd...> | --http <url>)\n")
        sys.exit(2)
    anyio.run(_amain, "stdio", args, allow, serve)


if __name__ == "__main__":
    main()
