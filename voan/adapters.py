"""Framework adapters — drop the firewall into agents you did NOT build.

The core `guard()` wraps plain functions; real agents wrap their tools in
framework objects (LangChain BaseTool, an OpenAI tool-dispatch table, etc.).
These adapters reach inside those objects and guard the underlying callable, so
the interception happens *inside the framework's own execution path* — not a toy
loop. Everything is duck-typed: none of these frameworks is a hard dependency.

Framework agents expect a tool to RETURN an observation, not raise. So unlike the
bare `guard()` (which raises BlockedAction), these adapters catch the block and
return it as a string result — the dangerous tool still never runs, but the agent
receives "Voan blocked …" as the tool output and can defer to the user instead of
crashing.
"""
import functools

from .hook import Firewall
from .schema import Action, BlockedAction, Decision


def _fw(firewall):
    return firewall or Firewall()


def _soft(fn):
    """Wrap a guarded callable so a block returns a tool-observation string
    instead of raising (the real tool still never runs on a block)."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BlockedAction as e:
            return (f"\U0001f6d1 Voan blocked this action: {e.verdict.reason} "
                    f"[{e.verdict.code} {e.verdict.severity}]. Do not retry it; "
                    f"tell the user it was blocked by policy.")
    return wrapped


def guard_langchain(tools, firewall=None):
    """Guard a list of LangChain tools (StructuredTool / BaseTool).

    LangChain runs a tool by ultimately calling its `.func`; we replace that
    callable with a guarded one keyed on the tool's real `.name`, so any
    `tool.invoke(...)` / agent execution flows through the policy first. Returns
    the same tool objects (mutated in place)."""
    fw = _fw(firewall)
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "tool")
        if getattr(t, "func", None) and callable(t.func):
            t.func = _soft(fw.guard(t.func, name=name))   # sync StructuredTool
        elif getattr(t, "coroutine", None):
            t.coroutine = _soft(fw.guard(t.coroutine, name=name))
        else:                                             # bare callable tool
            return guard_callables(tools, fw)
    return tools


def guard_openai_dispatch(dispatch, firewall=None):
    """Guard an OpenAI tool-calling dispatch table {tool_name: fn}.

    In an OpenAI function-calling loop you read `tool_calls` from the model and
    look the name up in a dispatch dict. Wrap that dict once and every call the
    model makes is checked before it runs."""
    fw = _fw(firewall)
    return {name: _soft(fw.guard(fn, name=name)) for name, fn in dispatch.items()}


def guard_callables(fns, firewall=None):
    """Guard a plain list of callables, preserving order."""
    fw = _fw(firewall)
    return [_soft(fw.guard(f)) for f in fns]


def guard_mcp(session, firewall=None):
    """Guard an MCP ClientSession — the protocol-level sensor.

    MCP tools run in a separate server over a transport, so the in-process hook
    can't wrap them. Instead we wrap the client's `call_tool`, so every tool call
    flows through Voan's policy BEFORE the request leaves the client for the server.
    On block it returns an error CallToolResult (the agent sees a tool error and can
    defer) instead of forwarding. Returns the same session (mutated)."""
    fw = _fw(firewall)
    orig = session.call_tool

    @functools.wraps(orig)
    async def guarded(name, arguments=None, *a, **k):
        action = Action(tool=name, args=arguments or {}, agent=fw.agent)
        verdict = fw._judge(action, fw._egress(action, fw.policy.evaluate(action)))
        fw.audit.record(action, verdict)
        deny = verdict.decision == Decision.BLOCK or (
            verdict.decision == Decision.ASK and
            not (fw.on_ask and fw.on_ask(action, verdict)))
        if deny and fw.mode != "monitor":
            from mcp.types import CallToolResult, TextContent
            return CallToolResult(isError=True, content=[TextContent(
                type="text", text=f"\U0001f6d1 Voan blocked {name}(): "
                f"{verdict.reason} [{verdict.code} {verdict.severity}]")])
        return await orig(name, arguments, *a, **k)

    session.call_tool = guarded
    return session
