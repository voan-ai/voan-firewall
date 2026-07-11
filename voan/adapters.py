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
import inspect

from .hook import Firewall
from .schema import Action, BlockedAction, Decision


def _fw(firewall):
    return firewall or Firewall()


def _blockmsg(e):
    return (f"\U0001f6d1 Voan blocked this action: {e.verdict.reason} "
            f"[{e.verdict.code} {e.verdict.severity}]. Do not retry it; "
            f"tell the user it was blocked by policy.")


def _soft(fn):
    """Sync: turn a BlockedAction into a tool-observation string (tool never runs)."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BlockedAction as e:
            return _blockmsg(e)
    return wrapped


def _softa(fn):
    """Async variant of _soft for a coroutine-returning guarded callable — the block
    is caught after awaiting, so an async tool doesn't raise into the agent loop."""
    @functools.wraps(fn)
    async def wrapped(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except BlockedAction as e:
            return _blockmsg(e)
    return wrapped


def _softg(fn):
    """Async-generator (streaming) variant: a block raised inside the stream becomes a
    yielded observation string instead of propagating into the agent loop."""
    @functools.wraps(fn)
    async def wrapped(*args, **kwargs):
        try:
            async for item in fn(*args, **kwargs):
                yield item
        except BlockedAction as e:
            yield _blockmsg(e)
    return wrapped


def _soft_any(guarded):
    """Pick the sync / async / async-generator soft wrapper for `guarded` (a
    guard()-wrapped callable), matching its call shape."""
    if inspect.isasyncgenfunction(guarded):
        return _softg(guarded)
    return _softa(guarded) if inspect.iscoroutinefunction(guarded) else _soft(guarded)


def guard_langchain(tools, firewall=None):
    """Guard a list of LangChain tools (StructuredTool / BaseTool), in place.

    Wraps the tool's real execution callable(s) — `.func` AND/OR `.coroutine` on a
    StructuredTool, or `._run`/`._arun` on a bare BaseTool subclass — so any
    `tool.invoke(...)` / `.ainvoke(...)` / agent run flows through the policy first.
    BOTH sync and async paths are guarded (a tool with both is otherwise half-guarded,
    and async agent runs would execute the unguarded coroutine). A tool exposing no
    wrappable callable RAISES (fail loud) rather than being left silently unguarded.
    If the whole list is plain callables, falls back to guard_callables. Returns the
    same tool objects (mutated in place)."""
    fw = _fw(firewall)
    unwrappable = []
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "tool")
        wrapped_any = False
        if getattr(t, "func", None) and callable(t.func):
            t.func = _soft_any(fw.guard(t.func, name=name))
            wrapped_any = True
        if getattr(t, "coroutine", None) and callable(t.coroutine):
            t.coroutine = _soft_any(fw.guard(t.coroutine, name=name))
            wrapped_any = True
        if not wrapped_any:                    # bare BaseTool: _run / _arun
            run = getattr(t, "_run", None)
            if callable(run):
                t._run = _soft_any(fw.guard(run, name=name))
                wrapped_any = True
            arun = getattr(t, "_arun", None)
            if inspect.iscoroutinefunction(arun):
                t._arun = _soft_any(fw.guard(arun, name=name))
                wrapped_any = True
        if not wrapped_any:
            unwrappable.append((name, t))
    if unwrappable:
        if len(unwrappable) == len(tools) and all(callable(t) for _, t in unwrappable):
            return guard_callables(tools, fw)   # whole list is plain callables
        names = [n for n, _ in unwrappable]
        raise TypeError(
            f"guard_langchain: {names} expose no .func/.coroutine/._run/._arun to "
            f"guard — they would run UNPROTECTED. Use guard_callables for plain "
            f"functions, or guard_langchain_auto.")
    return tools


def guard_openai_dispatch(dispatch, firewall=None):
    """Guard an OpenAI tool-calling dispatch table {tool_name: fn}.

    In an OpenAI function-calling loop you read `tool_calls` from the model and
    look the name up in a dispatch dict. Wrap that dict once and every call the
    model makes is checked before it runs."""
    fw = _fw(firewall)
    return {name: _soft_any(fw.guard(fn, name=name)) for name, fn in dispatch.items()}


def guard_callables(fns, firewall=None):
    """Guard a plain list of callables, preserving order (sync or async)."""
    fw = _fw(firewall)
    return [_soft_any(fw.guard(f)) for f in fns]


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
        # Run the FULL tier chain (taint / rule-of-two / flow / plan), not just
        # policy+egress+judge — otherwise those protections silently don't apply to
        # MCP tool calls.
        verdict = fw._evaluate(action)
        fw.audit.record(action, verdict)
        deny = verdict.decision == Decision.BLOCK
        if verdict.decision == Decision.ASK:
            approved = fw.on_ask(action, verdict) if fw.on_ask else False
            if inspect.isawaitable(approved):
                approved = await approved       # async confirm callbacks ARE awaited
            deny = not approved
        if deny and fw.mode != "monitor":
            from mcp.types import CallToolResult, TextContent
            return CallToolResult(isError=True, content=[TextContent(
                type="text", text=f"\U0001f6d1 Voan blocked {name}(): "
                f"{verdict.reason} [{verdict.code} {verdict.severity}]")])
        result = await orig(name, arguments, *a, **k)
        fw._record_output(name, getattr(result, "content", result))   # seed provenance
        return result

    session.call_tool = guarded
    return session
