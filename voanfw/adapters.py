"""Framework adapters — drop the firewall into agents you did NOT build.

The core `guard()` wraps plain functions; real agents wrap their tools in
framework objects (LangChain BaseTool, an OpenAI tool-dispatch table, etc.).
These adapters reach inside those objects and guard the underlying callable, so
the interception happens *inside the framework's own execution path* — not a toy
loop. Everything is duck-typed: none of these frameworks is a hard dependency.
"""
from .hook import Firewall


def _fw(firewall):
    return firewall or Firewall()


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
            t.func = fw.guard(t.func, name=name)          # sync StructuredTool
        elif getattr(t, "coroutine", None):
            t.coroutine = fw.guard(t.coroutine, name=name)
        else:                                             # bare callable tool
            return guard_callables(tools, fw)
    return tools


def guard_openai_dispatch(dispatch, firewall=None):
    """Guard an OpenAI tool-calling dispatch table {tool_name: fn}.

    In an OpenAI function-calling loop you read `tool_calls` from the model and
    look the name up in a dispatch dict. Wrap that dict once and every call the
    model makes is checked before it runs."""
    fw = _fw(firewall)
    return {name: fw.guard(fn, name=name) for name, fn in dispatch.items()}


def guard_callables(fns, firewall=None):
    """Guard a plain list of callables, preserving order."""
    fw = _fw(firewall)
    return [fw.guard(f) for f in fns]
