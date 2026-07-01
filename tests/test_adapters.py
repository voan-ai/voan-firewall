"""Framework adapters: a block returns an observation STRING (agent doesn't crash)
and the real tool never runs."""
import asyncio
import types

from voan.adapters import guard_callables, guard_langchain, guard_mcp, guard_openai_dispatch


def is_block(v):
    return isinstance(v, str) and v.startswith("\U0001f6d1 Voan blocked")


def test_openai_dispatch_soft_block():
    ran = {"v": False}

    def run_command(command):
        ran["v"] = True
        return "ran"

    guarded = guard_openai_dispatch({"run_command": run_command})
    out = guarded["run_command"](command="rm -rf /")
    assert is_block(out) and ran["v"] is False


def test_openai_dispatch_allows_benign():
    guarded = guard_openai_dispatch({"run_command": lambda command: f"ran {command}"})
    assert guarded["run_command"](command="ls") == "ran ls"


def test_guard_callables_soft_block_preserves_order():
    benign = lambda x: x + 1
    def shell(command):
        return "ran"
    g1, g2 = guard_callables([benign, shell])
    assert g1(41) == 42
    assert is_block(g2(command="rm -rf /"))


def test_guard_langchain_replaces_func():
    tool = types.SimpleNamespace(name="run_command",
                                 func=lambda command: "ran")
    guard_langchain([tool])
    assert is_block(tool.func(command="rm -rf /"))
    assert tool.func(command="ls") == "ran"


def test_guard_mcp_blocks_and_returns_error_result():
    import pytest
    pytest.importorskip("mcp")   # guard_mcp builds an error CallToolResult on block
    class FakeSession:
        async def call_tool(self, name, arguments=None):
            return f"real {name}"

    s = FakeSession()
    guard_mcp(s)

    async def go():
        blocked = await s.call_tool("run_command", {"command": "rm -rf /"})
        ok = await s.call_tool("get_weather", {"city": "X"})
        return blocked, ok

    blocked, ok = asyncio.run(go())
    assert getattr(blocked, "isError", False) is True
    assert ok == "real get_weather"
