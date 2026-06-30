"""Shared test fixtures. No network — the judge is always a stub callable."""
import pytest

from voan.schema import Action


def stub_llm(reply):
    """A deterministic LLM backend: callable(system, user) -> fixed reply. Records
    every prompt it was given so tests can assert on redaction etc."""
    calls = []

    def llm(system, user):
        calls.append((system, user))
        return reply

    llm.calls = calls
    return llm


@pytest.fixture
def act():
    """Build an Action quickly: act('run_command', command='rm -rf /')."""
    def make(tool, **args):
        return Action(tool=tool, args=args, agent="test")
    return make
