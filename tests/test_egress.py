"""Egress allowlist: deterministic destination check, fail-closed on dest fields."""
import pytest

from voan.rules import egress_violation

ALLOW = ["acme.com"]


@pytest.mark.parametrize("args", [
    {"dest": "acme-backups.net"},          # look-alike domain
    {"url": "http://2852039166/x"},        # decimal-encoded IP
    {"url": "http://[fd00::1]/x"},          # ipv6 literal
    {"to": "thief@evil-collector.com"},     # external recipient
    {"endpoint": "http://169.254.169.254/latest"},  # cloud metadata SSRF
    {"webhook": "https://hooks.evil.io/x"},
])
def test_violation_detected(args):
    assert egress_violation(args, ALLOW) is not None


@pytest.mark.parametrize("args", [
    {"dest": "acme.com"},
    {"dest": "backups.acme.com"},          # subdomain of allowlisted
    {"url": "https://acme.com/api/v1"},
    {"order_id": "ORD-1001", "amount": "50"},   # no destination at all
    {"note": "call me at extension 1234"},      # digits, not an IP
])
def test_no_violation(args):
    assert egress_violation(args, ALLOW) is None


def test_dest_field_fail_closed_beats_plain_scan():
    # a destination-named field must resolve to an allowlisted host even if the
    # value is an odd encoding; here a bare unapproved host in `dest`.
    assert egress_violation({"dest": "10.0.0.5"}, ALLOW) == "10.0.0.5"


def test_nested_args_walked():
    args = {"payload": {"options": [{"callback": "https://evil.net/cb"}]}}
    assert egress_violation(args, ALLOW) is not None


def test_empty_allowlist_blocks_any_destination():
    assert egress_violation({"dest": "acme.com"}, []) == "acme.com"
