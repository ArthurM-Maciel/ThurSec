"""Tests for the shared target validator (argument-injection defense)."""

import pytest

from thursec.core.target import TargetError, validate_target


# --- accepted targets ------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("  example.com  ", "example.com"),  # trimmed
        ("Example.COM", "example.com"),  # lowercased
        ("sub.domain.example.com", "sub.domain.example.com"),
        ("localhost", "localhost"),
        ("example.com.", "example.com"),  # trailing dot stripped
        ("93.184.216.34", "93.184.216.34"),
        ("10.0.0.5", "10.0.0.5"),
        ("203.0.113.0/24", "203.0.113.0/24"),  # IPv4 CIDR
        ("2001:db8::1", "2001:db8::1"),  # IPv6
        ("2001:db8::/32", "2001:db8::/32"),  # IPv6 CIDR
        ("[::1]", "::1"),  # bracketed IPv6
        ("[::1]:80", "::1"),  # bracketed IPv6 with port
        ("example.com:8443", "example.com"),  # host:port -> host
        ("https://example.com/path", "example.com"),  # URL host
        ("http://example.com:8080/a/b?q=1", "example.com"),
    ],
)
def test_validate_target_accepts(raw, expected):
    assert validate_target(raw) == expected


# --- rejected targets (the security cases) ---------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        "-sS",  # flag-shaped: would select a SYN scan
        "--script=http-shellshock,exploit",  # bypass the NSE allowlist
        "-oN/tmp/pwned",  # file write via output flag
        "-",  # lone dash
        "",  # empty
        "   ",  # whitespace-only
        "example.com extra",  # embedded space
        "exa mple.com",
        "bad\thost",  # control char (tab)
        "host\nname",  # control char (newline)
        "not a host!",
        "under_score.com",  # underscore not valid in a hostname label
        "-bad.example.com",  # leading-dash label
    ],
)
def test_validate_target_rejects(raw):
    with pytest.raises(TargetError):
        validate_target(raw)


def test_validate_target_error_message_mentions_flag():
    with pytest.raises(TargetError) as exc:
        validate_target("--script=exploit")
    assert "flag" in str(exc.value).lower()
