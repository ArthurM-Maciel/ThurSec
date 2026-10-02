from datetime import date, timedelta

import pytest

from thursec.core.scope import Scope, ScopeError


def _scope(**over):
    base = dict(
        engagement="t", authorized_by="me",
        targets=["*.lab.example", "10.0.0.5", "192.168.56.0/24", "exact.example"],
    )
    base.update(over)
    return Scope(**base)


@pytest.mark.parametrize("target", [
    "host.lab.example",
    "https://host.lab.example/path",
    "exact.example",
    "exact.example:443",
    "10.0.0.5",
    "192.168.56.42",
])
def test_in_scope(target):
    assert _scope().contains(target)


@pytest.mark.parametrize("target", [
    "lab.example",            # wildcard needs a label
    "deep.sub.lab.example",   # fnmatch '*' is one label here
    "evil.example",
    "10.0.0.6",
    "192.168.57.1",
])
def test_out_of_scope(target):
    assert not _scope().contains(target)


def test_enforce_raises_out_of_scope():
    with pytest.raises(ScopeError):
        _scope().enforce("evil.example")


def test_enforce_passes_in_scope():
    _scope().enforce("host.lab.example")  # no raise


def test_expired_scope_blocks_everything():
    s = _scope(expires=date.today() - timedelta(days=1))
    assert s.is_expired
    with pytest.raises(ScopeError):
        s.enforce("host.lab.example")


def test_wildcard_does_not_match_ip_entry_type():
    # a hostname must not match a CIDR entry
    assert not _scope(targets=["10.0.0.0/8"]).contains("host.lab.example")
