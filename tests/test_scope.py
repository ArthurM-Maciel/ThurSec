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


# --- o escopo e os módulos têm de ver o mesmo host -------------------------
import pytest as _pytest

from thursec.core.scope import _host_of
from thursec.core.target import parse_endpoint


@_pytest.mark.parametrize(
    "target",
    [
        "admin:senha@example.com",
        "https://admin:senha@example.com",
        "example.com",
        "example.com:8443",
        "https://example.com:8443/x",
        "[::1]:8443",
        "example.com/admin",
        # A caixa também: o host sai daqui para o SNI e para o cabeçalho Host.
        "https://ALVO.com",
        "ALVO.com:8443",
        "2001:DB8::1",
    ],
)
def test_escopo_e_modulos_leem_o_mesmo_host(target):
    """Divergir aqui autoriza um host e conecta em outro."""
    assert _host_of(target) == parse_endpoint(target, {})[1]


def test_faixa_continua_sendo_comparada_como_faixa():
    """Extrair "host" de um CIDR descartaria o prefixo e alargaria o escopo."""
    assert _host_of("10.0.0.0/24") == "10.0.0.0/24"


# --- faixa autorizada autoriza a própria faixa -----------------------------
@_pytest.mark.parametrize(
    "alvo, entrada, autorizado",
    [
        # A faixa exata que o arquivo autoriza — era recusada.
        ("10.0.0.0/24", "10.0.0.0/24", True),
        # Sub-faixa está contida.
        ("10.0.0.0/25", "10.0.0.0/24", True),
        ("10.0.0.5", "10.0.0.0/24", True),
        # Faixa maior que a autorizada NÃO está: a fronteira não alarga.
        ("10.0.0.0/23", "10.0.0.0/24", False),
        ("10.1.0.0/24", "10.0.0.0/24", False),
        # Famílias diferentes não se misturam.
        ("2001:db8::/32", "10.0.0.0/24", False),
        ("alvo.com", "10.0.0.0/24", False),
    ],
)
def test_faixa_dentro_de_faixa_autorizada(alvo, entrada, autorizado):
    from thursec.core.scope import _match

    assert _match(alvo, entrada) is autorizado
