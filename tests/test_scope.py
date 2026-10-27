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


# --- fronteira de autorização, adversarial ---------------------------------
# O gate é o código de maior consequência da ferramenta: um furo aqui faz o
# ThurSec varrer o que ninguém autorizou. Estes casos foram levantados à mão
# contra um escopo real e ficam aqui para não regredirem.
_ESCOPO_FRONTEIRA = """
engagement: "fronteira"
authorized_by: "x@example.com"
targets:
  - "interno.example.com"
  - "*.lab.example.com"
  - "10.0.0.0/24"
"""


@_pytest.fixture
def escopo_fronteira(tmp_path):
    caminho = tmp_path / "s.yaml"
    caminho.write_text(_ESCOPO_FRONTEIRA)
    from thursec.core.scope import Scope

    return Scope.from_file(str(caminho))


@_pytest.mark.parametrize(
    "alvo",
    [
        "evil.com",
        # Sufixo: o autorizado como prefixo de outro domínio.
        "interno.example.com.evil.com",
        "lab.example.com.evil.com",
        "xinterno.example.com",
        # Caminho, fragmento e query não podem carregar o host autorizado.
        "evil.com/interno.example.com",
        "evil.com#interno.example.com",
        "evil.com?x=interno.example.com",
        # userinfo: o que vem antes do '@' NÃO é o host.
        "interno.example.com@evil.com",
        "http://interno.example.com@evil.com",
        "https://user:interno.example.com@evil.com",
        # Caixa não ajuda a escapar.
        "INTERNO.EXAMPLE.COM.evil.com",
        # '*' cobre um rótulo só.
        "deep.sub.lab.example.com",
        # Faixa: fora dela, e faixas MAIORES que a autorizada.
        "10.0.1.5",
        "11.0.0.5",
        "10.0.0.0/16",
        "0.0.0.0/0",
    ],
)
def test_alvo_fora_do_escopo_e_recusado(escopo_fronteira, alvo):
    assert escopo_fronteira.contains(alvo) is False


@_pytest.mark.parametrize(
    "alvo",
    [
        "interno.example.com",
        "https://interno.example.com",
        "INTERNO.EXAMPLE.COM",
        "interno.example.com:8443",
        "a.lab.example.com",
        "10.0.0.5",
        "10.0.0.0/24",
        "10.0.0.0/25",
    ],
)
def test_alvo_dentro_do_escopo_e_aceito(escopo_fronteira, alvo):
    assert escopo_fronteira.contains(alvo) is True
