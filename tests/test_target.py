"""Tests for the shared target validator (argument-injection defense)."""

import pytest

from thursec.core.target import TargetError, looks_like_local_path, validate_target


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


# --- caminho local vs alvo de rede -----------------------------------------
@pytest.mark.parametrize(
    "alvo",
    [".", "..", "./repo", "../repo", "/tmp/projeto", "~/dev/raio"],
)
def test_reconhece_caminho_local(alvo):
    assert looks_like_local_path(alvo) is True


def test_caminho_relativo_sem_prefixo_decide_pela_existencia(tmp_path, monkeypatch):
    """'a/b' tem a mesma forma de 'host/path': quem decide é existir no disco."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()

    assert looks_like_local_path("a/b") is True
    assert looks_like_local_path("nao/existe") is False


@pytest.mark.parametrize(
    "alvo",
    [
        "example.com",
        "sub.example.com",
        "nginx:1.18.0",
        "http://127.0.0.1:8000",
        "https://example.com/a/b",
        "10.0.0.5",
        "localhost:8000",
        "backoffice",
        "",
    ],
)
def test_nao_confunde_alvo_de_rede_com_caminho(alvo):
    assert looks_like_local_path(alvo) is False


def test_um_diretorio_homonimo_nao_sequestra_um_host(tmp_path, monkeypatch):
    """Host interno não vira 'caminho' só porque existe pasta com o mesmo nome.

    'backoffice' é um hostname válido — e varrer um host de verdade importa
    mais do que silenciar o ruído de um diretório homônimo. Para auditar a
    pasta, use './backoffice'.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "backoffice").mkdir()

    assert looks_like_local_path("backoffice") is False
    assert looks_like_local_path("./backoffice") is True
    assert looks_like_local_path("https://backoffice/") is False


@pytest.mark.parametrize(
    "alvo",
    [
        "10.0.0.0/24",            # CIDR — barra não faz dele caminho
        "192.168.56.0/24",
        "example.com/admin",      # host com path
        "host.lab.example:8443/",
        "https://example.com/a",
    ],
)
def test_alvo_de_rede_com_barra_nao_e_caminho(alvo):
    """Pular em silêncio um alvo válido é falso negativo — pior que ruído."""
    assert looks_like_local_path(alvo) is False
    # E segue sendo um alvo que o validador aceita.
    validate_target(alvo)
