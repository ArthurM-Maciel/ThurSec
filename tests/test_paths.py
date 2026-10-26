"""core.paths — exclusão de caminhos pedida pelo operador."""

import pytest

from thursec.core.paths import is_excluded, parse_excludes


# --- leitura da opção ------------------------------------------------------
def test_parse_aceita_string_da_cli_e_lista_do_python():
    assert parse_excludes("tests/*, docs , *.md") == ("tests/*", "docs", "*.md")
    assert parse_excludes(["tests/*", "docs"]) == ("tests/*", "docs")


@pytest.mark.parametrize("valor", [None, 42, True, "", "  ,  ", {}])
def test_parse_devolve_vazio_para_o_que_nao_sabe_usar(valor):
    assert parse_excludes(valor) == ()


def test_sem_padrao_nada_e_excluido():
    """O padrão é não excluir nada: segredo comitado em teste acontece."""
    assert is_excluded("tests/chaves.py", ()) is False


# --- casamento -------------------------------------------------------------
@pytest.mark.parametrize(
    "relpath",
    [
        "tests/test_x.py",
        "pacote/tests/fixtures/chaves.py",  # aninhado: o caso que falhava
        "a/b/tests/c.py",
    ],
)
def test_padrao_casa_em_qualquer_profundidade(relpath):
    assert is_excluded(relpath, ("tests/*",)) is True


@pytest.mark.parametrize(
    "relpath", ["docs/BACKLOG.md", "sub/docs/x.md", "docs"]
)
def test_nome_de_diretorio_cobre_tudo_abaixo(relpath):
    assert is_excluded(relpath, ("docs",)) is True


@pytest.mark.parametrize(
    "relpath", ["thursec/cli.py", "README.md", "contests/x.py", "src/latest/y.py"]
)
def test_nao_casa_o_que_apenas_contem_o_nome(relpath):
    """'contests' e 'latest' contêm 'tests' — não podem ser excluídos."""
    assert is_excluded(relpath, ("tests/*", "docs")) is False


def test_separador_do_windows_e_normalizado():
    assert is_excluded("pacote\\tests\\x.py", ("tests/*",)) is True
