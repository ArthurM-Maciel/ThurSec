"""Tests for the i18n foundation (thursec.core.i18n)."""

import pytest

from thursec.core import i18n
from thursec.core.i18n import (
    DEFAULT_LANG,
    L,
    Lf,
    get_lang,
    init_lang_from_env,
    set_lang,
)


@pytest.fixture(autouse=True)
def _restore_lang():
    """Keep each test's language change from leaking into the next one."""
    previous = get_lang()
    try:
        yield
    finally:
        set_lang(previous)


# --- set_lang / get_lang / fallback ---------------------------------------
def test_default_lang_is_pt():
    assert DEFAULT_LANG == "pt"


def test_set_and_get_lang():
    assert set_lang("en") == "en"
    assert get_lang() == "en"
    assert set_lang("pt") == "pt"
    assert get_lang() == "pt"


def test_set_lang_is_case_insensitive_and_trims():
    assert set_lang("  EN ") == "en"
    assert get_lang() == "en"


@pytest.mark.parametrize("bad", ["fr", "", "xx", None, "english"])
def test_set_lang_falls_back_to_pt(bad):
    set_lang("en")  # move away from the default first
    assert set_lang(bad) == "pt"
    assert get_lang() == "pt"


# --- L() -------------------------------------------------------------------
def test_L_returns_pt_by_default():
    set_lang("pt")
    assert L("Porta aberta", "Open port") == "Porta aberta"


def test_L_returns_en_after_set_lang_en():
    set_lang("en")
    assert L("Porta aberta", "Open port") == "Open port"


def test_L_falls_back_to_pt_for_invalid_lang():
    set_lang("klingon")  # -> pt
    assert L("Porta aberta", "Open port") == "Porta aberta"


# --- Lf() ------------------------------------------------------------------
def test_Lf_interpolates_in_active_language():
    set_lang("pt")
    assert Lf("Rodando {n} módulos", "Running {n} modules", n=3) == "Rodando 3 módulos"
    set_lang("en")
    assert Lf("Rodando {n} módulos", "Running {n} modules", n=3) == "Running 3 modules"


# --- init_lang_from_env ----------------------------------------------------
def test_init_lang_from_env_respects_en(monkeypatch):
    monkeypatch.setenv("THURSEC_LANG", "en")
    assert init_lang_from_env() == "en"
    assert get_lang() == "en"


def test_init_lang_from_env_respects_pt(monkeypatch):
    monkeypatch.setenv("THURSEC_LANG", "pt")
    assert init_lang_from_env() == "pt"
    assert get_lang() == "pt"


def test_init_lang_from_env_invalid_falls_back_to_pt(monkeypatch):
    set_lang("en")
    monkeypatch.setenv("THURSEC_LANG", "zz")
    assert init_lang_from_env() == "pt"


def test_init_lang_from_env_unset_leaves_current(monkeypatch):
    monkeypatch.delenv("THURSEC_LANG", raising=False)
    set_lang("en")
    assert init_lang_from_env() == "en"
    assert get_lang() == "en"
