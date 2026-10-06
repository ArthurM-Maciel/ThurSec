"""Internationalization (i18n) foundation for ThurSec.

This module is the base every other module, the CLI, the TUI and the dashboard
build on to display text in the operator's language. It is deliberately tiny and
dependency-free: there is **no central catalogue** of message keys. Instead,
translations live *co-located* with the code that uses them, written inline at
the call site with :func:`L`.

The project supports two languages: Portuguese (``"pt"``, the default) and
English (``"en"``). The active language is process-global state, set once (from
``--lang`` or the ``THURSEC_LANG`` environment variable) and read everywhere.

How to write visible text
-------------------------
**Every** string a human sees — finding titles, descriptions and
recommendations, CLI help and output, error messages, TUI/dashboard labels —
MUST be wrapped in :func:`L`, giving the Portuguese text first and the English
text second::

    from thursec.core.i18n import L

    title = L("Porta aberta", "Open port")
    print(L("Nenhum alvo encontrado", "No target found"))

:func:`L` returns whichever string matches the active language. For messages
with interpolation, prefer :func:`Lf`, which runs ``str.format`` on the chosen
string::

    from thursec.core.i18n import Lf

    print(Lf("Rodando {n} módulo(s) contra {t}",
             "Running {n} module(s) against {t}", n=3, t="x.example"))

Setting the language
--------------------
* :func:`set_lang` — set the active language (``"pt"`` or ``"en"``); anything
  else falls back to ``"pt"`` silently (no exception, no stderr noise).
* :func:`get_lang` — read the active language.
* :func:`init_lang_from_env` — adopt ``THURSEC_LANG`` if it is set; otherwise
  leave the current language untouched.
"""

from __future__ import annotations

import os

__all__ = [
    "DEFAULT_LANG",
    "SUPPORTED_LANGS",
    "L",
    "Lf",
    "get_lang",
    "set_lang",
    "init_lang_from_env",
]

DEFAULT_LANG = "pt"
SUPPORTED_LANGS = ("pt", "en")

_LANG = DEFAULT_LANG


def set_lang(lang: str) -> str:
    """Set the active language and return the value actually applied.

    Accepts only ``"pt"`` and ``"en"`` (case-insensitive, surrounding
    whitespace ignored). Any other value — including ``None`` or an empty
    string — falls back to :data:`DEFAULT_LANG` (``"pt"``) silently: no
    exception is raised and nothing is written to stderr, so callers can feed it
    untrusted input (an env var, a CLI flag) without guarding it.
    """
    global _LANG
    normalized = (lang or "").strip().lower()
    _LANG = normalized if normalized in SUPPORTED_LANGS else DEFAULT_LANG
    return _LANG


def get_lang() -> str:
    """Return the active language code (``"pt"`` or ``"en"``)."""
    return _LANG


def L(pt: str, en: str) -> str:
    """Return ``pt`` or ``en`` according to the active language.

    This is the one function every visible string in the project goes through.
    Write the Portuguese text first and the English text second::

        L("Porta aberta", "Open port")
    """
    return en if _LANG == "en" else pt


def Lf(pt: str, en: str, **kwargs: object) -> str:
    """Like :func:`L`, but ``str.format(**kwargs)`` the chosen string.

    Convenient for interpolated messages, keeping both translations' placeholder
    names aligned::

        Lf("Relatório salvo em {path}", "Report written to {path}", path=p)
    """
    return L(pt, en).format(**kwargs)


def init_lang_from_env(var: str = "THURSEC_LANG") -> str:
    """Set the language from the environment if ``var`` is defined.

    Reads ``THURSEC_LANG`` (``pt``/``en``) and applies it through
    :func:`set_lang`, so an unsupported value falls back to ``"pt"``. If the
    variable is unset, the current language is left unchanged. Returns the
    active language after the call.
    """
    value = os.environ.get(var)
    if value is not None:
        return set_lang(value)
    return get_lang()
