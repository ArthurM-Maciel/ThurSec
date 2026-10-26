"""Path exclusion shared by the modules that walk a project tree.

A security scanner pointed at a repository finds its own test fixtures and the
bad-config examples in its documentation. Those matches are *correct* — a fake
AWS key in `tests/` really is an AWS-key-shaped string — but on every audit they
arrive at CRITICAL alongside the real findings and teach the operator to skim
past the severity column.

The fix is an exclusion the operator asks for, never a default: a scanner that
silently skips `tests/` would miss a credential genuinely committed there, which
happens. So the default excludes nothing, and `--opt exclude=` is how you say
"I know what is in there".
"""

from __future__ import annotations

from fnmatch import fnmatch


def parse_excludes(value: object) -> tuple[str, ...]:
    """Read ``--opt exclude=`` into a tuple of glob patterns.

    Accepts a comma-separated string (all ``--opt`` can deliver) or a list, so
    the option is usable from the CLI and from Python.
    """
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = [str(v) for v in value]
    else:
        return ()
    return tuple(p.strip() for p in items if p and p.strip())


def is_excluded(relpath: str, patterns: tuple[str, ...]) -> bool:
    """True when *relpath* matches any pattern.

    Matching is done on the path relative to the scan root, with ``/``
    separators, and reads the way it would in a `.gitignore`: ``tests/*``
    covers nested files, ``*.md`` covers any Markdown file, and a bare
    directory name like ``docs`` covers everything under it.

    Crucially, a pattern matches at **any depth**, not only at the root:
    ``tests/*`` must also silence ``pacote/tests/fixtures/chaves.py``, since a
    repository usually keeps its tests beside each package. Anchored matching
    made the documented ``--opt exclude=tests/*`` silence nothing in exactly
    those repositories.
    """
    if not patterns:
        return False
    normalized = relpath.replace("\\", "/")
    for pattern in patterns:
        p = pattern.strip("/")
        if not p:
            continue
        candidates = (p, f"{p}/*", f"*/{p}", f"*/{p}/*")
        if any(fnmatch(normalized, c) for c in candidates):
            return True
    return False
