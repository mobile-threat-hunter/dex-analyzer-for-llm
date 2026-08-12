"""Resolution of the bundled analysis data files, and the user override channel.

Two of the four files in ``data/`` carry HAND JUDGEMENT rather than mechanical
extraction — the capability catalog (``android_api_map.json``) and the ``family``
labels in ``content_uris.json`` — so a consumer legitimately wants to adjust them
for their own triage vocabulary. Before issue #33 they could not: both were module
constants, and monkeypatching one worked only before the first call because the
caches were module globals with no invalidation.

This module is that channel. Resolution is **arg -> env -> bundled**::

    summarize_capabilities(dk, data_dir="/etc/dexllm")   # explicit
    $DEXLLM_DATA_DIR=/etc/dexllm                          # process-wide
    (neither)                                             # the bundled file

The env var exists because it is the only form that also reaches the MCP and HTTP
servers, which take no such argument.

**Per-file replacement, not overlay.** A file found in the override directory is
used INSTEAD of the bundled one; a file absent there falls back to the bundle. So
overriding the catalog does not oblige you to also copy the 209-entry provider
dataset. Replacement (rather than merging user entries over bundled ones) is the
right semantics here because both files are small enough to copy and edit whole,
and because a merge would have to invent a per-key precedence rule that neither
file's schema expresses. The 5,150-row permission table is NOT in this channel for
exactly the opposite reason — it is mechanical AOSP extraction with no hand
content, and ``dataset_path=`` / ``$DEXLLM_AOSP_DATASET`` already serve its real
use case (a fresher AOSP snapshot).

**Failure modes are loud where they can be.** A ``data_dir`` that is named but is
not a directory raises, and a file that IS present but malformed raises naming its
path — rather than the bare ``JSONDecodeError`` / ``KeyError`` from inside a cached
loader that #33 reported. Two things deliberately do NOT raise: a file merely
ABSENT from the override directory (that is what makes per-file replacement work),
and an EMPTY ``data_dir`` / ``$DEXLLM_DATA_DIR``, which means "not configured"
through both spellings rather than the process CWD.

**Caching** is keyed by the ``resolve()``d path, so switching ``data_dir`` between
calls is honoured (the pre-#33 order-dependence is gone) and a relative directory
cannot alias two files onto one entry. Editing a file in place while the process
runs still serves the cached copy; call :func:`clear_data_caches` for that.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

__all__ = ["ENV_VAR", "clear_data_caches", "load_data_json", "resolve_data_file"]

ENV_VAR = "DEXLLM_DATA_DIR"

_BUNDLED_DIR = Path(__file__).parent / "data"

# resolved path -> the parsed, validated object, insertion-ordered so the oldest
# entry is evicted first. BOUNDED: the key is a caller-supplied path, not a file
# name, so a per-request or per-tenant `data_dir` grows this linearly (measured:
# 300 directories -> 600 entries, +44 MB). This repo has already shipped that bug
# once at 1.6 GB (`kMaxDeclaredIds`), and the sibling permission loader in
# `dangerous_api.py` bounds itself the same way with `lru_cache(maxsize=8)`.
# 16 = the 4 bundled files plus room for a few live overrides; a working set
# larger than this still WORKS, it just re-reads.
_MAX_CACHE_ENTRIES = 16
_CACHE: dict[str, Any] = {}


def resolve_data_file(filename: str, data_dir: str | os.PathLike | None = None) -> Path:
    """Return the path ``filename`` should be read from (arg -> env -> bundled).

    Args:
        filename: the bare data-file name, e.g. ``"content_uris.json"``.
        data_dir: an explicit override directory; falls back to ``$DEXLLM_DATA_DIR``
            and then to the bundled ``data/`` directory.

    Raises:
        NotADirectoryError: if an override directory was named but does not exist.
            A typo'd path silently serving bundled data is the failure this
            prevents; a file merely missing INSIDE a valid directory is the
            supported partial-override case and falls back instead.
    """
    # An EMPTY value means "not configured" through BOTH spellings. `Path("")` is
    # `Path(".")`, so testing `is not None` would silently make an unset config
    # variable threaded in as `data_dir=""` mean the process CWD — the same
    # silent-wrong-source failure the raise below exists to prevent, and the env
    # branch already treated `""` as unset, so this also removes an asymmetry.
    root = data_dir if data_dir else os.environ.get(ENV_VAR) or None
    if root is not None:
        root_path = Path(root)
        if not root_path.is_dir():
            raise NotADirectoryError(
                f"data directory {str(root)!r} does not exist or is not a "
                f"directory (from {'data_dir=' if data_dir else '$' + ENV_VAR})"
            )
        candidate = root_path / filename
        if candidate.is_file():
            return candidate
    return _BUNDLED_DIR / filename


def load_data_json(
    filename: str,
    *,
    data_dir: str | os.PathLike | None = None,
    validate: Callable[[Any, Path], None] | None = None,
) -> Any:
    """Load and cache a data file, resolved through the override channel.

    Args:
        filename: the bare data-file name.
        data_dir: see :func:`resolve_data_file`.
        validate: called as ``validate(obj, path)``; it should raise ``ValueError``
            naming ``path`` if the shape is wrong. Runs on EVERY call, not only on
            the first load — the validator is not part of the cache key, so
            checking once would let a call that passed no validator (this helper is
            public) permanently disable validation for that path. The data files
            are small, so re-checking is cheap.

    Raises:
        ValueError: if the file is not valid JSON, or ``validate`` rejects it.
        NotADirectoryError: see :func:`resolve_data_file`. Note that resolution
            runs BEFORE the cache lookup, so a cached copy never masks a
            now-broken ``data_dir`` (an unmounted config volume fails loudly
            rather than silently serving what it served an hour ago).
        OSError: propagated from the filesystem — e.g. ``PermissionError`` for an
            unreadable override directory. Only the two above are part of the
            documented contract; the rest are whatever the OS reports.
    """
    path = resolve_data_file(filename, data_dir)
    # resolve() so the key is a stable file identity: a RELATIVE `data_dir` is
    # CWD-dependent, so the spelled path would let two different files collide on
    # one entry after a chdir (and one file occupy two entries when spelled two
    # ways).
    key = str(path.resolve())
    if key not in _CACHE:
        try:
            # `json.loads` on bytes sniffs the encoding, so a non-UTF-8 file raises
            # UnicodeDecodeError, NOT JSONDecodeError — catching only the latter
            # would let a bare decoder error escape unnamed, which is the failure
            # this wrapper exists to remove.
            obj = json.loads(path.read_bytes())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"{path} is not valid JSON: {exc}") from exc
        if validate is not None:
            validate(obj, path)
        while len(_CACHE) >= _MAX_CACHE_ENTRIES:
            _CACHE.pop(next(iter(_CACHE)))  # oldest first (dicts keep insertion order)
        _CACHE[key] = obj
    elif validate is not None:
        validate(_CACHE[key], path)
    return _CACHE[key]


def clear_data_caches() -> None:
    """Drop this module's parsed-data cache so edited files are re-read.

    Switching ``data_dir`` does not need this (the cache is keyed by path); editing
    a file in place during a long-running process does.

    Scope is the two files in this channel (``android_api_map.json`` /
    ``content_uris.json``). The permission tables are cached separately by
    :mod:`dexllm.dangerous_api` behind its own ``lru_cache`` and are not in this
    channel at all.
    """
    _CACHE.clear()
