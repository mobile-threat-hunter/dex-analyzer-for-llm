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
not a directory raises; an entry that IS there but is not a regular file — a
directory, a FIFO, a **dangling symlink** — raises naming the path (issue #43: the
test was ``is_file()``, which read all of those as "absent", so an override that
was not really there silently ran the analysis on bundled data); and a file that is
present but malformed raises naming its path, rather than the bare
``JSONDecodeError`` / ``KeyError`` from inside a cached loader that #33 reported.
Two things deliberately do NOT raise: a file genuinely ABSENT from the override
directory (that is what makes per-file replacement work), and an EMPTY
``data_dir`` / ``$DEXLLM_DATA_DIR``, which means "not configured" through both
spellings rather than the process CWD. An override directory that exists but is
EMPTY is therefore *not* an error either — it is indistinguishable from a
deliberate partial override, which is worth knowing because that, rather than a
dangling symlink, is what a failed bind-mount most often leaves behind.

**Caching** is keyed by the ``resolve()``d path, so switching ``data_dir`` between
calls is honoured (the pre-#33 order-dependence is gone) and a relative directory
cannot alias two files onto one entry. Since #43 the per-file **decision to use an
override** is frozen the same way, so a ``rm`` + ``cp`` redeploy cannot demote a
long-running server to bundled data mid-request; a bundled FALLBACK is re-decided
every call, so an override appearing later is picked up, and one transient failure
cannot pin bundled data for the life of the process. Changing what is at a frozen
path — editing the bytes, or replacing the file — needs
:func:`clear_data_caches`; a frozen file that is DELETED keeps serving while its
content is cached and then falls back, rather than raising forever. Whether the override DIRECTORY still exists is checked
live on every call, deliberately: that asymmetry is what keeps an unmounted volume
loud while keeping a chosen override stable.
"""

from __future__ import annotations

import errno
import json
import os
import stat
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

# (resolved override root, filename) -> the resolved OVERRIDE path that decision
# produced. Only the override direction is frozen; see `resolve_data_file`. Bounded
# by the same rule and for the same reason as `_CACHE` — the key carries a
# caller-supplied path — though its key space is narrower (an entry per override
# directory that actually HELD the file, never a bundled fallback).
_RESOLVED: dict[tuple[str, str], Path] = {}


def _evict(cache: dict) -> None:
    """Drop oldest-first until there is room for one more (dicts keep order)."""
    while len(cache) >= _MAX_CACHE_ENTRIES:
        # the two `None` defaults do not make this atomic — `next(iter(...))` can
        # still race a concurrent write — but they turn the commonest interleaving
        # from a KeyError into a no-op. The residual race is pre-existing.
        cache.pop(next(iter(cache), None), None)


def _override_is_usable(candidate: Path, source: str, shown: Path) -> bool:
    """Report whether ``candidate`` is a usable regular file, or nothing at all.

    Raises ``OSError`` for anything in between — a directory, a FIFO, a dangling
    symlink, a symlink loop, a symlink to any of those — because "not a regular
    file" is a misconfiguration, not the partial-override case (issue #43).
    ``shown`` is the path the message names: for a frozen decision ``candidate`` is
    the resolved target, and blaming that would name neither the file nor the
    directory the operator configured.

    **The good answers cost ONE syscall**, deliberately. ``stat`` follows links, so
    a regular file and a symlink to one — the two configurations that work — are
    each decided by it alone, with no window for a concurrent writer to change the
    answer between two calls. The earlier cut asked ``is_file()`` then
    ``os.path.lexists()``, which disagreed with each other across the ``rm`` and
    the ``cp`` of a redeploy and raised about a perfectly good file (an adversarial
    review measured 13,435 such raises in 12 s against a concurrent rewriter; this
    ordering measures 0). The second call below runs only once the first has
    already said "not usable", and treats a file that REAPPEARED in between as
    usable rather than as a fault.

    **What is still indistinguishable at an instant:** a symlink whose TARGET is
    being replaced looks exactly like a dangling one, so a request landing in that
    window raises. Nothing observable separates the two — only the operator knows
    whether the target is coming back — and preferring the other interpretation
    would defeat the dangling-symlink detection this exists for. Relinking (a
    blue/green swap of the LINK) has no such window.
    """
    try:
        st = candidate.stat()  # follows the link: both working shapes, one call
    except FileNotFoundError:
        st = None  # absent, or a link whose target is not there
    except OSError as exc:
        if exc.errno != errno.ELOOP:
            raise  # EACCES / ENOTDIR / …: the OS's own report, not our verdict
        st = None
    if st is not None and stat.S_ISREG(st.st_mode):
        return True

    # Not usable as it stands. One lstat now says whether anything is there at all
    # — and catches the case where the file came back while we were asking.
    try:
        lst = candidate.lstat()
    except FileNotFoundError:
        return False  # genuinely absent -> the supported partial-override case
    if stat.S_ISREG(lst.st_mode):
        return True  # recreated between the two calls: a rewrite, not a fault
    raise OSError(
        f"{str(shown)!r} is present but is not a regular file (or is "
        f"a symlink that does not resolve to one), so it cannot be read as the "
        f"override for {shown.name} (from {source}); remove it or point it at "
        f"a real file — falling back to the bundled data here would run the "
        f"analysis on data you did not configure"
    )


def resolve_data_file(filename: str, data_dir: str | os.PathLike | None = None) -> Path:
    """Return the path ``filename`` should be read from (arg -> env -> bundled).

    **Once an override has been chosen it stays chosen** (issue #43). Resolution
    used to run per call, so a redeploy doing ``rm`` + ``cp`` had a window in which
    requests silently switched between the override and the bundled dataset —
    answering with different ``family`` labels from one request to the next.
    Caching the bytes while re-deciding their SOURCE every call was the
    inconsistency.

    Only the OVERRIDE direction is frozen. A **bundled fallback is re-decided every
    call**, deliberately: freezing it would turn a transient wrong answer into a
    permanent one — a single request landing inside the ``rm`` window would pin
    bundled data for the life of the process, which is the failure #43 reports made
    sticky. So an override file ADDED later IS picked up, while one REMOVED later
    does not silently demote a running server — until its cached content is gone
    too, at which point the decision has nothing left to serve and is dropped so
    the call re-decides. Handing back a dead path instead would make a deliberate
    `rm` a permanent error for that directory, decided by invisible cache
    pressure, which is the same stickiness the bundled direction is spared.

    Two things it does NOT do, both requiring :func:`clear_data_caches`: a frozen
    override is not re-read when its bytes change (that is the content cache's rule,
    unchanged), and it is not re-decided if the file is replaced by a DIFFERENT
    file at the same path — including through a repointed symlink, since the frozen
    value is fully resolved. Live reload was never a requested behaviour; stability
    across a redeploy is what a long-lived server needs.

    **Scope of the guarantee: the memo is bounded** (``_MAX_CACHE_ENTRIES``), so a
    caller rotating more override directories than that re-decides the evicted
    ones. The realistic deployments — one process-wide ``$DEXLLM_DATA_DIR``, or a
    handful of explicit directories — never reach it.

    Args:
        filename: the bare data-file name, e.g. ``"content_uris.json"``.
        data_dir: an explicit override directory; falls back to ``$DEXLLM_DATA_DIR``
            and then to the bundled ``data/`` directory. ``None`` and ``""`` both
            mean "not configured". Pass one of those for an unset config value —
            ``Path("")`` will NOT do, because pathlib turns it into ``Path(".")``
            before this function sees it, and that is a real request for the
            process CWD which nothing here can tell apart from a deliberate one.

    Raises:
        NotADirectoryError: if an override directory was named but does not exist.
            A typo'd path silently serving bundled data is the failure this
            prevents; a file merely missing INSIDE a valid directory is the
            supported partial-override case and falls back instead.
        OSError: if the override entry EXISTS but is not a regular file — see
            :func:`_override_is_usable`. The old test was ``is_file()``, which read
            a directory, a FIFO and a dangling symlink alike as "absent" and fell
            back, so an override that was not really there served bundled data
            while the operator believed it was live (issue #43). NOTE the shape it
            does NOT catch: an override directory that exists but is EMPTY — which
            is what a failed bind-mount usually leaves behind — is indistinguishable
            from a deliberate partial override, so it still falls back.
    """
    # An EMPTY value means "not configured" through BOTH spellings, so an unset
    # config variable threaded in as `data_dir=""` does not silently become the
    # process CWD (`Path("")` is `Path(".")`) — the same silent-wrong-source
    # failure the raises below exist to prevent, and the env branch already read
    # `""` as unset, so this also removes an asymmetry.
    #
    # The rule covers the `str` spelling only, and CANNOT be extended to
    # `Path("")`: pathlib collapses that to `Path(".")` at CONSTRUCTION, before
    # this function is called, so it arrives indistinguishable from a deliberate
    # `Path(".")` — which is a legitimate request. Normalising with `os.fspath`
    # here looks like it would help and provably does not (it yields `"."`); the
    # rule is stated in the docstring instead. Pass `None` or `""`.
    root = data_dir if data_dir else os.environ.get(ENV_VAR) or ""
    if not root:
        return _BUNDLED_DIR / filename

    source = "data_dir=" if data_dir else "$" + ENV_VAR
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(
            f"data directory {str(root)!r} does not exist or is not a "
            f"directory (from {source})"
        )
    # resolve() the ROOT so two spellings of one directory share a decision — and
    # so the memo VALUE below is absolute. Keying on the resolved path while
    # storing the spelled one would let a relative `data_dir` freeze a CWD-relative
    # answer that a later call re-anchors somewhere else entirely (adversarial
    # review: cwd=/a `data_dir="cfg"`, then cwd=/b `data_dir="/a/cfg"` served /b's
    # file — the very aliasing the content cache resolves its key to prevent).
    root_resolved = root_path.resolve()
    memo = (str(root_resolved), filename)
    frozen = _RESOLVED.get(memo)
    candidate = root_resolved / filename
    if frozen is not None:
        # The decision stands, but re-check its KIND: if something that is not a
        # regular file has since been put at that path, hand back a raise rather
        # than a path the loader would `read_bytes()` — a FIFO there blocks a
        # server thread forever. `candidate` is what the message names: `frozen` is
        # the resolved TARGET, which for a symlinked override is neither the file
        # nor the directory the operator configured.
        if _override_is_usable(frozen, source, candidate):
            return frozen
        # The frozen file is GONE. Keep the freeze while its content is still
        # cached — that IS the stability this exists for. Once the content has been
        # evicted too the decision has nothing left to serve, so drop it and
        # re-decide rather than hand back a path whose read can only raise: the two
        # dicts are bounded independently, and which of a silent stale answer or a
        # hard FileNotFoundError an operator got would otherwise be decided by
        # invisible cache pressure.
        if str(frozen) in _CACHE:
            return frozen
        del _RESOLVED[memo]

    if not _override_is_usable(candidate, source, candidate):
        return _BUNDLED_DIR / filename  # NOT memoised — see the docstring

    resolved = candidate.resolve()
    if resolved.is_symlink() or not resolved.is_file():
        # `Path.resolve()` is NON-STRICT: if the entry vanished between the check
        # above and this call it hands back the SPELLED path, and freezing a LINK
        # would make a later relink switch datasets — the exact opposite of the
        # guarantee. Skip the freeze this once and let the next call re-decide; a
        # transient miss is recoverable, a frozen wrong answer is not.
        return candidate
    _evict(_RESOLVED)
    _RESOLVED[memo] = resolved
    return resolved


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
        NotADirectoryError: see :func:`resolve_data_file`. Note that the DIRECTORY
            check runs BEFORE any cache or memo lookup, so neither a cached copy
            nor a frozen per-file decision masks a now-broken ``data_dir`` (an
            unmounted config volume fails loudly rather than silently serving what
            it served an hour ago).
        OSError: raised by :func:`resolve_data_file` for an override entry that is
            not a regular file, and otherwise propagated from the filesystem —
            e.g. ``PermissionError`` for an unreadable override directory, or
            ``FileNotFoundError`` if a frozen decision outlives both the file and
            its cached content. That last one is loud by design: a removed
            override must never degrade into silently answering from bundled data.
            Only the two above are part of the documented contract; the rest are
            whatever the OS reports.
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
        _evict(_CACHE)
        _CACHE[key] = obj
    elif validate is not None:
        validate(_CACHE[key], path)
    return _CACHE[key]


def clear_data_caches() -> None:
    """Drop this module's parsed data AND its frozen override decisions.

    Switching ``data_dir`` does not need this (both are keyed by path); changing
    what is at a path during a long-running process does — editing a file in
    place, and since issue #43 also REPLACING or REMOVING a file an override
    decision has already frozen on. Adding one does not: a bundled fallback is
    re-decided every call, so a newly-appearing override is picked up on its own.

    Scope is the two files in this channel (``android_api_map.json`` /
    ``content_uris.json``). The permission tables are cached separately by
    :mod:`dexllm.dangerous_api` behind its own ``lru_cache`` and are not in this
    channel at all.
    """
    _CACHE.clear()
    _RESOLVED.clear()
