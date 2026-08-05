"""Hang-safe wrappers around DexKit's decompile API.

⚠ CRITICAL — see CLAUDE.md "Known hang in DAD pipeline" section.

Direct calls to `DexKit.decompile_class` / `decompile_method`
can hang indefinitely in the C++ DAD IR pipeline on a small set of
classes (~12% rate per `intent_filter.apk` / `multiple_locale_appname_test.apk`
sweep when the process happens to hit a worst-case unordered_map iteration
order). The hang is in user-space (R-state, single thread, slow malloc),
so signal-based timeouts inside the C++ release-GIL window don't fire.

These wrappers run the call on a daemon thread and abandon it after the
deadline. The hung thread keeps consuming CPU/memory until the Python
process exits, but the caller continues. ALWAYS use these wrappers from
batch/automation code (sweeps, parity checks, CI). Reach for the raw
binding methods only in interactive single-class debugging.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

DEFAULT_TIMEOUT_S = 10.0


def _run_with_deadline(
    fn: Callable[..., Any],
    *args: Any,
    timeout: float,
    on_timeout: Any,
    **kwargs: Any,
) -> Any:
    result: list[Any] = [None]
    exc: list[BaseException | None] = [None]

    def _worker() -> None:
        try:
            result[0] = fn(*args, **kwargs)
        except BaseException as e:
            exc[0] = e

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        # Thread keeps running (leaked) until process exit — daemon=True
        # means the process can still exit cleanly.
        return on_timeout
    if exc[0] is not None:
        raise exc[0]
    return result[0]


def _bound_decompile(dk: Any, name: str, legacy_name: str) -> Callable[..., Any]:
    """Resolve ``dk``'s decompile entry point, tolerating the pre-rename name.

    ``dk`` is duck-typed, so the raw ``DexKit`` is not the only thing callers
    pass: an out-of-tree stand-in or test double may still implement only the
    legacy ``*_java`` spelling. Falling back keeps those working — without it,
    the very back-compat aliases below would be name-compatible but NOT
    contract-compatible, which is what an alias exists to prevent.
    """
    fn = getattr(dk, name, None)
    if fn is None:
        fn = getattr(dk, legacy_name, None)
    if fn is None:
        raise AttributeError(
            f"{type(dk).__name__} has neither {name} nor {legacy_name}; pass the "
            "raw DexKit (a dexllm.sdk session exposes it as `.raw`)"
        )
    return fn


def _require_text(out: Any, dk: Any, name: str) -> str:
    """Fail loudly when ``dk`` returned something other than Java text.

    A ``dexllm.sdk`` session also has a ``decompile_method`` — but it returns a
    typed model, not ``str``. Without this check that mistake would flow on
    silently (``is_timeout_marker`` isinstance-guards, so it reports False), and
    break far from its origin. Before the rename it was a loud AttributeError.
    """
    if not isinstance(out, str):
        raise TypeError(
            f"{type(dk).__name__}.{name} returned {type(out).__name__}, not str — "
            "the safe wrappers take the raw DexKit (a dexllm.sdk session exposes "
            "it as `.raw`)"
        )
    return out


def safe_decompile_class(
    dk: Any,
    class_descriptor: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> str:
    """Decompile a class with a wall-clock deadline.

    Returns DexKit's Java text on success, or a `// TIMEOUT` marker on
    deadline expiry. Re-raises exceptions other than timeout. ``dk`` must be the
    raw ``DexKit`` (a ``dexllm.sdk`` session exposes it as ``.raw``).
    """
    marker = f"// TIMEOUT after {timeout:.1f}s: {class_descriptor}\n"
    fn = _bound_decompile(dk, "decompile_class", "decompile_class_java")
    return _require_text(
        _run_with_deadline(
            fn,
            class_descriptor,
            timeout=timeout,
            on_timeout=marker,
        ),
        dk,
        "decompile_class",
    )


def safe_decompile_method(
    dk: Any,
    method_descriptor: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> str:
    """Return the method-level counterpart of `safe_decompile_class`."""
    marker = f"// TIMEOUT after {timeout:.1f}s: {method_descriptor}\n"
    fn = _bound_decompile(dk, "decompile_method", "decompile_method_java")
    return _require_text(
        _run_with_deadline(
            fn,
            method_descriptor,
            timeout=timeout,
            on_timeout=marker,
        ),
        dk,
        "decompile_method",
    )


# Back-compat aliases for the names released before the decompile_* family
# dropped its redundant `_java` suffix. Plain module-level aliases are safe here
# (unlike the class-attribute case in sdk/adapter.py) — these are functions, not
# methods, so there is no subclass-override dispatch to bypass.
safe_decompile_class_java = safe_decompile_class
safe_decompile_method_java = safe_decompile_method


def is_timeout_marker(text: str) -> bool:
    """Return True if `text` is a `// TIMEOUT after Ns` deadline marker.

    The marker is produced by the safe wrappers above. Useful for downstream
    classification (sweep/parity) to separate genuine output from deadline
    events.
    """
    return isinstance(text, str) and text.startswith("// TIMEOUT after ")
