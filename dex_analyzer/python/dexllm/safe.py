"""Hang-safe wrappers around DexKit's decompile API.

⚠ CRITICAL — see CLAUDE.md "Known hang in DAD pipeline" section.

Direct calls to `DexKit.decompile_class_java` / `decompile_method_java`
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


def safe_decompile_class_java(
    dk: Any,
    class_descriptor: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> str:
    """Decompile a class with a wall-clock deadline.

    Returns DexKit's Java text on success, or a `// TIMEOUT` marker on
    deadline expiry. Re-raises exceptions other than timeout.
    """
    marker = f"// TIMEOUT after {timeout:.1f}s: {class_descriptor}\n"
    return _run_with_deadline(
        dk.decompile_class_java, class_descriptor,
        timeout=timeout, on_timeout=marker,
    )


def safe_decompile_method_java(
    dk: Any,
    method_descriptor: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> str:
    """Method-level counterpart of `safe_decompile_class_java`."""
    marker = f"// TIMEOUT after {timeout:.1f}s: {method_descriptor}\n"
    return _run_with_deadline(
        dk.decompile_method_java, method_descriptor,
        timeout=timeout, on_timeout=marker,
    )


def is_timeout_marker(text: str) -> bool:
    """True if `text` is one of the `// TIMEOUT after Ns` markers produced
    by the safe wrappers above. Useful for downstream classification
    (sweep/parity) to separate genuine output from deadline events."""
    return isinstance(text, str) and text.startswith("// TIMEOUT after ")
