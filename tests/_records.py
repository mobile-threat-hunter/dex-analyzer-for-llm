"""ONE walker over every public record in the package — and ONE skip policy.

Two audits need it: dexllm#68's `signature`-is-reserved / descriptor-valued pair
in [test_sdk.py](test_sdk.py), and dexllm#69's vocabulary set in
[test_record_vocabulary.py](test_record_vocabulary.py). It lived privately in the
first and was re-implemented, WEAKER, in the second — a correctness reviewer found
the copy blind to `NamedTuple` records (the exact hole a dexllm#68 reviewer had
already had to construct against the original) and hard-failing on a module whose
optional extra is absent, which is the CI shape.

So it is one module, imported by both, and an IDENTITY guard pins that they share
it — a correct COPY passes every behavioural test and drifts on the first edit,
which is the `_callers.py` / `_argkinds.py` precedent this repo already applies to
production code.
"""

from __future__ import annotations

import dataclasses
import importlib
import pkgutil

#: Modules that need an OPTIONAL extra and may legitimately be absent, so the scan
#: is allowed to skip them. Anything else failing to import is a broken import, not
#: a smaller API, and must not shrink an audit silently. CI installs `.[ioc]` only,
#: so BOTH of these are absent there.
OPTIONAL_MODULES = frozenset({"dexllm.mcp_server", "dexllm.server"})


def _is_record(t) -> bool:
    """A dataclass OR a NamedTuple — both are public record shapes here."""
    return dataclasses.is_dataclass(t) or (
        isinstance(t, type) and issubclass(t, tuple) and hasattr(t, "_fields")
    )


def _fields_of(t) -> set[str]:
    if dataclasses.is_dataclass(t):
        return set(t.__dataclass_fields__)
    return set(t._fields)


def public_record_attrs():
    """``({'raw.X' | '<module>.X': {attrs}}, [(skipped_module, reason)])``.

    Every pybind record plus EVERY dataclass / NamedTuple in the package — WALKED
    rather than hand-listed, because a hand list is how `dexllm.capability.ApiUsage`
    (a public record, the raw counterpart of the SDK's `ApiUsage`) would sit outside
    an audit while looking covered.
    """
    import dexllm
    from dexllm import _dexkit_core as core

    out: dict[str, set[str]] = {}
    skipped: list[tuple[str, str]] = []
    for n in dir(core):
        t = getattr(core, n)
        if n.startswith("_") or n == "DexKit" or not isinstance(t, type):
            continue
        out[f"raw.{n}"] = {a for a in dir(t) if not a.startswith("_")}
    for m in pkgutil.walk_packages(dexllm.__path__, "dexllm."):
        try:
            mod = importlib.import_module(m.name)
        except ImportError as e:  # an optional extra is not installed
            skipped.append((m.name, str(e)))
            continue
        for n in dir(mod):
            t = getattr(mod, n)
            if n.startswith("_") or not isinstance(t, type):
                continue
            if getattr(t, "__module__", "") != m.name or not _is_record(t):
                continue
            out[f"{m.name}.{n}"] = _fields_of(t)
    return out, skipped


def assert_skips_are_optional(skipped):
    """A module the scan could not import is one it did not audit.

    An optional extra may be absent; anything else is a broken import, not a
    smaller API, and must fail loudly rather than shrink the scan. The exception
    is EARNED, not merely listed: when the extra IS installed the module must
    genuinely declare no record, or listing it would hide one from the audit in
    any environment lacking the extra.
    """
    for name, err in skipped:
        assert name in OPTIONAL_MODULES, f"{name} failed to import: {err}"
    for name in sorted(OPTIONAL_MODULES):
        try:
            mod = importlib.import_module(name)
        except ImportError:
            continue  # the extra is absent here; nothing to verify
        declared = [
            n
            for n in dir(mod)
            if not n.startswith("_")
            and isinstance(getattr(mod, n), type)
            and getattr(getattr(mod, n), "__module__", "") == name
            and _is_record(getattr(mod, n))
        ]
        assert not declared, (
            f"{name} is listed as an optional module the audit may skip, but it "
            f"declares records {declared} — they would be unaudited without the extra"
        )
