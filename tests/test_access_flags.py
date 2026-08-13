"""Method access flags are the dex's OWN bits — no java.lang.reflect.Modifier rewrite.

Upstream DexKit rewrote ``ACC_DECLARED_SYNCHRONIZED`` (0x20000) to
``ACC_SYNCHRONIZED`` (0x20) while parsing ``class_data``, for compatibility with
``java.lang.reflect.Modifier``. dexllm removed that rewrite, because:

* it is **lossy** — in dex, 0x20 means JNI ``synchronized native``, a different
  property, so the rewritten value conflates two distinct facts and drops one
  when a method carries both bits;
* it made one method describe itself two ways — ``get_class_summary`` said
  ``synchronized`` while the decompiler (which read a second, raw copy of the
  same vector) emitted ``declared_synchronized``.

Removing it also retired the whole ``method_raw_access_flags`` duplicate vector.
These tests pin the resulting contract from the Python side.

**Corpus dependency is a SKIP, never a failure.** "This APK declares a
synchronized method" is a property of the sample, not of the code under test,
and ``$DEXLLM_TEST_APK`` (a documented override, see conftest) can narrow the
fixtures to an APK that has none — 8 of the 22 bundled APKs do. A test that
asserted on it would report "the rewrite is back" for an environment change.
The discriminator used instead is ``decompile_method_ast``, which reads the same
flags through the DAD path and reported the raw form under BOTH behaviours: if a
method exists whose AST says ``declared_synchronized``, the summary must agree.
"""

from __future__ import annotations

import pytest

ACC_SYNCHRONIZED = 0x20
ACC_DECLARED_SYNCHRONIZED = 0x20000
_EITHER_SYNC = ACC_SYNCHRONIZED | ACC_DECLARED_SYNCHRONIZED

# native/dad_cpp/util.cpp AccessFlagsMethodsTable (DAD util.py:67), which is what
# decompile_method_ast()["access"] renders. Kept in step with that table — note
# 0x200/0x2000/0x4000 are absent there too (faithful to androguard), and the C++
# emits "unkn_<flag>" for those; see _ast_modifiers.
_METHOD_FLAG_NAMES = {
    0x1: "public",
    0x2: "private",
    0x4: "protected",
    0x8: "static",
    0x10: "final",
    0x20: "synchronized",
    0x40: "bridge",
    0x80: "varargs",
    0x100: "native",
    0x400: "abstract",
    0x800: "strictfp",
    0x1000: "synthetic",
    0x10000: "constructor",
    0x20000: "declared_synchronized",
}


def _ast_modifiers(ast) -> set[str]:
    """Named modifiers from an AST ``access`` list.

    ``GetAccessImpl`` walks ACCESS_ORDER, which carries three bits the name
    table has no entry for (0x200/0x2000/0x4000), and emits ``unkn_<flag>`` for
    them. Method access flags are NOT validated by the structural verifier
    (docs/dexkit-vs-art-dex-handling.md), so a crafted or obfuscated dex can set
    them; drop those so this suite compares only the named bits it models.
    """
    return {a for a in ast["access"] if not a.startswith("unkn_")}


def _sync_candidates(dk, limit=None):
    """(class, method) for every method carrying EITHER synchronized bit.

    Non-empty under both behaviours for a genuinely synchronized method (0x20
    under the rewrite, 0x20000 without it), so an empty result means the sample
    has no such method — not that a regression occurred.
    """
    out = []
    for cls in dk.list_classes():
        try:
            summary = dk.get_class_summary(cls)
        except Exception:
            continue
        for m in summary.methods:
            if m.access_flags & _EITHER_SYNC:
                out.append((cls, m))
                if limit is not None and len(out) >= limit:
                    return out
    return out


def test_declared_synchronized_bit_survives_class_summary(loadable_apks):
    """A method the DAD path calls ``declared_synchronized`` must report 0x20000.

    Fails against the pre-removal build: there the AST said
    ``declared_synchronized`` (it read the raw copy) while the summary reported
    0x20. Skips — rather than failing — when the sample has no synchronized
    method at all, which is a property of the APK, not of the parser.
    """
    import dexllm

    checked = 0
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for cls, m in _sync_candidates(dk):
            ast = dk.decompile_method_ast(
                f"{cls}->{m.name}{m.proto}", include_source=False
            )
            if not ast["found"] or "declared_synchronized" not in ast["access"]:
                continue  # a genuine JNI synchronized-native method, or bodiless
            checked += 1
            assert m.access_flags & ACC_DECLARED_SYNCHRONIZED, (
                f"{apk}: {cls}->{m.name}{m.proto} is declared_synchronized per the "
                f"decompiler but the summary reports {m.access_flags:#x} — the "
                f"java.lang.reflect.Modifier rewrite is back"
            )
    if not checked:
        pytest.skip("no declared-synchronized method in the available APK(s)")


def test_declared_synchronized_is_not_rewritten_to_synchronized(dk):
    """The rewrite was ``(flags ^ 0x20000) | 0x20``; assert neither half happened.

    A dex method may legitimately carry 0x20 (JNI synchronized-native), so this
    checks the two bits are reported independently rather than banning 0x20.
    """
    found = [
        (c, m)
        for c, m in _sync_candidates(dk, limit=200)
        if m.access_flags & ACC_DECLARED_SYNCHRONIZED
    ]
    if not found:
        pytest.skip("this APK declares no synchronized methods")
    for cls, m in found:
        assert not (m.access_flags & ACC_SYNCHRONIZED), (
            f"{cls}->{m.name}{m.proto} carries both 0x20000 and 0x20 "
            f"({m.access_flags:#x}) — the rewrite's `| 0x20` half is back"
        )


def test_summary_flags_agree_with_the_decompiler_modifiers(dk):
    """Cross-layer oracle: the summary bits and the AST modifier names must agree.

    ``get_class_summary`` and ``decompile_method_ast`` read the same vector by
    two different routes (``DexKitExt`` and the DAD adapter). Before the removal
    those routes read two DIFFERENT vectors and disagreed for every declared-
    synchronized method. This decodes the summary bits with the AST's own name
    table and compares, so it fails on any such divergence, not only that one.

    The sample is stratified — a broad head-of-corpus slice PLUS every method
    carrying either sync bit — because scoping it to declared-synchronized
    methods makes it vacuous exactly when the rewrite is present. ``sync_checked``
    is asserted separately: the aggregate count is satisfiable by the broad slice
    alone, so it would not prove the sync stratum was ever reached.
    """
    sample, broad = [], 0
    for cls in dk.list_classes():
        try:
            summary = dk.get_class_summary(cls)
        except Exception:
            continue
        for m in summary.methods:
            if m.access_flags & _EITHER_SYNC:
                sample.append((cls, m))
            elif broad < 400:
                sample.append((cls, m))
                broad += 1

    checked = sync_checked = 0
    for cls, m in sample:
        ast = dk.decompile_method_ast(f"{cls}->{m.name}{m.proto}", include_source=False)
        if not ast["found"]:
            continue
        expected = {
            name for bit, name in _METHOD_FLAG_NAMES.items() if m.access_flags & bit
        }
        assert expected == _ast_modifiers(ast), (
            f"{cls}->{m.name}{m.proto}: summary {m.access_flags:#x} decodes to "
            f"{sorted(expected)} but the AST says {sorted(ast['access'])}"
        )
        checked += 1
        if m.access_flags & _EITHER_SYNC:
            sync_checked += 1

    if not sync_checked:
        pytest.skip("no synchronized method with a body in this APK")
    assert checked >= min(100, len(sample)), (
        f"oracle ran on only {checked} of {len(sample)} sampled methods"
    )


def test_dad_path_still_reports_declared_synchronized(loadable_apks):
    """Pin the DAD path independently of the summary path.

    The oracle above compares the two routes, so it stays green if BOTH regress
    the same way. This asserts the decompiler's own output directly against a
    known-synchronized method, so a reintroduced rewrite that fed both routes
    would still be caught here.
    """
    import dexllm

    target_cls = "Landroid/support/v4/util/LruCache;"
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        if target_cls not in set(dk.list_classes()):
            continue
        ast = dk.decompile_method_ast(f"{target_cls}->size()I", include_source=False)
        assert ast["found"], f"{apk}: {target_cls}->size()I has no body"
        assert set(ast["access"]) == {"public", "final", "declared_synchronized"}, (
            f"{apk}: LruCache.size() modifiers are {sorted(ast['access'])} — the DAD "
            f"path no longer sees the raw declared_synchronized bit"
        )
        src = dk.decompile_class(target_cls)
        assert "declared_synchronized int size()" in src, (
            f"{apk}: decompile_class no longer emits declared_synchronized for "
            f"LruCache.size()"
        )
        return
    pytest.skip(f"{target_cls} not present in the available APK(s)")


def test_field_xref_is_per_instruction_not_per_method(loadable_apks):
    """Pin the undeduplicated contract the docs now state across all four layers.

    ``find_methods_reading_field`` / ``_writing_field`` return one entry per
    ACCESS INSTRUCTION (like ``CallSite``), so a method with two ``iget``s of the
    field appears twice. This was undocumented until 2026-08-06 and is easy to
    "fix" into a dedup by accident, which would silently change the meaning of
    every count built on it.
    """
    import dexllm

    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for fd in dk.list_fields()[:4000]:
            readers = dk.find_methods_reading_field(fd)
            if len(readers) > len(set(readers)):
                # the repeat must be a genuine multi-access method, and the
                # smali must show at least as many reads as the repeat count
                dup = max(set(readers), key=readers.count)
                smali = dk.render_method_smali(dup)
                reads = sum(
                    1
                    for line in smali.splitlines()
                    if fd in line and "get" in line.split(",")[0].split(":")[-1]
                )
                assert reads >= readers.count(dup), (
                    f"{dup} appears {readers.count(dup)}x in the reader list but "
                    f"the smali shows only {reads} read(s) of {fd}"
                )
                return
    pytest.skip("no field with a repeated reader in the available APK(s)")
