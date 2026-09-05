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
from conftest import require_corpus_shape

ACC_SYNCHRONIZED = 0x20
ACC_DECLARED_SYNCHRONIZED = 0x20000
_EITHER_SYNC = ACC_SYNCHRONIZED | ACC_DECLARED_SYNCHRONIZED

# native/dad_cpp/util.cpp AccessFlagsMethodsTable (DAD util.py:67), which is what
# decompile_method_ast()["access_flags"] renders. Kept in step with that table — note
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
    return {a for a in ast["access_flags"] if not a.startswith("unkn_")}


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
            if not ast["found"] or "declared_synchronized" not in ast["access_flags"]:
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
            f"{sorted(expected)} but the AST says {sorted(ast['access_flags'])}"
        )
        checked += 1
        if m.access_flags & _EITHER_SYNC:
            sync_checked += 1

    if not sync_checked:
        pytest.skip("no synchronized method with a body in this APK")
    assert checked >= min(
        100, len(sample)
    ), f"oracle ran on only {checked} of {len(sample)} sampled methods"


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
        assert set(ast["access_flags"]) == {
            "public",
            "final",
            "declared_synchronized",
        }, (
            f"{apk}: LruCache.size() modifiers are {sorted(ast['access_flags'])} — the DAD "
            f"path no longer sees the raw declared_synchronized bit"
        )
        src = dk.decompile_class(target_cls)
        assert "declared_synchronized int size()" in src, (
            f"{apk}: decompile_class no longer emits declared_synchronized for "
            f"LruCache.size()"
        )
        return
    pytest.skip(f"{target_cls} not present in the available APK(s)")


def test_field_xref_is_per_instruction_in_the_value_too(loadable_apks):
    """Pin the per-instruction contract in the VALUE, not only in the count.

    INVERTED from `test_field_xref_is_per_instruction_not_per_method` (dexllm#84).
    That guard pinned the same contract on `find_methods_reading_field`'s
    `list[str]`, where a method reading the field four times produced four
    IDENTICAL strings: the contract held in the COUNT and was lost in the VALUE,
    and 48% of the fields with a read in the bundled corpus returned such rows.
    The rows are `FieldAccessSite` now, so the repeats must be DISTINCT records —
    which is the half no assertion could make before.

    Still corpus-ground-truthed against the smali, so a fabricated offset fails.
    """
    import dexllm

    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for fd in dk.list_fields()[:4000]:
            by_method: dict[str, list[int]] = {}
            for site in dk.find_field_read_sites(fd):
                by_method.setdefault(site.method_descriptor, []).append(
                    site.bytecode_offset
                )
            dup = next((m for m, offs in by_method.items() if len(offs) > 1), None)
            if dup is None:
                continue
            offs = by_method[dup]
            assert len(set(offs)) == len(offs), (
                f"{dup} accesses {fd} {len(offs)}x but the rows repeat an offset: "
                f"{offs} — the per-instruction contract is lost in the value again"
            )
            # the offsets must be REAL read instructions of that field, not
            # fabricated: the smali lists each one at its own offset.
            smali = dk.render_method_smali(dup)
            reads = {
                int(line.split(":", 1)[0].strip(), 16)
                for line in smali.splitlines()
                if fd in line and "get" in line.split(",")[0].split(":")[-1]
            }
            assert set(offs) <= reads, (
                f"{dup} reports read offsets {sorted(offs)} for {fd} but the smali "
                f"shows reads only at {sorted(reads)}"
            )
            return
    require_corpus_shape(
        False,
        "field read twice by one method",
        "the field xref stopped reporting per-instruction rows, so this guard "
        "verified nothing",
    )


# --- UNKNOWN is not 0 (dexllm#41) ---------------------------------------------
#
# `get_class_summary` reports members it cannot read modifiers for. Two sources:
#
#   * an EXTERNAL class (one no loaded dex declares) has no `class_data` at all —
#     its members are reconstructed from the `method_ids` / `field_ids` entries
#     other classes reference;
#   * an INTERNAL class's FIELD list is keyed on the whole `field_ids` table, so
#     it also holds inherited fields the class only REFERENCES, whose flag slot no
#     class_data list ever wrote (2,238 across the bundled corpus, 1,151 of which
#     have a NONZERO real declaration elsewhere in the same APK).
#
# Both used to report 0, which in dex is a LEGAL value — package-private,
# non-static, non-final — held by 5.1% of the corpus's methods, 8.7% of its
# fields and 34.9% of its classes. "Unknown" and a real declaration were the same
# value, so every framework class read as package-private and
# `m.access_flags & ACC_NATIVE` answered [] with confidence.

ACC_NATIVE = 0x100
ACC_STATIC = 0x8


def _external_with(dk, member: str):
    """First external class carrying at least one `methods` / `fields` entry."""
    for ref in dk.list_external_type_refs(framework_only=True):
        summary = dk.get_class_summary(ref.descriptor)
        if getattr(summary, member):
            return summary
    return None


def test_an_external_class_reports_unknown_method_flags_not_zero(dk):
    summary = _external_with(dk, "methods")
    if summary is None:
        pytest.skip("no external class in this corpus carries method refs")
    assert summary.is_internal is False and summary.dex_id == -1
    assert summary.access_flags is None, "the class's own flags are unknown too"
    assert all(m.access_flags is None for m in summary.methods)


def test_an_external_class_reports_unknown_field_flags_not_zero(dk):
    """The FIELD half — asserted on a class that actually HAS fields.

    The first external class with methods usually has none, so an `all(...)` over
    its (empty) fields is vacuous: reverting FieldInfo alone passed the whole
    suite until this test picked its own subject.
    """
    summary = _external_with(dk, "fields")
    if summary is None:
        pytest.skip("no external class in this corpus carries field refs")
    assert summary.fields, "the subject must actually carry fields"
    assert summary.is_internal is False
    assert all(f.access_flags is None for f in summary.fields)


def _uleb128(buf, off):
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, off
        shift += 7


def _declared_fields_oracle(raw: bytes):
    """{class descriptor: {(field name, type descriptor)}} parsed from class_data.

    An INDEPENDENT reader of the dex bytes — it does not go through DexKit — so it
    can say which fields a class DECLARES without using the value under test.
    """
    u32 = lambda o: int.from_bytes(raw[o : o + 4], "little")  # noqa: E731
    str_off = u32(0x3C)
    type_off = u32(0x44)
    fld_off, fld_cnt = u32(0x54), u32(0x50)
    cd_off, cd_cnt = u32(0x64), u32(0x60)

    def string(idx):
        data = u32(str_off + 4 * idx)
        _, o = _uleb128(raw, data)  # utf16 length
        end = raw.index(b"\x00", o)
        return raw[o:end].decode("utf-8", "replace")

    def type_desc(idx):
        return string(u32(type_off + 4 * idx))

    fields = []  # field_ids index -> (name, type descriptor)
    for i in range(fld_cnt):
        base = fld_off + 8 * i
        type_idx = int.from_bytes(raw[base + 2 : base + 4], "little")
        fields.append((string(u32(base + 4)), type_desc(type_idx)))

    declared = {}
    for i in range(cd_cnt):
        base = cd_off + 32 * i
        cls = type_desc(u32(base))
        data_off = u32(base + 24)
        if data_off == 0:
            declared[cls] = set()
            continue
        static_n, o = _uleb128(raw, data_off)
        instance_n, o = _uleb128(raw, o)
        _, o = _uleb128(raw, o)  # direct methods
        _, o = _uleb128(raw, o)  # virtual methods
        own = set()
        for count in (static_n, instance_n):
            idx = 0
            for _ in range(count):
                delta, o = _uleb128(raw, o)
                idx += delta
                _, o = _uleb128(raw, o)  # access_flags
                own.add(fields[idx])
        declared[cls] = own
    return declared


def test_an_internal_class_lists_exactly_the_fields_it_declares(dk):
    """An INTERNAL class's field list is its `class_data`, nothing more.

    This test used to assert the OPPOSITE half of the same fact: before dexllm#45
    a subclass DID list inherited fields (`class_field_ids` groups every
    `field_ids` entry under the class named in the REFERENCE) and #41 only made
    their modifiers honest, so the guard checked that those entries reported
    UNKNOWN. #45 removed the entries, which would have left that assertion
    vacuously true — so it is inverted here rather than deleted, the way the
    overlong-MUTF-8 (#22) and lone-surrogate (#29) guards were.

    Which fields a class declares is established by parsing `class_data` directly
    from the dex bytes, NOT from the value under test, so the set equality is
    checked rather than assumed. The equality also subsumes #41's assertion in the
    surviving direction: every listed field is declared, hence its flags are known.
    """
    raw = dk.extract_dex(0)["bytes"]
    declared = _declared_fields_oracle(raw)
    checked = 0
    for cls, own in declared.items():
        summary = dk.get_class_summary(cls)
        if not summary.is_internal:
            continue
        checked += 1
        listed = {(f.name, f.type) for f in summary.fields}
        assert listed == own, (
            f"{cls} lists {sorted(listed - own)} which its class_data does not "
            f"declare, and omits {sorted(own - listed)} which it does"
        )
        for f in summary.fields:
            assert f.access_flags is not None, (
                f"{cls}->{f.name}:{f.type} IS declared in class_data but reports "
                f"unknown"
            )
    # Non-vacuity: the dex must have contained internal classes at all. This is a
    # property of any dex, so it holds under a narrowing too — no skip branch.
    assert checked, "dex 0 declares no class — the oracle read nothing"


def test_reading_a_modifier_off_an_unknown_member_fails_loudly(dk):
    """The silent wrong answer is now a TypeError — the point of the change."""
    summary = _external_with(dk, "methods")
    if summary is None:
        pytest.skip("no external class in this corpus carries method refs")
    with pytest.raises(TypeError):
        [m for m in summary.methods if m.access_flags & ACC_NATIVE]


def test_a_declared_zero_is_still_zero_and_is_corroborated(dk):
    """The other half: a REAL package-private member keeps its 0.

    Unknown moved out of the encoding; 0 did not move with it. `zero_seen` alone
    would be satisfied by a fabricated 0, so a declared 0 is corroborated through
    the DAD path (`decompile_method_ast(...)["access_flags"]`), which reads the same
    class_data by a different route: no modifier name may appear for it.
    """
    zero_corroborated = 0
    for cls in dk.list_classes():
        summary = dk.get_class_summary(cls)
        assert summary.is_internal is True
        assert summary.access_flags is not None, "a class_def always knows its own"
        assert all(
            m.access_flags is not None for m in summary.methods
        ), "class_method_ids comes from class_data — a method's flags are known"
        for m in summary.methods:
            if m.access_flags != 0:
                continue
            names = _ast_modifiers(dk.decompile_method_ast(f"{cls}->{m.name}{m.proto}"))
            assert not names, (
                f"{cls}->{m.name}{m.proto} reports flags 0 but the DAD path "
                f"decodes {sorted(names)} — the 0 is fabricated, not declared"
            )
            zero_corroborated += 1
            if zero_corroborated >= 5:
                return
    if not zero_corroborated:
        pytest.skip("no genuine package-private method in this APK")


def test_unknown_flags_reach_the_sdk_and_the_tool_output(dk, apk_path):
    """None must survive the SDK models and stay JSON-serialisable for MCP."""
    import json

    import dexllm
    from dexllm.sdk import open_apk

    summary = _external_with(dk, "methods")
    if summary is None:
        pytest.skip("no external class in this corpus carries method refs")
    desc = summary.descriptor
    session = open_apk(apk_path)
    assert session.class_info(desc).access_flags is None
    methods = session.class_methods(desc)
    assert methods and all(m.access_flags is None for m in methods)
    out = dexllm.tools.execute("get_class_summary", {"class_descriptor": desc}, dk)
    assert out["access_flags"] is None
    assert json.loads(json.dumps(out))["access_flags"] is None

    with_fields = _external_with(dk, "fields")
    if with_fields is not None:
        fields = session.class_fields(with_fields.descriptor)
        assert fields and all(f.access_flags is None for f in fields)
