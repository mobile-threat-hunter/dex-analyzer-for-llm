"""Python-level smoke/regression tests for dexllm.

Self-contained tests (import, API surface) always run. APK-dependent tests
use the `dk`/`sample_method` fixtures and skip when no test APK is present.

Run:  pytest tests -v
"""

import glob
import re
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]

# ── self-contained (no APK) ──────────────────────────────────────────────────


def test_import_and_version():
    assert isinstance(dexllm.__version__, str)
    assert dexllm.DexKit is not None


def test_optional_extras_bound_incompatible_majors():
    """Every optional dependency whose MAJOR bump is known to break us must carry an
    upper bound (#18).

    `mcp` 2.x removed the low-level `Server` decorators `dexllm.mcp_server` is written
    against, so an unbounded `mcp>=1.0` let a clean install resolve a version that
    fails at IMPORT and aborted pytest collection for the whole suite. This guards the
    bound itself — the runtime cannot, since by then the wrong version is installed.
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    spec = re.search(r'^mcp = \["mcp([^"]*)"\]', pyproject, re.M)
    assert spec, "the [mcp] extra no longer declares a single `mcp` requirement"
    assert "<2" in spec.group(1), (
        "dexllm.mcp_server targets the mcp 1.x Server API; the extra must stay "
        f"upper-bounded until it is ported (found: mcp{spec.group(1)})"
    )


def test_tools_catalog():
    defs = dexllm.tools.tool_definitions()
    assert len(defs) >= 10
    names = {d["name"] for d in defs}
    assert {"decompile_method", "list_classes", "find_methods_using_strings"} <= names


# ── enumeration ──────────────────────────────────────────────────────────────


def test_enumeration(dk):
    classes = dk.list_classes()
    assert len(classes) > 0
    methods = dk.list_class_methods(classes[0])
    assert isinstance(methods, list)


# ── forward string accessors (dexllm#17) ─────────────────────────────────────

# `const-string`/`const-string/jumbo vN, "…"` as render_*_smali prints it.
_CONST_STRING_RE = re.compile(
    r'\bconst-string(?:/jumbo)?\s+v\d+,\s*"((?:[^"\\]|\\.)*)"'
)


def _unescape_smali(s):
    """Invert EscapeSmaliString (dex_item.cpp) — \\\\ \\" \\n \\r \\t \\xNN."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "x":
            out.append(chr(int(s[i + 2 : i + 4], 16)))
            i += 4
        else:
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            i += 2
    return "".join(out)


def _smali_strings(dk, method_descriptor):
    """Ground truth: the const-string operands of a method, from its smali text.

    This is the workaround dexllm#17 replaces — it renders a whole listing and
    un-escapes by hand — so it is an INDEPENDENT oracle for the new accessor.
    """
    seen, out = set(), []
    for raw in _CONST_STRING_RE.findall(dk.render_method_smali(method_descriptor)):
        v = _unescape_smali(raw)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def test_method_strings_match_smali_ground_truth(dk):
    """list_method_strings ≡ the const-string operands of the method's smali,
    deduplicated in first-occurrence order — over a real sample, not one method."""
    checked = with_strings = 0
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            got = dk.list_method_strings(m)
            assert got == list(dict.fromkeys(got))  # dedup + order preserved
            try:
                expected = _smali_strings(dk, m)
            except UnicodeDecodeError:
                # The oracle itself fails here: render_*_smali hands back raw MUTF-8,
                # so a surrogate / embedded-NUL literal is undecodable (26 methods in
                # the bundled corpus). That is exactly what these accessors fix — skip
                # the method rather than let the oracle's limitation ERROR the test.
                continue
            assert got == expected, m
            checked += 1
            with_strings += bool(got)
        if with_strings >= 25:
            break
    assert checked > 0 and with_strings > 0  # the oracle actually saw strings


def test_class_strings_are_method_union_then_static_init(dk):
    """list_class_strings = ∪ declared methods' strings (ascending method_idx),
    then the class's static-field VALUE_STRING initializers. Deduped.

    The prefix property is asserted for EVERY class; the static-init tail is the
    issue's semantics choice #1 (a `static final String` belongs to class scope, not
    to any method) and is asserted directly on the first class that has one.
    """
    static_only_checked = False
    for cls in dk.list_classes():
        cs = dk.list_class_strings(cls)
        assert cs == list(dict.fromkeys(cs))
        per_method = {m: dk.list_method_strings(m) for m in dk.list_class_methods(cls)}
        union = list(dict.fromkeys(s for v in per_method.values() for s in v))
        assert cs[: len(union)] == union, cls  # code first, order preserved
        if len(cs) > len(union) and not static_only_checked:
            # the tail is static-init: present at class scope, absent from EVERY
            # method of the class (incl. <clinit>) — semantics choice #1, pinned.
            for s in cs[len(union) :]:
                for m, ms in per_method.items():
                    assert s not in ms, (cls, m, s)
            static_only_checked = True
        if static_only_checked and len(union) > 3:
            break
    if not static_only_checked:
        # Corpus-dependent (a small APK may have no static-final-String at all) —
        # skip rather than fail: the prefix property above was still asserted.
        pytest.skip("no class with a static-final-String initializer in this corpus")


def test_class_strings_subset_of_value_strings(dk):
    """A class's strings are a subset of the app-wide value-string feed — the two
    accessors read the same const-string + VALUE_STRING sources at different scope."""
    app = set(dk.list_value_strings())
    for cls in dk.list_classes()[:200]:
        assert set(dk.list_class_strings(cls)) <= app, cls


def test_method_strings_round_trips_into_the_reverse_query(dk):
    """A bytecode string reported for M finds M again via find_methods_using_strings."""
    checked = 0
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            for s in dk.list_method_strings(m):
                hits = dk.find_methods_using_strings([s], "equals")
                assert any(h.descriptor == m for h in hits), (m, s)
                checked += 1
        if checked >= 20:
            break
    assert checked > 0, "no const-string in the corpus"


def test_non_ascii_literals_round_trip():
    """dexllm#19: a supplementary-plane or NUL-bearing literal must round-trip.

    This is the ONLY Python-level guard for the MUTF-8 query encoding, and it must
    SEEK such a string: the plain round-trip test above stops after 20 strings and
    never reaches one (measured: 0 astral/NUL among the first 20 in every corpus APK),
    so it passes even with the encoder regressed to identity.

    It scans the bundled corpus DIRECTLY rather than through the `loadable_apks`
    fixture, which honours `$DEXLLM_TEST_APK` — pointing that documented knob at a
    small APK (TC-debug, multidex, com.politedroid) would otherwise turn this guard
    into a hard failure instead of leaving it to the corpus.

    Covers all FIVE converted entry points: they share one helper, so a wholesale
    revert is caught by any of them, but a partial one (dropping the conversion from
    a single call site) is only caught by exercising each.
    """
    apks = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk")))
    if not apks:
        pytest.skip("no bundled corpus")
    checked = 0
    for apk in apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:  # noqa: BLE001
            continue
        for cls in dk.list_classes():
            for m in dk.list_class_methods(cls):
                for s in dk.list_method_strings(m):
                    if all(ord(c) <= 0xFFFF for c in s) and "\x00" not in s:
                        continue
                    assert any(
                        h.descriptor == m
                        for h in dk.find_methods_using_strings([s], "equals")
                    ), f"find_methods_using_strings lost {s!r} (reported for {m})"
                    assert dk.find_classes_using_strings([s], "equals"), s
                    assert dk.batch_find_methods_using_strings({"k": [s]})["k"], s
                    assert dk.batch_find_classes_using_strings({"k": [s]})["k"], s
                    checked += 1
                    if checked >= 5:
                        break
                if checked >= 5:
                    break
            if checked >= 5:
                break
        if checked >= 5:
            break
    assert checked > 0, (
        "no astral / NUL-bearing literal reached — this test is the only Python guard "
        "for dexllm#19 and must not pass vacuously"
    )
    # the fifth converted entry point: a declaration-side query
    for apk in apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:  # noqa: BLE001
            continue
        for cls in dk.list_classes():
            for s in dk.list_class_strings(cls):
                if all(ord(c) <= 0xFFFF for c in s) and "\x00" not in s:
                    continue
                if dk.find_classes_declaring_strings([s], "equals"):
                    return  # a declared astral constant resolves through the encoder
    # none declared as a constant in this corpus — the four above already ran


def test_lone_surrogate_query_is_rejected_not_silently_wrong(dk):
    """dexllm#19 residual, pinned: a lone surrogate cannot be queried as a `str`.

    Not because Python forbids it (a ``str`` may hold U+D800) but because pybind11
    encodes arguments as strict UTF-8 and rejects an unpaired surrogate — a LOUD
    failure, not a silent miss, which is the property worth keeping.
    """
    with pytest.raises(TypeError):
        dk.find_methods_using_strings(["\ud800"], "equals")


def test_forward_strings_empty_for_bodyless_and_unknown(dk):
    """External / unknown / malformed / bodyless targets return [] (no raise) — the
    same graceful-empty contract as render_method_smali / decompile_method_java."""
    assert dk.list_method_strings("Landroid/util/Log;->d(Ljava/lang/String;)I") == []
    assert dk.list_class_strings("Ljava/lang/String;") == []
    assert dk.list_class_strings("Lnope/NotHere;") == []
    assert dk.list_method_strings("not-a-descriptor") == []
    assert dk.list_method_strings("") == []
    # abstract: declared and resolvable, but no code_item → [] (documented). Every
    # method of an interface (ACC_INTERFACE = 0x200) is abstract.
    bodyless = 0
    for cls in dk.list_classes():
        if not dk.get_class_summary(cls).access_flags & 0x200:
            continue
        for m in dk.list_class_methods(cls):
            assert dk.list_method_strings(m) == [], m
            bodyless += 1
        if bodyless >= 5:
            break
    assert bodyless > 0, "no interface (abstract) method in the corpus"


# ── declaration-side string lookup (dexllm#20) ───────────────────────────────


def test_find_classes_declaring_strings_finds_what_using_cannot(dk):
    """dexllm#20: a `static final String` the app never LOADS has no const-string, so
    find_classes_using_strings correctly returns nothing — the declaration index is the
    only way to locate it. Verified on real static-init-only strings of this corpus."""
    code = set()
    for c in dk.list_classes():
        for m in dk.list_class_methods(c):
            code.update(dk.list_method_strings(m))
    checked = 0
    for cls in dk.list_classes():
        for s in dk.list_class_strings(cls):
            if s in code or not s:
                continue  # loaded somewhere → `using` finds it; that is its own test
            assert dk.find_classes_using_strings([s], "equals") == []
            declaring = [
                m.descriptor for m in dk.find_classes_declaring_strings([s], "equals")
            ]
            assert cls in declaring, (cls, s, declaring)
            checked += 1
            if checked >= 10:
                return
    pytest.skip("no static-init-only string in this corpus")


def test_declaring_matcher_shares_the_family_semantics(dk):
    """match_type / ignore_case / ALL-strings behave as in find_classes_using_strings
    (the implementation reuses the core's own DexItem::IsStringMatched).

    The target MUST be a declaration-only string: `list_class_strings` emits method
    const-strings first, so picking its first entry would yield a method string, every
    `declaring` query would return the empty set, and every assertion below would hold
    vacuously — verified: a stub implementation returning nothing passed that version.
    """
    code = set()
    for c in dk.list_classes():
        for m in dk.list_class_methods(c):
            code.update(dk.list_method_strings(m))
    target = None
    for cls in dk.list_classes():
        for s in dk.list_class_strings(cls):
            if s not in code and len(s) > 8 and s.isascii() and s.islower():
                target = (cls, s)
                break
        if target:
            break
    if not target:
        pytest.skip("no declaration-only ASCII string in this corpus")
    cls, s = target

    eq = {m.descriptor for m in dk.find_classes_declaring_strings([s], "equals")}
    assert cls in eq, (cls, s, eq)  # non-vacuous anchor: the query must actually hit
    assert eq == {
        m.descriptor for m in dk.find_classes_declaring_strings([f"^{s}$"], "regex")
    }
    assert eq <= {
        m.descriptor for m in dk.find_classes_declaring_strings([s[:6]], "starts_with")
    }
    assert eq <= {
        m.descriptor
        for m in dk.find_classes_declaring_strings([s.upper()], "equals", True)
    }
    # ALL semantics: a pair no single class declares together yields nothing
    assert (
        dk.find_classes_declaring_strings([s, "\x00no-such-string\x00"], "equals") == []
    )
    # Empty query returns nothing — a DELIBERATE divergence from the `using` family,
    # where an empty matcher list is vacuously true and returns every class.
    assert dk.find_classes_declaring_strings([], "equals") == []
    assert len(dk.find_classes_using_strings([], "equals")) > 0


# ── L4 arg resolution: join-aware dataflow (dexllm#16) ───────────────────────


def _dk_with(loadable_apks, class_descriptor):
    """First loadable APK that declares `class_descriptor` → its DexKit, else skip.

    These L4 tests are PINNED to concrete bytecode shapes (verified by hand against
    the smali), which is what makes them fail on the pre-fix implementation — a
    corpus-wide "did anything resolve" count does not.
    """
    for apk in loadable_apks:
        try:
            d = dexllm.DexKit(apk)
        except Exception:
            continue
        if class_descriptor in set(d.list_classes()):
            return d
    pytest.skip(f"{class_descriptor} not in the corpus")


# ActivityCompat.setEnterSharedElementCallback is the canonical shape for BOTH
# defects, verified against its smali:
#     0x0  const/4 v0, #0                 <- v0 = null on the branch-taken path
#     0xa  if-lt  v1, v2, +13
#     0xe  if-eqz v4, +7                  -> 0x1c   (v0 still null here)
#     0x12 new-instance v0, …23Impl       <- v0 = a fresh object on the fall-through
#     0x1c invoke-virtual {v3, v0}, Activity;->setEnterSharedElementCallback(…)
# v3 (a parameter) DOMINATES the site — defect 1: it must resolve.
# v0 is genuinely conditional — defect 2: it must NOT be reported as NewInstance.
_SEC_CLASS = "Landroid/support/v4/app/ActivityCompat;"
_SEC_API = (
    "Landroid/app/Activity;->setEnterSharedElementCallback"
    "(Landroid/app/SharedElementCallback;)V"
)


def _sec_site(loadable_apks):
    """The pinned site itself (not merely the class) — several corpus APKs ship
    different support-library versions, so search until the exact shape is found."""
    for apk in loadable_apks:
        try:
            d = dexllm.DexKit(apk)
        except Exception:
            continue
        for s in d.resolve_call_args(_SEC_API):
            if s.caller_descriptor.startswith(_SEC_CLASS) and s.bytecode_offset == 0x1C:
                return s
    pytest.skip("pinned setEnterSharedElementCallback site not in the corpus")


def test_dominating_definition_survives_a_branch(loadable_apks):
    """dexllm#16 defect 1: a definition that reaches the call on EVERY path must be
    reported even though branches sit between it and the site.

    Pre-fix the register file was wiped at each branch, so this argument was Unknown.
    """
    args = _sec_site(loadable_apks).args
    assert args[0].kind == "Parameter", args[0].kind  # v3, the receiver parameter
    assert args[0].parameter_index == 0
    assert args[0].crossed_branch is False


def test_conditional_argument_is_not_reported_as_unconditional(loadable_apks):
    """dexllm#16 defect 2: a value that holds on only ONE path must degrade to
    Unknown + crossed_branch.

    Pre-fix this argument was reported as `NewInstance …SharedElementCallback23Impl`,
    which is false whenever the `if-eqz v4` branch is taken (v0 is still null).
    """
    args = _sec_site(loadable_apks).args
    assert args[1].kind == "Unknown", f"one-path value reported as {args[1].kind}"
    assert args[1].crossed_branch is True


def test_switch_case_targets_are_join_points(loadable_apks):
    """A packed-switch case target is a join like any other: a parameter defined
    before the switch must survive into the case bodies (pre-fix: Unknown)."""
    cls = "Landroid/arch/lifecycle/ClassesInfoCache$MethodReference;"
    dk = _dk_with(loadable_apks, cls)
    seen = 0
    for s in dk.resolve_call_args(
        "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)"
        "Ljava/lang/Object;"
    ):
        if not s.caller_descriptor.startswith(cls):
            continue
        assert s.args[1].kind == "Parameter", s.args[1].kind
        seen += 1
    assert seen >= 2, "expected several switch-case call sites"


def test_lit8_lit16_kill_their_real_destination(loadable_apks):
    """Regression for the swapped `*-int/lit8` / `*-int/lit16` destination decoding.

    `add-int/lit16 v1, v9, #4096` (format k22s) writes the 4-bit A, not AA. Decoding
    it as AA erased an unrelated register, so v1 kept a stale pre-branch `const/16
    v1, #16384` and the join then agreed on it — a one-path value reported as
    unconditional (exactly the defect this change removes).
    """
    cls = "Lcom/bumptech/glide/gifdecoder/StandardGifDecoder;"
    dk = _dk_with(loadable_apks, cls)
    checked = 0
    for s in dk.resolve_call_args("Ljava/io/ByteArrayOutputStream;-><init>(I)V"):
        if not s.caller_descriptor.startswith(cls):
            continue
        assert s.args[1].kind != "ConstInt", "stale value survived an arithmetic write"
        checked += 1
    assert checked > 0, "pinned StandardGifDecoder site not present"


def test_wide_value_high_half_has_no_stale_origin(loadable_apks):
    """A 64-bit value occupies vN and vN+1; the high half must not keep an unrelated
    tracked origin (invoke-* lists one arg entry per register, so it IS surfaced).

    `PagingIndicator.createDotAlphaAnimator` builds `[F` in v3, then a const-wide into
    v2/v3 clobbers it; the `setDuration(J)` site must not report v3 as `NewArray [F`.
    """
    cls = "Landroid/support/v17/leanback/widget/PagingIndicator;"
    dk = _dk_with(loadable_apks, cls)
    checked = 0
    for s in dk.resolve_call_args(
        "Landroid/animation/ObjectAnimator;->setDuration(J)"
        "Landroid/animation/ObjectAnimator;"
    ):
        if not s.caller_descriptor.startswith(cls):
            continue
        assert s.args[1].kind == "ConstWide"  # the wide value itself
        assert s.args[2].kind == "Unknown", s.args[2].kind  # its high half
        checked += 1
    assert checked > 0, "pinned PagingIndicator site not present"


def test_catch_handler_starts_from_an_unknown_register_file(loadable_apks):
    """A catch handler is reachable from any instruction of its try region, so no
    tracked definition may be carried into it.

    Anchored on the instruction FOLLOWING a `move-exception` (the handler's first real
    instruction is the move-exception itself, so a call site there is inside it), and
    it asserts that it checked something — the earlier version compared the invoke's
    offset with the move-exception's own offset, which can never match, so its
    assertion never ran.
    """
    checked = 0
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for api in (
            "Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I",
            "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)"
            "Ljava/lang/StringBuilder;",
        ):
            for s in dk.resolve_call_args(api):
                try:
                    smali = dk.render_method_smali(s.caller_descriptor)
                except UnicodeDecodeError:
                    continue
                offs = [
                    int(m.group(1), 16)
                    for line in smali.splitlines()
                    if "move-exception" in line
                    and (m := re.match(r"^\s*0x([0-9a-f]+):", line))
                ]
                # the invoke immediately after a move-exception: register file is unknown
                for off in offs:
                    if 0 < s.bytecode_offset - off <= 4:
                        for a in s.args:
                            assert a.kind == "Unknown", (s.caller_descriptor, a.kind)
                        checked += 1
    if checked == 0:
        pytest.skip("no call site directly inside a catch handler in this corpus")


# ── decompile: Java ──────────────────────────────────────────────────────────


def test_decompile_method_java(dk, sample_method):
    src = dk.decompile_method_java(sample_method)
    assert src and "{" in src


def test_decompile_class_java(dk):
    for cls in dk.list_classes():
        out = dk.decompile_class_java(cls)
        if out:
            assert out.lstrip().startswith(
                ("package", "public", "class", "final", "abstract", "interface", "enum")
            )
            return


def test_external_method_returns_empty(dk):
    # External / framework methods must decompile to "" (graceful — androguard crashes).
    out = dk.decompile_method_java(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    )
    assert out == ""


# ── decompile: AST (dast.py port) ────────────────────────────────────────────


def test_decompile_method_ast_shape(dk, sample_method):
    res = dk.decompile_method_ast(sample_method)
    assert res["found"] is True
    ast = res["ast"]
    assert set(ast.keys()) == {"triple", "flags", "ret", "params", "comments", "body"}
    assert ast["body"][0] == "BlockStatement"  # nested-list AST tag
    assert len(ast["triple"]) == 3


def test_decompile_method_ast_include_source(dk, sample_method):
    full = dk.decompile_method_ast(sample_method)  # source + ast
    ast_only = dk.decompile_method_ast(sample_method, include_source=False)
    assert ast_only["source"] == ""
    assert ast_only["ast"] == full["ast"]  # AST identical regardless of source


# ── search (L1–L7) ───────────────────────────────────────────────────────────


def test_search_classes_by_name(dk):
    hits = dk.find_classes_by_name("a", "contains")
    assert isinstance(hits, list)


def test_search_call_sites(dk):
    sites = dk.find_call_sites_to(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    )
    assert isinstance(sites, list)  # may be empty if the APK never logs


def test_call_sites_from_method_is_forward_of_to_api(dk):
    """find_call_sites_from (callees) is the exact FORWARD of
    find_call_sites_to (callers): if M invokes C, then M appears among C's callers.
    Verified structurally on a real method, plus the external/unresolved empty case."""
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            callees = dk.find_call_sites_from(m)
            if len(callees) >= 1:
                for s in callees:
                    assert s.caller_descriptor == m  # caller is fixed to M
                    assert "->" in s.callee_descriptor
                # symmetry over EVERY distinct callee (not just the first): M must be
                # among the callers of each method it invokes (forward ≡ reverse edge).
                for callee in {c.callee_descriptor for c in callees}:
                    callers = {
                        x.caller_descriptor for x in dk.find_call_sites_to(callee)
                    }
                    assert m in callers, f"{m} invokes {callee} but is not its caller"
                assert dk.find_call_sites_from("Lno/such/C;->x()V") == []
                return
    pytest.skip("no method with a callee in the test APK")


def test_field_read_write_xref(dk):
    """L2.5 field xref — methods that iget/sget (read) vs iput/sput (write) a field.

    The DIRECTION is verified against the method's smali, so a reader/writer swap
    (FieldGetMethods vs FieldPutMethods wired backwards) is caught, not just the
    membership. An unknown field returns []."""
    assert dk.find_field_read_methods("Lno/such/Class;->x:I") == []
    for cls in dk.list_classes():
        for f in getattr(dk.get_class_summary(cls), "fields", []):
            fd = f"{cls}->{f.name}:{f.type}"
            rd = dk.find_field_read_methods(fd)
            wr = dk.find_field_write_methods(fd)
            assert all(isinstance(m, str) and "->" in m for m in rd + wr)
            # a method that ONLY reads must contain an iget*/sget* of the field;
            # a method that ONLY writes must contain an iput*/sput* — verified via
            # smali so the two directions can't be silently swapped.
            reader_only = [m for m in rd if m not in wr]
            writer_only = [m for m in wr if m not in rd]
            if reader_only:
                sm = dk.render_method_smali(reader_only[0])
                assert f.name in sm and ("iget" in sm or "sget" in sm)
                return
            if writer_only:
                sm = dk.render_method_smali(writer_only[0])
                assert f.name in sm and ("iput" in sm or "sput" in sm)
                return
    pytest.skip("no field with a direction-distinct read/write xref in the test APK")


def test_call_sites_cross_dex_multidex():
    """find_call_sites_to / resolve_call_args must find a CROSS-DEX caller — a
    target method declared in one classes*.dex but invoked from another. The caller
    reverse-index redesign made this the sharp edge (DexKit aggregates cross-dex
    callers into the declaring dex, tagged with their source dex_id)."""
    import glob
    import os

    apk = os.path.join(
        os.path.dirname(__file__), "..", "test_apk", "APK", "multidex.apk"
    )
    if not glob.glob(apk):
        pytest.skip("multidex.apk fixture missing")
    dk = dexllm.DexKit(apk)
    assert dk.dex_count() > 1
    # Foobar is declared in dex 0; Blafoo (dex 1) calls its <init> and somemethod.
    for target in (
        "Lcom/foobar/foo/Foobar;-><init>()V",
        "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V",
    ):
        callers = {s.caller_descriptor for s in dk.find_call_sites_to(target)}
        assert any(
            "Lcom/blafoo/bar/Blafoo;" in c for c in callers
        ), f"cross-dex caller of {target} lost: {callers}"
        # resolve_call_args must also see the cross-dex caller (same reverse-index path)
        rca = {s.caller_descriptor for s in dk.resolve_call_args(target)}
        assert any("Lcom/blafoo/bar/Blafoo;" in c for c in rca)
        # ORDER CONTRACT: the reverse-index path emits callers in (living-dex,
        # caller_method_idx) order — identical to the pre-redesign forward scan. Lock
        # it so a future grouping change can't silently reorder the returned list.
        sites = dk.find_call_sites_to(target)
        keys = [(s.caller_dex_id, s.caller_method_idx) for s in sites]
        assert keys == sorted(
            keys
        ), f"caller order not (dex, method_idx)-sorted: {keys}"

    # CROSS-DEX callee direction: a Blafoo (dex 1) caller of Foobar.somemethod (dex 0)
    # must, via find_call_sites_from, list that dex-0 method as a callee — the
    # forward path resolving a cross-dex edge round-trips against the reverse index.
    target = "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V"
    caller = next(
        s.caller_descriptor
        for s in dk.find_call_sites_to(target)
        if "Lcom/blafoo/bar/Blafoo;" in s.caller_descriptor
    )
    callee_descs = {s.callee_descriptor for s in dk.find_call_sites_from(caller)}
    assert target in callee_descs, f"cross-dex callee {target} lost from {caller}"


# ── external API enumeration ─────────────────────────────────────────────────


def test_type_references(dk):
    """L2.5 type xref — fields of / methods returning / methods taking a type."""
    tr = dk.find_type_references("Ljava/lang/String;")
    assert all(m.endswith(")Ljava/lang/String;") for m in tr.methods_returning)
    assert all(":Ljava/lang/String;" in f for f in tr.fields)
    assert dk.find_type_references("Lno/such/T;").fields == []


def test_enumeration_companions(dk):
    """Per-dex enumeration + extraction: uniform bare/all vs ...InDex(dex_id) axis."""
    all_classes = set(dk.list_classes())
    per_dex = set()
    for d in range(dk.dex_count()):
        per_dex |= set(dk.list_classes_in_dex(d))
    assert per_dex == all_classes  # union of per-dex == all (classes: declared)
    assert dk.list_classes_in_dex(9999) == []
    # field/method descriptors: the all-dexes form is exactly the concatenation of
    # the per-dex form (id-table references, so cross-dex refs recur — a set union
    # would drop them; concatenation is the correct invariant here).
    f_concat, m_concat = [], []
    for d in range(dk.dex_count()):
        f_concat += dk.list_field_descriptors_in_dex(d)
        m_concat += dk.list_method_descriptors_in_dex(d)
    assert f_concat == dk.list_field_descriptors() and len(f_concat) > 0
    assert m_concat == dk.list_method_descriptors() and len(m_concat) > 0
    assert dk.list_field_descriptors_in_dex(9999) == []
    assert dk.list_method_descriptors_in_dex(-1) == []
    raw = dk.extract_dex_bytes(0)
    assert isinstance(raw, bytes) and raw[:4] == b"dex\n"
    # the slice is THIS dex only — length == the header's file_size, not the map len
    assert len(raw) == int.from_bytes(raw[32:36], "little")
    assert dk.extract_dex_bytes(9999) == b""


def test_extract_dex_bytes_slices_concatenated_container(apk_path, tmp_path):
    """extract_dex_bytes must return THIS logical dex's slice (header_off applied),
    not the whole shared MemMap — the packer/concatenated-dex case. A single buffer
    of two dexes splits into two logical dexes sharing one image; each extract must
    yield its own dex (own magic, own file_size), NOT the full container."""
    import zipfile

    if not zipfile.is_zipfile(apk_path):
        pytest.skip("fixture is not a zip apk")
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist() if n.endswith(".dex")]
        if not names:
            pytest.skip("apk has no dex")
        one = z.read(names[0])
    cat = tmp_path / "concat.dex"
    cat.write_bytes(one + one)  # two logical dexes in one buffer
    dk = dexllm.DexKit(str(cat))
    if dk.dex_count() < 2:
        pytest.skip("core did not split the concatenated buffer")
    a, b = dk.extract_dex_bytes(0), dk.extract_dex_bytes(1)
    assert a[:4] == b"dex\n" and b[:4] == b"dex\n"  # each starts at its own magic
    assert len(a) == len(one) and len(b) == len(one)  # each is one dex, not the pair


def test_external_refs(dk):
    refs = dk.list_external_method_refs(framework_only=True)
    assert isinstance(refs, list)
    if refs:
        r = refs[0]
        assert r.class_descriptor and r.name and r.java_signature


# ── regression: EncodedValue must emit valid Java literals, not Python ones ───


def test_no_python_literals_in_output(dk):
    """null/true/false, never None/True/False (androguard-bug fix)."""
    pat = re.compile(r"=\s*(None|True|False)\b")
    for cls in dk.list_classes()[:500]:
        out = dk.decompile_class_java(cls)
        if out:
            assert not pat.search(out), f"python literal leaked in {cls}"
