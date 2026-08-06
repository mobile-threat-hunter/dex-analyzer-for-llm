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
            # No UnicodeDecodeError guard: the renderer decodes MUTF-8 before
            # escaping (dexllm#22), so the oracle no longer needs to skip those
            # methods. This loop stops at 25 string-bearing methods, so it does not
            # by itself reach an affected one — test_render_smali_decodes_mutf8
            # and test_smali_never_contains_raw_control_chars are the real guards.
            expected = _smali_strings(dk, m)
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
    same graceful-empty contract as render_method_smali / decompile_method."""
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
                # No UnicodeDecodeError guard: dexllm#22 made the renderer decode
                # MUTF-8 before escaping, so smali is always valid text now.
                smali = dk.render_method_smali(s.caller_descriptor)
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


def test_decompile_method(dk, sample_method):
    src = dk.decompile_method(sample_method)
    assert src and "{" in src


def test_decompile_class(dk):
    for cls in dk.list_classes():
        out = dk.decompile_class(cls)
        if out:
            assert out.lstrip().startswith(
                ("package", "public", "class", "final", "abstract", "interface", "enum")
            )
            return


def test_external_method_returns_empty(dk):
    # External / framework methods must decompile to "" (graceful — androguard crashes).
    out = dk.decompile_method(
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
    assert dk.find_methods_reading_field("Lno/such/Class;->x:I") == []
    saw_xref = False
    for cls in dk.list_classes():
        for f in getattr(dk.get_class_summary(cls), "fields", []):
            fd = f"{cls}->{f.name}:{f.type}"
            rd = dk.find_methods_reading_field(fd)
            wr = dk.find_methods_writing_field(fd)
            saw_xref = saw_xref or bool(rd or wr)
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
    # A fixture with NO field xref at all cannot exercise direction — skip. But if
    # xref data existed and NOT ONE field distinguished readers from writers, that is
    # the signature of the two entry points collapsing onto one C++ impl (which a
    # copy-paste in the duplicated `.def` block makes plausible) — fail, don't skip.
    if saw_xref:
        pytest.fail(
            "field xref returned results but no field had a direction-distinct "
            "read/write set — readers and writers may be wired to the same impl"
        )
    pytest.skip("no field read/write xref in this fixture")


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
        out = dk.decompile_class(cls)
        if out:
            assert not pat.search(out), f"python literal leaked in {cls}"


# ── regression: the decompile_* family dropped its redundant `_java` suffix ───


def test_deprecated_decompile_names_still_work(dk):
    """dexllm#21 stage 2: the pre-rename spellings stay available as aliases.

    `_java` advertised a parallelism with decompile_method_ast that does not
    exist — the AST call returns the SAME Java text in its `source` — so the
    family is base-vs-enriched, not two output formats. Each old name must still
    resolve and return byte-identical output; the names are hard-coded here (a
    loop over a mapping would delete its own coverage if an entry were removed).
    """
    import dexllm

    # Search class and method JOINTLY: picking the first decompilable class and
    # then requiring a decompilable method INSIDE it silently skips the whole
    # test on a fixture whose first class is a marker interface / annotation
    # (reproducible with DEXLLM_TEST_APK=test_apk/APK/hello-world.apk).
    pair = next(
        (
            (c, x)
            for c in dk.list_classes()
            for x in dk.list_class_methods(c)
            if dk.decompile_method(x)
        ),
        None,
    )
    if pair is None:
        pytest.skip("no decompilable method in the fixture")
    cls, m = pair

    assert dk.decompile_method_java(m) == dk.decompile_method(m) != ""
    assert dk.decompile_class_java(cls) == dk.decompile_class(cls) != ""
    pc = dk.decompile_method_with_pc_map(m)
    assert pc["source"]  # non-vacuous: both names failing alike must not pass
    assert dk.decompile_method_java_with_pc(m) == pc
    # the module-level hang-safe wrappers moved with them. They are the SAME
    # function object, so comparing their output would be a tautology — state
    # the real invariant, then check the output separately.
    assert dexllm.safe_decompile_method_java is dexllm.safe_decompile_method
    assert dexllm.safe_decompile_class_java is dexllm.safe_decompile_class
    assert dexllm.safe_decompile_method_java(dk, m) == dk.decompile_method(m) != ""
    # and every name is exported / advertised
    for n in (
        "safe_decompile_method",
        "safe_decompile_class",
        "safe_decompile_method_java",
        "safe_decompile_class_java",
    ):
        assert n in dexllm.__all__ and hasattr(dexllm, n)


def test_safe_wrappers_take_the_raw_dexkit(apk_path, dk):
    """dexllm#21 stage 2: the safe wrappers' duck-typed contract, both ways.

    They accept `dk: Any`, so the rename could have changed what they REQUIRE of
    that argument. A stand-in implementing only the pre-rename spelling must keep
    working (that is what the aliases are for), and a dexllm.sdk session — which
    has a same-named `decompile_method` returning a typed model, not str — must
    fail LOUDLY rather than return a non-str through a `-> str` signature.
    """
    import dexllm
    from dexllm.sdk import open_apk

    m = next(
        x
        for c in dk.list_classes()
        for x in dk.list_class_methods(c)
        if dk.decompile_method(x)
    )

    class LegacyStandIn:
        def decompile_method_java(self, d):
            return "// legacy\n"

        def decompile_class_java(self, d):
            return "// legacy class\n"

    legacy = LegacyStandIn()
    assert dexllm.safe_decompile_method(legacy, m) == "// legacy\n"
    assert dexllm.safe_decompile_class(legacy, "La/B;") == "// legacy class\n"

    with pytest.raises(TypeError, match="not str"):
        dexllm.safe_decompile_method(open_apk(apk_path), m)
    with pytest.raises(AttributeError, match="neither"):
        dexllm.safe_decompile_method(object(), m)


def test_ast_source_matches_the_text_decompile(dk):
    """The claim the stage-2 rename rests on, over a bounded sample.

    `_java` was dropped because decompile_method_ast is not a parallel output
    FORMAT — it returns the same Java text in its `source` — so the family is
    base-vs-enriched. Pinning that on one method would not catch an IR change
    that desyncs the AST emitter from the text emitter on a subset (a <clinit>,
    a float literal, ...), which is exactly what would invalidate the naming.
    """
    checked = 0
    for c in dk.list_classes():
        for m in dk.list_class_methods(c):
            text = dk.decompile_method(m)
            if not text:
                continue
            a = dk.decompile_method_ast(m)
            assert a["source"] == text, m
            assert dk.decompile_method_with_pc_map(m)["source"] == text, m
            checked += 1
            if checked >= 200:
                # documented opt-out: the AST-only path carries no source
                assert dk.decompile_method_ast(m, include_source=False)["source"] == ""
                return
    if checked == 0:
        pytest.skip("no decompilable method in the fixture")

    # the suffix claim itself: _ast carries the same Java text as the bare call
    assert dk.decompile_method_ast(m)["source"] == dk.decompile_method(m)


def test_stage3_deprecated_names_still_work(dk):
    """dexllm#21 stage 3: field-xref and cache-action renames keep their aliases.

    The find_* family names what it RETURNS right after `find_` (find_classes_*,
    find_methods_*, find_call_sites_*); the field pair returned METHOD descriptors
    while naming the queried FIELD — the only inversion in the family. Cache
    control uses verb-first for ACTIONS and nouns for read-only accessors, which
    `warm_analysis_caches` already did. Both old spellings stay as aliases.
    """
    fd = next(
        (f for f in dk.list_field_descriptors() if dk.find_methods_reading_field(f)),
        None,
    )
    if fd is None:
        pytest.skip("no read field in the fixture")
    assert dk.find_field_read_methods(fd) == dk.find_methods_reading_field(fd) != []
    wr = dk.find_methods_writing_field(fd)
    assert dk.find_field_write_methods(fd) == wr

    m = next(
        (
            x
            for c in dk.list_classes()
            for x in dk.list_class_methods(c)
            if dk.decompile_method(x)
        ),
        None,
    )
    if m is None:
        pytest.skip("no decompilable method in the fixture")
    # `dk` is session-scoped, so restore the ORIGINAL capacity (not a hardcoded
    # default) even if an assertion below fails.
    original = dk.decompiler_cache_capacity()
    try:
        dk.set_decompiler_cache_capacity(64)  # canonical setter
        assert dk.decompiler_cache_capacity() == 64
        dk.decompiler_set_cache_capacity(128)  # deprecated alias
        assert dk.decompiler_cache_capacity() == 128
        for clear in (dk.clear_decompiler_cache, dk.decompiler_clear_cache):
            clear()
            dk.decompile_method(m)
            assert dk.decompiler_cache_size() > 0  # non-vacuous: something to clear
            clear()  # canonical on the first pass, deprecated alias on the second
            assert dk.decompiler_cache_size() == 0
    finally:
        dk.set_decompiler_cache_capacity(original)


# ── regression: rendered smali must decode MUTF-8 (dexllm#22) ────────────────


def test_render_smali_decodes_mutf8_literals(loadable_apks):
    """dexllm#22: a literal pybind's strict UTF-8 cannot accept must not RAISE.

    `EscapeSmaliString` escapes only \\ " \\n \\r \\t and bytes < 0x20, so every byte
    >= 0x20 of a MUTF-8 literal survived into the rendered text. A supplementary-
    plane character (stored as a SURROGATE PAIR, `ED ..`) or an embedded NUL
    (`C0 80`) is not valid UTF-8, so `std::string -> py::str` raised
    UnicodeDecodeError where text was expected — 29 of 201,079 methods and 25 of
    26,938 classes in the bundled corpus, across 11 files.

    Finds such a literal through `list_value_strings` (which always decoded), then
    asserts BOTH renderers return text and that the rendered literal round-trips to
    the same value the string accessor reports.
    """
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        # Exactly the shapes whose RAW MUTF-8 strict UTF-8 rejects: a supplementary
        # code point (stored as a surrogate PAIR) or an embedded NUL (`C0 80`).
        # U+FFFD is deliberately NOT a selector — a genuine U+FFFD literal is valid
        # UTF-8 and never raised, so selecting one would make this pass vacuously.
        hard = [
            s
            for s in dk.list_value_strings()
            if any(ord(ch) > 0xFFFF or ch == "\x00" for ch in s)
        ]
        if not hard:
            continue
        hits = dk.find_methods_using_strings([hard[0]], "equals")
        if not hits:
            continue
        m = hits[0].descriptor
        sm = dk.render_method_smali(m)  # would raise UnicodeDecodeError pre-fix
        assert sm, m
        cls = m.split("->")[0]
        assert dk.render_class_smali(cls), cls  # the class renderer too
        # The renderer and the string accessor agree on the decoded value. Compare
        # through the un-escape oracle, not a substring: EscapeSmaliString doubles
        # backslashes, so a literal containing one is not a verbatim substring.
        assert hard[0] in _smali_strings(dk, m), m
        assert hard[0] in dk.list_method_strings(m), m
        return
    pytest.skip("no supplementary/NUL/lone-surrogate literal in the corpus")


def test_smali_never_contains_raw_control_chars(loadable_apks):
    """dexllm#22: a rendered listing must not carry a RAW C0 control character.

    `EscapeSmaliString` hex-escapes bytes < 0x20, but a dex NUL arrives as the
    two bytes `C0 80` and a decode-AFTER-escape design turned it into a real
    U+0000 inside the text — the same literal then showed `\\x01` escaped and NUL
    raw. Escaping the DECODED characters makes every C0 control escape alike.
    Newline is the format's own line separator, so it is excluded.

    Scope note: this asserts C0 only (`cp < 0x20`), which is exactly what the
    escaper covers. DEL, the C1 range and the Unicode line separators U+2028 /
    U+2029 / U+0085 are emitted as themselves — see the encoding contract in
    docs/api.md; a consumer must split on `\\n`, never `str.splitlines()`.

    Must run over the WHOLE loadable corpus, not the `dk` fixture: that fixture
    resolves to an APK with ZERO control-bearing literals, so the assertion could
    not be violated by any implementation and the test passed even against the
    broken escapers it exists to catch.
    """
    seen_candidate = False
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        # Does this APK even carry a control character to get wrong?
        seen_candidate = seen_candidate or any(
            any(ord(ch) < 0x20 for ch in s) for s in dk.list_value_strings()
        )
        for cls in dk.list_classes():
            text = dk.render_class_smali(cls)
            assert not any(ord(c) < 0x20 and c != "\n" for c in text), (apk, cls)
    # Without this the test is vacuous — it would "pass" on a corpus that has
    # nothing to escape, which is precisely how it slipped through review.
    assert seen_candidate, "no control-bearing literal in the corpus — test vacuous"


def _find_two_byte_seq(buf):
    """Offset of a substitutable 2-byte MUTF-8 sequence (same LCP rule as above)."""
    import struct as _s

    def _uleb(b, o):
        r = sh = 0
        while True:
            x = b[o]
            o += 1
            r |= (x & 0x7F) << sh
            sh += 7
            if not (x & 0x80):
                return r, o

    n, off0 = _s.unpack_from("<II", buf, 56)
    data = []
    for i in range(n):
        o = _s.unpack_from("<I", buf, off0 + 4 * i)[0]
        _len, d = _uleb(buf, o)
        data.append((d, bytes(buf[d : buf.index(0, d)])))

    def lcp(a, b):
        k = 0
        while k < len(a) and k < len(b) and a[k] == b[k]:
            k += 1
        return k

    for i, (d, s) in enumerate(data):
        prev = data[i - 1][1] if i else b""
        nxt = data[i + 1][1] if i + 1 < len(data) else b""
        safe = max(lcp(s, prev), lcp(s, nxt)) + 1
        for j in range(d + safe, d + len(s) - 1):
            if 0xC2 <= buf[j] <= 0xDF and 0x80 <= buf[j + 1] <= 0xBF:
                return j
    return None


def test_overlong_mutf8_is_rejected_at_the_verifier(tmp_path):
    """An overlong sequence must never reach the renderer — it is REJECTED at load.

    History, because the assertion here inverted. This guard was written when
    `VerifyMutf8` checked lead/continuation shape only, on the belief that ART did
    the same; a non-NUL OVERLONG was therefore legal input (`E0 80 A2` decodes to
    `"`, `E0 80 8A` to a newline), and the guard proved that escaping the DECODED
    characters stopped it from injecting structure into a rendered literal.

    ART does NOT accept them: `CheckIntraStringDataItem` rejects both forms as an
    "Illegal representation" (dex_file_verifier.cc:1897 / :1922). Porting those two
    checks (dexllm#22) closed a worse hole — an overlong IDENTIFIER decodes to a
    canonical character that cannot be re-encoded, so it enumerated fine and then
    resolved to nothing, silently — and it dissolves this guard's premise. So the
    assertion moves to where the contract now lives: such a dex does not load.

    The escaping in `EscapeSmaliString` stays and is still exercised by
    `test_smali_never_contains_raw_control_chars`; it is now defence in depth
    rather than the only barrier.

    Crafts the input in place: a 3-byte MUTF-8 sequence is replaced by a 3-byte
    overlong, so byte length, utf16_len and string_ids order are all unchanged —
    the ONLY thing that changes is the canonicality of the encoding.
    """
    import struct

    def uleb(buf, off):
        r = s = 0
        while True:
            x = buf[off]
            off += 1
            r |= (x & 0x7F) << s
            s += 7
            if not (x & 0x80):
                return r, off

    def find_seq(buf):
        """Offset of a 3-byte MUTF-8 sequence that can be substituted in place.

        The site must lie past the longest common prefix with BOTH `string_ids`
        neighbours, so replacing it cannot reorder the pool — otherwise the
        canonical-substitution control below could fail with `Out-of-order
        string_ids`, a false failure attributable to the sample rather than the
        code.
        """
        n, off0 = struct.unpack_from("<II", buf, 56)
        data = []
        for i in range(n):
            o = struct.unpack_from("<I", buf, off0 + 4 * i)[0]
            _len, d = uleb(buf, o)
            data.append((d, bytes(buf[d : buf.index(0, d)])))

        def lcp(a, b):
            k = 0
            while k < len(a) and k < len(b) and a[k] == b[k]:
                k += 1
            return k

        for i, (d, s) in enumerate(data):
            prev = data[i - 1][1] if i else b""
            nxt = data[i + 1][1] if i + 1 < len(data) else b""
            safe = max(lcp(s, prev), lcp(s, nxt)) + 1
            for j in range(d + safe, d + len(s) - 2):
                if (
                    0xE0 <= buf[j] <= 0xEF
                    and 0x80 <= buf[j + 1] <= 0xBF
                    and 0x80 <= buf[j + 2] <= 0xBF
                ):
                    return j
        return None

    # Scan EVERY bare .dex, not just the first — the alphabetically-first one has
    # no non-ASCII literal, and skipping here would silently disarm the guard.
    src = pos = None
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = open(cand, "rb").read()
        if raw[:4] != b"dex\n":
            continue
        found = find_seq(bytearray(raw))
        if found is not None:
            src, pos = cand, found
            break
    if src is None:
        pytest.skip("no .dex with a 3-byte MUTF-8 literal in the corpus")

    for payload, what in (
        (b"\xe0\x80\xa2", 'overlong "'),
        (b"\xe0\x80\x8a", "overlong \\n"),
    ):
        b = bytearray(open(src, "rb").read())
        b[pos : pos + 3] = payload

        f = tmp_path / "overlong.dex"
        f.write_bytes(bytes(b))

        report = dexllm.verify(str(f))
        assert not report[0]["valid"], f"{what} must be rejected at load"
        assert "representation" in report[0]["reason"], (what, report[0]["reason"])
        # …and the load path refuses it, so nothing downstream can ever see it.
        with pytest.raises(Exception):
            dexllm.DexKit(str(f))

    # The 2-byte arm needs its own case: every payload above is 3-byte, so the
    # `v2 != 0 && v2 < 0x80` check could be deleted and this guard would still
    # pass. `C1 A9` decodes to 'i' — an overlong spelling of a 1-byte character.
    # (Its `v2 != 0` exemption, the encoded NUL, is covered by the corpus itself:
    # `C0 80` occurs 16,129 times in bundled string_data, so rejecting it would
    # break test_type_id_check_does_not_false_reject_the_corpus.)
    b2 = bytearray(open(src, "rb").read())
    two = _find_two_byte_seq(b2)
    if two is not None:
        b2[two : two + 2] = b"\xc1\xa9"
        f2 = tmp_path / "overlong2.dex"
        f2.write_bytes(bytes(b2))
        rep2 = dexllm.verify(str(f2))
        assert not rep2[0]["valid"], "a 2-byte overlong must be rejected at load"
        assert "representation" in rep2[0]["reason"], rep2[0]["reason"]

    # Non-vacuity: the SAME patch site with a CANONICAL 3-byte sequence must
    # still load. Otherwise this guard would also pass on a dex the verifier
    # rejects for some unrelated reason, proving nothing about canonicality.
    b = bytearray(open(src, "rb").read())
    b[pos : pos + 3] = b"\xe2\x9c\x93"  # U+2713, canonical
    f = tmp_path / "canonical.dex"
    f.write_bytes(bytes(b))
    assert dexllm.verify(str(f))[0]["valid"], dexllm.verify(str(f))[0]["reason"]
