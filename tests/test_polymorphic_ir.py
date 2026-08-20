"""The IR models `invoke-polymorphic`, so a `move-result` after one resolves (dexllm#60).

The builder had no handler for 0xFA/0xFB, so the following `move-result-object`
found no invoke to take its value from and hit the documented null-guard at
`instruction.cpp:274`. The guard did its job — the failure was contained and
reported — but the method was lost, and these are exactly the methods a
`MethodHandle`-using sample is interesting for: 6 of `method_handles.dex`'s 142.

**The signature comes from the CALL SITE, not from the method.** Every
`MethodHandle.invoke` shares one declaration,
`([Ljava/lang/Object;)Ljava/lang/Object;`, so using it would group N arguments as
ONE and type every result `Object`. `invoke-polymorphic` carries a second operand —
a `proto_ids` index — that says how many registers each argument occupies (a `J` or
`D` takes two) and what the result really is. That is why the snapshot ABI gained a
call-site proto and the port gained `GetProto`.

**beyond-DAD.** androguard's own instruction table is 227 entries and stops before
0xFA, so there is no `// DAD:` analogue to be faithful to.

Everything here runs on committed fixtures: no corpus, narrowing-proof.
"""

from __future__ import annotations

import pytest
from conftest import REPO_ROOT

_POLY = REPO_ROOT / "tests" / "data" / "invoke-polymorphic.dex"
_HANDLES = REPO_ROOT / "tests" / "data" / "method_handles.dex"
_CUSTOM = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"


def _dk(path):
    dexllm = pytest.importorskip("dexllm")
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{path.name} missing")
    return dexllm, dexllm.DexKit(str(path))


def _decompile_all(dexllm, dk):
    return {
        m: (dexllm.safe_decompile_method(dk, m, timeout=15.0) or "")
        for c in dk.list_classes()
        for m in dk.list_class_methods(c)
    }


@pytest.mark.parametrize("path,before", [(_HANDLES, 6), (_POLY, 1)])
def test_a_polymorphic_call_no_longer_breaks_its_method(path, before) -> None:
    """Pre-fix these files emitted `before` DECOMPILE ERRORs; now zero.

    The count is in the parametrisation so the test states what it is worth: 6 of
    142 methods on one file and the only method with a body on the other.
    """
    dexllm, dk = _dk(path)
    bad = [
        m for m, src in _decompile_all(dexllm, dk).items() if "DECOMPILE ERROR" in src
    ]
    assert not bad, bad[:3]


def test_the_argument_list_comes_from_the_call_site_proto() -> None:
    """The decisive property, and the reason the snapshot ABI changed.

    `{v0 .. v6}` is SEVEN registers; the call-site proto
    `(Ljava/lang/String;DILjava/lang/Object;I)Ljava/lang/String;` says that is a
    receiver plus FIVE arguments, one of which is a `double` occupying two of them.
    Using the method's own declaration instead would parse ONE parameter and emit
    one argument — so this assertion is what separates the two, and no count of
    registers could stand in for it.
    """
    dexllm, dk = _dk(_POLY)
    src = next(s for s in _decompile_all(dexllm, dk).values() if ".invoke(" in s)
    calls = [ln.strip() for ln in src.split("\n") if ".invoke" in ln]
    arg_lists = [ln[ln.index("(") + 1 : ln.rindex(")")].split(", ") for ln in calls]

    # All THREE sites, because the two instruction formats take different register
    # paths: the first is `k4rcc` ({vC .. vC+vA-1}) and the other two are `k45cc`
    # ({vC, arg[0..3]}, NOT arg[0..4]). Asserting only the first leaves the k45cc
    # walk — the one that can silently emit a proto index as a register — covered
    # by nothing here.
    assert [len(a) for a in arg_lists] == [5, 2, 3], calls

    # EVERY slot, not just the first two. A review deleted the arm that supplies
    # the FIFTH register (`if (count > 4) r.g = ...`) and this file passed 12/12
    # while three real arguments became `unknownType v` on both fixtures — the
    # last slot was unasserted at every arity. The values below come from the
    # fixture's own consts (`const-wide 2.2`, `const/4 1`, `const/4 0`).
    assert arg_lists[0] == ['"a"', "2.2000000000000002", "1", "0", "1"], calls[0]
    assert arg_lists[1] == ["2.2000000000000002", "1"], calls[1]
    assert arg_lists[2] == ['"a"', "2.2000000000000002", "1"], calls[2]


def test_a_void_call_site_emits_a_statement_not_an_assignment() -> None:
    """A polymorphic call whose result nothing reads renders as a statement.

    The docstring here USED to claim this distinguishes a call-site return type
    from the method's declared `Object`. A review built exactly that mutant
    (`param_type` from the call site, `ret_type` from the declaration) and it
    passed — because what removes an unread value is DCE, which runs whatever the
    type says. So this pins the rendering, not the ret-type half; that one is
    pinned by `test_the_result_type_comes_from_the_call_site` below.
    """
    dexllm, dk = _dk(_POLY)
    src = next(s for s in _decompile_all(dexllm, dk).values() if ".invoke(" in s)
    voidish = [
        ln.strip()
        for ln in src.split("\n")
        if ".invoke(" in ln and not ln.strip().startswith(("return", "}"))
    ]
    assert voidish, src
    assert all("=" not in ln.split("(")[0] for ln in voidish), voidish


def test_the_result_type_comes_from_the_call_site() -> None:
    """The ret-type half, which nothing else in this file constrains.

    A review found it completely unguarded: forcing every polymorphic result to
    `int` turns this very line into the uncompilable `int v0 = ...invokeExact(...)`
    and the whole file still passed. `Jazzer.consume`'s call site returns
    `Ljava/lang/Object;` and its result is LIVE, so the declared type is observable
    here.

    KNOWN GAP, stated rather than implied: on these fixtures the only live
    non-void call-site return happens to BE `Object`, which is also what the
    declaration says — so a mutant that takes the return type from the declaration
    is currently EQUIVALENT and cannot be killed from the committed corpus. Closing
    it needs a fixture with a live, non-`Object`, non-void polymorphic result.
    """
    dexllm, dk = _dk(_HANDLES)
    lines = [
        ln.strip()
        for src in _decompile_all(dexllm, dk).values()
        for ln in src.split("\n")
        if "CONSUME.invokeExact(" in ln
    ]
    assert lines, "the fixture no longer carries a live polymorphic result"
    assert all(ln.startswith("Object ") for ln in lines), lines


def test_the_ast_and_the_text_agree_on_the_argument_count() -> None:
    """A beyond-DAD IR change must not make the two emitters disagree.

    The AST node's own `triple` is deliberately the METHOD's — identity, not
    signature — so its proto still reads `([Ljava/lang/Object;)Ljava/lang/Object;`
    beside N params. That asymmetry is intended and documented; what must NOT
    diverge is the argument LIST, which both emitters build from the same IR.
    `params` carries the receiver as well, hence the +1.
    """
    dexllm, dk = _dk(_POLY)
    for c in dk.list_classes():
        for m in dk.list_class_methods(c):
            ast = dk.decompile_method_ast(m)
            text = dexllm.safe_decompile_method(dk, m, timeout=15.0) or ""
            calls = [ln for ln in text.split("\n") if ".invoke" in ln]
            if not calls:
                continue
            found = []

            def walk(node):
                if isinstance(node, list):
                    if node and node[0] == "MethodInvocation":
                        found.append(len(node[1]))
                    for x in node:
                        walk(x)

            walk(ast["ast"]["body"])
            text_counts = [
                len(ln[ln.index("(") + 1 : ln.rindex(")")].split(", ")) for ln in calls
            ]
            assert (
                found
            ), "the AST reports no MethodInvocation for a method that has one"
            assert sorted(found) == sorted(n + 1 for n in text_counts), (found, calls)


def test_the_canonical_method_decompiles_to_its_call() -> None:
    """The shape a reader actually gets back, pinned.

    `Jazzer.autofuzz` was one of the six lost methods. Its polymorphic call takes
    two reference arguments and its result is returned, so the line exercises the
    register layout (`{vC, arg[0..3]}`, not `arg[0..4]`), the call-site arity and
    the non-void result at once.
    """
    dexllm, dk = _dk(_HANDLES)
    srcs = _decompile_all(dexllm, dk)
    hit = [
        s
        for m, s in srcs.items()
        if "autofuzz" in m and "AUTOFUZZ_FUNCTION_1.invoke(" in s
    ]
    assert hit, "the canonical method no longer carries the call"
    assert any(
        "return com.code_intelligence.jazzer.api.Jazzer.AUTOFUZZ_FUNCTION_1"
        ".invoke(p2, p3);" in s.replace("\n", " ").replace("  ", " ")
        or "AUTOFUZZ_FUNCTION_1.invoke(p2, p3)" in s
        for s in hit
    ), hit[0][:400]


def test_invoke_custom_is_still_unmodelled_and_that_is_the_boundary() -> None:
    """Non-discriminating BY DESIGN — it states what dexllm#60 did NOT do.

    `invoke-custom` (0xFC/0xFD) hits the same null-guard for the same reason, but
    its operand is a `call_site_ids` index rather than a method, so modelling it
    needs a call-site reader this port does not have. Five methods here still fail,
    and a future change that fixes them should DELETE this test rather than let it
    quietly become a description of a bug that is gone.
    """
    dexllm, dk = _dk(_CUSTOM)
    bad = [
        m for m, src in _decompile_all(dexllm, dk).items() if "DECOMPILE ERROR" in src
    ]
    assert bad, "invoke-custom decompiles now — delete this test and update the docs"
    for m in bad:
        assert "invoke-custom" in dk.render_method_smali(m), (
            f"{m} fails for some OTHER reason than invoke-custom — that is a "
            "regression this test was not written to allow"
        )


def _polymorphic_offset(raw: bytearray) -> int:
    """Byte offset of an `invoke-polymorphic`, asserted to BE one.

    A bare `raw[i] == 0xFA` scan over the whole file can land on a constant or on
    a string byte. The repo's own crafting helpers assert the shape they are about
    to patch; this checks the second code unit is a plausible method index and the
    fourth a plausible proto index, and fails loudly rather than patching blind.
    """
    import struct

    for i in range(0, len(raw) - 8, 2):
        if raw[i] != 0xFA:
            continue
        meth = struct.unpack_from("<H", raw, i + 2)[0]
        proto = struct.unpack_from("<H", raw, i + 6)[0]
        if meth < 0x1000 and proto < 0x1000:
            return i
    raise AssertionError("the fixture no longer carries an invoke-polymorphic")


# -- the shapes this change newly makes reachable on verify-valid input --------


@pytest.mark.parametrize("arity", [0, 6, 15])
def test_an_out_of_window_register_count_is_safe(arity, tmp_path) -> None:
    """`vA` is a 4-bit nibble and `arg` is `u4 arg[5]`.

    The SISTER commit's smali renderer had a CONFIRMED stack overread from exactly
    this shape — it walked `arg[0..vA-1]` — so the IR builder is pinned rather than
    assumed. `BuildPolymorphicRegs` reads at most `arg[3]` whatever `vA` says, and
    `kVerifyVarArgNonZero` is NOT enforced (`VerifyInsns` clamps), so `vA` 0, 6 and
    15 all verify VALID and reach the builder.

    The assertion is that output is UNCHANGED from the unpatched fixture for a
    count above the window (the extra registers do not exist, so nothing may come
    from them) and that a zero count does not crash — degraded output on a crafted
    dex is the documented GIGO posture, a read past a stack object is not.
    """
    dexllm, dk = _dk(_POLY)
    src = _POLY.read_bytes()
    baseline = "".join(
        dexllm.safe_decompile_class(dk, c, timeout=15.0) or ""
        for c in dk.list_classes()
    )
    raw = bytearray(src)
    off = _polymorphic_offset(raw)
    raw[off + 1] = (arity << 4) | (raw[off + 1] & 0x0F)
    dst = tmp_path / f"a{arity}.dex"
    dst.write_bytes(bytes(raw))
    if not dexllm.verify(str(dst))[0]["valid"]:  # pragma: no cover
        pytest.skip("the craft no longer verifies")
    dk2 = dexllm.DexKit(str(dst))
    out = "".join(
        dexllm.safe_decompile_class(dk2, c, timeout=15.0) or ""
        for c in dk2.list_classes()
    )
    assert out, "the crafted dex produced no output at all"
    if arity > 5:
        assert out == baseline, "a register beyond the 5-slot window reached the output"


def test_an_out_of_range_call_site_proto_is_rejected_at_the_gate(tmp_path) -> None:
    """INVERTED by review, and the inversion is the finding.

    This test used to assert the IR "falls back safely" to the method's
    declaration. A reviewer showed that is not safe in this repo's own terms: the
    fallback is `MethodHandle.invoke`'s ONE `Object` parameter, so a 4-argument
    call renders with ONE — a plausible, silently wrong argument list, while the
    smali view of the SAME instruction says `<bad-proto-idx>`.

    `VerifyInsns` had left the proto operand unbounded, and the comment justifying
    that (written one commit earlier, for the smali half) said the reason was that
    its one reader yields "a visible, distinguishable value rather than the empty
    descriptor that made the METHOD half a wrong ANSWER". The IR is a SECOND reader
    and cannot signal that way, so the operand is bounded at the gate instead —
    which is exactly what dexllm#61 did for the method half.

    The old assertion also held on the UNPATCHED fixture, so it observed only "did
    not crash".
    """
    dexllm = pytest.importorskip("dexllm")
    if not _POLY.is_file():  # pragma: no cover - the file is committed
        pytest.skip("invoke-polymorphic.dex missing")
    raw = bytearray(_POLY.read_bytes())
    off = _polymorphic_offset(raw)
    raw[off + 6], raw[off + 7] = 0xFF, 0xFF
    dst = tmp_path / "badproto.dex"
    dst.write_bytes(bytes(raw))

    strict = dexllm.verify(str(dst))[0]
    assert not strict["valid"]
    assert "proto index" in strict["reason"], strict["reason"]
    # lenient skips VerifyInsns wholesale by design — the documented GIGO boundary.
    assert dexllm.verify(str(dst), lenient=True)[0]["valid"]
