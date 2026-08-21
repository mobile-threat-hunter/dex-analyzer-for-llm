"""The IR models `invoke-custom`, so its bootstrap chain is reconstructed (dexllm#67).

dexllm#60 modelled `invoke-polymorphic` and left this behind, pinned by a test
that said a future change should delete it. This is that change.

**Two failure modes, and the LOUD one was the smaller half.** 5 of
`invoke-custom.dex`'s 144 methods emitted `// DECOMPILE ERROR` (a `move-result`
after an unmodelled invoke, the documented null-guard). Another 6 lost the call
SILENTLY — a void or unconsumed `invoke-custom` simply vanished from the body,
and in `TestLinkerUnrelatedBSM` the following `move-result` bound to an earlier,
unrelated temp, so the method read `assertEquals(2.5f, vtmp1)` where `vtmp1` was
a `getName()` result. A confident wrong answer with no error anywhere.

**What a call site IS** is settled by ART's `CheckInterCallSiteIdItem`: element 0
the bootstrap method handle, element 1 the target name, element 2 the call type,
then the bootstrap's extra arguments. The reconstruction below is what the
runtime does with those, which is jadx's model (the reference oracle CLAUDE.md
names) — and the trailing `/* invoke-custom */` says it IS a reconstruction.

Everything here runs on committed fixtures: no corpus, narrowing-proof.
"""

from __future__ import annotations

import pathlib
import struct

import pytest
from conftest import REPO_ROOT

_CUSTOM = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
_HANDLES = REPO_ROOT / "tests" / "data" / "method_handles.dex"

_CALL_SITE_ID_ITEM = 0x0007
_METHOD_HANDLE_ITEM = 0x0008


def _dk(path, *, dexllm=None):
    dexllm = dexllm or pytest.importorskip("dexllm")
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{path.name} missing")
    return dexllm, dexllm.DexKit(str(path))


def _reconstructed_lines(dk) -> str:
    """Only the lines carrying a reconstructed chain.

    Scoping matters: the fixture's OWN Java calls `MethodType.methodType(...)`,
    so a `methodType(Integer.TYPE)` assertion over the whole output is satisfied
    by the pre-fix build — one parametrised case was non-discriminating for
    exactly that reason (a correctness reviewer measured it).
    """
    return "\n".join(
        ln
        for src in _decompile_all(dk).values()
        for ln in src.splitlines()
        if "/* invoke-custom */" in ln
    )


def _decompile_all(dk) -> dict[str, str]:
    return {
        m: dk.decompile_method(m)
        for c in dk.list_classes()
        for m in dk.list_class_methods(c)
    }


# -- reading the fixture's own call_site_ids, independently of the binding ----


def _uleb(raw: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = raw[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, off


def _strings(raw: bytes) -> list[str]:
    size, off = struct.unpack_from("<II", raw, 0x38)
    out = []
    for i in range(size):
        data_off = struct.unpack_from("<I", raw, off + i * 4)[0]
        _, p = _uleb(raw, data_off)
        out.append(raw[p : raw.index(b"\0", p)].decode("utf-8", "replace"))
    return out


def _map_section(raw: bytes, want: int) -> tuple[int, int]:
    map_off = struct.unpack_from("<I", raw, 0x34)[0]
    n = struct.unpack_from("<I", raw, map_off)[0]
    for i in range(n):
        kind, _, size, off = struct.unpack_from("<HHII", raw, map_off + 4 + i * 12)
        if kind == want:
            return size, off
    raise AssertionError(f"the fixture no longer carries map section {want:#06x}")


class _Element:
    """One encoded_value of a call site, with the offsets a craft needs."""

    def __init__(self, kind: int, arg: int, header_off: int, payload_off: int):
        self.kind = kind
        self.arg = arg
        self.header_off = header_off
        self.payload_off = payload_off
        self.width = 0 if kind in (0x1E, 0x1F) else arg + 1


def _elements(raw: bytes, data_off: int) -> list[_Element]:
    count, off = _uleb(raw, data_off)
    out = []
    for _ in range(count):
        header_off = off
        header = raw[off]
        off += 1
        el = _Element(header & 0x1F, (header >> 5) & 0x07, header_off, off)
        off += el.width
        out.append(el)
    return out


def _site_by_name(raw: bytes, name: str) -> list[_Element]:
    """The call site whose TARGET NAME is `name`, asserted to have one.

    Located by what it MEANS rather than by a hard-coded index, so a
    substituted fixture fails loudly instead of being patched at a wrong offset.
    """
    strings = _strings(raw)
    size, off = _map_section(raw, _CALL_SITE_ID_ITEM)
    for i in range(size):
        data_off = struct.unpack_from("<I", raw, off + i * 4)[0]
        els = _elements(raw, data_off)
        assert len(els) >= 3, f"call_site@{i} is malformed in the fixture itself"
        if els[1].kind != 0x17:
            continue
        idx = int.from_bytes(
            raw[els[1].payload_off : els[1].payload_off + els[1].width], "little"
        )
        if idx < len(strings) and strings[idx] == name:
            return els
    raise AssertionError(f"the fixture no longer carries a call site named {name!r}")


def _crafted(tmp_path, patches: dict[int, bytes], stem: str):
    """The fixture with bytes replaced IN PLACE, so no offset or size moves."""
    raw = bytearray(_CUSTOM.read_bytes())
    for off, data in patches.items():
        assert raw[off : off + len(data)] != data, f"patch at {off:#x} is a no-op"
        raw[off : off + len(data)] = data
    out = tmp_path / f"{stem}.dex"
    out.write_bytes(bytes(raw))
    return out


# -- the defect this closes ---------------------------------------------------


def test_the_fixture_decompiles_with_no_errors() -> None:
    """The headline: 11 methods, 5 loud and 6 silent, all recovered."""
    _, dk = _dk(_CUSTOM)
    srcs = _decompile_all(dk)
    assert len(srcs) >= 140, len(srcs)
    bad = {m: s for m, s in srcs.items() if "DECOMPILE ERROR" in s}
    assert not bad, sorted(bad)
    # Non-vacuity: the file must actually still carry the opcode.
    assert sum(s.count("/* invoke-custom */") for s in srcs.values()) >= 40


def test_the_silently_dropped_call_is_back_and_the_wrong_value_is_gone() -> None:
    """The half no error ever reported.

    Before, `invoke-custom` emitted nothing, so this `move-result` took the value
    of the PREVIOUS invoke — `getName()` — and the assertion read
    `assertEquals(2.5f, vtmp1)` with `vtmp1` a String. Nothing raised.
    """
    _, dk = _dk(_CUSTOM)
    src = dk.decompile_class("LTestLinkerUnrelatedBSM;")
    assert "assertEquals(2.5f, UnrelatedBSM.bsm(" in src, src
    assert "assertEquals(2.5f, vtmp" not in src, src


# -- the reconstruction -------------------------------------------------------

_ADD = (
    "TestLinkerMethodMinimalArguments.linkerMethod("
    'invoke.MethodHandles.lookup(), "_add", '
    "invoke.MethodType.methodType(Integer.TYPE, Integer.TYPE, Integer.TYPE))"
    ".dynamicInvoker().invoke(p4, p5) /* invoke-custom */"
)


def test_the_bootstrap_chain_is_reconstructed() -> None:
    """Pinned as a LITERAL — the whole chain, in order, with its marker.

    Every clause is load-bearing and fails on its own mutant: the bootstrap
    (`linkerMethod`), the `Lookup`, the target name, the call type as
    `methodType(RET, params…)` with the RETURN type FIRST, the primitive class
    literals, `dynamicInvoker()`, the real registers on `invoke`, and the marker.
    """
    _, dk = _dk(_CUSTOM)
    src = dk.decompile_method("LTestLinkerMethodMinimalArguments;->test(III)V")
    assert _ADD in src, src


def test_the_call_type_comes_from_the_call_site_not_from_the_method() -> None:
    """`MethodHandle.invoke` declares `([Ljava/lang/Object;)Ljava/lang/Object;`.

    Using that declaration would group N arguments as ONE and type every result
    `Object`; the site's method type is what says `(FF)F` here — which is also
    why the two float registers render as float LITERALS rather than raw bits.
    """
    _, dk = _dk(_CUSTOM)
    src = dk.decompile_class("LTestLinkerUnrelatedBSM;")
    assert ".dynamicInvoker().invoke(2f, 0.5f) /* invoke-custom */" in src, src


def test_bootstrap_arguments_keep_their_own_types() -> None:
    """int / float / double / String / class literal / long, each round-tripped.

    No CHAR — the fixture encodes every char argument as an INT (`97` here is
    `0x04`), which is why the CHAR path had no coverage and its bug shipped. It
    is covered by `test_a_char_bootstrap_argument_is_zero_extended` instead.
    """
    _, dk = _dk(_CUSTOM)
    src = dk.decompile_class("LTestLinkerMethodMultipleArgumentTypes;")
    assert (
        '), -1, 1, 97, 1024, 1, 11.1000004f, 2.2000000000000002, "Hello", '
        "TestLinkerMethodMultipleArgumentTypes.class, 123456789)" in src
    ), src


@pytest.mark.parametrize(
    "literal",
    ["methodType(Void.TYPE)", "methodType(Integer.TYPE)", "methodType(Float.TYPE,"],
)
def test_a_primitive_class_literal_is_spelled_as_a_class_literal(literal) -> None:
    """`Integer.TYPE`, not `int` and not `"I"` — the value IS a `Class`."""
    _, dk = _dk(_CUSTOM)
    assert literal in _reconstructed_lines(dk), literal


@pytest.mark.parametrize(
    "proto, literal",
    [
        # `(I)V` — a void return in front of one parameter.
        ("(I)V", "methodType(Void.TYPE, Integer.TYPE)"),
        # `(ILjava/lang/String;Ljava/lang/Double;)I` — three DIFFERENT types.
        (
            "(ILString;LDouble;)I",
            "methodType(Integer.TYPE, Integer.TYPE, String.class, Double.class)",
        ),
    ],
)
def test_the_call_type_puts_the_RETURN_type_first(proto, literal) -> None:
    """`MethodType.methodType(rtype, ptypes…)` — the return type LEADS.

    Every other `methodType` this fixture produces is homogeneous (`(II)I` is
    three `Integer.TYPE`), so a reordering is invisible there — a mutant that
    appends the return type LAST passed the whole file until these two cases,
    whose signatures are deliberately mixed, were added.
    """
    _, dk = _dk(_CUSTOM)
    assert literal in _reconstructed_lines(dk), (proto, literal)


def test_the_marker_is_inert_for_every_other_invoke() -> None:
    """It marks a RECONSTRUCTION. A real call must never carry it.

    `method_handles.dex` is the sibling fixture: 16 `invoke-polymorphic` sites,
    which dexllm#60 models with the ORDINARY virtual handlers, so nothing there
    is reconstructed and nothing there may be marked.
    """
    _, dk = _dk(_HANDLES)
    joined = "\n".join(_decompile_all(dk).values())
    assert "invoke-custom" not in joined
    assert ".invoke(" in joined, "the sibling fixture lost its polymorphic calls"


def test_the_smali_view_is_untouched() -> None:
    """dexllm#66 owns the listing; this change may not move it.

    Non-discriminating BY DESIGN for the IR — it pins the boundary between the
    two changes, so an operand rendered into smali from the new reader would show.
    """
    _, dk = _dk(_CUSTOM)
    joined = "\n".join(dk.render_class_smali(c) for c in dk.list_classes())
    assert "call_site@27" in joined
    assert "invoke-custom" in joined
    # The reconstruction lives in the Java view only. The tokens have to be the
    # JAVA spellings: the fixture's own code really does call
    # `Ljava/lang/invoke/MethodType;->methodType(...)`, so a bare `methodType(`
    # is present in the listing on BOTH sides and would assert nothing.
    for token in (
        "/* invoke-custom */",
        ".dynamicInvoker()",
        "invoke.MethodHandles.lookup()",
        "invoke.MethodType.methodType(",
    ):
        assert token not in joined, token


def test_the_ast_carries_the_same_chain() -> None:
    """A root-cause IR change, so both emitters get it — and only the text has
    the marker, which is a comment and has no slot in androguard's AST shape."""
    import json

    _, dk = _dk(_CUSTOM)
    ast = dk.decompile_method_ast(
        "LTestLinkerMethodMinimalArguments;->test(III)V", include_source=False
    )
    blob = json.dumps(ast["ast"])
    for token in ("lookup", "methodType", "dynamicInvoker", "_add", "linkerMethod"):
        assert token in blob, token
    assert "invoke-custom" not in blob


# -- crafted: the shapes the fixture does not carry ---------------------------


def test_invoke_custom_range_is_modelled_too(tmp_path) -> None:
    """0xFD has ZERO sites in the fixture, so it is crafted.

    `35c` (`AG|op BBBB FEDC`) and `3rc` (`AA|op BBBB CCCC`) are both 3 code units,
    so retyping one to the other is length-preserving; the registers are rewritten
    to a range that fits the frame, and the craft is asserted to still verify.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = bytearray(_CUSTOM.read_bytes())
    # `invoke-custom {v4, v5}, call_site@27` at 0x2c of the method's insns —
    # located by its exact code units rather than by a bare 0xFC scan.
    want = bytes([0xFC, 0x20]) + struct.pack("<H", 27) + bytes([0x54, 0x00])
    at = raw.find(want)
    assert at >= 0 and at % 2 == 0, f"fixture shape moved ({want.hex()})"
    assert raw.find(want, at + 1) < 0, "the shape is not unique in the fixture"
    # AA = 2 registers starting at v4  ->  {v4, v5}, the same pair.
    raw[at : at + 6] = (
        bytes([0xFD, 0x02]) + struct.pack("<H", 27) + struct.pack("<H", 4)
    )
    out = tmp_path / "range.dex"
    out.write_bytes(bytes(raw))
    assert all(r["valid"] for r in dexllm.verify(str(out))), dexllm.verify(str(out))
    dk = dexllm.DexKit(str(out))
    src = dk.decompile_method("LTestLinkerMethodMinimalArguments;->test(III)V")
    assert "DECOMPILE ERROR" not in src, src
    assert ".dynamicInvoker().invoke(p4, p5) /* invoke-custom */" in src, src


def test_two_bootstrap_arguments_that_print_alike_stay_distinct(tmp_path) -> None:
    """An IR node is keyed by a VALUE-derived id, so `2` and `"2"` collide.

    `extraArguments` passes `1, "2", 3`; making the third argument `2` gives two
    arguments whose ids are both `c2` and whose renderings differ. Without the
    synthetic id the invoke's `var_map` keeps ONE of them and renders it twice.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "extraArguments")
    assert [e.kind for e in els[3:]] == [0x04, 0x17, 0x04], [e.kind for e in els]
    assert els[5].width == 1
    out = _crafted(tmp_path, {els[5].payload_off: bytes([2])}, "alike")
    dk = dexllm.DexKit(str(out))
    src = dk.decompile_class("LTestBadBootstrapArguments;")
    assert '"extraArguments", invoke.MethodType.methodType(Void.TYPE), 1, "2", 2)' in (
        src
    ), [ln for ln in src.splitlines() if "extraArguments" in ln]


def test_a_short_encoded_float_argument_is_zero_extended_to_the_right(
    tmp_path,
) -> None:
    """The dex spec fills a float payload from the MSB end, and so does ART.

    A left-justified read turns `40 C0` (-3.0f) into the 0x0000C040 denormal.
    The fixture's floats are all full width, where the two readings agree, so the
    LAST element of a site is shortened in place — the two bytes it stops using
    are simply not read, and no offset moves.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "methodI")
    last = els[-1]
    assert last.kind == 0x10 and last.arg == 3, (last.kind, last.arg)
    out = _crafted(
        tmp_path,
        {
            last.header_off: bytes([0x10 | (1 << 5)]),
            last.payload_off: bytes([0x40, 0xC0]),
        },
        "shortfloat",
    )
    dk = dexllm.DexKit(str(out))
    src = dk.decompile_class("LTestVariableArityLinkerMethod;")
    assert '"methodI"' in src, src
    line = next(
        ln for ln in src.splitlines() if '"methodI"' in ln and "dynamicInvoker" in ln
    )
    assert "-3f).dynamicInvoker().invoke() /* invoke-custom */" in line, line


def test_a_method_handle_argument_renders_as_a_method_reference(tmp_path) -> None:
    """A `MethodHandle` bootstrap argument has no Java literal at all.

    Zero of the fixture's 46 sites carry one — every handle there is the
    BOOTSTRAP, which is element 0 — yet it is the common shape in real
    invoke-dynamic (`LambdaMetafactory.metafactory` takes one). So an `int`
    argument is retyped in place to the handle the site already names.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "methodF")
    assert [e.kind for e in els[3:]] == [0x04], [e.kind for e in els]
    handle_idx = raw[els[0].payload_off]
    out = _crafted(
        tmp_path,
        {els[3].header_off: bytes([0x16]), els[3].payload_off: bytes([handle_idx])},
        "handlearg",
    )
    dk = dexllm.DexKit(str(out))
    src = dk.decompile_class("LTestVariableArityLinkerMethod;")
    line = next(
        ln for ln in src.splitlines() if '"methodF"' in ln and "dynamicInvoker" in ln
    )
    # Unquoted: a method reference is a NAME, not a string literal.
    assert (
        "methodType(Void.TYPE), "
        "TestVariableArityLinkerMethod::bsmWithIntAndStringArray)" in line
    ), line
    assert '"TestVariableArityLinkerMethod::' not in line, line


def test_an_unresolvable_call_site_emits_nothing_rather_than_guessing(
    tmp_path,
) -> None:
    """The documented fallback: the pre-dexllm#67 behaviour, not fabricated output.

    Element 1 must be a String; retyping it to an int makes the site
    unresolvable, and the method that consumes its result goes back to the
    null-guard — loudly, and without touching the sibling methods.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "_add")
    assert els[1].kind == 0x17 and els[1].width == 1
    out = _crafted(tmp_path, {els[1].header_off: bytes([0x04])}, "unresolvable")
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    dk = dexllm.DexKit(str(out))
    src = dk.decompile_method("LTestLinkerMethodMinimalArguments;->test(III)V")
    assert "DECOMPILE ERROR" in src, src
    # Everything else still decompiles: one bad site is not a lost dex.
    others = [
        m
        for m, s in _decompile_all(dk).items()
        if "DECOMPILE ERROR" in s and "MinimalArguments" not in m
    ]
    assert not others, others


def test_an_unresolvable_void_call_site_fabricates_nothing(tmp_path) -> None:
    """The half that a consumed result hides.

    A site whose result IS consumed falls back to the null-guard whether or not
    the bail exists, because an unresolved site has no call type and reads as
    void — so the observable difference lives on a VOID site. Without the bail,
    the bootstrap (which is resolved BEFORE the failing element) is rendered
    beside an empty name and a fabricated `methodType(Void.TYPE)`: a plausible
    call nobody read. That is the confidently-wrong shape this change exists to
    remove, so it is asserted, not assumed.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "missingParameterTypes")
    assert els[1].kind == 0x17 and els[1].width == 2
    out = _crafted(
        tmp_path, {els[1].header_off: bytes([0x04 | (1 << 5)])}, "void_unresolvable"
    )
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    _, clean = _dk(_CUSTOM, dexllm=dexllm)
    before = clean.decompile_class("LTestBadBootstrapArguments;")
    after = dexllm.DexKit(str(out)).decompile_class("LTestBadBootstrapArguments;")
    # The property, stated directly: the unreadable site contributes NOTHING,
    # and its siblings in the same method are untouched. Asserting the COUNT
    # rather than the absence of one spelling is what catches a fabrication
    # built from an empty bootstrap (`.(lookup(), "", methodType(Void.TYPE))`)
    # as well as one built from a half-read record.
    assert before.count("/* invoke-custom */") >= 5, before
    assert after.count("/* invoke-custom */") == before.count("/* invoke-custom */") - 1
    assert 'lookup(), "",' not in after, after


# -- what the adversarial review found -----------------------------------------


@pytest.mark.parametrize(
    "payload, rendered",
    [(0x41, "65"), (0x7F, "127"), (0x80, "128"), (0xFF, "255")],
)
def test_a_char_bootstrap_argument_is_zero_extended(payload, rendered, tmp_path):
    """CHAR is the ONE unsigned member of the encoded_value integer family.

    ART reads it with `ReadUnsignedInt`. Sign-extending it and masking back to 16
    bits cannot undo the damage — a one-byte `0x80` becomes `0xFF80` = 65408
    instead of 128, which is what d8 emits for any char in 128..255, so this is
    reachable from an ordinarily compiled dex and not only from a craft. Caught
    by an adversarial reviewer against jadx as the oracle; the fixture's own
    chars are encoded as INT, so nothing here exercised the CHAR path at all.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "narrowArguments")
    target = els[5]
    assert target.kind == 0x04 and target.width == 1, (target.kind, target.width)
    patched = bytearray(raw)
    patched[target.header_off] = 0x03  # CHAR, one payload byte
    patched[target.payload_off] = payload
    out = tmp_path / f"char{payload}.dex"
    out.write_bytes(bytes(patched))
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    dk = dexllm.DexKit(str(out))
    line = next(
        ln
        for ln in dk.decompile_class("LTestBadBootstrapArguments;").splitlines()
        if '"narrowArguments"' in ln and "dynamicInvoker" in ln
    )
    assert f", 127, {rendered}, -32768)" in line, line


@pytest.mark.parametrize(
    "element, retyped, why",
    [
        (0, 0x17, "the bootstrap must be a method HANDLE"),
        (2, 0x04, "the call type must be a method TYPE"),
    ],
)
def test_every_fixed_element_must_have_its_declared_kind(
    element, retyped, why, tmp_path
) -> None:
    """ART's `CheckInterCallSiteIdItem` fixes all THREE element kinds.

    Only the middle one had a guard, so two of the three checks were revertible
    with a green suite — an adversarial reviewer built both mutants. The property
    is the same one the void-unresolvable test states: an unreadable site
    contributes NOTHING rather than a chain built from what was read before the
    check failed.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "missingParameterTypes")
    target = els[element]
    keep_arg = target.arg << 5
    out = _crafted(
        tmp_path, {target.header_off: bytes([retyped | keep_arg])}, f"el{element}"
    )
    assert all(r["valid"] for r in dexllm.verify(str(out))), why
    _, clean = _dk(_CUSTOM, dexllm=dexllm)
    before = clean.decompile_class("LTestBadBootstrapArguments;")
    after = dexllm.DexKit(str(out)).decompile_class("LTestBadBootstrapArguments;")
    assert after.count("/* invoke-custom */") == (
        before.count("/* invoke-custom */") - 1
    ), why


def _method_handle_entry(raw: bytes, idx: int) -> int:
    """Byte offset of `method_handle_item[idx]`, asserted to exist."""
    size, off = _map_section(raw, _METHOD_HANDLE_ITEM)
    assert idx < size, (idx, size)
    return off + idx * 8


@pytest.mark.parametrize(
    "handle_type, expected, unexpected",
    [
        # 0x06 invoke-constructor — method-reference syntax says `::new`.
        (0x06, "::new)", "::bsmWithIntAndStringArray"),
        # 0x01 static-get — a FIELD, which `::` cannot express, so `Cls.name`.
        (0x01, ".field_or_method)", "::"),
    ],
    ids=["constructor", "field"],
)
def test_a_handle_argument_renders_by_its_KIND(
    handle_type, expected, unexpected, tmp_path
) -> None:
    """All 29 handles in the fixture are `invoke-static`, so two of the three
    rendering arms had no coverage at all — an adversarial reviewer built both
    mutants (always `::`, and never `new`) and both passed.

    The handle's own `method_handle_type` is patched in place, and for a FIELD
    kind its member index is repointed at a real `field_id` (the fixture's
    handles name METHOD ids, which are out of range for the field table and
    would make the site unresolvable for an unrelated reason).
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "methodF")
    assert [e.kind for e in els[3:]] == [0x04], [e.kind for e in els]
    handle_idx = raw[els[0].payload_off]
    entry = _method_handle_entry(raw, handle_idx)
    patches = {
        entry: struct.pack("<H", handle_type),
        els[3].header_off: bytes([0x16]),
        els[3].payload_off: bytes([handle_idx]),
    }
    if handle_type <= 0x03:
        patches[entry + 4] = struct.pack("<H", 0)  # field_ids[0]
    out = _crafted(tmp_path, patches, f"handle{handle_type}")
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    dk = dexllm.DexKit(str(out))
    line = next(
        ln
        for ln in dk.decompile_class("LTestVariableArityLinkerMethod;").splitlines()
        if '"methodF"' in ln and "dynamicInvoker" in ln
    )
    if handle_type <= 0x03:
        assert unexpected not in line, line
        assert line.count(".") >= 1 and "methodType(Void.TYPE), " in line, line
    else:
        assert expected in line, line
        assert unexpected not in line, line


def test_a_float_or_double_bootstrap_argument_round_trips() -> None:
    """`%g` is six significant figures, and the AST never used it.

    `Double.MAX_VALUE` printed `1.79769e+308` in the text while the AST rendered
    the same node as `1.7976931348623157e+308` — so the "text and AST agree"
    claim was false for exactly these values, which only this change can produce
    (every `const*` opcode builds an INTEGER-typed Constant, so no double-valued
    Constant reached an emitter before).
    """
    import json

    _, dk = _dk(_CUSTOM)
    method = next(
        m
        for m in dk.list_class_methods("LTestBadBootstrapArguments;")
        if "e+308" in dk.decompile_method(m)
    )
    text = dk.decompile_method(method)
    assert "1.7976931348623157e+308" in text, text
    assert "1.79769e+308," not in text, text
    blob = json.dumps(dk.decompile_method_ast(method, include_source=False)["ast"])
    assert "1.7976931348623157e+308" in blob, "the AST and the text disagree"


_CONTAINER = pathlib.Path(
    "/home/nyahumi/Project/aosp/art/test/dexdump/multidex-container.dex"
)


def test_a_v41_container_slice_resolves_against_the_CONTAINER_base() -> None:
    """`Reader::Header()` is SLICE-relative; every offset is CONTAINER-relative.

    The slicer's ctor sets `header_ = ptr<Header>(0)` and only THEN
    `ValidateHeader` does `image_ -= header_->ContainerOff()`. A span based at the
    header therefore rejects the second slice's own `map_off` (measured on this
    file: slice at +564, `map_off` 1332, container 1468 bytes) — and for a
    geometry where the sum lands back in range it would read ANOTHER slice's
    bytes, which is how a fabricated bootstrap chain gets built out of them.

    NON-DISCRIMINATING for the bug it guards, and it says so: no v41 container
    carrying a `call_site_ids` section exists to test end to end, so what this
    pins is that a container's later slices still decompile at all through the
    changed span helper. SKIPPED without a local AOSP checkout — an environment
    fact (issue #46).
    """
    dexllm = pytest.importorskip("dexllm")
    if not _CONTAINER.is_file():
        pytest.skip("no local AOSP checkout")
    dk = dexllm.DexKit(str(_CONTAINER))
    assert dk.dex_count() == 2, dk.dex_count()
    assert [d["offset"] for d in dk.extract_dexes()] == [0, 564]
    classes = dk.list_classes()
    assert classes, "the container stopped loading"
    for c in classes:
        assert "DECOMPILE ERROR" not in dk.decompile_class(c), c


def test_a_call_type_wider_than_the_instruction_fabricates_no_arguments(
    tmp_path,
) -> None:
    """The call-site proto is UNVERIFIED, so it can claim more than vA registers.

    `BuildInvokeRegs` always yields a 5-slot window with empty names in the
    unused slots; handing all five to `GetArgs` then materialises
    `unknownType v` arguments that no register holds. Truncating to vA makes
    `GetArgs` bail and render none — refusing beats inventing, the same rule the
    unresolved-site path follows. Constructed by a correctness reviewer.
    """
    dexllm = pytest.importorskip("dexllm")
    raw = _CUSTOM.read_bytes()
    els = _site_by_name(raw, "happy")  # `()V`, and the instruction passes vA = 0
    assert els[2].kind == 0x15 and els[2].width == 1
    proto_size, proto_off = struct.unpack_from("<II", raw, 0x48)
    wide = next(
        i
        for i in range(proto_size)
        if (po := struct.unpack_from("<III", raw, proto_off + i * 12)[2])
        and struct.unpack_from("<I", raw, po)[0] == 3
    )
    out = _crafted(tmp_path, {els[2].payload_off: bytes([wide])}, "wideproto")
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    dk = dexllm.DexKit(str(out))
    line = next(
        ln
        for ln in dk.decompile_class("LTestBadBootstrapArguments;").splitlines()
        if '"happy"' in ln and "dynamicInvoker" in ln
    )
    # The three-parameter call type is still SHOWN — it is what the dex says —
    # but the call itself passes the registers that exist, which is none.
    assert "methodType(Integer.TYPE, Integer.TYPE, String.class, Double.class)" in line
    assert ".dynamicInvoker().invoke() /* invoke-custom */" in line, line
    assert "unknownType" not in line, line


def test_the_span_base_subtracts_the_container_offset() -> None:
    """SOURCE-level, because no runtime input in reach can discriminate it.

    A v41 container's later slices are where `Header()` and the slicer's `image_`
    diverge, and **no such container carrying a `call_site_ids` section exists**:
    the bundled corpus has none, and rebasing `invoke-custom.dex` into one is not
    a length-preserving craft (every offset inside it would have to move). The
    sibling runtime test therefore pins only that a container still loads, and a
    reviewer's mutant restoring the slice base passes the whole suite.

    An unreachable-but-load-bearing line still has to be pinned somewhere, and
    source is the only place left — the same argument dexllm#63 makes for its
    `default:` arm. Comment-stripped, so commenting the subtraction out is not a
    way past it.
    """
    src = (REPO_ROOT / "native" / "core_ext" / "dexitem_code_source.cpp").read_text()
    body = "\n".join(
        ln.split("//")[0] for ln in src.splitlines() if not ln.strip().startswith("//")
    )
    body = body[body.index("ImageSpan SpanOf(") :]
    body = body[: body.index("\n}\n")]
    assert "hdr->ContainerOff()" in body, body
    assert "- hdr->ContainerOff()" in body.replace("  ", " "), body
