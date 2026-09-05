"""dexllm#64 - an unrenderable static initializer must not look like none.

`DecodeEncodedValueText` returned an EMPTY string for five `encoded_value`
types, and that empty string is filtered out twice (once by the producer, once
by the renderer), so a field whose `static_values` entry exists but could not be
spelled and a field with no entry at all produced BYTE-IDENTICAL Java::

    public static final MethodHandle H;   // has a handle in static_values
    public static final MethodHandle H;   // has no initializer

The constant was recoverable from nowhere else - `decompile_class` is the only
surface that reads `static_values` at all (`render_class_smali` emits none since
dexllm#45, and neither the SDK nor MCP exposes an initializer accessor). It sat
against this repo's own make-ignorance-representable precedent (dexllm#41's
`access_flags` -> `None`, dexllm#49's `dropped_touches`).

**Both reference decompilers do worse, which is why this follows neither.**
androguard renders the wrapper OBJECT, so `0x1c`/`0x1d` emit a memory address -
non-deterministic across runs, which this project gates against. jadx 1.5.0
THROWS on `0x15`/`0x16` (`Can't decode value: ENCODED_METHOD_TYPE`) and loses the
whole CLASS, and emits a bare `= ;` for `0x1a`. Only its `0x1c` `{...}` is worth
matching, and it is matched.

**Two shapes, not one.** A `MethodType` and an array HAVE Java expression forms,
so they render as initializers. A method handle, a method reference and an
annotation do NOT - Java cannot assign any of them to a field - so they ride as
a trailing `// = ...` comment. The flag travels with the VALUE rather than being
decided per type, because an array holding a method handle has no expression
form either.

Every craft below runs on the committed `tests/data/invoke-custom.dex`: no
corpus, so these hold in the CI leg and under any `$DEXLLM_TEST_APK` narrowing
(issue #46). The bundled corpus carries ZERO values of all five types (the
issue's census: 55 sources / 113,349 top-level values / 0 hits), so a corpus
measurement is blind to this by construction and the crafts are the whole proof.
"""

from __future__ import annotations

import pathlib
import struct

import pytest
from conftest import REPO_ROOT

_CUSTOM = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
_FIXTURE_CLASS = "LTestLinkerMethodMinimalArguments;"

# `LTestLinkerMethodMinimalArguments`'s static_values, the same eight bytes
# dexllm#70 re-lays: four one-byte INT (0x04) elements in 29641..29648, count at
# 29640.  A craft re-lays THOSE EIGHT BYTES and nothing else - a payload of N
# bytes takes 1 + N, so the count drops to 1 + (7 - N) // 2 and the surviving
# INTs follow.  No offset, no section size, no neighbouring structure moves.
_EL0_COUNT_OFF = 29640
_EL0_HEADER_OFF = 29641
_EL0_PAYLOAD_OFF = 29642
_ARRAY_BYTES = 8
_TAIL_VALUES = (2, 0, 3)

# The field element [0] is paired with, and one that has no static value at all.
_FIELD0 = "FAILURE_TYPE_LINKER_METHOD_RETURNS_NULL"

# Fixture indices, each chosen to reach a DIFFERENT branch.  Resolved by an
# independent walk of the dex (`class_defs` / `proto_ids` / `method_ids` / the
# method_handle map section), not by asking the decoder under test.
_PROTO_0 = 0  # (LTestInvocationKinds;)D
_PROTO_II_I = 4  # (II)I - the proto the fixture's OWN bootstrap chain uses
# (ILjava/lang/String;Ljava/lang/Double;)I - MIXED, so argument ORDER is visible.
# It is not sufficient ALONE: its return type is `I` and its first parameter is
# `I` too, so a mutant that moves the return type to position 1 renders the same
# string. `mt0` - `(LTestInvocationKinds;)D` - is what kills that one. The pair
# is required, and a delta reviewer had to point out that nothing said so.
# `(II)I` is homogeneous and `_PROTO_0` has one parameter, so neither can see a
# reordering: dexllm#67 paid for that exact hole once (its M9), and an
# adversarial review built the mutant that walks `ParseParamsType` backwards and
# passed the whole 875-test suite on the strength of it.
_PROTO_MIXED = 5
_METHOD_INIT = 0  # LMain;-><init>()V        -> the `::new` branch
_METHOD_PLAIN = 1  # LMain;->TestLinker...()V -> the `::name` branch
_METHOD_CLINIT = 63  # a `<clinit>`, which HAS a method_id (four of them here)
_HANDLE_0 = 0  # kind 4, LTestBadBootstrapArguments;->bsm
_TYPE_ANNOTATION = 20  # Lannotations/BootstrapMethod;
_STRING_WITH_NEWLINE = 3  # "... was invoked % 2d times\n" - a RAW 0x0A
_STRING_NAME = 44  # "Hello" - a plain identifier, standing in for an element name


def _craft(
    tmp_path,
    value_type: int,
    payload: bytes,
    stem: str,
    string3: bytes | None = None,
) -> pathlib.Path:
    """Retype element [0] to `value_type` with `payload`, LENGTH-PRESERVING.

    `value_arg` is derived from the payload width for the index-shaped types and
    forced to 0 for ARRAY/ANNOTATION, whose gate arms reject any other value.
    """
    n = len(payload)
    # The whole craft lives in the array's own eight bytes: one header plus the
    # payload, with the surviving INTs (two bytes each) after it.
    assert 1 <= n <= _ARRAY_BYTES - 1, n
    arg = 0 if value_type in (0x1C, 0x1D) else n - 1
    survivors = (_ARRAY_BYTES - (1 + n)) // 2
    raw = bytearray(_CUSTOM.read_bytes())
    # The fixture must still have the shape the craft assumes, or it would be
    # patched at a wrong offset and the test would assert about nothing.
    assert raw[_EL0_COUNT_OFF] == 0x04, hex(raw[_EL0_COUNT_OFF])
    assert raw[_EL0_HEADER_OFF] == 0x04, hex(raw[_EL0_HEADER_OFF])
    raw[_EL0_COUNT_OFF] = 1 + survivors
    raw[_EL0_HEADER_OFF] = value_type | (arg << 5)
    off = _EL0_PAYLOAD_OFF
    raw[off : off + n] = payload
    off += n
    for value in _TAIL_VALUES[:survivors]:
        raw[off] = 0x04  # INT, value_arg 0
        raw[off + 1] = value
        off += 2
    assert off <= _EL0_PAYLOAD_OFF + _ARRAY_BYTES - 1, off
    if string3 is not None:
        _relay_string3(raw, string3)
    out = tmp_path / f"{stem}.dex"
    out.write_bytes(bytes(raw))
    return out


# `string_ids[3]` — " Call site instance #%02d was invoked % 2d times\n", 49 bytes.
# Long enough to hold a forged declaration, and a plain `string_data_item`, so it
# can be re-laid in place: byte length preserved, `utf16_len` recomputed.
_STRING3_LEN = 49


def _method_handle_entry(raw: bytearray, index: int) -> int:
    """Byte offset of `method_handle_item[index]`, found through the map."""
    map_off = struct.unpack_from("<I", raw, 0x34)[0]
    for i in range(struct.unpack_from("<I", raw, map_off)[0]):
        e = map_off + 4 + 12 * i
        if struct.unpack_from("<H", raw, e)[0] == 0x0008:  # TYPE_METHOD_HANDLE_ITEM
            size, off = struct.unpack_from("<II", raw, e + 4)
            assert index < size, (index, size)
            return off + 8 * index
    raise AssertionError("the fixture has no method_handle section")


def _uleb(raw: bytearray, off: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = raw[off]
        off += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, off


def _relay_string3(raw: bytearray, body: bytes) -> None:
    """Overwrite pool string 3 with `body`, preserving its byte length.

    `utf16_len` is a CODE UNIT count, not a byte count, so a multibyte injection
    changes it even when the byte length does not — and the verifier checks it.

    Counted over MUTF-8, not by decoding as UTF-8: the pool is MUTF-8, where
    `C0 80` is U+0000 and an astral character is a SURROGATE PAIR of two 3-byte
    sequences. Neither decodes as UTF-8 at all. Every MUTF-8 sequence is exactly
    one UTF-16 code unit, so the count is the number of NON-continuation bytes.
    """
    off = struct.unpack_from("<I", raw, struct.unpack_from("<I", raw, 0x3C)[0] + 12)[0]
    length, data = _uleb(raw, off)
    assert length == _STRING3_LEN, length
    assert data - off == 1, "utf16_len is not a one-byte uleb any more"
    body = (body + b" " * length)[:length]
    units = sum(1 for b in body if (b & 0xC0) != 0x80)
    assert units < 0x80, units
    raw[off] = units
    raw[data : data + length] = body


def _decl(tmp_path, value_type: int, payload: bytes, stem: str) -> str:
    """The one declaration line element [0] lands on."""
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, value_type, payload, stem)
    # The craft must still LOAD, or a rejection would be doing the asserting.
    report = dexllm.verify(str(out))
    assert report and all(r["valid"] for r in report), report
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)
    # `split("\n")`, not `splitlines()`: since dexllm#83 a declaration can carry a
    # raw U+0085 / U+2028 / U+2029 inside its literal, and `splitlines()` breaks on
    # all three where the emitter does not. That is the contract docs/api.md states
    # for this output; a helper that parses it must not be the counterexample.
    hits = [ln.strip() for ln in src.split("\n") if _FIELD0 in ln]
    assert len(hits) == 1, hits
    return hits[0]


# -- the two shapes -----------------------------------------------------------

# `stem, value_type, payload, expected declaration` - PINNED literals, because a
# guard parametrised over the production rendering cannot catch an edit OF it.
_EXPRESSIONS = [
    (
        "mt0",
        0x15,
        bytes([_PROTO_0]),
        f"static final int {_FIELD0} = "
        "invoke.MethodType.methodType(Double.TYPE, TestInvocationKinds.class);",
    ),
    (
        "mt_ii_i",
        0x15,
        bytes([_PROTO_II_I]),
        f"static final int {_FIELD0} = "
        "invoke.MethodType.methodType(Integer.TYPE, Integer.TYPE, Integer.TYPE);",
    ),
    (
        "mt_mixed",
        0x15,
        bytes([_PROTO_MIXED]),
        f"static final int {_FIELD0} = "
        "invoke.MethodType.methodType(Integer.TYPE, Integer.TYPE, "
        "String.class, Double.class);",
    ),
    ("arr", 0x1C, bytes([1, 0x04, 7]), f"static final int {_FIELD0} = {{7}};"),
    ("arr_empty", 0x1C, bytes([0]), f"static final int {_FIELD0} = {{}};"),
]

_COMMENTS = [
    (
        "mh0",
        0x16,
        bytes([_HANDLE_0]),
        f"static final int {_FIELD0};  // = TestBadBootstrapArguments::bsm",
    ),
    (
        "m_init",
        0x1A,
        bytes([_METHOD_INIT]),
        f"static final int {_FIELD0};  // = Main::new",
    ),
    (
        "m_plain",
        0x1A,
        bytes([_METHOD_PLAIN]),
        f"static final int {_FIELD0};  " "// = Main::TestLinkerMethodMinimalArguments",
    ),
    (
        "m_clinit",
        0x1A,
        bytes([_METHOD_CLINIT]),
        f"static final int {_FIELD0};  " "// = TestDynamicBootstrapArguments::<clinit>",
    ),
    (
        "annot",
        0x1D,
        bytes([_TYPE_ANNOTATION, 0]),
        f"static final int {_FIELD0};  // = @annotations.BootstrapMethod",
    ),
    (
        "annot_arg",
        0x1D,
        bytes([_TYPE_ANNOTATION, 1, _STRING_NAME, 0x04, 7]),
        f"static final int {_FIELD0};  " "// = @annotations.BootstrapMethod(Hello = 7)",
    ),
]


@pytest.mark.parametrize("stem,vt,payload,want", _EXPRESSIONS, ids=lambda v: v)
def test_a_value_with_a_java_form_renders_as_an_initializer(
    tmp_path, stem, vt, payload, want
):
    """0x15 and 0x1c ARE Java expressions, so they go on the right of `=`.

    `MethodType.methodType(...)` is exactly how a MethodType constant is written,
    and `{7}` is a real array initializer - the one rendering jadx also produces.
    """
    assert _decl(tmp_path, vt, payload, stem) == want


@pytest.mark.parametrize("stem,vt,payload,want", _COMMENTS, ids=lambda v: v)
def test_a_value_with_no_java_form_rides_as_a_comment(
    tmp_path, stem, vt, payload, want
):
    """0x16 / 0x1a / 0x1d have NO expression form, so the declaration stays valid.

    Rendering `= Foo::bar` would put uncompilable Java in a field declaration -
    a method reference is only assignable to a functional interface - which is
    what jadx's `= ;` and androguard's `= ['Lcom/Foo;', 'bar', '()V']` both do.
    """
    assert _decl(tmp_path, vt, payload, stem) == want


def test_an_unrenderable_value_is_distinguishable_from_no_value(tmp_path):
    """The defect itself: the two used to be byte-identical.

    Asserts the DIFFERENCE, not merely that a comment appeared - a field with no
    static value at all must keep reading exactly as it did.
    """
    handle = _decl(tmp_path, 0x16, bytes([_HANDLE_0]), "distinct_mh")
    # The craft shortens the array, so the LAST field loses its value entirely -
    # that is the "no initializer" half, from the same file, same run.
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, 0x16, bytes([_HANDLE_0]), "distinct_src")
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)
    bare = [
        ln.strip()
        for ln in src.split("\n")
        if ln.strip().startswith("static final") and ln.strip().endswith(";")
    ]
    assert bare, src
    assert handle not in bare, "the unrenderable value still reads as no value"
    assert any("//" not in ln for ln in bare), "no bare declaration left to contrast"


# -- composition --------------------------------------------------------------


def test_an_array_holding_an_unspellable_value_is_not_an_expression(tmp_path):
    """`{Foo::bar}` is not a Java initializer either, so the whole array moves.

    This is why the flag travels with the VALUE and is not a property of the type
    code: an array is an expression exactly when every element is one.
    """
    decl = _decl(tmp_path, 0x1C, bytes([1, 0x16, _HANDLE_0]), "arr_mh")
    assert decl == (
        f"static final int {_FIELD0};  " "// = {TestBadBootstrapArguments::bsm}"
    ), decl


def test_an_unrenderable_element_demotes_the_array_and_shows_a_placeholder():
    """RE-BASED to a SOURCE pin by dexllm#72, which closed the only channel.

    This used to be two crafted dexes: a `0x16` whose index the gate did not
    bound rendered nothing, so an array holding it came back `{?}` / `{?, 9}`.
    dexllm#72 ported ART :1204/:1212, so the gate now bounds that index and every
    `0x16` a loadable dex can carry RESOLVES — which is what closes the channel.
    An empty member name would be the other route and `IsValidMemberName` rejects
    it, so nothing in `DecodeEncodedValueText` can return empty text from a dex
    that verifies.

    Both halves of the line stay load-bearing and BOTH are pinned, because they
    are separately deletable: `? : "?"` is what stops a hole reading as an empty
    value, and `|| el.text.empty()` is what stops the array claiming to be an
    EXPRESSION and emitting `= {?};` — uncompilable Java on the right of an `=`,
    which an adversarial review built as a mutant that passed the whole suite.

    A source pin is WEAKER than the crafted dexes it replaces: it cannot see a
    line that is present and wrong. Saying so is the point of the docstring.
    """
    body = _decoder_body()
    assert 'out.text += el.text.empty() ? "?" : el.text;' in body, body[-2000:]
    assert "if (!el.expression || el.text.empty()) out.expression = false;" in body


def test_an_annotation_element_that_cannot_resolve_shows_a_placeholder():
    """The symmetric twin, pinned the same way and for the same reason.

    A delta reviewer dropped the annotation arm's `?` and all 46 cases passed,
    leaving `@Foo(Hello = )` — a hole that reads as an empty value rather than an
    unresolved one. It was reached the same way as the array's, so dexllm#72 took
    that route away too.
    """
    body = _decoder_body()
    assert body.count('out.text += el.text.empty() ? "?" : el.text;') == 2, body[-2000:]
    # The annotation TYPE and each element NAME have their own placeholders, on
    # index bounds dexllm#71 added; those are unreachable while the walk stays in
    # lockstep with the gate, which is that issue's whole subject.
    assert '? dexkit::dad::GetType(type_names[type_idx]) : "?";' in body
    assert '? std::string(strings[name_idx]) : "?";' in body


def test_an_eight_byte_handle_index_is_rejected_at_the_gate(tmp_path):
    """INVERTED by dexllm#72 — the gate used to LET an 8-byte 0x16 index through.

    That was the point of this guard: 0x15 and 0x1a went through
    `VerifyEncodedValue`'s `idx` lambda, which rejects `arg > 3`, while 0x16 used
    `skip(arg + 1)` with no cap — so `2**32` was a legal encoding and truncating
    it to `uint32_t` would yield 0, a REAL handle fabricated for a value naming
    none. dexllm#72 ported ART :1204, so the encoding is refused at load and the
    reader's `idx > UINT32_MAX` clause is defence in depth rather than the only
    line. It is pinned at source below, because nothing can reach it any more
    THROUGH A STATIC VALUE.
    """
    dexllm = pytest.importorskip("dexllm")
    payload = (1 << 32).to_bytes(8, "little")
    raw = bytearray(_CUSTOM.read_bytes())
    # An 8-byte payload does not fit the array's own bytes, so this craft drops
    # the count to ONE value and uses all eight for it.
    assert raw[_EL0_COUNT_OFF] == 0x04 and raw[_EL0_HEADER_OFF] == 0x04
    raw[_EL0_COUNT_OFF] = 1
    raw[_EL0_HEADER_OFF] = 0x16 | (7 << 5)
    raw[_EL0_PAYLOAD_OFF : _EL0_PAYLOAD_OFF + 8] = payload
    out = tmp_path / "mh8.dex"
    out.write_bytes(bytes(raw))
    rows = dexllm.verify(str(out))
    assert rows and not any(r["valid"] for r in rows), rows
    assert "bad index size" in rows[0]["reason"], rows


def test_the_static_value_handle_index_is_still_bounded_at_the_reader():
    """Defence in depth, pinned at source because dexllm#72 made it unreachable.

    Two clauses, separately deletable, and neither can now be reached through a
    static value on a loadable dex:

      * `idx > UINT32_MAX` — the width guard above. An adversarial review removed
        it and 113 tests still passed even when the encoding WAS gate-legal,
        because every other 0x16 craft in this file is one byte wide.
      * `mh_idx >= handles.size()` inside `ResolveMethodHandle` — the index bound
        the gate now duplicates.

    The second one is NOT dead: `ParseCallSiteArg` shares it, and a call_site's
    CONTENTS are deliberately out of the verifier's scope, so a crafted call site
    still reaches it. `tests/test_invoke_custom_ir.py` is where that route lives.
    """
    body = _decoder_body()
    assert "if (idx > UINT32_MAX ||" in body, body[-2000:]
    resolver = _strip_comments(_CORE_EXT.read_text())
    # rindex, not index: the forward DECLARATION comes first and has no body.
    start = resolver.rindex("bool ResolveMethodHandle(DexItemCodeSource& src")
    assert (
        "if (mh_idx >= handles.size()) return false;" in resolver[start : start + 900]
    )


# `field_ids[0]` and `method_ids[0]` name DIFFERENT members, which is the whole
# point: the rendered NAME is what reveals which table `ResolveMethodHandle`
# consulted.  The `.` / `::` separator does NOT - `MethodHandleText` derives that
# from the KIND alone, so an assertion on the separator tests the speller, not
# the dispatch.  The first version of this guard did exactly that and an
# adversarial mutant that always took the method table passed all 128 cases.
_HANDLE_KIND_CASES = [
    # kind, field_or_method_id override, expected rendering
    (0x01, 0, "TestDynamicBootstrapArguments.bsmCalls"),
    (0x04, None, "TestBadBootstrapArguments::bsm"),
]


@pytest.mark.parametrize(
    "handle_type,fom,want", _HANDLE_KIND_CASES, ids=["field-kind", "method-kind"]
)
def test_the_static_value_route_dispatches_on_the_handle_kind(
    tmp_path, handle_type, fom, want
):
    """`ResolveMethodHandle` picks the FIELD or METHOD table on the kind.

    Every handle in all three committed fixtures is kind 4 or 5 (a census, not an
    assumption), so no unmodified craft can reach the field branch.  dexllm#67's
    `test_a_handle_argument_renders_by_its_KIND` patches the kind in place for
    the IR path and pins `MethodHandleText`'s SPELLING - but it never enters
    `DecodeEncodedValueText`, so the field-vs-method dispatch inside
    `ResolveMethodHandle` was unexercised from `decompile_class`.  A correctness
    review found that gap.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, 0x16, bytes([_HANDLE_0]), f"kind{handle_type:02x}")
    raw = bytearray(out.read_bytes())
    entry = _method_handle_entry(raw, _HANDLE_0)
    struct.pack_into("<H", raw, entry, handle_type)
    if fom is not None:
        struct.pack_into("<H", raw, entry + 4, fom)
    out.write_bytes(bytes(raw))
    assert all(r["valid"] for r in dexllm.verify(str(out))), "the craft must load"
    hits = [
        ln.strip()
        for ln in dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS).split("\n")
        if _FIELD0 in ln
    ]
    assert hits == [f"static final int {_FIELD0};  // = {want}"], hits


def test_an_array_of_spellable_values_stays_an_expression(tmp_path):
    """The control for the test above: composition must not be a blanket demotion."""
    decl = _decl(tmp_path, 0x1C, bytes([2, 0x04, 7, 0x1E]), "arr_ok")
    assert decl == f"static final int {_FIELD0} = {{7, null}};", decl


@pytest.mark.parametrize(
    "payload,want",
    [
        (bytes([1, 0x1C, 1, 0x04, 5]), f"static final int {_FIELD0} = {{{{5}}}};"),
        (bytes([2, 0x1C, 0, 0x1E]), f"static final int {_FIELD0} = {{{{}}, null}};"),
        (
            bytes([_TYPE_ANNOTATION, 1, _STRING_NAME, 0x1C, 1, 0x04, 9]),
            f"static final int {_FIELD0};  "
            "// = @annotations.BootstrapMethod(Hello = {9})",
        ),
        # Nesting INTO 0x1d, the fourth composition - nothing reached it before,
        # which a delta reviewer noted after probing all four by hand.
        (
            bytes([_TYPE_ANNOTATION, 1, _STRING_NAME, 0x1D, _TYPE_ANNOTATION, 0]),
            f"static final int {_FIELD0};  "
            "// = @annotations.BootstrapMethod(Hello = @annotations.BootstrapMethod)",
        ),
        (
            bytes([1, 0x1D, _TYPE_ANNOTATION, 0]),
            f"static final int {_FIELD0};  " "// = {@annotations.BootstrapMethod}",
        ),
    ],
    ids=[
        "array-in-array",
        "empty-array-in-array",
        "array-in-annotation",
        "annotation-in-annotation",
        "annotation-in-array",
    ],
)
def test_a_nested_value_renders_through(tmp_path, payload, want):
    """Both recursive arms nest, and the gate caps the depth at 16 for them.

    Only one level was covered before; a correctness review pointed out that the
    composition rule, the separator placement and the empty-array case all have a
    second level nobody looked at.
    """
    vt = 0x1D if payload[0] == _TYPE_ANNOTATION else 0x1C
    assert _decl(tmp_path, vt, payload, "nested") == want


def test_no_field_carries_both_an_expression_and_a_comment(tmp_path):
    """The two vectors are DISJOINT, and the renderer would emit both if not.

    `decompile_class` writes `= <text>` and then `  // = <comment>` from two
    parallel vectors; a field present in both would assert two different values
    on one line.  Enforced only by `GetClassInfo` picking one branch, so it is
    pinned here rather than left to inspection.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, 0x16, bytes([_HANDLE_0]), "disjoint")
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)
    for line in src.split("\n"):
        stripped = line.strip()
        if not stripped.startswith(("static ", "public ", "private ", "protected ")):
            continue
        if "(" in stripped.split("=")[0]:
            continue  # a method signature, not a field
        head = stripped.split("// = ")[0]
        assert not ("= " in head and "// = " in stripped), stripped


# -- the injection channel ----------------------------------------------------


def test_the_fixture_itself_carries_a_newline_the_comment_must_escape(tmp_path):
    """The channel needs NO string crafting - the fixture already ships the byte.

    The parametrised guard above re-lays pool string 3 to build a forged
    declaration; this one leaves the pool ALONE and just points an annotation
    element name at string 3 as committed, which ends in a raw 0x0A.  So the
    reachability is a property of `tests/data/invoke-custom.dex` as it stands,
    not of the craft.
    """
    dexllm = pytest.importorskip("dexllm")
    payload = bytes([_TYPE_ANNOTATION, 1, _STRING_WITH_NEWLINE, 0x04, 7])
    out = _craft(tmp_path, 0x1D, payload, "newline")
    assert all(r["valid"] for r in dexllm.verify(str(out)))
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)
    hits = [ln for ln in src.split("\n") if _FIELD0 in ln]
    assert len(hits) == 1, hits
    assert "<U+000A>" in hits[0], hits[0]  # escaped, and therefore still one line
    # And the line it sits on is a whole declaration, not a fragment.
    assert hits[0].strip().startswith("static final int "), hits[0]
    assert hits[0].strip().endswith(" = 7)"), hits[0]


# Every byte a consumer may treat as a line break, plus the ones that reach a
# terminal as an escape.  Python's `str.split("\n")` breaks on ALL of these;
# `\n` alone is the smallest part of the problem, and an earlier version of the
# fix folded only `\n` and `\r`.
_SEPARATORS = [
    ("vt", b"\x0b", "<U+000B>"),
    ("ff", b"\x0c", "<U+000C>"),
    ("fs", b"\x1c", "<U+001C>"),
    ("gs", b"\x1d", "<U+001D>"),
    ("rs", b"\x1e", "<U+001E>"),
    ("lf", b"\n", "<U+000A>"),
    ("cr", b"\r", "<U+000D>"),
    ("esc", b"\x1b", "<U+001B>"),
    ("del", b"\x7f", "<U+007F>"),
    ("nel", b"\xc2\x85", "<U+0085>"),
    ("u2028", b"\xe2\x80\xa8", "<U+2028>"),
    ("u2029", b"\xe2\x80\xa9", "<U+2029>"),
    # C1 other than NEL. A member NAME cannot hold one - ART's
    # `IsValidPartOfMemberNameUtf8Slow` has `case 0x00: return leading >= 0x00a0`
    # - so before dexllm#64 no C1 could reach a declaration line at all. 0x9B is
    # the 8-bit CSI, an escape introducer.
    ("c1_80", b"\xc2\x80", "<U+0080>"),
    ("csi_9b", b"\xc2\x9b", "<U+009B>"),
    ("c1_9f", b"\xc2\x9f", "<U+009F>"),
    # A BACKSLASH, and an attacker-WRITTEN `\uXXXX`: javac translates a unicode
    # escape BEFORE it recognises comments (JLS 3.3), so an escape IS a line
    # break. This is what the first version of the fix got wrong - it escaped
    # AS `\uXXXX` and re-forged the line it had just folded.
    ("backslash", b"\\", "<U+005C>"),
]


@pytest.mark.parametrize("tag,sep,want", _SEPARATORS, ids=[c[0] for c in _SEPARATORS])
def test_no_byte_in_a_comment_can_forge_a_line_of_java(tmp_path, tag, sep, want):
    """The channel is an annotation element NAME, and it is REAL.

    `VerifyEncodedAnnotation` bounds `name_idx` as a string INDEX and never
    validates it as a member name, so it can point at ANY pool string.  This
    craft re-lays pool string 3 with a forged declaration around a separator and
    puts it in the name position.

    An adversarial review built exactly this and got a `static final String
    PWNED` onto a line of its own, then proved it a REGRESSION of dexllm#64 by
    running the same crafts against the previous build (where 0x1d rendered
    nothing, so the name never reached the output).  `SanitizeUtf8` cannot help:
    its ASCII fast path passes every byte below 0x80 verbatim - which is what
    lets the Writer's own newlines survive - and its multibyte path renders a
    BMP separator READABLY (dexllm#28), right for an identifier and wrong here.

    Folding only `\n` and `\r` leaves TEN of these twelve open.
    """
    dexllm = pytest.importorskip("dexllm")
    body = b" C" + sep + b'  static final String PWNED = "owned";  //'
    out = _craft(
        tmp_path,
        0x1D,
        bytes([_TYPE_ANNOTATION, 1, _STRING_WITH_NEWLINE, 0x04, 7]),
        f"forge_{tag}",
        string3=body,
    )
    assert all(r["valid"] for r in dexllm.verify(str(out))), "the gate lets it in"
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)

    # 1. The forged text never starts a line under ANY line-splitting rule.
    for line in src.split("\n"):
        if "PWNED" in line:
            assert "//" in line.split("PWNED")[0], line

    # 2. No raw control character survives anywhere in the output - C1 included,
    #    which the first version of this assertion did not look at.
    stray = sorted(
        {
            hex(ord(c))
            for c in src
            if (ord(c) < 0x20 and c != "\n")
            or ord(c) == 0x7F
            or 0x80 <= ord(c) < 0xA0
            or ord(c) in (0x2028, 0x2029)
        }
    )
    assert stray == [], stray

    # 4. THE invariant: no backslash reaches a comment, so no `\uXXXX` can exist
    #    for javac to translate into a line break ahead of comment recognition.
    for line in src.split("\n"):
        if "// = " in line:
            assert "\\" not in line.split("// = ", 1)[1], line

    # 3. The separator is present, escaped - so the value is not merely dropped.
    assert want in src, (want, [ln for ln in src.split("\n") if "PWNED" in ln])


# Non-ASCII names, which pin the OTHER half of `CommentSafe(SanitizeUtf8(...))`.
# Every other craft in this file is pure ASCII, and on ASCII the two forms are
# byte-identical - so dropping `SanitizeUtf8` from that composition passed the
# WHOLE 899-test suite when a delta reviewer built it, while a lone surrogate in
# an annotation element name made `decompile_class` raise `UnicodeDecodeError`.
# That is the dexllm#22 failure class, re-opened with a green suite.
#
# `utf16_len` is a CODE UNIT count, so an astral character costs 2 while its
# CESU-8 encoding costs 6 bytes; `_relay_string3` recomputes it.
_NON_ASCII_NAMES = [
    # MUTF-8 NUL. `SanitizeUtf8` renders a decoded control as the SIX CHARACTERS
    # `\u0000`, and those are themselves the JLS 3.3 hazard - so the escape this
    # repo's own sanitiser produces is defanged by the backslash rule, not only
    # an attacker-written one. That composition is the assertion.
    ("mutf8_nul", b" C\xc0\x80D", "<U+005C>u0000"),
    # A surrogate PAIR: valid CESU-8, one astral character.
    ("astral", b" C\xed\xa0\x80\xed\xb0\x80D", "\U00010000"),
    # A LONE leading surrogate - legal in a pool string, and NOT valid UTF-8, so
    # it must not cross the pybind boundary raw.
    ("lone_surrogate", b" C\xed\xa0\x80D", None),
]


@pytest.mark.parametrize(
    "tag,body,want", _NON_ASCII_NAMES, ids=[c[0] for c in _NON_ASCII_NAMES]
)
def test_a_non_ascii_annotation_name_survives_the_boundary(tmp_path, tag, body, want):
    """`SanitizeUtf8` is what turns raw MUTF-8 into something Python can decode.

    Reaching this at all is the point: `decompile_class` returns a `str`, so a
    raw CESU-8 surrogate or a `C0 80` NUL crossing pybind11's strict codec is a
    RAISE, not a garbled string.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(
        tmp_path,
        0x1D,
        bytes([_TYPE_ANNOTATION, 1, _STRING_WITH_NEWLINE, 0x04, 7]),
        f"nonascii_{tag}",
        string3=body,
    )
    assert all(r["valid"] for r in dexllm.verify(str(out))), "the gate lets it in"
    src = dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS)  # must not raise
    hits = [ln for ln in src.split("\n") if _FIELD0 in ln]
    assert len(hits) == 1, hits
    if want is not None:
        assert want in hits[0], (want, hits[0])
    else:
        # A lone surrogate has no UTF-8 form; what matters is that it arrived as
        # a `str` at all, and that it did not become a line break or a control.
        assert "\\" not in hits[0].split("// = ", 1)[1], hits[0]


def test_a_string_element_cannot_close_a_block_comment(tmp_path):
    """Why the marker is `//` and not `/* ... */`.

    A string element inside a rendered array is escaped by `EscapeJavaString`
    (`PythonUnicodeEscape` until dexllm#83 — the argument is unchanged, only the
    function name moved), which escapes quotes, backslashes and control
    characters - but NOT `*` or `/`.  So a literal containing `*/` would end a
    block comment early and turn the rest of the line into code.  A line comment
    has no such terminator.
    """
    decl = _decl(tmp_path, 0x1C, bytes([1, 0x16, _HANDLE_0]), "no_block_comment")
    assert "/*" not in decl and "*/" not in decl, decl
    assert "// = " in decl, decl


def test_a_string_element_in_an_ARRAY_uses_the_shared_escaper(tmp_path):
    r"""The EXPRESSION direction of the same recursion, which nothing exercised.

    `0x1c` recurses into `0x17`, so an array of STRINGS renders each element
    through the escaper dexllm#83 changed. The corpus has **0** string-bearing
    array initializers and every pre-existing `0x1C` craft here is an int array,
    an empty array, a nested array or a method-handle array (the COMMENT
    direction) - so this path had no coverage at all on either side.

    The element CONTENT is what makes it discriminate, and the first cut of this
    guard got that wrong: `"Hello"` and `string_ids[3]` are pure ASCII plus a raw
    0x0A, which BOTH escapers render identically, so it PASSED against the
    pre-fix build. Pool string 3 is re-laid with a VT and a U+00E9 - the two
    places the rules genuinely differ (`\x0b` vs `\u000b`, and `\u00e9` vs the
    readable character). `"Hello"` stays as the agreeing control.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(
        tmp_path,
        0x1C,
        bytes([2, 0x17, _STRING_NAME, 0x17, _STRING_WITH_NEWLINE]),
        "arr_of_strings",
        # The ` C` prefix is the shape the separator crafts above already use:
        # `string_ids` must stay in ART UTF-16 sort order, and a body that starts
        # elsewhere reorders string 3 past a neighbour and the dex stops verifying.
        string3=b" C\x0b\xc3\xa9",
    )
    assert all(r["valid"] for r in dexllm.verify(str(out))), "the craft must load"
    hits = [
        ln.strip()
        for ln in dexllm.DexKit(str(out)).decompile_class(_FIXTURE_CLASS).split("\n")
        if _FIELD0 in ln
    ]
    assert len(hits) == 1, hits
    decl = hits[0]
    # An EXPRESSION, not the `// = ` comment: both elements have a Java form.
    assert " = {" in decl and "// = " not in decl, decl
    assert '"Hello"' in decl, decl
    # The shared rule: a control below 0x20 escapes as Java, a BMP char is read.
    assert "\\u000b" in decl, decl
    assert chr(0xE9) in decl, decl
    # ...and NOT the rules the deleted escaper had.
    assert "\\x0b" not in decl, decl
    assert "\\u00e9" not in decl, decl


def test_a_string_element_in_a_comment_is_folded_not_escaped(tmp_path):
    r"""The one place dexllm#83's "one rendering" does NOT hold, pinned as such.

    An array holding a STRING and a method handle has no Java expression form, so
    the whole value rides in the `// = ...` comment - and the string element goes
    through `CommentSafe` on top of the escaper, which folds every backslash to
    `<U+005C>` so the comment cannot be terminated by a `\uXXXX` the Java lexer
    would translate first (JLS 3.3).

    Until dexllm#83 no test could reach this: its sibling above uses an array of
    ONE method handle, so no string element had ever met `CommentSafe`, and 0
    comment-path initializers exist anywhere in the corpus. It matters now
    because the escaper that feeds it changed - `string_ids[3]` ends in a RAW
    0x0A, which the old escaper and the new one both render `\n`, and it is the
    FOLDING that keeps that safe rather than the escaping.
    """
    decl = _decl(
        tmp_path,
        0x1C,
        bytes([2, 0x17, _STRING_WITH_NEWLINE, 0x16, _HANDLE_0]),
        "comment_string_element",
    )
    assert "// = " in decl, decl
    comment = decl.split("// = ", 1)[1]
    assert "TestBadBootstrapArguments::bsm" in comment, decl  # the handle element
    assert "<U+005C>n" in comment, decl  # the string element's escape, FOLDED
    # The invariant CommentSafe exists for: no backslash survives, so nothing in
    # the comment can be a unicode escape and nothing can end the line.
    assert "\\" not in comment, decl


# -- cross-layer agreement ----------------------------------------------------


def test_the_two_layers_spell_a_method_type_identically(tmp_path):
    """The static-value decoder and the IR builder must not drift apart.

    dexllm#67 taught the IR path to reconstruct an `invoke-custom` bootstrap
    chain, which spells a proto as `MethodType.methodType(...)`; dexllm#64 gave
    that rendering a SECOND caller in `core_ext`.  A rule read twice drifts
    (dexllm#70), so both go through `ClassLiteralText` / `MethodTypeText` in
    `dad_cpp/util`.

    The proto is `(ILjava/lang/String;Ljava/lang/Double;)I`, which the fixture's
    OWN bootstrap chain uses, so the IR path renders it WITHOUT any crafting -
    the two texts have to come from genuinely different code paths for the
    comparison to mean anything.  It is also MIXED: an earlier version used
    `(II)I`, and an adversarial review reversed the parameter walk and passed the
    entire suite, because a homogeneous signature cannot see an ordering change.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, 0x15, bytes([_PROTO_MIXED]), "agree")
    dk = dexllm.DexKit(str(out))
    decl = [
        ln for ln in dk.decompile_class(_FIXTURE_CLASS).split("\n") if _FIELD0 in ln
    ][0]
    rendered = decl.split(" = ", 1)[1].rstrip(";")
    # Not merely "some methodType text": the parameters must be in this order.
    assert rendered.endswith(
        "(Integer.TYPE, Integer.TYPE, String.class, Double.class)"
    ), rendered
    ir = dk.decompile_method("LTestDynamicBootstrapArguments;->testCallSites()V")
    assert rendered in ir, (rendered, ir[:400])


# -- the bound the gate does not provide --------------------------------------


def test_an_out_of_range_static_value_handle_index_is_rejected_at_the_gate(tmp_path):
    """INVERTED by dexllm#72, and the sentence it inverts is the finding.

    This used to assert that the dex VERIFIED and the field rendered nothing,
    with a docstring saying `VerifyEncodedValue`'s 0x16 arm "does NOT bound the
    index, and says so" — the bound lived at the READER, the tier the safety
    contract permits for an out-of-scope section. dexllm#59 put the section IN
    scope and dexllm#72 the index, so the arm bounds it now (ART :1212) and the
    dex does not load.

    What is NOT inverted is the reader's own behaviour on an unresolvable handle:
    render NOTHING rather than a guess (dexllm#67's rule). That is still live via
    a crafted call_site, whose contents stay out of scope — see the source pin
    above and `tests/test_invoke_custom_ir.py`.

    0xFF is past the fixture's 29 handles, which is what makes this exact.
    """
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, 0x16, bytes([0xFF]), "mh_oob")
    rows = dexllm.verify(str(out))
    assert rows and not any(r["valid"] for r in rows), rows
    assert "encoded method_handle idx" in rows[0]["reason"], rows
    # A handle index the gate CAN vouch for still renders, so the rejection is
    # not "0x16 stopped working".
    ok = _craft(tmp_path, 0x16, bytes([_HANDLE_0]), "mh_ok")
    assert all(r["valid"] for r in dexllm.verify(str(ok))), "the in-range craft"


# -- the shared vocabulary (source level) -------------------------------------

_UTIL_H = REPO_ROOT / "native/dad_cpp/include/util.h"
_UTIL_CPP = REPO_ROOT / "native/dad_cpp/util.cpp"
_DISPATCH = REPO_ROOT / "native/dad_cpp/instruction_dispatch.cpp"
_CORE_EXT = REPO_ROOT / "native/core_ext/dexitem_code_source.cpp"


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, scanning left to right.

    Two independent regex passes would be wrong: a `//` line can contain `/*`
    (`dexitem_code_source.cpp` has `// ---- const-wide/* ----`), so a block pass
    applied first swallows hundreds of lines and SHRINKS the audit silently
    instead of failing it.  dexllm#32 and dexllm#57 each paid for this.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def test_the_comment_stripper_sees_through_the_trap_that_bit_this_repo():
    """Non-discriminating BY DESIGN - it guards the guard below."""
    assert "keep" in _strip_comments("// a /* b\nkeep")
    assert "gone" not in _strip_comments("/* gone */")
    assert "gone" not in _strip_comments("// gone")


def _decoder_body() -> str:
    """`DecodeEncodedValueText`'s stripped body — the static-value renderer.

    Comments are stripped first: a fix that survives only as a COMMENT is not a
    fix, which is the mutant shape a reviewer used on dexllm#57.
    """
    text = _strip_comments(_CORE_EXT.read_text())
    start = text.index("EncodedValueText DecodeEncodedValueText(")
    depth, i = 0, text.index("{", text.index(")", start))
    for k in range(i, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[i : k + 1]
    raise AssertionError("DecodeEncodedValueText has no balanced body")


@pytest.mark.parametrize(
    "helper", ["ClassLiteralText", "MethodTypeText", "MethodHandleText"]
)
def test_the_rendering_vocabulary_is_declared_once(helper):
    """Each rule is spelled in ONE place, whatever its caller count.

    A correct but DUPLICATED body passes every behavioural test in this file and
    drifts on the first edit - which is exactly what "add a fifth reading of the
    same rule" looks like, and what dexllm#70 pinned for the float justification.

    Two of these are genuinely SHARED (`ClassLiteralText` and
    `MethodHandleText`: the IR builder and the static-value decoder both call
    them). `MethodTypeText` has ONE caller - the IR path assembles `methodType`
    from IR nodes, because the AST needs structure a flat string cannot carry, so
    it shares only the per-argument literal. An adversarial review caught this
    file, CLAUDE.md and the docs all claiming otherwise.
    """
    assert helper in _strip_comments(_UTIL_H.read_text()), "not declared in util.h"
    assert helper in _strip_comments(_UTIL_CPP.read_text()), "not defined in util.cpp"


def test_the_ir_builder_calls_the_shared_helpers():
    """dexllm#67's own rendering must go through util, or the two layers drift."""
    body = _strip_comments(_DISPATCH.read_text())
    assert "ClassLiteralText(" in body
    assert "MethodHandleText(" in body
    # ...and must not re-spell the kind rule it used to carry inline.
    assert '"::"' not in body, "the handle kind rule is back in the IR builder"


def test_the_static_value_decoder_calls_the_shared_helpers():
    """The dexllm#64 side of the same property."""
    body = _strip_comments(_CORE_EXT.read_text())
    for helper in ("MethodTypeText(", "MethodHandleText(", "MethodRefText("):
        assert helper in body, helper
    assert "Integer.TYPE" not in body, "the class-literal table is duplicated here"


def test_the_decoder_reuses_the_bounded_handle_resolver():
    """The 0x16 arm must not grow a second, unbounded resolution of its own.

    `ResolveMethodHandle` is the one place that bounds BOTH the handle index and
    the handle's own `field_or_method_id`; dexllm#59 is the open issue for the
    latter being a reader-tier bound rather than a gate one.
    """
    body = _strip_comments(_CORE_EXT.read_text())
    assert body.count("ResolveMethodHandle(") >= 3, "declaration + definition + call"
    # And the section is READ in exactly one place, so a second arm cannot grow
    # its own unbounded `MethodHandles()[idx]`.
    assert body.count("MethodHandles()") == 1, "a second method_handle reader appeared"
