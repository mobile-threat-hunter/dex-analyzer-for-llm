"""dexllm#86 — a `Z` return type constrains the returned register's type.

Dalvik has no boolean, so every `const*` builds an int-typed value and DAD types
a version from the register's LAST write.  A flag returned from a `boolean`
method therefore came out declared `int`, which `javac` rejects: on the bundled
corpus 57 of the 60 sites where a `boolean` method returns a VARIABLE declared it
`int`.  The fix reads the return type as a use-bound BOOLEAN source.

Every case here runs on the COMMITTED fixture, so they hold in the corpus-less CI
leg and under any `$DEXLLM_TEST_APK` narrowing.

Java cannot express the shapes that must be REFUSED — a `boolean` local used as
an arithmetic operand or an array index is a compile error — so those arrive by
CRAFT: `_repoint_proto` rewrites ONE u2, an `(I)I` method's `proto_idx`, to the
`(I)Z` proto the fixture already carries.  That is length-preserving to the byte,
it cannot disturb the `method_ids` sort (the order key is class, then NAME, and
every method here is uniquely named, so `proto_idx` is never the discriminator),
and each craft ASSERTS the dex still verifies — a rejected dex never reaches the
IR builder, so a guard that skipped that could pass for the wrong reason.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

import dexllm

FIXTURE = Path(__file__).parent / "data" / "bool-return.dex"
CLS = "LBoolReturn;"


# --------------------------------------------------------------------------
# dex surgery — one u2, located rather than hard-coded
# --------------------------------------------------------------------------


def _u4(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u2(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _strings(b: bytes) -> list[str]:
    n, off = _u4(b, 56), _u4(b, 60)
    out = []
    for i in range(n):
        p = _u4(b, off + 4 * i)
        while b[p] & 0x80:  # skip the uleb128 utf16_size
            p += 1
        p += 1
        out.append(b[p : b.index(b"\x00", p)].decode("utf-8", "replace"))
    return out


def _method_id_index(b: bytes, name: str) -> int:
    """The `method_ids` index of the uniquely-named method `name`."""
    names = _strings(b)
    try:
        name_idx = names.index(name)
    except ValueError:  # pragma: no cover - fixture drift
        raise AssertionError(f"fixture no longer carries the name {name!r}")
    n, off = _u4(b, 88), _u4(b, 92)
    hits = [i for i in range(n) if _u4(b, off + 8 * i + 4) == name_idx]
    assert len(hits) == 1, f"{name!r} is not uniquely named ({len(hits)} method_ids)"
    return hits[0]


def _repoint_proto(dst: str, src: str) -> bytes:
    """Give method `dst` the proto of method `src` — one u2, nothing else."""
    b = bytearray(FIXTURE.read_bytes())
    off = _u4(b, 92)
    di, si = _method_id_index(b, dst), _method_id_index(b, src)
    src_proto = _u2(b, off + 8 * si + 2)
    dst_proto = _u2(b, off + 8 * di + 2)
    assert src_proto != dst_proto, "the craft would be a no-op"
    before = bytes(b)
    struct.pack_into("<H", b, off + 8 * di + 2, src_proto)
    assert sum(x != y for x, y in zip(before, b)) <= 2, "craft is not one u2"
    assert len(b) == len(before), "craft changed the length"
    return bytes(b)


@pytest.fixture(scope="module")
def pristine() -> dexllm.DexKit:
    return dexllm.DexKit(str(FIXTURE))


def _crafted(tmp_path: Path, dst: str, src: str = "flag") -> dexllm.DexKit:
    p = tmp_path / f"crafted-{dst}.dex"
    p.write_bytes(_repoint_proto(dst, src))
    verdicts = [r["valid"] for r in dexllm.verify(str(p))]
    assert verdicts == [True], (
        f"the {dst} craft no longer verifies ({verdicts}) — a rejected dex never "
        "reaches the IR builder, so every assertion below would pass vacuously"
    )
    return dexllm.DexKit(str(p))


def _body(dk: dexllm.DexKit, name: str) -> str:
    src = dk.decompile_class(CLS)
    m = re.search(
        r"\n([^\n(]*\b%s\([^)]*\))\n\{\n(.*?)\n\}" % re.escape(name), src, re.S
    )
    assert m, f"{name} not found in the decompiled class"
    return m.group(1) + "\n" + m.group(2)


# --------------------------------------------------------------------------
# premise
# --------------------------------------------------------------------------


def test_the_fixture_verifies_and_carries_the_shape(pristine):
    """Non-discriminating BY DESIGN — it pins what the other cases rest on."""
    assert [r["valid"] for r in dexllm.verify(str(FIXTURE))] == [True]
    assert "boolean flag(int" in _body(pristine, "flag")
    # every craft base is an `(I)I`/`(I)J` method, i.e. NOT yet boolean-returning
    for n in ("arrayIndex", "cmpUsed", "notBoolean", "intUsed"):
        assert re.search(r"\bint %s\(" % n, _body(pristine, n)), n
    assert re.search(r"\blong wide\(", _body(pristine, "wide"))


# --------------------------------------------------------------------------
# the fix
# --------------------------------------------------------------------------


def test_a_boolean_method_no_longer_returns_an_int_local(pristine):
    body = _body(pristine, "flag")
    assert re.search(r"^\s*boolean v\d", body, re.M), body
    assert not re.search(r"^\s*int v", body, re.M), body


def test_the_flag_assignments_render_as_boolean_literals(pristine):
    """The type is the whole fix: no emitter changed, so `= true` / `= false`
    fall out of the Z-lhs branch `write_inplace_if_possible` already had."""
    body = _body(pristine, "flag")
    assert "= true;" in body and "= false;" in body, body
    assert not re.search(r"=\s*[01];", body), body


def test_a_z_returning_call_is_a_boolean_valued_def(pristine):
    """`viaCall`'s def is an invoke typed `Z`, not a constant — the resolver's
    other arm.  A rule that only accepted 0/1 constants would leave it."""
    body = _body(pristine, "viaCall")
    assert re.search(r"^\s*boolean v\d", body, re.M), body
    assert 'equals("x")' in body and "= false;" in body, body


def test_the_type_propagates_backwards_along_move_edges(pristine):
    """Only `b` is returned, so only `b` carries the constraint — but `b`'s value
    ARRIVES from `a`.  Typing `b` alone would leave `boolean b = a;` with `a`
    still `int`, i.e. one invalid line traded for another; measured over the
    corpus that partial answer costs +16 such lines, and +147 once the resolver
    also resolves move cycles.  BOTH must be boolean."""
    body = _body(pristine, "viaLocal")
    assert len(re.findall(r"^\s*boolean v\d", body, re.M)) == 2, body
    assert not re.search(r"^\s*int v", body, re.M), body
    assert not re.search(r"=\s*[01];", body), body


def test_propagation_stops_at_a_source_that_is_genuinely_an_int(pristine):
    """`a` is `p + 1`, so it is a real int and must keep its type even though the
    boolean it feeds is re-typed.  Without this, a build that propagated
    unconditionally would emit `boolean a` and then `a + p`."""
    body = _body(pristine, "viaLocalConflated")
    assert re.search(r"^\s*int v\d", body, re.M), body
    assert re.search(r"^\s*boolean v\d", body, re.M), body


def test_a_flag_also_passed_at_an_int_parameter_is_refused(pristine):
    """The INVOKE-ARGUMENT arm, on a committed fixture.

    This is the position whose absence turned valid corpus Java into
    `setFlags(boolean)`.  A delta review showed the arm was revertible with the
    corpus-less leg GREEN — the fixture had craft bases for the iput, sput and
    aput arms and none for this one, so only a corpus-gated case held it.
    """
    body = _body(pristine, "passedAtInt")
    assert re.search(r"^\s*int v\d", body, re.M), body
    assert not re.search(r"^\s*boolean v\d", body, re.M), body
    assert "sinkInt(" in body, body


def test_a_flag_used_as_a_filled_array_element_is_refused(pristine):
    """The FOURTH int-requiring position, and the one the other three missed.

    `new int[]{boolean}` does not compile, and javac + d8 produce the shape with
    no crafting: the ternary folds onto the flag's own register.  Found by a
    delta review AFTER the invoke/field/array-store arms were added, which is
    why the position list is derived from the language rather than from the
    guards that already existed.
    """
    body = _body(pristine, "fillArr")
    assert re.search(r"^\s*int v\d", body, re.M), body
    assert not re.search(r"^\s*boolean v\d", body, re.M), body
    assert "new int[]" in body, body


def test_a_wide_parameter_does_not_shift_the_declared_param_map(pristine):
    """`declared_params` advances the register by `GetTypeSize`, so a `long`
    ahead of the flag moves every later parameter by TWO.  Nothing exercised
    that: a mutant using `+= 1` passed the whole suite while rendering
    `p3 = 1` here instead of `p3 = true`."""
    body = _body(pristine, "wideParam")
    assert "p3 = true;" in body, body
    assert "p3 = 1;" not in body, body


def test_a_flag_passed_at_a_boolean_parameter_is_still_fixed(pristine):
    """`prim_use_vids` records a NON-boolean primitive position only.

    Passing a boolean at a `Z` parameter is exactly right, so it must not block
    — and nothing else in the file would notice if it did: a guard widened to
    `IJBSCFDZ` gives back a large share of the fix and every other case still
    passes.  Measured: that mutant survived the whole suite before this case.
    """
    body = _body(pristine, "passedAtBoolean")
    assert re.search(r"^\s*boolean v\d", body, re.M), body
    assert "sinkBool(" in body and "= true;" in body, body


def test_a_written_boolean_param_renders_a_boolean_literal(pristine):
    """Writing to a param register corrupts the `Param`'s own type to `I` (the
    same mechanism that corrupts `this`), so the Z-lhs render did not fire and
    the body read `p1 = 1`.  Fixing the version type restores it."""
    body = _body(pristine, "viaParam")
    assert "p1 = true;" in body, body
    assert "p1 = 1;" not in body, body


# --------------------------------------------------------------------------
# controls — the rule reads the RETURN TYPE, not "any 0/1 register"
# --------------------------------------------------------------------------


def test_an_int_method_with_the_same_shape_is_untouched(pristine):
    """`keepsInt` is `flag` with one thing changed — the return type.  Without
    this, a build that re-typed every 0/1 flag would pass every case above."""
    body = _body(pristine, "keepsInt")
    assert re.search(r"^\s*int v\d", body, re.M), body
    assert "true" not in body and "false" not in body, body


def test_an_int_method_doing_arithmetic_is_untouched(pristine):
    body = _body(pristine, "keepsArith")
    assert re.search(r"^\s*int v\d", body, re.M), body


# --------------------------------------------------------------------------
# the crafts — each refused by exactly ONE guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,decl,why",
    [
        (
            "arrayIndex",
            "int",
            "an ARRAY INDEX — note this lands in BOTH use sets, so it cannot "
            "separate them; newArraySize is what isolates int_required_vids",
        ),
        (
            "newArraySize",
            "int",
            "int_required_vids ONLY — an array-CREATION size is recorded there "
            "and nowhere else",
        ),
        (
            "cmpUsed",
            "int",
            "int_use_vids — the register is an ORDERED-comparison operand",
        ),
        ("notBoolean", "int", "the def-anchor — 5 is a genuine int, not a `true`"),
        ("intUsed", "int", "the def-anchor — an arithmetic def is not boolean-valued"),
        (
            "wide",
            "long",
            "is_narrow_int(cur) — a wide value must never be narrowed to Z",
        ),
        (
            "fieldStoreInstance",
            "int",
            "prim_use_vids on the IPUT arm — `iput` and `sput` are recorded by "
            "two separate arms, so a static-field case leaves this one open",
        ),
        (
            "fieldStore",
            "int",
            "prim_use_vids on the FIELD-STORE arm — the value goes into an "
            "`int` field",
        ),
        (
            "arrayValue",
            "int",
            "prim_use_vids on the ARRAY-STORE VALUE arm — note this is the "
            "stored value, not the index, and only one guard sees each",
        ),
    ],
)
def test_a_conflated_register_keeps_its_type(tmp_path, name, decl, why):
    dk = _crafted(tmp_path, name)
    body = _body(dk, name)
    assert re.search(r"\bboolean %s\(" % name, body), (
        "the craft did not take — this method must be Z-returning now, or the "
        "case proves nothing:\n" + body
    )
    assert re.search(r"^\s*%s v\d" % decl, body, re.M), f"{why}\n{body}"
    assert not re.search(r"^\s*boolean v\d", body, re.M), f"{why}\n{body}"


def test_the_craft_mechanism_can_produce_the_fix_too(tmp_path):
    """The crafts above all assert a REFUSAL, so on their own they are satisfied
    by a build that re-types nothing at all.  Repointing `keepsInt` — whose only
    difference from `flag` is its return type — must FIX it, which is the same
    mechanism reaching the opposite verdict."""
    dk = _crafted(tmp_path, "keepsInt")
    body = _body(dk, "keepsInt")
    assert re.search(r"\bboolean keepsInt\(", body), body
    assert re.search(r"^\s*boolean v\d", body, re.M), body
    assert "= true;" in body and "= false;" in body, body


# --------------------------------------------------------------------------
# the two emitters must agree
# --------------------------------------------------------------------------


def test_a_real_apk_no_longer_returns_int_locals_from_boolean_methods(dk):
    """The fixture proves the mechanism; this proves it reaches real code.  The
    dominant corpus shape is `equals`, where two registers move into EACH OTHER
    across the branch — the case the resolver's cycle handling and the backwards
    propagation exist for, and the one no authored fixture reproduces reliably
    (which register d8 reuses is its choice, not the source's).

    A CEILING, not a zero: `boolean` bitwise idioms (`flag |= cond`) compile to
    int OR and are correctly left, so the residual is real and bounded.
    """
    from conftest import require_corpus_shape

    bad = ok = 0
    sample = None
    for c in dk.list_classes()[:400]:
        try:
            src = dk.decompile_class(c)
        except Exception:
            continue
        for rtype, name, body in _methods(src):
            if rtype != "boolean":
                continue
            decls = {}
            for line in body:
                m = re.match(r"^\s*([\w.$\[\]]+)\s+(v\d+(?:_\d+)?)\s*(?:=|;)", line)
                if m and m.group(1) not in ("return", "new"):
                    decls.setdefault(m.group(2), m.group(1))
            for line in body:
                m = re.match(r"^\s*return\s+(v\d+(?:_\d+)?)\s*;", line)
                if not m:
                    continue
                t = decls.get(m.group(1))
                if t == "boolean":
                    ok += 1
                elif t in ("int", "Object", "byte", "short", "char"):
                    bad += 1
                    if sample is None:
                        sample = (c, name, t)
    require_corpus_shape(
        ok + bad > 0,
        "boolean method returning a variable",
        "the scan found none at all, so it can no longer see this defect",
    )
    assert ok > bad, (
        f"{ok} correctly typed vs {bad} still `int` — the return type is no "
        f"longer constraining the returned register.  First: {sample}"
    )


_METHOD_HDR = re.compile(
    r"^(?:(?:public|private|protected|static|final|synchronized|native|abstract"
    r"|transient|volatile|declared_synchronized|bridge|synthetic|varargs"
    r"|strictfp)\s+)*([\w.$\[\]]+)\s+([\w$<>]+)\s*\([^)]*\)\s*$"
)


def _methods(src):
    """Method bodies by brace matching.  `decompile_class` output is split on
    "\\n" — never `splitlines()` — which is the documented contract (dexllm#83)."""
    lines = src.split("\n")
    i = 0
    while i < len(lines):
        m = _METHOD_HDR.match(lines[i])
        if m and i + 1 < len(lines) and lines[i + 1].strip() == "{":
            depth, j, body = 0, i + 1, []
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                body.append(lines[j])
                j += 1
                if depth == 0:
                    break
            yield m.group(1), m.group(2), body
            i = j
        else:
            i += 1


def test_no_boolean_local_is_used_as_an_int(loadable_apks):
    """The headline property, stated as a CEILING on real APKs.

    Re-typing a version to `Z` is only correct if nothing then uses it as an
    int, and the backwards propagation multiplies the ways that could go wrong:
    it walks move edges away from the seed, so a guard dropped THERE types a
    genuinely-conflated source boolean and the arithmetic on it becomes invalid.
    No authored fixture reaches that — Java cannot write `boolean b = intLocal`,
    so a move between an int and a boolean exists only through d8's register
    reuse — which is why the ceiling is measured on the corpus instead.

    THREE things about the shape of this scan were wrong in the first cut, and an
    adversarial review found a real valid→invalid regression that all three hid:

    * it matched arithmetic / ordered compare / array INDEX only.  It still
      does, and that is a STATED LIMIT rather than a fix: the decompiled text
      does not carry a callee's parameter types or a field's declared type, so
      the positions `prim_use_vids` exists for cannot be judged from it at all.
      They are held by the named case below and by the fixture crafts, one per
      arm.  A delta review measured this: removing every `prim_use_vids` insert
      site leaves THIS test passing;
    * both regressed classes sat at index 438 and 1836 of 5,907, outside a
      `[:400]` window;
    * the `dk` fixture resolved to a 286-class sample with 51 boolean
      declarations, so a ceiling of `max(5, n//100)` had five units of slack.

    It walks several APKs, deeper, and the bound scales with what it saw.
    """
    from conftest import require_corpus_shape

    bools_seen = bad = 0
    sample = None
    arith = re.compile(r"(v\d+(?:_\d+)?)\s*(?:[+\-*/%]|<<|>>)\s")
    order = re.compile(r"(v\d+(?:_\d+)?)\s*(?:<|>|<=|>=)[^=]")
    index = re.compile(r"\[(v\d+(?:_\d+)?)\]")
    # DEF side too.  A guard dropped in the propagation shows up as a boolean
    # local ASSIGNED an int expression rather than as a bad use, and the use
    # scan is blind to that — measured: a mutant that propagates without
    # re-checking the def-anchor survived the use scan alone.
    assign_arith = re.compile(
        r"^\s*(?:boolean\s+)?(v\d+(?:_\d+)?)\s*=\s*[^;]*?"
        r"[\w)\]]\s*(?:[+\-*/%]|<<|>>|&|\|(?!\|)|\^)\s*[\w(]"
    )
    for dk in _ceiling_dexkits(loadable_apks):
        for c in dk.list_classes()[:1200]:
            try:
                src = dk.decompile_class(c)
            except Exception:
                continue
            for _rtype, name, body in _methods(src):
                bools = {
                    m.group(1)
                    for line in body
                    for m in [re.match(r"^\s*boolean (v\d+(?:_\d+)?)\b", line)]
                    if m
                }
                if not bools:
                    continue
                bools_seen += len(bools)
                for line in body:
                    for rx in (arith, order, index):
                        for m in rx.finditer(line):
                            if m.group(1) in bools:
                                bad += 1
                                if sample is None:
                                    sample = (c, name, line.strip())
                    m = assign_arith.match(line)
                    if m and m.group(1) in bools:
                        bad += 1
                        if sample is None:
                            sample = (c, name, line.strip())
    require_corpus_shape(
        bools_seen > 500,
        "a corpus large enough to bound (>500 boolean locals)",
        "the scan reached too little to be a ceiling at all",
    )
    # Measured on the shipped build: 28 corpus-wide, all PRE-EXISTING (identical
    # on both halves of the a/b).  The bound is absolute rather than scaled, so
    # it does not loosen as the boolean population grows — which is exactly what
    # this change makes it do.
    assert bad <= 40, (
        f"{bad} int uses of a boolean local over {bools_seen} declarations — a "
        f"type re-type is reaching versions that are genuinely ints.  First: "
        f"{sample}"
    )


def _ceiling_dexkits(loadable_apks, limit=6):
    """The APKs the ceilings scan, LARGEST FIRST.

    The two classes that regressed in review sat at index 438 and 1836 of a
    5,907-class APK that is 23rd in the candidate order, so neither "the first
    few" nor "a small one" is a ceiling.  Sorting by class count puts the APKs
    that can actually carry the shape at the front.
    """
    out = []
    for p in loadable_apks:
        try:
            dk = dexllm.DexKit(p)
        except Exception:
            continue
        out.append((len(dk.list_classes()), p, dk))
    out.sort(key=lambda t: -t[0])
    return [dk for _n, _p, dk in out[:limit]]


def test_a_boolean_is_not_passed_where_an_int_is_required(loadable_apks):
    """The method an adversarial review found turning valid Java INVALID.

    `maybeHandleMenuActionViaPerformReceiveContent` is ordinary support-library
    code: it `return`s a 0/1 flag from a `Z` method AND passes the same register
    at `Builder.setFlags(int)` — a position no guard recorded until
    `prim_use_vids`.  It is pinned by NAME because the ceiling above cannot see
    it: the decompiled text does not carry the callee's parameter types, so only
    a named case can assert that THIS argument is an int one.

    The review offered a SECOND site, `InputConnectionCompat`'s
    `v2.send(v3, 0)`.  It is NOT pinned here, because it is PRE-EXISTING: on a
    clean pre-fix build (`.so` 59a979ac) that line already reads
    `boolean v3 = false; … v2.send(v3, 0);`.  `v3` is typed from
    `onCommitContent()Z`, which is correct; the defect is an int/boolean
    conflation at the CALL, which this change neither causes nor closes.
    """
    from conftest import require_corpus_shape

    want = {
        (
            "Landroidx/appcompat/widget/AppCompatReceiveContentHelper;",
            "maybeHandleMenuActionViaPerformReceiveContent",
            "setFlags(",
        ),
    }
    checked = 0
    for dk in _ceiling_dexkits(loadable_apks):
        classes = set(dk.list_classes())
        for cls, meth, call in want:
            if cls not in classes:
                continue
            try:
                src = dk.decompile_class(cls)
            except Exception:
                continue
            for _rtype, name, body in _methods(src):
                if name != meth:
                    continue
                text = "\n".join(body)
                if call not in text:
                    continue
                checked += 1
                for line in body:
                    m = re.search(re.escape(call) + r"\s*(v\d+(?:_\d+)?)", line)
                    if not m:
                        continue
                    decl = re.search(
                        r"^\s*(\w+) %s\s*(?:=|;)" % re.escape(m.group(1)), text, re.M
                    )
                    assert decl and decl.group(1) != "boolean", (
                        f"{cls}->{meth}: {m.group(1)} is passed at an int "
                        f"parameter and must not be declared boolean\n{text}"
                    )
    require_corpus_shape(
        checked > 0,
        "the AppCompat/InputConnection int-argument shape",
        "neither reviewer-found regression site is reachable, so this cannot "
        "see the defect it was written for",
    )


def test_the_unreachable_guards_are_present_in_the_source():
    """Three conditions cannot be reached from any dex that verifies, so no
    behavioural case can hold them and the mutation matrix showed all three
    surviving.  A SOURCE pin is weaker than a behavioural one — it cannot see a
    condition that is present and wrong — and that is stated rather than implied.

    * `object_vids` — a version with all-0/1 defs used as a receiver or at a
      reference argument is invalid Dalvik, so only a lenient dump reaches it.
    * `ground` — a def closure of nothing but moves is reported `'M'` by `gt()`,
      which makes the caller `continue` before the resolver is consulted.
    * the `ThisParam` exclusion — a receiver register is reference-typed, so the
      `cur_prim` gate already excludes it; the cast makes it structural, exactly
      as the mirror branch above does.
    """
    src = (
        Path(__file__).resolve().parents[1] / "native/dad_cpp/dataflow.cpp"
    ).read_text()
    body = " ".join(_strip_comments(src).split())

    # The WHOLE condition, not a needle per conjunct: `!object_vids.count(vid) &&`
    # also occurs in the move-opcode fixpoint below, so a per-conjunct check is
    # satisfied by that other occurrence and the mutant survives — measured, it
    # did.  Whitespace is normalised so a re-wrap is not a false positive.
    branch = " ".join("""
        } else if (cur_prim && cur != "Z" && is_narrow_int(cur) &&
                   bool_ret_vids.count(vid) &&
                   !int_use_vids.count(vid) &&
                   !int_required_vids.count(vid) &&
                   !prim_use_vids.count(vid) &&
                   !object_vids.count(vid) &&
                   !dynamic_cast<ThisParam*>(vit->second.get()) &&
                   declared_param_is_boolean(vid, vit->second.get()) &&
                   all_defs_boolean_valued(vid, dvec)) {""".split())
    assert branch in body, (
        "the Z branch's condition changed.  Every conjunct is a guard a review "
        "or a mutant put there; dropping one is a deliberate edit, so this "
        "assertion is the place to record that it was deliberate."
    )

    propagation = " ".join("""
                if (st == "Z" || !is_narrow_int(st)) continue;
                if (int_use_vids.count(sid) || int_required_vids.count(sid) ||
                    prim_use_vids.count(sid) || object_vids.count(sid)) continue;
                if (dynamic_cast<ThisParam*>(svit->second.get())) continue;
                if (!declared_param_is_boolean(sid, svit->second.get())) continue;
                if (already.count(svit->second.get())) continue;
                if (!all_defs_boolean_valued(sid, sdefs->second)) continue;""".split())
    assert propagation in body, (
        "the backwards propagation's guards changed — it re-types versions the "
        "return type never reached, so it must re-check every one of them."
    )

    # The param arm.  `declared_param_is_boolean` covers a version that IS a
    # parameter; this covers the one-hop form, a MOVE off a def-less source.  A
    # reviewer relaxed it to `if (false)` and passed every behavioural case —
    # the fixture's boolean param is genuinely `Z`, and no dex that VERIFIES can
    # return an `int` parameter from a `Z` method.
    # The WHOLE arm, not the needle: `if (r->get_type() != "Z") return false;`
    # occurs TWICE (the def-less source, and the leaf), so a per-needle check is
    # satisfied by the other occurrence — measured, a reviewer's mutant of the
    # first one survived it.  The same hole the `object_vids` pin had.
    param_arm = " ".join("""
                auto it = defs_of.find(sid);
                if (it == defs_of.end()) {
                    auto dp = declared_params.find(sid);
                    const std::string& dt =
                        dp != declared_params.end() ? dp->second : r->get_type();
                    if (dt != "Z") return false;
                    ground = true;
                    return true;
                }""".split())
    assert param_arm in body, (
        "a def-less move source must be a declared `Z`, or a move off an `int` "
        "parameter reads as boolean-valued"
    )

    # The root form of the same rule.  A version that IS a parameter has no
    # entry in `defs_of` for its incoming value, so only this can refuse it.
    declared_param = " ".join("""
        if (!dynamic_cast<Param*>(var)) return true;
        auto it = declared_params.find(vid);
        return it != declared_params.end() && it->second == "Z";""".split())
    assert declared_param in body, (
        "`declared_param_is_boolean` must consult the DECLARED type — the "
        "`Param`'s own `get_type()` is corrupted by a write to its register, "
        "which is the case this pass repairs"
    )

    # The work cap must bail CONSERVATIVELY.  Unreachable on any input measured
    # (the budget is 2,000,000 and `gt()` exhausts its own first), so a source
    # pin is the only instrument; inverting it declares a version boolean on no
    # evidence at all.
    assert (
        "if (bv_budget == 0) return false;" in body
    ), "the work cap must REFUSE on exhaustion, not accept"

    # `is_prim_nonbool`'s membership.  Its EXCLUSION of `Z` is behavioural
    # (`passedAtBoolean` dies if `Z` is added), but its INCLUSION of the wide
    # widths is not — a delta review dropped `F` and `D` and the corpus output
    # was byte-identical, because no corpus flag is passed at a `float`
    # parameter.  Pinned as a literal so the set is a deliberate edit.
    assert (
        'return t.size() == 1 && std::string("IJBSCFD").find(t[0]) '
        "!= std::string::npos;" in body
    ), (
        "`is_prim_nonbool` must cover every non-boolean primitive width and must "
        "NOT cover `Z` — passing a boolean at a `Z` parameter is correct"
    )

    # The array-store marker set, same reason: adding `Z` there is corpus-neutral
    # (a `boolean[]` store of a flag is correct), so only a pin holds it.
    assert 'if (m.empty() || m == "W" || m == "B" || m == "C" || m == "S")' in body, (
        "the array-store arm must record a non-boolean primitive element and must "
        "skip `Z` (a boolean array) and `O` (an object array)"
    )

    assert "return ground;" in body, (
        "the def-anchor must require a ground producer, or a closure of nothing "
        "but moves satisfies the all-quantifier vacuously"
    )

    # The resolver's own narrow-width check on a CONSTANT.  It and
    # `is_narrow_int(cur)` in the branch above each refuse a wide value on their
    # own, so removing either alone is output-equivalent and only removing BOTH
    # is observable — measured.  Pinning both is what makes each one's deletion
    # a failure instead of a silent halving of the defence.
    assert "if (!is_narrow_int(c->get_type())) return false;" in body, (
        "a wide constant must not count as boolean-valued, or a `long` version "
        "whose `cur` gate is ever relaxed could be narrowed to `Z`"
    )


def _strip_comments(text: str) -> str:
    """Left-to-right scan.  A regex pass for `/* */` applied first swallows this
    file's own `// ---- const-wide/* ----`, which shrinks the audit silently
    instead of failing it — the trap dexllm#32 and dexllm#57 each paid for."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    out.append(text[i])
                    i += 1
                if i < n:
                    out.append(text[i])
                    i += 1
            if i < n:
                out.append(text[i])
                i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            i = text.find("*/", i)
            i = n if i < 0 else i + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_the_comment_stripper_strips_comments_and_nothing_else():
    """A stripper that eats too much makes the pin above vacuous just as surely
    as one that eats too little, so both directions are checked."""
    src = """int a = 1;  // keep\nchar *s = "// not a comment";\n/* gone */ int b;\n"""
    out = _strip_comments(src)
    assert "keep" not in out and "gone" not in out
    assert "// not a comment" in out
    assert "int a = 1;" in out and "int b;" in out


def test_the_text_and_the_ast_agree(pristine):
    """The fix is a TYPE decision in the dataflow layer, not an emitter mask, so
    the AST must carry the same rendering the text does — the divergence
    dexllm#63's review found for `boolean v = 0` is what this pins.

    `ast["source"] == decompile_method(...)` is NOT asserted here: a correctness
    review pointed out it is a tautology, since `DecompileMethodAst` assigns that
    field from the very same call.  What discriminates is the AST's own type and
    literal nodes, which the text path does not produce.
    """
    ast = pristine.decompile_method_ast(f"{CLS}->flag(I)Z")
    blob = repr(ast["ast"])
    assert "'.boolean'" in blob, blob[:400]
    assert "'true'" in blob and "'false'" in blob, blob[:400]


def test_a_real_apk_declares_the_same_booleans_in_the_text_and_the_ast(dk):
    """The fixture pins agreement on ONE method.  A correctness review measured
    the property over 95 real corpus methods and found 95/95 — this keeps that
    outside the fixture, where the shapes are not ones anybody authored."""
    from conftest import require_corpus_shape

    checked = 0
    for c in dk.list_classes()[:300]:
        try:
            src = dk.decompile_class(c)
        except Exception:
            continue
        if "boolean v" not in src:
            continue
        for _rtype, name, body in _methods(src):
            text_bools = {
                m.group(1)
                for line in body
                for m in [re.match(r"^\s*boolean (v\d+(?:_\d+)?)\b", line)]
                if m
            }
            if not text_bools:
                continue
            for desc in dk.list_class_methods(c):
                if f"->{name}(" not in desc:
                    continue
                try:
                    ast = dk.decompile_method_ast(desc, include_source=False)
                except Exception:
                    continue
                if not ast.get("ast"):
                    continue
                blob = repr(ast["ast"])
                for v in text_bools:
                    assert "'.boolean'" in blob, (
                        f"{c}->{name}: the text declares `boolean {v}` and the "
                        f"AST carries no boolean type node"
                    )
                checked += 1
                break
    require_corpus_shape(
        checked > 0,
        "a corpus method declaring a boolean local",
        "the scan found none, so it cannot see a text/AST divergence",
    )
