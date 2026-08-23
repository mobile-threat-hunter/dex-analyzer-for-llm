"""dexllm#73 — a code item with NO decodable instruction must not SEGV.

``MethodSnapshotBuilder`` set ``entry_block_id = 0`` for every method that has a
code item at all, and that value PROMISES ``blocks[0]`` exists: ``Construct``
seeds its bfs with ``snap.blocks[*entry_block_id]`` and finishes with
``nodes[*entry_block_id]``, neither bounds-checked.  A code item can carry no
decodable instruction, and then there is no leader and no block — so the promise
was an out-of-bounds read, i.e. a SIGSEGV no ``catch (...)`` and no ``safe.py``
deadline can contain.

Not a gate gap.  ART's STRUCTURAL verifier — the ``DexFileVerifier`` this port
mirrors — accepts a zero-opcode code item too; it is the runtime
``method_verifier`` that rejects one ("code item has no opcode",
``method_verifier.cc:1734``), and that pass is deliberately not vendored.  So
``VerifyDex`` behaved as documented and the promise was what was wrong.

**Two shapes, both crafted here, because a fix keyed on ``insns_size == 0``
alone would miss the second:**

* ``A`` — ``insns_size == 0``.  The real-world exemplar is AOSP's own
  ``art/tools/fuzzer/class-verifier-corpus/b391844326.dex`` (unmodified), whose
  ``LMain;->throwsIfParamIsZero(I)V`` is exactly this and which ``verify()``
  calls valid in BOTH modes.
* ``B`` — ``insns_size != 0`` but the body is nothing but a switch payload,
  which ``DecodeAllInsns`` skips.  Same empty-``blocks`` state, reached a second
  way.

Every craft is on ``tests/data/multidex.apk``, the one container this repo
commits, so these run in the corpus-less CI leg and under any
``$DEXLLM_TEST_APK`` narrowing.  Both are length-preserving to the byte — only
the code item's own ``insns_size``/instruction words are rewritten, so no
offset, no section size and no neighbouring structure moves, and the craft's
verify verdict is asserted rather than assumed.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from conftest import committed_container

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]


# ── an independent walk of class_data, so the target is not chosen by the
#    code under test ────────────────────────────────────────────────────────


def _uleb(b: bytes, o: int) -> tuple[int, int]:
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            break
    return r, o


def _code_items(b: bytes) -> list[tuple[str, int, int, int, int, int]]:
    """``[(descriptor, code_off, tries_size, insns_size, acc_off, acc_len)]``.

    ``acc_off``/``acc_len`` locate the member's ``access_flags`` uleb inside
    ``class_data``, which the crafts below rewrite in place.
    """

    def u4(o: int) -> int:
        return struct.unpack_from("<I", b, o)[0]

    def u2(o: int) -> int:
        return struct.unpack_from("<H", b, o)[0]

    string_ids_off, type_ids_off = u4(0x3C), u4(0x44)
    proto_ids_off, method_ids_off = u4(0x4C), u4(0x5C)
    class_defs_size, class_defs_off = u4(0x60), u4(0x64)

    def s(i: int) -> str:
        o = u4(string_ids_off + 4 * i)
        _, o = _uleb(b, o)
        return b[o : b.index(b"\x00", o)].decode()

    def t(i: int) -> str:
        return s(u4(type_ids_off + 4 * i))

    def proto(i: int) -> str:
        o = proto_ids_off + 12 * i
        ret, params_off = t(u4(o + 4)), u4(o + 8)
        args = ""
        if params_off:
            for k in range(u4(params_off)):
                args += t(u2(params_off + 4 + 2 * k))
        return f"({args}){ret}"

    def desc(i: int) -> str:
        o = method_ids_off + 8 * i
        return f"{t(u2(o))}->{s(u4(o + 4))}{proto(u2(o + 2))}"

    out: list[tuple[str, int, int, int]] = []
    for c in range(class_defs_size):
        cd = u4(class_defs_off + 32 * c + 24)
        if not cd:
            continue
        p = cd
        sf, p = _uleb(b, p)
        inf, p = _uleb(b, p)
        dm, p = _uleb(b, p)
        vm, p = _uleb(b, p)
        for _ in range(sf + inf):
            _, p = _uleb(b, p)
            _, p = _uleb(b, p)
        for n in (dm, vm):
            idx = 0
            for _ in range(n):
                d, p = _uleb(b, p)
                idx += d
                acc_off = p
                _, p = _uleb(b, p)
                acc_len = p - acc_off
                co, p = _uleb(b, p)
                if co:
                    out.append(
                        (desc(idx), co, u2(co + 6), u4(co + 12), acc_off, acc_len)
                    )
    return out


# ── the crafts ──────────────────────────────────────────────────────────────

_MIN_UNITS = 6  # a size-1 packed-switch payload is exactly 6 code units


@pytest.fixture(scope="module")
def target():
    """``(zip_bytes, dex_bytes, descriptor, code_off, insns_size)``.

    Premises asserted rather than assumed: a method with a code item that has NO
    try blocks (so ``insns_size`` is the last thing ``VerifyCodeItem`` reads for
    it, and shape A cannot move a try table) and room for a payload, plus a real
    body — otherwise the crafts would remove nothing and every assertion below
    would hold vacuously.
    """
    zip_bytes, dex = committed_container()
    cands = [
        c
        for c in _code_items(dex)
        if c[2] == 0 and c[3] >= _MIN_UNITS and c[3] % 2 == 0
    ]
    assert cands, "the committed fixture carries no try-free code item of >= 6 units"
    d, co, _tries, isz, acc_off, acc_len = cands[0]
    return zip_bytes, dex, d, co, isz, acc_off, acc_len


def _rezip(tmp_path: Path, zip_bytes: bytes, dex: bytes, name: str) -> str:
    src = tmp_path / "orig.apk"
    src.write_bytes(zip_bytes)
    out = tmp_path / name
    with (
        zipfile.ZipFile(src) as zin,
        zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo,
    ):
        for n in zin.namelist():
            zo.writestr(n, dex if n == "classes.dex" else zin.read(n))
    return str(out)


def _craft(tmp_path: Path, target, shape: str) -> str:
    zip_bytes, dex, _desc, co, isz, _ao, _al = target
    b = bytearray(dex)
    if shape == "A":
        struct.pack_into("<I", b, co + 12, 0)
    elif shape == "B":
        # A well-formed packed-switch payload filling the whole body:
        # ident 0x0100, size, first_key (u4), size * u4 targets.
        size = (isz - 4) // 2
        struct.pack_into("<HHi", b, co + 16, 0x0100, size, 0)
        for k in range(size):
            struct.pack_into("<I", b, co + 24 + 4 * k, 0)
    else:  # pragma: no cover - parametrisation is closed
        raise AssertionError(shape)
    assert len(b) == len(dex), "the craft must be length-preserving"
    path = _rezip(tmp_path, zip_bytes, bytes(b), f"empty_{shape}.apk")
    # The premise: the gate accepts it. Without this the guards below could pass
    # for the wrong reason — a rejected dex never reaches the IR builder at all.
    for lenient in (False, True):
        rows = dexllm.verify(path, lenient=lenient)
        assert all(r["valid"] for r in rows), (shape, lenient, rows)
    return path


_SHAPES = ["A", "B"]


# ── every observation is made in a CHILD ────────────────────────────────────
#
# A SIGSEGV kills the process it happens in, so an in-process assertion cannot
# survive the thing it asserts about — and a regression here would abort the
# whole `pytest tests/` session at this alphabetically-early file rather than
# report. So NO decompile of a CRAFTED dex happens in the pytest process: one
# child gathers every observation and the tests assert on its JSON. (`verify`
# is called here — it is the gate, it never reaches the IR builder, and its
# verdict is the premise each craft must establish before anything else runs;
# the one in-process decompile is on an unmodified committed fixture.)

_PROBE = r"""
import json, sys
import dexllm

path, desc = sys.argv[1], sys.argv[2]
cls = desc.split(";->")[0] + ";"
dk = dexllm.DexKit(path)
ast = dk.decompile_method_ast(desc)
json.dump(
    {
        "text": dk.decompile_method(desc),
        "ast_present": ast["ast"] is not None,
        "ast_found": ast["found"],
        "ast_body": (ast["ast"] or {}).get("body"),
        "ast_source": ast["source"],
        "ast_flags": (ast["ast"] or {}).get("flags"),
        "class_text": dk.decompile_class(cls),
        "smali": dk.render_method_smali(desc),
        "pc_map": dk.decompile_method_with_pc_map(desc)["pc_map"],
        "methods": {m: dk.decompile_method(m) for m in dk.list_class_methods(cls)},
    },
    sys.stdout,
)
"""

_probe_cache: dict[tuple[str, str], dict] = {}


def probe(path: str, desc: str) -> dict:
    """Run the whole observation set in a subprocess; a signal is the regression."""
    key = (path, desc)
    if key not in _probe_cache:
        p = subprocess.run(
            [sys.executable, "-c", _PROBE, path, desc],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=REPO_ROOT,
        )
        assert p.returncode >= 0, (
            f"killed by signal {-p.returncode} — entry_block_id named a block "
            f"that does not exist ({path})"
        )
        assert p.returncode == 0, p.stdout + p.stderr
        _probe_cache[key] = json.loads(p.stdout)
    return _probe_cache[key]


@pytest.mark.parametrize("shape", _SHAPES)
def test_a_body_less_method_does_not_kill_the_process(tmp_path, target, shape):
    """THE guard: the pre-fix build dies with signal 11 on both shapes."""
    obs = probe(_craft(tmp_path, target, shape), target[2])
    assert obs["text"], obs


# ── what it emits instead ───────────────────────────────────────────────────


@pytest.mark.parametrize("shape", _SHAPES)
def test_a_body_less_method_renders_as_a_signature(tmp_path, target, shape):
    """There is no body to render, so refusing beats inventing one.

    An empty ``{ }`` would assert the method does nothing, which is a
    fabrication.  This is the signature-only path abstract/native methods
    already take; the emitted modifiers are what still separate this from
    either, so they are asserted on the DECLARATION line rather than as a
    whole-source substring (which any comment could satisfy).
    """
    obs = probe(_craft(tmp_path, target, shape), target[2])
    decl = [ln for ln in obs["text"].splitlines() if ln.strip()][-1]
    assert decl.rstrip().endswith("// no instructions"), obs["text"]
    assert decl.split("//")[0].rstrip().endswith(";"), obs["text"]
    assert "{" not in obs["text"], obs["text"]
    assert "abstract" not in decl.split() and "native" not in decl.split(), decl
    # ...and the modifiers a consumer reads programmatically agree with the text.
    assert obs["ast_flags"] and "abstract" not in obs["ast_flags"], obs["ast_flags"]
    assert "native" not in obs["ast_flags"], obs["ast_flags"]


@pytest.mark.parametrize("shape", _SHAPES)
def test_the_ast_agrees_with_the_text(tmp_path, target, shape):
    """The AST is a second emitter over the same graph.

    ``ast_present`` is asserted separately because ``(ast or {}).get("body")``
    is ``None`` both when the AST carries a null body and when there is no AST
    at all — only one of those is the intended answer.
    """
    obs = probe(_craft(tmp_path, target, shape), target[2])
    assert obs["ast_found"] is True, obs
    assert obs["ast_present"] is True, obs
    assert obs["ast_body"] is None, obs["ast_body"]
    assert obs["ast_source"] == obs["text"], (obs["ast_source"], obs["text"])
    assert obs["pc_map"] == [], obs["pc_map"]


@pytest.mark.parametrize("shape", _SHAPES)
def test_the_sibling_method_is_untouched(tmp_path, target, shape):
    """No collateral: only the crafted method loses its body.

    Without this the guards above are satisfied by a build that renders EVERY
    method as a signature.
    """
    ref = probe(str(REPO_ROOT / "tests" / "data" / "multidex.apk"), target[2])
    obs = probe(_craft(tmp_path, target, shape), target[2])
    others = {m for m in ref["methods"] if m != target[2]}
    assert others, "the fixture class has only the crafted method"
    for m in others:
        assert obs["methods"][m] == ref["methods"][m], m


def test_the_uncrafted_method_has_a_body(target):
    """Non-vacuity: the craft must actually remove something.

    Non-discriminating BY DESIGN — it holds on both sides of the fix — but a
    fixture whose target were already body-less would make every assertion above
    true for the wrong reason.
    """
    obs = probe(str(REPO_ROOT / "tests" / "data" / "multidex.apk"), target[2])
    assert "{" in obs["text"] and "}" in obs["text"], obs["text"]


def test_the_class_still_decompiles_whole(tmp_path, target):
    """``decompile_class`` is the surface the issue reported dying.

    It must carry the body-less member's own declaration — a class shell that
    merely omitted it would satisfy a bare brace count.
    """
    obs = probe(_craft(tmp_path, target, "A"), target[2])
    out = obs["class_text"]
    name = target[2].split(";->")[1].split("(")[0]
    assert "DECOMPILE ERROR" not in out and "METHOD ERROR" not in out, out
    assert any(
        ln.strip().startswith(("public", "private", "protected", "static"))
        and name in ln
        and ln.rstrip().endswith("// no instructions")
        for ln in out.splitlines()
    ), out
    assert out.rstrip().endswith("}"), out


def test_a_body_less_code_item_with_try_blocks_is_rejected_at_the_gate(tmp_path):
    """Why the crafts above are restricted to a TRY-FREE method — a measurement,
    not an accident.

    ``VerifyCodeItem`` locates the try table at ``insns_end``, so zeroing
    ``insns_size`` moves it and the handler list no longer parses; every
    ``start_addr``/handler ``addr`` must also be ``< insns_size``, which nothing
    satisfies at 0. So shape A is reachable ONLY with ``tries_size == 0``, and
    the fixture's filter states that rather than stumbling on it.
    """
    blob = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
    dex = blob.read_bytes()
    with_tries = [c for c in _code_items(dex) if c[2] != 0]
    assert with_tries, "the fixture no longer carries a method with try blocks"
    _d, co, _t, _i, _a, _l = with_tries[0]
    b = bytearray(dex)
    struct.pack_into("<I", b, co + 12, 0)
    out = tmp_path / "tries_zero.dex"
    out.write_bytes(bytes(b))
    for lenient in (False, True):
        rows = dexllm.verify(str(out), lenient=lenient)
        assert not any(r["valid"] for r in rows), (lenient, rows)


def test_a_class_whose_every_method_is_body_less_still_renders(tmp_path, target):
    """The class shell must survive, not just one method.

    Without this, a build that rendered the whole CLASS as empty (or died on the
    first body-less member) would satisfy every per-method case above.
    """
    zip_bytes, dex, desc, _co, _isz, _ao, _al = target
    b = bytearray(dex)
    for _d, co, tries, _i, _a, _l in _code_items(dex):
        if tries == 0:
            struct.pack_into("<I", b, co + 12, 0)
    path = _rezip(tmp_path, zip_bytes, bytes(b), "all_body_less.apk")
    assert all(r["valid"] for r in dexllm.verify(path))
    out = probe(path, desc)["class_text"]  # a CHILD: a regression here is a signal
    assert out.startswith("package ") and out.rstrip().endswith("}"), out
    assert "DECOMPILE ERROR" not in out and "METHOD ERROR" not in out, out
    # every member is a marked, bare signature
    assert out.count("// no instructions") == 2, out
    assert "{\n" in out and out.count("{") == 1, out  # only the class brace


def test_a_payload_only_body_with_try_blocks_is_also_body_less(tmp_path):
    """The shape that makes ``blocks`` the WRONG predicate (correctness review).

    Stage 3 of the builder seeds a leader per try-range START, so a payload-only
    body that also carries a try table produces blocks — each with an empty
    ``ins`` span — and a guard keyed on ``blocks.empty()`` therefore let it
    through, rendering an empty ``try { } catch { }`` for a method with no
    instruction at all.  Keyed on ``ins_storage`` it is body-less like every
    other no-instruction shape.  Crafted on the committed ``invoke-custom.dex``,
    the only fixture carrying a method with try blocks.
    """
    blob = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
    dex = blob.read_bytes()
    cands = [
        c
        for c in _code_items(dex)
        if c[2] != 0 and c[3] >= _MIN_UNITS and c[3] % 2 == 0
    ]
    assert cands, "the fixture no longer carries a method with try blocks"
    desc, co, _tries, isz, _a, _l = cands[0]
    b = bytearray(dex)
    # one packed-switch payload filling the whole body; the try ranges and
    # handler addresses still refer to offsets < insns_size, which is unchanged.
    size = (isz - 4) // 2
    struct.pack_into("<HHi", b, co + 16, 0x0100, size, 0)
    for k in range(size):
        struct.pack_into("<I", b, co + 24 + 4 * k, 0)
    assert len(b) == len(dex)
    out = tmp_path / "payload_try.dex"
    out.write_bytes(bytes(b))
    for lenient in (False, True):
        assert all(r["valid"] for r in dexllm.verify(str(out), lenient=lenient))

    obs = probe(str(out), desc)
    assert "try" not in obs["text"] and "catch" not in obs["text"], obs["text"]
    assert "{" not in obs["text"], obs["text"]
    assert obs["text"].rstrip().endswith("// no instructions"), obs["text"]
    assert obs["ast_body"] is None, obs["ast_body"]


def test_an_abstract_method_does_not_get_the_marker():
    """The marker must name the REFUSAL, not every body-less declaration.

    Abstract and native methods reach the SAME signature-only Writer branch and
    already say what they are with a modifier; marking them too would make the
    marker meaningless and would change output on every interface in the corpus.

    Driven on ``method_handles.dex`` because the multidex fixture has no abstract
    or native method at all — a version of this guard scoped to the crafted class
    was VACUOUS and let a mutant that emits the marker unconditionally pass the
    whole file (adversarial review).  The floor below is what says it is not.
    """
    blob = REPO_ROOT / "tests" / "data" / "method_handles.dex"
    dk = dexllm.DexKit(str(blob))
    seen = 0
    for cls in dk.list_classes():
        for desc in dk.list_class_methods(cls):
            src = dk.decompile_method(desc)
            if not src.rstrip().endswith(";"):
                continue
            mods = src.strip().split("(")[0].split()
            if "abstract" in mods or "native" in mods:
                seen += 1
                assert "// no instructions" not in src, (desc, src)
    assert seen >= 2, f"fixture carries no abstract/native method ({seen})"


# ── what the ADVERSARIAL delta review of the shipped change found ────────────


def _uleb_bytes_fixed(value: int, width: int) -> bytes:
    """`value` as a uleb128 padded to exactly `width` bytes (redundant
    continuation bits are legal and keep the craft length-preserving)."""
    out = bytearray()
    for i in range(width):
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if i + 1 < width else 0))
    assert value == 0, "value does not fit in the original uleb width"
    return bytes(out)


def test_a_package_private_body_less_method_still_appears(tmp_path, target):
    """It DISAPPEARED — a regression the shipped change introduced.

    ``DvMethod::Process`` uses ``meta.access.empty()`` as a proxy for "external
    reference, emit nothing", and a package-private member has access flags 0,
    i.e. an empty vector too.  That was unreachable while every method with a
    code item got a graph; making one graph-less created the route, and the
    method then vanished from ``decompile_class`` with no declaration, no marker
    and no error — the exact outcome
    ``test_the_class_still_decompiles_whole`` forbids.  Every fixture method and
    the real AOSP exemplar are ``public``, so no corpus a/b could reach it.
    """
    zip_bytes, dex, desc, co, _isz, acc_off, acc_len = target
    b = bytearray(dex)
    struct.pack_into("<I", b, co + 12, 0)  # no instructions
    b[acc_off : acc_off + acc_len] = _uleb_bytes_fixed(0, acc_len)  # package-private
    assert len(b) == len(dex)
    path = _rezip(tmp_path, zip_bytes, bytes(b), "package_private.apk")
    for lenient in (False, True):
        assert all(r["valid"] for r in dexllm.verify(path, lenient=lenient))

    obs = probe(path, desc)
    name = desc.split(";->")[1].split("(")[0]
    assert obs["text"].strip(), "the method emitted nothing at all"
    assert obs["text"].rstrip().endswith("// no instructions"), obs["text"]
    assert any(
        name in ln and ln.rstrip().endswith("// no instructions")
        for ln in obs["class_text"].splitlines()
    ), obs["class_text"]


def test_a_clinit_with_no_instructions_is_an_empty_static_block(tmp_path):
    """`static;` is not Java, and `static { }` is both valid AND true here.

    A `<clinit>` reaching the signature-only branch has already emitted the bare
    `static` keyword (the beyond-DAD `<clinit>` rendering), so the shared `;`
    produced uncompilable output on a shape this change created.  With no
    instruction nothing executes, which is the one case where `{ }` is not the
    fabrication the marker exists to refuse.
    """
    blob = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
    dex = blob.read_bytes()
    clinits = [
        c for c in _code_items(dex) if c[0].split(";->")[1].startswith("<clinit>")
    ]
    assert clinits, "the fixture no longer carries a <clinit>"
    desc, co, _t, _i, _a, _l = clinits[0]
    b = bytearray(dex)
    struct.pack_into("<I", b, co + 12, 0)
    assert len(b) == len(dex)
    out = tmp_path / "clinit_empty.dex"
    out.write_bytes(bytes(b))
    assert all(r["valid"] for r in dexllm.verify(str(out)))

    text = probe(str(out), desc)["text"]
    assert "static { }" in text, text
    assert "static;" not in text, text
    assert "// no instructions" in text, text


def test_a_crafted_abstract_method_with_a_code_item_is_still_marked(tmp_path, target):
    """The marker follows the CODE ITEM, not the modifiers — pinned, not implied.

    A well-formed abstract or native method has no code item at all, so it never
    sets the flag; that is what ``test_an_abstract_method_does_not_get_the_marker``
    checks on a real fixture.  A method that is BOTH abstract and code-bearing is
    malformed (ART's member access-flag validation is out of the gate's scope),
    and for it "no instructions" is simply true — so the marker appears.  This
    case exists so that stays a decision rather than an accident.
    """
    zip_bytes, dex, _d, _co, _isz, _ao, _al = target

    def flags(off: int, width: int) -> int:
        v = 0
        for i in range(width):
            v |= (dex[off + i] & 0x7F) << (7 * i)
        return v

    # ACC_ABSTRACT must fit the member's EXISTING uleb width, or the craft is
    # not length-preserving. `<init>` carries public|constructor in 3 bytes,
    # which has room; a bare `public` is one byte and does not.
    cands = [
        c
        for c in _code_items(dex)
        if c[2] == 0 and (flags(c[4], c[5]) | 0x0400) >> (7 * c[5]) == 0
    ]
    assert cands, "no member's access uleb has room for ACC_ABSTRACT"
    desc, co, _t, _i, acc_off, acc_len = cands[0]
    b = bytearray(dex)
    struct.pack_into("<I", b, co + 12, 0)
    b[acc_off : acc_off + acc_len] = _uleb_bytes_fixed(
        flags(acc_off, acc_len) | 0x0400, acc_len
    )
    assert len(b) == len(dex)
    path = _rezip(tmp_path, zip_bytes, bytes(b), "abstract_with_code.apk")
    assert all(r["valid"] for r in dexllm.verify(path))

    text = probe(path, desc)["text"]
    assert "abstract" in text.split("(")[0].split(), text
    assert text.rstrip().endswith("// no instructions"), text
