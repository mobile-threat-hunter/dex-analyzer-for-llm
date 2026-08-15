"""dexllm#48 — every `class_data` member must belong to the class declaring it.

ART's `CheckInterClassDataItem` (`dex_file_verifier.cc:3208`, field loop `:3226`,
method loop `:3244`, plus a per-member re-check in `CheckClassDataItemField` `:934`
/ `CheckClassDataItemMethod` `:961`) rejects any entry whose `field_id.class_idx` /
`method_id.class_idx` is not the declaring class. The port read only the FIRST
member (`FindFirstClassDataDefiner`, defined `:2579`, called `:3070`), so a
`class_data` whose first entry was its own could declare another class's members
and still verify clean — a real gap in the "readable 1:1 port of ART
DexFileVerifier" claim.

It is a wrong-ANSWER gap, not a memory-safety one: `VerifyClassData` already bounds
every index, so nothing reads out of range. What it corrupts is the data the core
builds while walking `class_data`, which is written BY INDEX with no check that the
index belongs to the class being walked
([dex_item.cpp](../vendor/dexkit_core/Core/dexkit/dex_item.cpp)):

* fields — `field_access_flags[idx]` / `field_access_flags_declared[idx]`, so a
  class reports another's modifiers, or (since dexllm#45) silently loses its own;
* methods — the same, **plus** `methods.emplace_back(class_method_idx)`, which
  injects the foreign method into this class's `class_method_ids`, so
  `list_class_methods` / `get_class_summary().methods` / `render_class_smali` all
  report a method the class does not declare.

The fixtures below craft IN PLACE and length-preserving (the replacement uleb
encodes to the same byte count), so every offset in the file — and therefore every
other check — is untouched.
"""

import glob
import struct
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]


def _uleb(buf, off):
    r = s = 0
    while True:
        x = buf[off]
        off += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            return r, off


def _enc_uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _decode(raw, data_off):
    """-> {list name: [(diff byte offset, diff value, resolved index)]}.

    EACH of the four lists restarts its delta chain at 0 — the first element is
    absolute, the rest relative to the previous element OF THE SAME LIST (dex
    spec; `VerifyClassData` and ART's `ClassAccessor::NextSection` both do this).
    Getting this wrong is not academic: an earlier cut of this file accumulated
    one chain across static+instance, and on `FieldsTest.dex` (sf=1, inf=2, real
    indices static=[2] instance=[0,1]) it modelled [2,2,3] and produced a patch
    that left the dex VALID — so the test hard-FAILED instead of skipping, on the
    very semantics under test.
    """
    o = data_off
    counts = []
    for _ in range(4):
        n, o = _uleb(raw, o)
        counts.append(n)
    out = {}
    for name, n, is_method in (
        ("static_fields", counts[0], False),
        ("instance_fields", counts[1], False),
        ("direct_methods", counts[2], True),
        ("virtual_methods", counts[3], True),
    ):
        idx = 0
        entries = []
        for _ in range(n):
            start = o
            d, o = _uleb(raw, o)
            idx += d
            _access, o = _uleb(raw, o)
            if is_method:
                _code_off, o = _uleb(raw, o)
            entries.append((start, d, idx))
        out[name] = entries
    return out


def _owner(raw, ids_off, idx, stride):
    return struct.unpack_from("<H", raw, ids_off + stride * idx)[0]


_FIELD_LISTS = ("static_fields", "instance_fields")
_METHOD_LISTS = ("direct_methods", "virtual_methods")


def _forge(raw, want_list, entry_pos):
    """Point ONE entry of `want_list` at an id owned by a DIFFERENT class.

    Targeting a NAMED list, not "a field" — a reviewer showed that picking
    whichever list happened to have entries left `fields(inf)` and both method
    loops unguarded: the chosen class had `sf=0`, so "drop the static check" and
    "drop the method checks" were both invisible. Each list now gets its own test.

    `entry_pos` 0 patches the FIRST member of the list — the only case the pre-#48
    code caught — and 1 the second, the case it waved through.

    The premise is VERIFIED after patching by re-decoding with the correct
    per-list rule: the result must contain a genuine OWNER mismatch and no
    out-of-range index. Both halves matter. Without the first, a candidate that
    silently stays valid reaches the test as an assertion failure instead of a
    skip (an earlier cut did exactly that on `FieldsTest.dex`). Without the
    second, a patch that shifts a later index out of range is rejected by the
    INTRA pass with `... idx out of range`, and a test asserting the definer
    reason fails on what is really an environment fact — this repo's issue #46
    rule (an environment fact must SKIP, never fail).
    """
    raw = bytearray(raw)

    def u32(o):
        return struct.unpack_from("<I", raw, o)[0]

    if want_list in _METHOD_LISTS:
        ids_size, ids_off = u32(0x58), u32(0x5C)
        siblings = _METHOD_LISTS
    else:
        ids_size, ids_off = u32(0x50), u32(0x54)
        siblings = _FIELD_LISTS
    stride = 8
    cd_size, cd_off = u32(0x60), u32(0x64)

    for c in range(cd_size):
        base = cd_off + 32 * c
        cls_idx, data_off = u32(base), u32(base + 24)
        if not data_off:
            continue
        entries = _decode(raw, data_off)[want_list]
        if len(entries) <= entry_pos:
            continue
        start, diff, _idx = entries[entry_pos]
        prev = entries[entry_pos - 1][2] if entry_pos else 0
        lo = prev + 1 if entry_pos else 0
        for cand in range(lo, min(ids_size, lo + 5000)):
            if _owner(raw, ids_off, cand, stride) == cls_idx:
                continue
            new = _enc_uleb(cand - prev)
            if len(new) != len(_enc_uleb(diff)):
                continue
            trial = bytearray(raw)
            trial[start : start + len(new)] = new
            after = [
                i for lst in siblings for (_s, _d, i) in _decode(trial, data_off)[lst]
            ]
            if any(i >= ids_size for i in after):
                continue  # the intra pass would reject this first, with its reason
            if not any(_owner(trial, ids_off, i, stride) != cls_idx for i in after):
                continue  # no actual mismatch — the patch would still verify
            return bytes(trial), cls_idx
    return None, None


def _forged_dex(tmp_path, name, want_list, entry_pos=1):
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = open(cand, "rb").read()
        if raw[:4] != b"dex\n":
            continue
        patched, cls_idx = _forge(raw, want_list, entry_pos)
        if patched is None:
            continue
        f = tmp_path / name
        f.write_bytes(patched)
        return str(f), cls_idx
    pytest.skip(
        f"no bare .dex in the corpus has a patchable {want_list} entry "
        f"at position {entry_pos}"
    )


@pytest.mark.parametrize("want_list", _FIELD_LISTS + _METHOD_LISTS)
def test_a_class_data_declaring_another_class_s_member_is_rejected(tmp_path, want_list):
    """The verdict, at the verifier — the project's single gate. Once per LIST.

    All four, because `CheckClassDataDefiners` checks four independently and a
    reviewer killed the single-fixture version with two surviving mutants: leaving
    `fields(inf)` unchecked, and leaving both method loops unchecked. Whichever
    list a "pick the first with entries" fixture lands on, the other three go
    unguarded.

    Position 1, so the FIRST member is still the class's own and the pre-#48
    `FindFirstClassDataDefiner` sees a correct definer — the shape it waved
    through.

    The method half is the worse of the two: besides flags written by index, the
    core appends the foreign method to this class's `class_method_ids`, so it is
    then reported as declared by `list_class_methods` and friends.
    """
    path, _cls = _forged_dex(tmp_path, f"mismatched_{want_list}.dex", want_list)

    report = dexllm.verify(path)
    assert not report[0]["valid"], f"a foreign member in {want_list} must be rejected"
    # the definer check specifically, not some invariant the forgery also broke,
    # and naming the right member KIND
    reason = report[0]["reason"]
    assert "Mismatched defining class" in reason, reason
    kind = "method" if want_list in _METHOD_LISTS else "field"
    assert reason.endswith(kind), reason

    with pytest.raises(Exception):
        dexllm.DexKit(path)


def test_it_is_rejected_leniently_too(tmp_path):
    """`lenient=True` skips only `VerifyInsns`, and a packer dump is a first-class
    mode, so the channel must not reopen there.

    NOTE the corpus cannot exercise the population this actually matters for: a
    partially-decrypted dump whose class_data is in range but wrongly owned. The
    bundled sources are clean, so their lenient verdicts are trivially equal to
    their strict ones — the a/b's "lenient" axis carries near-zero information and
    this test pins the code path, not a corpus fact.
    """
    path, _cls = _forged_dex(tmp_path, "mismatched_lenient.dex", "instance_fields")
    report = dexllm.verify(path, lenient=True)
    assert not report[0]["valid"]
    assert "Mismatched defining class" in report[0]["reason"], report[0]["reason"]


def test_the_first_member_is_still_checked(tmp_path):
    """The pre-#48 behaviour must survive, not be replaced.

    NON-DISCRIMINATING BY DESIGN — it holds on both sides. The REASON differs, and
    the pattern accepts either: #48 adopted ART's own wording (`Mismatched defining
    class for class_data_item field` / `... method`, which also says WHICH list),
    replacing `class_data_item defines members of another class`. Anything matching
    the old string sees a changed message. Asserting one of the two, rather than a
    bare `not valid`, keeps this from passing on an unrelated rejection.
    """
    path, _cls = _forged_dex(tmp_path, "first_member.dex", "instance_fields", 0)
    report = dexllm.verify(path)
    assert not report[0]["valid"]
    reason = report[0]["reason"]
    assert (
        "Mismatched defining class" in reason  # since dexllm#48
        or "defines members of another class" in reason  # before it
    ), reason


def test_an_empty_class_data_is_accepted(tmp_path):
    """ART allows it explicitly — such an item "could be shared by multiple
    classes" — and the new loop writes that branch from scratch (four counts of
    zero means four loops that never run). A rewrite that rejected it would break
    real dexes, which the corpus sweep would catch only if the corpus has one.
    """
    seen = 0
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = open(cand, "rb").read()
        if raw[:4] != b"dex\n":
            continue
        cd_size, cd_off = struct.unpack_from("<II", raw, 0x60)
        for c in range(cd_size):
            base = cd_off + 32 * c
            data_off = struct.unpack_from("<I", raw, base + 24)[0]
            if not data_off:
                continue
            d = _decode(bytearray(raw), data_off)
            if not any(d.values()):
                seen += 1
        if seen:
            assert dexllm.verify(cand)[0]["valid"], cand
            return
    pytest.skip("no bare .dex in the corpus declares an empty class_data")


def test_the_definer_check_does_not_false_reject_the_corpus():
    """Zero false-reject: ART runs this exact check, so anything Android loads passes.

    NON-DISCRIMINATING BY DESIGN — it must hold on BOTH sides of #48. A new
    verifier check that rejects a real app is worse than the gap it closes, and
    this one now walks every member of every class_data rather than one.
    """
    checked = 0
    for p in sorted(
        glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk"))
        + glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))
    ):
        try:
            # A resources-only container carries no dex and is not a verifier
            # verdict at all — the same pre-filter the sibling #23 guard uses.
            if dexllm.identify(p).get("dex_count", 0) == 0:
                continue
        except Exception:  # noqa: BLE001
            continue
        for r in dexllm.verify(p):
            assert r["valid"], (p, r["dex_id"], r["reason"])
            checked += 1
    if not checked:
        pytest.skip("no loadable dex container in the corpus")
