"""A dex whose VALUE strings are out of order loads under ``lenient=True`` (dexllm#112).

The shape is a post-build string swap: a builder overwrites some string
constants (a real sample swapped AppsFlyer URL templates for gambling URLs),
fixes the length fields and the checksum, and does not re-sort ``string_ids``.
ART refuses such a dex (``CheckInterStringIdItem``, ``dex_file_verifier.cc
:2720``) because its runtime BINARY-SEARCHES the table. This stack never does;
what its readers rely on is narrower, and the lenient pass accepts on exactly
that:

* I1 -- the strings used as IDENTIFIERS (type descriptors, proto shorty,
  field / method names) are strictly ordered among themselves;
* I3 -- the empty string, if present, is only at index 0.

Anything else keeps ART's failure, a strict verify is ART's verdict unchanged,
and an accepted deviation is REPORTED on the verify row (``art_deviations``).

Every craft rewrites ``string_ids`` entries of the committed
``tests/data/literal-escapes.dex`` -- u4 swaps, length-preserving -- so the
whole file runs in the corpus-less CI leg.
"""

import pathlib
import struct

import pytest

import dexllm

FIXTURE = pathlib.Path(__file__).resolve().parent / "data" / "literal-escapes.dex"
CLS = "LLiteralEscapes;"
OOO = "Out-of-order string_ids"


def _table(b):
    n, off = struct.unpack_from("<II", b, 0x38)
    return n, off


def _strings(b):
    n, off = _table(b)
    out = []
    for i in range(n):
        (so,) = struct.unpack_from("<I", b, off + 4 * i)
        p = so
        while b[p] & 0x80:
            p += 1
        p += 1
        out.append(b[p : b.index(b"\0", p)])
    return out


def _identifier_indices(b):
    """The string indices the id tables use as identifiers (the roles I1 is
    about), read from the raw tables -- not through the code under test."""

    def tbl(at):
        return struct.unpack_from("<II", b, at)

    tn, to = tbl(0x40)
    pn, po = tbl(0x48)
    fn, fo = tbl(0x50)
    mn, mo = tbl(0x58)
    ident = set()
    ident |= {struct.unpack_from("<I", b, to + 4 * i)[0] for i in range(tn)}
    ident |= {struct.unpack_from("<I", b, po + 12 * i)[0] for i in range(pn)}
    ident |= {struct.unpack_from("<I", b, fo + 8 * i + 4)[0] for i in range(fn)}
    ident |= {struct.unpack_from("<I", b, mo + 8 * i + 4)[0] for i in range(mn)}
    return ident


def _craft(tmp_path, name, edit):
    b = bytearray(FIXTURE.read_bytes())
    n, off = _table(b)

    def get(i):
        return struct.unpack_from("<I", b, off + 4 * i)[0]

    def put(i, v):
        struct.pack_into("<I", b, off + 4 * i, v)

    edit(b, get, put)
    p = tmp_path / f"{name}.dex"
    p.write_bytes(bytes(b))
    return str(p)


def _index_of(content):
    s = _strings(FIXTURE.read_bytes())
    return s.index(content)


def _swap(i, j):
    def edit(b, get, put):
        a, c = get(i), get(j)
        put(i, c)
        put(j, a)

    return edit


# Two VALUE strings of the fixture, and two IDENTIFIERS.
V1, V2 = b"a\tb", b"a\x7fb"
I1A, I1B = b"APOS", b"ASTRAL"


def test_the_fixture_premises_hold():
    """Which strings are values and which are identifiers is read from the raw
    id tables; a fixture that stopped offering the shape fails here, not as a
    confusing verdict below."""
    b = FIXTURE.read_bytes()
    s = _strings(b)
    ident = _identifier_indices(b)
    assert s[0] == b""
    assert _index_of(V1) not in ident and _index_of(V2) not in ident
    assert _index_of(I1A) in ident and _index_of(I1B) in ident
    assert _index_of(V1) < _index_of(V2)  # swapping them breaks the order
    assert dexllm.verify(str(FIXTURE))[0]["valid"]


@pytest.fixture
def value_swapped(tmp_path):
    return _craft(tmp_path, "value_swap", _swap(_index_of(V1), _index_of(V2)))


@pytest.fixture
def value_duplicated(tmp_path):
    i, j = _index_of(V1), _index_of(V2)

    def edit(b, get, put):
        put(j, get(i))  # index j now names the SAME bytes as index i

    return _craft(tmp_path, "value_dup", edit)


def test_strict_verify_is_arts_verdict(value_swapped):
    """ART rejects this dex, and a strict verify says so with ART's reason and
    no deviation -- the strict half of the claim is unchanged."""
    [row] = dexllm.verify(value_swapped)
    assert (row["valid"], row["reason"], row["art_deviations"]) == (False, OOO, [])
    with pytest.raises(RuntimeError, match=OOO):
        dexllm.DexKit(value_swapped)


@pytest.mark.parametrize("craft", ["value_swapped", "value_duplicated"])
def test_lenient_accepts_and_reports_the_deviation(craft, request):
    path = request.getfixturevalue(craft)
    [row] = dexllm.verify(path, lenient=True)
    assert row["valid"] and row["reason"] == "", row
    [dev] = row["art_deviations"]
    assert dev.startswith("string_ids: ") and "ART" in dev, dev
    dk = dexllm.DexKit([path], lenient=True)
    # the load-time record and the load-free verify agree, deviation included
    assert dk.verify_report() == dexllm.verify(path, lenient=True)
    assert CLS in dk.list_classes()


def test_a_swapped_value_string_is_read_by_index(value_swapped):
    """Every reference to a string is by INDEX, so after the swap each const-
    string and static initializer names the OTHER content -- and the decompiler,
    the smali view and the value-string listing all say the same thing."""
    dk = dexllm.DexKit([value_swapped], lenient=True)
    values = set(dk.list_value_strings())
    assert {"a\tb", "a\x7fb"} <= values
    smali = dk.render_class_smali(CLS)
    java = dk.decompile_class(CLS)
    # TAB was at the lower index; the field that named it now reads DEL.
    assert 'TAB = "a\x7fb";' in java, java
    assert 'DEL = "a\\tb";' in java, java
    assert '"a\\tb"' in smali and '"a\x7fb"' in smali


def test_a_duplicated_value_string_is_found_by_content(value_duplicated):
    dk = dexllm.DexKit([value_duplicated], lenient=True)
    hits = dk.find_methods_using_strings(["a\tb"], match_type="equal")
    assert [h.descriptor for h in hits], hits
    assert dk.list_value_strings().count("a\tb") == 1  # deduplicated by content


def test_an_identifier_out_of_order_is_still_rejected(tmp_path):
    """I1: two FIELD NAMES swapped. Every name stays valid and every id table
    stays index-ordered, so only the string order says anything -- and the
    lenient pass refuses it, because type / member identity keys on content."""
    p = _craft(tmp_path, "ident_swap", _swap(_index_of(I1A), _index_of(I1B)))
    for lenient in (False, True):
        [row] = dexllm.verify(p, lenient=lenient)
        assert (row["valid"], row["reason"]) == (False, OOO), (lenient, row)


def test_an_empty_string_off_index_0_is_still_rejected(tmp_path):
    """I3: the empty string moved to a value index. No identifier moves, so I1
    holds; DexKit's `""` search looks for it at index 0 only."""
    p = _craft(tmp_path, "empty_moved", _swap(0, _index_of(V1)))
    [row] = dexllm.verify(p, lenient=True)
    assert (row["valid"], row["reason"]) == (False, OOO), row


def test_the_sdk_and_mcp_carry_the_deviation(value_swapped):
    from dexllm import sdk

    [st] = sdk.verify(value_swapped, lenient=True)
    assert st.valid and st.art_deviations and "ART" in st.art_deviations[0]
    [st] = sdk.verify(value_swapped)
    assert (st.valid, st.art_deviations) == (False, ())


def test_the_servers_fall_back_to_lenient_and_say_so(value_swapped):
    """MCP and HTTP take a path from a caller who cannot pass lenient=True:
    strict first, lenient on refusal, and the refusal comes back."""
    from dexllm._open import open_strict_then_lenient

    dk, refusal = open_strict_then_lenient(value_swapped)
    assert OOO in refusal and CLS in dk.list_classes()
    dk, refusal = open_strict_then_lenient(str(FIXTURE))
    assert refusal == ""


def test_the_mcp_answer_carries_a_session_note(value_swapped):
    mcp_server = pytest.importorskip("dexllm.mcp_server")
    r = mcp_server.dispatch_tool("dexllm_verify_report", {"apk_path": value_swapped})
    assert "lenient=True" in r["session_note"] and OOO in r["session_note"]
    assert r["dexes"][0]["art_deviations"]
    r = mcp_server.dispatch_tool("dexllm_verify_report", {"apk_path": str(FIXTURE)})
    assert "session_note" not in r


def test_a_file_neither_mode_loads_raises_the_strict_error(tmp_path):
    from dexllm._open import open_strict_then_lenient

    p = tmp_path / "ident.dex"
    p.write_bytes(
        open(_craft(tmp_path, "i", _swap(_index_of(I1A), _index_of(I1B))), "rb").read()
    )
    with pytest.raises(RuntimeError, match=OOO):
        open_strict_then_lenient(str(p))


def _role_indices(b):
    def tbl(at):
        return struct.unpack_from("<II", b, at)

    tn, to = tbl(0x40)
    pn, po = tbl(0x48)
    fn, fo = tbl(0x50)
    mn, mo = tbl(0x58)
    return {
        "type": {struct.unpack_from("<I", b, to + 4 * i)[0] for i in range(tn)},
        "shorty": {struct.unpack_from("<I", b, po + 12 * i)[0] for i in range(pn)},
        "field_name": {
            struct.unpack_from("<I", b, fo + 8 * i + 4)[0] for i in range(fn)
        },
        "method_name": {
            struct.unpack_from("<I", b, mo + 8 * i + 4)[0] for i in range(mn)
        },
    }


# One identifier per ROLE, each used in THAT role only, moved into a value
# slot where it lands out of order among the identifiers. A role missing from
# the verifier's identifier set would let exactly that craft through.
_ROLE_MOVES = {
    "type": (b"LLiteralEscapes;", b"\x0c"),
    "shorty": (b"L", b"a\tb"),
    "field_name": (b"APOS", b"a\x7fb"),
    "method_name": (b"all", b"\xc0\x80"),
}


@pytest.mark.parametrize("role", sorted(_ROLE_MOVES))
def test_an_identifier_of_every_role_moved_out_of_order_is_rejected(role, tmp_path):
    ident, value = _ROLE_MOVES[role]
    b = FIXTURE.read_bytes()
    roles = _role_indices(b)
    i, v = _index_of(ident), _index_of(value)
    # premises: `ident` is used in this role and no other, `value` in none
    assert [r for r, ids in roles.items() if i in ids] == [role]
    assert not any(v in ids for ids in roles.values())
    p = _craft(tmp_path, f"move_{role}", _swap(i, v))
    [row] = dexllm.verify(p, lenient=True)
    assert (row["valid"], row["reason"]) == (False, OOO), row


def test_the_http_upload_falls_back_to_lenient_and_says_so(value_swapped):
    """`/upload` takes bytes from a client who cannot ask for leniency: a dex
    the strict verifier refuses still opens, and the response says how."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    c = TestClient(server.app)
    sids = []
    try:
        data = pathlib.Path(value_swapped).read_bytes()
        r = c.post("/upload", files={"apk": ("swap", data, "application/dex")})
        assert r.status_code == 200, r.text
        body = r.json()
        sids.append(body["session_id"])
        assert body["opened"] == "lenient" and OOO in body["strict_refusal"], body
        r = c.post(
            "/upload",
            files={"apk": ("clean", FIXTURE.read_bytes(), "application/dex")},
        )
        body = r.json()
        sids.append(body["session_id"])
        assert (body["opened"], body["strict_refusal"]) == ("strict", ""), body
    finally:
        for sid in sids:
            c.delete(f"/session/{sid}")


def _zip_with(tmp_path, first_dex_path):
    """An APK-shaped zip: `classes.dex` = the given dex, `classes2.dex` = the
    committed multidex fixture's own first dex (verifies on its own)."""
    import zipfile

    src = pathlib.Path(__file__).resolve().parent / "data" / "multidex.apk"
    with zipfile.ZipFile(src) as z:
        good = z.read("classes.dex")
    out = tmp_path / "app.apk"
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("classes.dex", pathlib.Path(first_dex_path).read_bytes())
        z.writestr("classes2.dex", good)
    return str(out)


def test_a_rejected_main_dex_beside_a_good_sibling_is_not_silently_dropped(
    value_swapped, tmp_path
):
    """The realistic shape: the app's classes.dex carries the string swap and
    a classes2.dex does not. A strict load does not RAISE here -- the sibling
    loads (dexllm#25) -- so a fallback keyed on an exception dropped the main
    dex with no note at all (review finding). Retry on a rejected row too."""
    from dexllm._open import open_strict_then_lenient

    apk = _zip_with(tmp_path, value_swapped)
    strict = dexllm.DexKit(apk)
    assert strict.dex_count() == 1 and CLS not in strict.list_classes()  # premise
    dk, refusal = open_strict_then_lenient(apk)
    assert dk.dex_count() == 2 and CLS in dk.list_classes()
    assert "classes.dex" in refusal and OOO in refusal, refusal


def _dup(i, j):
    def edit(b, get, put):
        put(j, get(i))  # index j names index i's bytes: two equal contents

    return edit


@pytest.mark.parametrize(
    "src,dst",
    [(I1A, I1B), (b"Ljava/lang/Object;", b"Ljava/lang/String;")],
    ids=["field_name", "type_descriptor"],
)
def test_two_identifiers_with_equal_content_are_rejected(src, dst, tmp_path):
    """I1 is STRICT increase: equal identifier contents would merge two fields
    (`APOS` twice) or two types (every String field read as Object) in the
    content-keyed readers. A `> 0` comparison passed every other case here."""
    p = _craft(tmp_path, "dup_ident", _dup(_index_of(src), _index_of(dst)))
    [row] = dexllm.verify(p, lenient=True)
    assert (row["valid"], row["reason"]) == (False, OOO), row


def test_a_stale_mcp_note_does_not_survive_a_clean_reopen(value_swapped, tmp_path):
    """The note belongs to the session, not the path: a path re-opened cleanly
    after its leniently-opened session was evicted must not keep the note."""
    mcp_server = pytest.importorskip("dexllm.mcp_server")
    p = tmp_path / "x.dex"
    p.write_bytes(pathlib.Path(value_swapped).read_bytes())
    r = mcp_server.dispatch_tool("dexllm_verify_report", {"apk_path": str(p)})
    assert "session_note" in r
    mcp_server._dk_cache.clear()
    p.write_bytes(FIXTURE.read_bytes())
    r = mcp_server.dispatch_tool("dexllm_verify_report", {"apk_path": str(p)})
    assert "session_note" not in r, r
