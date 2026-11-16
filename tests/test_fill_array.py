"""A fill-array-data payload is spelled by its array's element type (dexllm#93).

A `fill-array-data` payload is untyped bytes: a `float[]` and an `int[]` both
carry 4-byte elements. DAD writes each element as the integer the payload
holds, so `float[] v = {0f, 1f}` rendered `{0, 1065353216}` and a `long` too
wide for an `int` did not lex. The element type now comes from the array's
type (falling back to the payload width), and both emitters spell each
element by it. A parameter's type is its DECLARED one (a later write to the
register corrupts the shared parameter's type), a `char` element is unsigned,
and a `boolean` element is `true` / `false`.

The fixture is authored smali (`tests/data/fill-array.smali`).
"""

from __future__ import annotations

import json
import pathlib

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "fill-array.dex"

EXPECTED = {
    "floats()[F": "v0_1 = {0f, 1f, 0.5f, Float.NaN};",
    # whole-number doubles print as integers, as the scalar path does (#118)
    "doubles()[D": "v0_1 = {0, 1, -1.5};",
    "longs()[J": "v0_1 = {9223372036854775807L, 5L};",
    # controls: int[] and char[] payloads stay integers
    "ints()[I": "v0_1 = {1065353216, -1, 7};",
    "chars()[C": "v0_1 = {65, 66};",
    # a reused parameter register: the DECLARED int[] decides, not the float[]
    "intParamThenFloat([I)[F": "p1 = {7, 1065353216};",
    # a char is unsigned
    "highChar()[C": "v0_1 = {65535, 65};",
    "bools()[Z": "v0_1 = {true, false};",
    # an array of unknown type: the payload width decides (8 bytes = long)
    "untypedTarget(Ljava/lang/Object;)V": "p0 = {9223372036854775807L};",
    # a type that disagrees with the width (crafted): the width decides
    "mismatchedWidth()[I": "v0_1 = {9223372036854775807L};",
    # two definitions of different types reach the fill: the width decides
    "fillAfterMerge(Z)Ljava/lang/Object;": "v0 = {1065353216, 7};",
    "fillAfterMergeSwapped(Z)Ljava/lang/Object;": "v0 = {1065353216, 7};",
}

AST_KIND = {
    "floats()[F": ".float",
    "doubles()[D": ".double",
    "longs()[J": ".long",
    "ints()[I": ".int",
    "chars()[C": ".int",
    "highChar()[C": ".int",
    "bools()[Z": ".boolean",
}


@pytest.fixture(scope="module")
def dk():
    return dexllm.DexKit(str(FIXTURE))


def test_the_fixture_verifies():
    [row] = dexllm.verify(str(FIXTURE))
    assert row["valid"] and row["art_open"], row


@pytest.mark.parametrize("member", sorted(EXPECTED))
def test_each_element_is_spelled_by_the_array_type(dk, member):
    lines = [x.strip() for x in dk.decompile_method(f"LF;->{member}").split("\n")]
    assert EXPECTED[member] in lines, lines


def _initializer_kinds(node):
    """The literal kinds inside every ArrayInitializer of an AST."""
    out = []
    if isinstance(node, list):
        if node and node[0] == "ArrayInitializer":
            out += [json.dumps(e) for e in node[1]]
        for x in node:
            out += _initializer_kinds(x)
    elif isinstance(node, dict):
        for x in node.values():
            out += _initializer_kinds(x)
    return out


@pytest.mark.parametrize("member", sorted(AST_KIND))
def test_the_ast_types_the_elements_the_same_way(dk, member):
    elems = _initializer_kinds(dk.decompile_method_ast(f"LF;->{member}")["ast"])
    assert elems, "no ArrayInitializer in the AST"
    assert all(f'"{AST_KIND[member]}"' in e for e in elems), elems


def test_the_ast_spells_a_char_unsigned(dk):
    elems = _initializer_kinds(dk.decompile_method_ast("LF;->highChar()[C")["ast"])
    assert any('"65535"' in e for e in elems), elems


def test_each_branch_of_a_merge_is_spelled_by_its_own_array(dk):
    """A register filled as an int[] on one branch and a float[] on the
    other: the merged version has no single type, so each fill is typed by the
    definition that reaches it."""
    lines = [
        x.strip()
        for x in dk.decompile_method("LF;->branchMerge(Z)Ljava/lang/Object;").split(
            "\n"
        )
    ]
    assert "v0 = {1065353216, 7};" in lines, lines
    assert "v0 = {1f, 2f};" in lines, lines
