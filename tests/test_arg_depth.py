"""`resolve_call_args` is bounded to a basic-block window whose radius is `depth`.

The analysis used to simulate the WHOLE method in two linear passes. It now builds
the code item's basic-block CFG and, for each block holding an invoke, resolves the
arguments from that block plus `depth` predecessor levels above it — nothing outside
the window is looked at. `depth` defaults to 2 on every layer.

These guards pin the three things that can silently rot: that `depth` is a real knob
(not an accepted-and-ignored argument), that the default is 2 everywhere, and that the
window's boundary conditions are the sound ones — in particular that the METHOD ENTRY
counts as an edge, which is where the first cut of this change was wrong.
"""

import re

import pytest
from conftest import require_corpus_shape

import dexllm
from dexllm import tools
from dexllm.sdk.adapter import DexKitAdapter
from dexllm.sdk.ports import CrossReferencePort

# `ActivityCompat.setEnterSharedElementCallback` — the dexllm#16 fixture, reused
# because its CFG is exactly the shape `depth` is about: the receiver `v3` is a
# parameter defined in the ENTRY block and the call sits two predecessor levels
# below it, so it resolves at the default and not at depth 1.
_SEC_CLASS = "Landroid/support/v4/app/ActivityCompat;"
_SEC_API = (
    "Landroid/app/Activity;->setEnterSharedElementCallback"
    "(Landroid/app/SharedElementCallback;)V"
)
_SEC_OFFSET = 0x1C


def _sec_site(loadable_apks, depth=None):
    """The pinned site itself, at `depth` (None = the binding's own default)."""
    for apk in loadable_apks:
        try:
            d = dexllm.DexKit(apk)
        except Exception:  # noqa: BLE001 - a corpus entry that will not load
            continue
        sites = (
            d.resolve_call_args(_SEC_API)
            if depth is None
            else d.resolve_call_args(_SEC_API, depth)
        )
        for s in sites:
            if (
                s.caller_descriptor.startswith(_SEC_CLASS)
                and s.bytecode_offset == _SEC_OFFSET
            ):
                return s
    return None


def _origins(loadable_apks, depth):
    """`(kind, crossed_branch)` per argument at `depth`.

    Both halves, deliberately. Comparing `kind` alone cannot see a window that is one
    level too WIDE: an off-by-one in the BFS bound leaves every kind unchanged at
    depth 0 and only flips `crossed_branch` — a mutant that survived the first cut of
    this file with the whole suite green.
    """
    return [(a.kind, a.crossed_branch) for a in _sec_site(loadable_apks, depth).args]


def test_depth_is_a_real_knob_not_an_ignored_argument(loadable_apks):
    """The same site gives THREE distinct answers at depth 0, 1 and 2.

    An argument that is accepted and dropped would give three identical ones, so this
    is what separates "the window is wired" from "the signature grew". Asserting only
    the endpoints is not enough — `depth=1` is the answer an off-by-one bound moves.
    """
    require_corpus_shape(
        _sec_site(loadable_apks) is not None,
        f"{_SEC_CLASS} site at 0x{_SEC_OFFSET:x}",
        "the depth-window fixture is gone — repin it before trusting this file",
    )
    at = {d: _origins(loadable_apks, d) for d in (0, 1, 2)}
    # depth 0 — the call's own block defines neither register, and a single block has
    # no merge in it, so NEITHER argument may carry `crossed_branch`.
    assert at[0] == [("Unknown", False), ("Unknown", False)], at[0]
    # depth 1 — one level up. `v0` is now the merge of the `null` and the
    # `new-instance` paths (tombstoned); `v3`'s definition is still a level away.
    assert at[1] == [("Unknown", False), ("Unknown", True)], at[1]
    # depth 2 — the window reaches the entry block, where the receiver is defined.
    assert at[2] == [("Parameter", False), ("Unknown", True)], at[2]
    assert len({tuple(v) for v in at.values()}) == 3, at


def test_the_two_flavours_of_unknown_say_different_things(loadable_apks):
    """`crossed_branch` distinguishes "discarded at a merge" from "never seen".

    A definition that lies OUTSIDE the window is not tombstoned — no in-window edge
    carries it, so it is simply absent and reports `False`. Tombstoning needs a merge
    in which some OTHER edge does carry a definition. Both flavours are `Unknown` and
    both may resolve at a larger `depth`, so neither is the "raise depth" signal on
    its own — which is exactly why the flag must not be documented as one.
    """
    require_corpus_shape(
        _sec_site(loadable_apks) is not None,
        f"{_SEC_CLASS} site at 0x{_SEC_OFFSET:x}",
        "the depth-window fixture is gone — repin it before trusting this file",
    )
    # v3 at depth 1: a genuine Parameter defined exactly ONE block outside the
    # window. Absent, not tombstoned.
    assert _origins(loadable_apks, 1)[0] == ("Unknown", False)
    # v3 at depth 2: the same register, once the window reaches its definition.
    assert _origins(loadable_apks, 2)[0] == ("Parameter", False)
    # v0 at depth 2: two in-window predecessors carry DIFFERENT values (null vs the
    # new-instance), so the merge tombstones it.
    assert _origins(loadable_apks, 2)[1] == ("Unknown", True)


# `SearchView$AutoCompleteTextViewReflector.<init>()V` in the support library wraps
# each `getDeclaredMethod` in its own try/catch and continues on the next statement,
# so the block holding the SECOND and THIRD `setAccessible` call IS a catch handler
# while the first one's block is not. The premise below is the method's smali TEXT,
# which is independent of the analysis under test; several corpus APKs ship a build
# with different offsets, and those simply do not match.
_REFL_CLASS = "Landroid/support/v7/widget/SearchView$AutoCompleteTextViewReflector;"
_REFL_METHOD = _REFL_CLASS + "-><init>()V"
_REFL_API = "Ljava/lang/reflect/Method;->setAccessible(Z)V"
_REFL_SETACCESSIBLE = "invoke-virtual {v2, v1}, " + _REFL_API
# (offset, is the block a catch handler)
_REFL_SITES = ((0x26, False), (0x48, True))


def _reflector_build(loadable_apks):
    """The APK whose build of that method has the pinned shape, or None."""
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:  # noqa: BLE001
            continue
        if _REFL_METHOD not in dk.list_class_methods(_REFL_CLASS):
            continue
        smali = dk.render_method_smali(_REFL_METHOD)
        want = ["0x8: const/4 v1, #1"] + [
            f"0x{off:x}: {_REFL_SETACCESSIBLE}" for off, _ in _REFL_SITES
        ]
        if all(any(line.strip() == w for line in smali.splitlines()) for w in want):
            return dk
    return None


def test_a_catch_handler_is_entered_with_an_empty_state(loadable_apks):
    """No definition from outside a catch handler's own block may reach an invoke
    inside it — and what is missing reports `crossed_branch=False`, not True.

    A handler is reachable from any instruction of its try region, so its incoming
    register file is unknown; and because nothing is carried IN, there is nothing to
    tombstone either. The whole-method analysis this replaced tombstoned instead (it
    had a live register file to tombstone), so the flag genuinely reports something
    different here and the docs say `False`.

    `v1` is `const/4 v1, #1` in the entry block and never written again, so the two
    sites differ only in whether the walk can reach that block: the non-handler site
    resolves it, the handler site cannot — at ANY depth, since a handler is a hard
    stop rather than a radius. Asserting BOTH is what keeps this from degenerating
    into "everything is Unknown".

    Two guards in `AnalyzeInvokes` produce this, and each MASKS the other: the
    BFS stops at a handler, and a handler's IN is forced empty. Removing either alone
    is unobservable (verified over the whole corpus); removing BOTH lets a value leak
    in, and this is the test that catches it.
    """
    dk = _reflector_build(loadable_apks)
    require_corpus_shape(
        dk is not None,
        "the pinned SearchView$AutoCompleteTextViewReflector build",
        "the catch-handler fixture is gone — repin it before trusting this file",
    )
    for depth in (0, 2, 40):
        seen = {
            s.bytecode_offset: s.args
            for s in dk.resolve_call_args(_REFL_API, depth)
            if s.caller_descriptor == _REFL_METHOD
        }
        for off, is_handler in _REFL_SITES:
            args = seen[off]
            assert args[1].reg_num == 1, (off, args[1].reg_num)
            if is_handler:
                assert (args[1].kind, args[1].crossed_branch) == ("Unknown", False), (
                    f"0x{off:x} at depth {depth}: {args[1].kind}/"
                    f"{args[1].crossed_branch} — a handler carries nothing IN, so "
                    "neither a value may leak in nor a tombstone appear"
                )
            else:
                assert args[1].kind == "ConstInt" and args[1].int_value == 1, (
                    f"0x{off:x} at depth {depth}: {args[1].kind} — this block is NOT "
                    "a handler, so the guard must not cut its walk either"
                )


def test_the_default_depth_is_two_on_every_layer():
    """The raw binding, the port, the adapter and the MCP schema agree on 2.

    A Protocol carries no runtime conformance for default VALUES and mypy does not
    check them either, so a port declaring a different default type-checks clean; the
    schema default is separately what an LLM reads to decide whether to pass the
    argument at all. dexllm#49 established this axis.
    """
    # pybind renders the annotation itself (`typing.SupportsInt | ...`), so only the
    # name and the default are pinned here — the type is the stub's business.
    doc = (dexllm.DexKit.resolve_call_args.__doc__ or "").splitlines()[0]
    assert re.search(r"\bdepth\b[^,)]*=\s*2\b", doc), doc

    assert CrossReferencePort.resolve_call_args.__defaults__ == (2,)
    assert DexKitAdapter.resolve_call_args.__defaults__ == (2,)
    assert tools.TOOL_IMPLS["resolve_call_args"].__defaults__[0] == 2

    schema = next(
        t for t in tools.TOOL_DEFINITIONS if t["name"] == "resolve_call_args"
    )["input_schema"]
    assert schema["properties"]["depth"] == {"type": "integer", "default": 2}
    assert "depth" not in schema["required"]


def test_depth_reaches_the_binding_through_the_adapter_and_the_tool(loadable_apks):
    """The port default is not enough: the adapter must FORWARD the argument.

    An adapter that accepts `depth` and calls the binding without it type-checks,
    satisfies the Protocol and passes every naming audit, while returning the wrong
    answer.
    """
    require_corpus_shape(
        _sec_site(loadable_apks) is not None,
        f"{_SEC_CLASS} site at 0x{_SEC_OFFSET:x}",
        "the depth-window fixture is gone — repin it",
    )
    apk = next(
        a
        for a in loadable_apks
        if any(
            s.bytecode_offset == _SEC_OFFSET
            and s.caller_descriptor.startswith(_SEC_CLASS)
            for s in _sites_or_empty(a)
        )
    )
    session = dexllm.sdk.open_apk(apk)
    for depth, expected in ((0, "Unknown"), (2, "Parameter")):
        hit = next(
            s
            for s in session.resolve_call_args(_SEC_API, depth)
            if s.bytecode_offset == _SEC_OFFSET
            and s.caller_descriptor.startswith(_SEC_CLASS)
        )
        assert hit.args[0].kind == expected, (depth, hit.args[0].kind)

    dk = dexllm.DexKit(apk)
    seen = {}
    for depth in (0, 2):
        out = tools.execute(
            "resolve_call_args",
            {"method_descriptor": _SEC_API, "depth": depth, "limit": 500},
            dk,
        )
        seen[depth] = [
            i["args"][0]["kind"]
            for i in out["items"]
            if i["caller"].startswith(_SEC_CLASS)
            and i["bytecode_offset"] == _SEC_OFFSET
        ]
    assert seen[0] == ["Unknown"] and seen[2] == ["Parameter"], seen


def _sites_or_empty(apk):
    try:
        return dexllm.DexKit(apk).resolve_call_args(_SEC_API)
    except Exception:  # noqa: BLE001
        return []


def test_the_site_set_does_not_depend_on_depth(dk, apk_path):
    """`depth` changes the ARGUMENTS, never which call sites exist.

    The sites are emitted while walking a block's instructions and the window only
    supplies the incoming register state, so an implementation that skipped blocks it
    could not resolve would silently drop rows. This is also what lets
    `find_call_sites_from` ask for depth 0 without changing its own output.
    """
    apis = sorted({r.signature for r in dk.list_external_method_refs()})[:120]
    checked = 0
    for api in apis:
        sets = {}
        for depth in (0, 1, 3):
            sets[depth] = [
                (s.caller_descriptor, s.caller_dex_id, s.bytecode_offset, len(s.args))
                for s in dk.resolve_call_args(api, depth)
            ]
        assert sets[0] == sets[1] == sets[3], api
        checked += len(sets[0])
    require_corpus_shape(
        checked > 0,
        "resolved call sites for any external API",
        "resolve_call_args stopped returning rows",
    )


def test_a_negative_depth_is_the_block_only_window(loadable_apks):
    """A negative `depth` must not wrap into an enormous unsigned window.

    The C++ side takes an unsigned depth, so an unchecked conversion would turn -1
    into 4294967295 — an argument that silently means its own opposite.
    """
    require_corpus_shape(
        _sec_site(loadable_apks) is not None,
        f"{_SEC_CLASS} site at 0x{_SEC_OFFSET:x}",
        "the depth-window fixture is gone — repin it",
    )
    at_neg = _origins(loadable_apks, -1)
    at_zero = _origins(loadable_apks, 0)
    # Tuples, not kinds: a window one level too wide leaves the kinds alone here and
    # only flips `crossed_branch`.
    assert at_neg == at_zero == [("Unknown", False), ("Unknown", False)], (
        at_neg,
        at_zero,
    )


def test_raising_depth_only_adds_information(dk):
    """Corpus property: going deeper may resolve an Unknown, and may tombstone a
    value whose merge partner only becomes visible at the larger radius — but it must
    never swap one concrete origin for a DIFFERENT concrete origin.

    A concrete→concrete flip is the one shape that means an answer was wrong at one of
    the two depths, so it is the property worth asserting corpus-wide.
    """
    apis = sorted({r.signature for r in dk.list_external_method_refs()})[:200]
    compared = 0
    for api in apis:
        shallow = dk.resolve_call_args(api, 1)
        deep = dk.resolve_call_args(api, 3)
        assert len(shallow) == len(deep)
        for a, b in zip(shallow, deep):
            for x, y in zip(a.args, b.args):
                compared += 1
                if x.kind != "Unknown" and y.kind != "Unknown":
                    assert x.kind == y.kind, (
                        f"{api} @0x{a.bytecode_offset:x} v{x.reg_num}: "
                        f"{x.kind} at depth 1 but {y.kind} at depth 3"
                    )
    require_corpus_shape(
        compared > 0,
        "resolved arguments for any external API",
        "resolve_call_args stopped returning arguments",
    )


@pytest.mark.parametrize("depth", [0, 1, 2, 5, 40])
def test_every_depth_is_answerable_without_crashing(dk, sample_method, depth):
    """Including a depth far past any real CFG radius, where the window degenerates
    to the whole reachable-backwards graph."""
    callees = {s.callee_descriptor for s in dk.find_call_sites_from(sample_method)}
    require_corpus_shape(
        bool(callees),
        "a sample method that calls something",
        "the sample-method fixture stopped selecting a method with a code item",
    )
    for callee in sorted(callees)[:5]:
        dk.resolve_call_args(callee, depth)
