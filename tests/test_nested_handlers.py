"""A catch handler covered by its own try is rendered when it is nested (dexllm#137).

DAD's ``catch_struct`` skips every handler block that has catch edges of its
own (``if catch_block in graph.catch_edges: continue``). That is right for the
``$SwitchMap`` ``<clinit>`` d8 emits, where a try's handler IS the next try's
first block, and for a ``synchronized`` block's catch-all, which covers its own
``monitor-exit`` + rethrow. It is wrong for a handler that sits inside an
enclosing try: a ``synchronized`` body's inner catch, a try-with-resources
close. There the handler's code -- calls included -- was dropped from the Java
text with no marker. Such a handler is rendered now.

Coupled: a catch clause with no catch variable named the type DAD's
``add_catch_edge`` had copied onto the block from the other end of a catch
edge -- and again when SplitIfNodes splits a handler that opens with an
``if`` -- so such a clause could name another handler's type. The clause now names the try table's
own type for that handler block.

The fixture is authored smali (``tests/data/nested-handlers.smali``). The
pinned clauses are the try table's TYPES, not a claim that the try SCOPING is
right: ``innerCatch`` renders the inner and outer catch as siblings, and
``partlyNested`` hangs the catch-all on a try it does not cover. Both are the
pre-existing try-follow scoping, the same on the pre-fix build; what this
change adds is that the handler code is there at all.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from test_multi_catch import _ast_catch_decls, _ast_types, _desc, _handlers, _java

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "nested-handlers.dex"
CORPUS = pathlib.Path(__file__).parent.parent / "test_apk" / "APK"

CLAUSES = {
    # the inner catch of a synchronized body: covered by the monitor's catch-all
    "syncInner(Ljava/lang/Object;)V": ["catch (java.io.IOException v0)"],
    # an inner try/catch inside an outer try
    "innerCatch()V": [
        "catch (java.io.IOException v0)",
        "catch (IllegalStateException v1)",
    ],
    # a nested handler with no move-exception names its own type, not the
    # Throwable of the catch-all covering it
    "unboundNested()V": [
        "catch (java.io.IOException _)",
        "catch (Throwable v1)",
    ],
    # two variable-less handlers of one try, the first opening with an `if`:
    # on the pre-fix build both clauses named IllegalStateException
    "twoUnbound()V": [
        "catch (java.io.IOException _)",
        "catch (IllegalStateException _)",
    ],
    # two tries share a handler and only one is inside an enclosing try: one
    # covered thrower is enough to keep the handler
    "partlyNested()V": [
        "catch (java.io.IOException v0)",
        "catch (Throwable v1)",
    ],
    # CONTROLS: the $SwitchMap chain and a self-covering catch-all stay skipped
    "switchMap()V": ["catch (NoSuchFieldError _)"],
    "selfCatchAll(Ljava/lang/Object;)V": [],
}

# each nested handler's own statement, which the pre-fix build dropped
BODIES = {
    "syncInner(Ljava/lang/Object;)V": ["C.log(v0);"],
    "innerCatch()V": ["C.log(v0);", "C.log(v1);"],
    "unboundNested()V": ['C.str("io");', "C.log(v1);"],
    "twoUnbound()V": ["C.b();", 'C.str("io");', 'C.str("ise");'],
    "partlyNested()V": ["C.log(v0);", "C.log(v1);"],
}

_CLAUSE = re.compile(r"catch \([^)]*\)")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_clauses_are_the_handlers_the_try_table_names(dk, method):
    text = dk.decompile_method("LC;->" + method)
    assert _CLAUSE.findall(text) == CLAUSES[method], text


@pytest.mark.parametrize("method", sorted(BODIES))
def test_a_nested_handler_keeps_its_code(dk, method):
    lines = [ln.strip() for ln in dk.decompile_method("LC;->" + method).split("\n")]
    for stmt in BODIES[method]:
        assert stmt in lines, (method, stmt)


def test_the_switchmap_chain_is_not_restructured(dk):
    """The control the narrowing exists for: removing DAD's skip outright
    nests each of these tries inside the previous one's catch."""
    text = dk.decompile_method("LC;->switchMap()V")
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    assert lines[lines.index("{") + 1 :] == [
        "C.a();",
        "try {",
        "C.b();",
        "} catch (NoSuchFieldError _) {",
        "}",
        "return;",
        "}",
    ], text


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_ast_carries_the_same_types(dk, method):
    """Each emitter spells a variable-less clause by itself."""
    ast = dk.decompile_method_ast("LC;->" + method)["ast"]
    got = [_ast_types(d[0]) for d in _ast_catch_decls(ast, [])]
    want = [
        [_desc(re.match(r"catch \((.*) \S+\)$", c).group(1))] for c in CLAUSES[method]
    ]
    assert got == want


def test_every_clause_names_a_type_its_handler_catches(dk):
    """Raw try-table oracle: a clause's type is one the try table gives the
    handler block it renders, never another handler's."""
    per_method = _handlers(dk.extract_dex(0)["bytes"])
    methods = dk.list_methods_in_dex(0)
    checked = 0
    for (cls, idx), per in per_method.items():
        text = dk.decompile_method(methods[idx])
        names = [
            re.match(r"catch \((.*) \S+\)", c).group(1) for c in _CLAUSE.findall(text)
        ]
        allowed = {
            _java(t) if t != "*" else "Throwable" for ts in per.values() for t in ts
        }
        for n in names:
            assert n in allowed, (methods[idx], n, allowed)
            checked += 1
    assert checked >= 8


def _corpus(name):
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not in the corpus")
    return dexllm.DexKit(str(p))


def test_the_issue_repro_keeps_its_log_calls():
    kit = _corpus("com.example.android.wearable.wear.weardrawers.apk")
    text = kit.decompile_method(
        "Lcom/google/android/gms/common/internal/zzbf;->zzcr(Landroid/content/Context;)V"
    )
    assert (
        "catch (android.content.pm.PackageManager.NameNotFoundException v0_4)" in text
    ), text
    assert (
        'android.util.Log.wtf("MetadataValueReader", "This should never happen.", v0_4);'
        in text
    )


def test_a_synchronized_inner_catch_is_rendered():
    kit = _corpus("a2dp.Vol_137.apk")
    text = kit.decompile_method(
        "Landroid/support/v4/app/NotificationCompatJellybean;->getAction("
        "Landroid/app/Notification;I"
        "Landroid/support/v4/app/NotificationCompatBase$Action$Factory;"
        "Landroid/support/v4/app/RemoteInputCompatBase$RemoteInput$Factory;)"
        "Landroid/support/v4/app/NotificationCompatBase$Action;"
    )
    assert "catch (IllegalAccessException v8)" in text, text
    assert "Unable to access notification actions" in text, text


def test_two_variable_less_handlers_keep_their_own_types():
    """SuggestionsAdapter: the pre-fix build swapped the two clause types."""
    kit = _corpus("com.test.intent_filter.apk")
    text = kit.decompile_method(
        "Landroid/support/v7/widget/SuggestionsAdapter;->getDrawableFromResourceValue"
        "(Ljava/lang/String;)Landroid/graphics/drawable/Drawable;"
    )
    nfe = text.index("catch (NumberFormatException _)")
    nf = text.index("catch (android.content.res.Resources.NotFoundException _)")
    assert "this.checkIconCache(p5)" in text[nfe:nf], text
    assert "Icon resource not found: " in text[nf:], text
