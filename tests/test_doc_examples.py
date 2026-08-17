"""Execute the documented python examples, so prose cannot drift from the API.

``tests/test_stubs.py`` makes the ``.pyi`` bidirectionally runtime-checked, so the
stubs cannot advertise a name the runtime lacks. Nothing did the equivalent for
PROSE, and it showed (issue #34): four copy-paste-first fences — the first code a
reader of that section runs — used names or signatures that do not exist. Three of
them are corrected alongside this file; the fourth (``crypto.hits``) had already
been fixed in 7747246. The headline case is ``ref.java_class``, which the stubs had
deliberately avoided because introspecting the live module showed the real
attribute is ``java_name``: the stubs dodged the mistake, the docs kept it, and a
FIFTH instance of the same one survived in an ``api.md`` prose table that no fence
runner can ever see.

The earlier argument-name audit (feaf60c) compared documented CALL SIGNATURES to
the runtime and fixed ten wrong parameter names, but it only checked
declaration-shaped signatures — so attribute access on a RETURNED object, where
three of the four lived, was a blind spot by construction, and so is a call written
inside a fence (``method_ref_java`` was passed one argument where the runtime takes
three). Executing the fence closes both, because it checks the whole example rather
than one syntactic slice of it.

Three things make the runner check more than a naive one would, each of which was
a measured hole in its first cut:

* **Placeholders are SUBSTITUTED, not skipped.** ``"app.apk"``, ``/path/to/…``,
  ``/tmp/dump.dex`` and ``/etc/dexllm`` are bound to a real corpus APK and to the
  bundled data directory. Skipping them instead left README at ZERO executed
  fences and the whole ``dexllm.sdk`` surface unchecked — the front door and the
  documented embedding layer.
* **A fence runs its longest self-contained LEADING RUN of statements**, not
  all-or-nothing. Doc fences end with a narrative line (``format_class_summary(s)``
  where ``s`` came from an earlier fence, ``batch_find_classes_using_strings({...})``
  as a shape), and discarding the whole fence for it cost real coverage of calls
  whose argument names had just been renamed.
* **A loop whose body never executes is not coverage.** A fence is retried across
  the corpus until every loop body actually runs; if no source covers it, the test
  SKIPS. Without this, 5 of 44 fences asserted nothing at all — injected
  ``hit.totally_bogus_attribute`` defects passed — and how many was a function of
  which APK the shared fixture happened to pick.

Known limit, by construction: a defect that manifests as an undefined BARE NAME
(``summarise(dk)`` where no such function exists) is skipped, not failed, because
that is indistinguishable from the narrative shorthand above. This runner catches
attribute, argument and signature defects — which is what all four of #34's were.

Corpus-dependent, so it SKIPS without one — an environment fact must never fail
the suite.
"""

import ast
import builtins
import json
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ("README.md", "docs/api.md", "docs/usage.md", "docs/sdk.md")

# A placeholder FILE argument is bound to a real corpus source rather than skipped.
# Matched by SHAPE, not by an exact list: the first cut listed literals and missed
# `suspicious.apk`, `dumped_real.dex` and `classes2.dex`, which is the failure mode
# an exact list always has.
_PLACEHOLDER_FILE = re.compile(
    r"""(['"])((?:/path/to/|/tmp/)[^'"]*|[\w.-]+\.(?:apk|dex|png))\1"""
)
# The data-directory placeholder is bound to the bundled `dexllm/data/`, which is a
# real directory holding both overridable files.
_PLACEHOLDER_DATA_DIR = "/etc/dexllm"

# What cannot be bound to anything real. A statement containing one of these is
# dropped from the run, with everything after it.
#
#   "..."                  a literal shown for its SHAPE — an elided descriptor
#                          (`'...->getInstance(...)'`) or an argument as `{...}`.
#   "Lcom/example/Utils;"  a stand-in class no corpus source declares, in a fence
#                          that then INDEXES the result (`ast["ast"]["body"]`).
#
# The second is stated rather than left to chance: the other stand-ins in these
# docs (`Lcom/x/Y;`, `Lcom/evil/RealC2;`, …) run fine, because a missing class
# yields `''` / `[]` / `found=False` rather than raising — they are excluded only
# where the fence goes on to subscript that result. A DIFFERENT stand-in in a
# subscripting fence would need adding here, which is the trade for not
# blanket-excluding every `Lcom/`-prefixed descriptor (`Lcom/foo/Bar;` is passed to
# the pure string helper `method_ref_java`, which must keep running — it is one of
# the three defects this file was written to catch).
UNRUNNABLE = ("...", "Lcom/example/Utils;")

_FENCE = re.compile(r"```python\n(.*?)```", re.S)

# Names the prelude provides; everything else must be bound by the fence itself.
_PROVIDED = {"dexllm", "dk"} | set(dir(builtins))

_MARKER = "__DOC_FENCE_LINES__"


def _free_names(tree):
    """Names read without being bound — the fence's unmet dependencies.

    Deliberately coarse: a binding anywhere counts as satisfying a read, because
    the question is "can this run on its own", not "is it in scope at that point".
    The non-``ast.Name`` binders each caused a real over-exclusion: an
    ``except ... as e`` handler, a star-import, and a ``match`` capture all store
    their name as a plain ``str`` on the node, so without these branches a
    perfectly self-contained error-handling example would be dropped forever.
    """
    bound, read = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            (bound if isinstance(node.ctx, (ast.Store, ast.Del)) else read).add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    return read - bound - _PROVIDED


def _runnable_prefix(code):
    """The longest leading run of top-level statements that can run on its own."""
    try:
        tree = ast.parse(code)
    except SyntaxError:  # a fragment shown for shape, not for running
        return ""
    kept = []
    for stmt in tree.body:
        segment = ast.get_source_segment(code, stmt, padded=True)
        if segment is None or any(u in segment for u in UNRUNNABLE):
            break
        candidate = kept + [segment]
        if _free_names(ast.parse("\n".join(candidate))):
            break
        kept = candidate
    return "\n".join(kept)


def _loop_body_lines(code):
    """First line of each loop body — what must execute for the fence to assert."""
    tree = ast.parse(code)
    return {
        node.body[0].lineno
        for node in ast.walk(tree)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and node.body
    }


def _strip_comments(code):
    """Code with `#` comments removed, so a pin cannot be satisfied by a mention."""
    import io
    import tokenize

    try:
        toks = [
            t
            for t in tokenize.generate_tokens(io.StringIO(code).readline)
            if t.type != tokenize.COMMENT
        ]
    except (tokenize.TokenError, IndentationError):
        return code
    return tokenize.untokenize(toks)


def _fences(path):
    """Yield (line, code) for every python fence in a doc."""
    md = (REPO_ROOT / path).read_text()
    for m in _FENCE.finditer(md):
        yield md[: m.start()].count("\n") + 2, m.group(1)


def _cases():
    """Every fence with a non-empty runnable prefix."""
    out = []
    for path in DOCS:
        for line, code in _fences(path):
            runnable = _runnable_prefix(code)
            if runnable.strip():
                out.append(pytest.param(path, line, runnable, id=f"{path}:{line}"))
    return out


_CHILD = f"""
import json, sys
import dexllm
src = json.loads(sys.argv[1])
apk = sys.argv[2]
code = compile(src, "<fence>", "exec")
seen = set()

def tracer(frame, event, arg):
    if frame.f_code.co_filename == "<fence>":
        if event == "line":
            seen.add(frame.f_lineno)
        return tracer
    return None

env = {{"dexllm": dexllm, "dk": dexllm.DexKit(apk)}}
sys.settrace(tracer)
try:
    exec(code, env)
finally:
    sys.settrace(None)
sys.stderr.write("{_MARKER}" + json.dumps(sorted(seen)) + "\\n")
"""


def _run(code, apk):
    """Execute a fence against one APK -> (CompletedProcess, executed line set).

    A hang is turned into a normal failure result rather than letting
    ``TimeoutExpired`` propagate, so it reports through the caller's formatted
    message ("<doc>:<line> raises: …") instead of as a bare test ERROR.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", _CHILD, json.dumps(code), str(apk)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess([], 1, "", "timed out after 180s"), set()
    executed = set()
    for out_line in result.stderr.splitlines():
        if out_line.startswith(_MARKER):
            executed = set(json.loads(out_line[len(_MARKER) :]))
    return result, executed


@pytest.mark.parametrize("path,line,code", _cases())
def test_documented_example_runs(path, line, code, apk_path, loadable_apks):
    """A documented example must execute against a real APK — loop bodies included.

    Each fence runs in its own interpreter so that one calling a cache-control or
    process-wide API (``set_decompiler_cache_capacity``, ``clear_data_caches``)
    cannot leak into the rest of the suite.

    Only that it RUNS is asserted, not what it prints: the corpus APK varies, so a
    fence's commented-out sample output is about a different APK and is not a
    promise about this one. What IS asserted beyond "no exception" is REACHABILITY
    — a fence whose `for` body never runs would let `hit.no_such_attribute` pass,
    which is the exact defect class this file exists to catch.
    """
    import dexllm

    data_dir = pathlib.Path(dexllm.__file__).parent / "data"
    required = _loop_body_lines(code)

    # try the shared APK first, then the rest — a fence's loop may only have a body
    # to run on a source that happens to contain the thing it iterates
    ordered = [apk_path] + [a for a in loadable_apks if a != apk_path]
    last = None
    for apk in ordered:
        program = code.replace(_PLACEHOLDER_DATA_DIR, str(data_dir))
        program = _PLACEHOLDER_FILE.sub(lambda _m: repr(str(apk)), program)
        result, executed = _run(program, apk)
        assert result.returncode == 0, (
            f"{path}:{line} raises:\n{result.stderr.strip()}\n" f"--- fence ---\n{code}"
        )
        last = apk
        if required <= executed:
            return

    pytest.skip(
        f"{path}:{line} runs but no corpus source exercises its loop body "
        f"(needs lines {sorted(required - executed)}; {len(ordered)} tried, last {last})"
    )


def test_the_runner_is_not_vacuous():
    """Guard the guard: the selection must still collect a real population.

    Every failure mode of this runner is silent — a fence syntax change, a
    substitution that stops matching, a free-name rule that over-excludes — and
    each turns the suite green while checking nothing.

    The floor is a RATCHET at the current value, not a loose bound: a floor well
    below reality lets half the coverage disappear unnoticed (a plausible new
    placeholder entry was measured killing 4 fences while a `>= 20` floor stayed
    satisfied). Raise it deliberately when fences are added; lowering it is a
    decision, not an accident. Same convention as `jadx_parity_baseline.json`.

    The pins search COMMENT-STRIPPED code and name the load-bearing expression, not
    the API. Pinning `"method_ref_java"` as a bare substring was demonstrably
    vacuous — replacing the call with `# dexllm.method_ref_java(...) removed` keeps
    the needle, keeps the fence collected, and stops exercising anything; and
    `print(ref)` instead of `print(ref.java_name)` defeats it without even a
    comment. What broke in #34 was an ATTRIBUTE and an ARITY, so those are what is
    pinned.
    """
    cases = _cases()
    assert len(cases) >= 77, f"only {len(cases)} runnable fences collected"

    per_doc = {}
    for case in cases:
        per_doc.setdefault(case.values[0], 0)
        per_doc[case.values[0]] += 1
    assert set(per_doc) == set(DOCS), f"a doc contributes no runnable fence: {per_doc}"

    bodies = [_strip_comments(c.values[2]) for c in cases]
    for needle in (
        "ref.java_name",  # the attribute, not just the call that returns it
        "method_ref_java('Lcom/foo/Bar;', 'baz', '(I)V')",  # the arity
        "summary.is_internal",
        "open_apk",  # the SDK surface, otherwise wholly unexercised
        # The depth argument: a fence that merely MENTIONS it in a comment would
        # keep the needle while exercising nothing, so the keyword call is pinned.
        "resolve_call_args(API, depth=6)",
    ):
        assert any(needle in b for b in bodies), f"nothing exercises {needle!r}"
