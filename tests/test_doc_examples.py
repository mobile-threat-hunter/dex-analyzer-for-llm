"""Execute the documented python examples, so prose cannot drift from the API.

``tests/test_stubs.py`` makes the ``.pyi`` bidirectionally runtime-checked, so the
stubs cannot advertise a name the runtime lacks. Nothing did the equivalent for
PROSE, and it showed (issue #34): four copy-paste-first fences — the first code a
reader of that section runs — used names or signatures that do not exist. Three of
them are corrected alongside this file; the fourth (``crypto.hits``) had already
been fixed in 7747246. The headline case is ``ref.java_class``, which the stubs had
deliberately avoided because introspecting the live module showed the real
attribute is ``java_type``: the stubs dodged the mistake, the docs kept it, and a
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
    `print(ref)` instead of `print(ref.java_type)` defeats it without even a
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
        "ref.java_type",  # the attribute, not just the call that returns it
        "method_ref_java('Lcom/foo/Bar;', 'baz', '(I)V')",  # the arity
        "summary.is_internal",
        "open_apk",  # the SDK surface, otherwise wholly unexercised
        # The depth argument: a fence that merely MENTIONS it in a comment would
        # keep the needle while exercising nothing, so the keyword call is pinned.
        "resolve_call_args(API, depth=6)",
    ):
        assert any(needle in b for b in bodies), f"nothing exercises {needle!r}"


# ── the docs' PROSE, not just their fences ───────────────────────────────────
#
# A fence RUNS, so a rename breaks it. A prose enumeration of a record's fields
# does not run, and three of these went stale for several releases before anyone
# looked: `docs/api.md` advertised `ResolvedArg.kind` values the binding has never
# emitted (`StringConst` / `IntConst` / `Field` — it emits `ConstString` /
# `ConstInt` / `FieldRead`), and both `api.md` and `sdk.md` never gained
# `CapabilityReport.dropped_touches` / `dropped_apis` (dexllm#49). A consumer
# branching on the documented `kind` gets nothing, silently.

#: A heading may legitimately document TWO records at once; the claimed field set
#: is then checked against their UNION. JUSTIFIED, not merely listed: both records
#: must exist, and the doc must genuinely name fields from each.
_DOC_SHARED_HEADINGS = {"MethodInfo / FieldInfo": ("MethodInfo", "FieldInfo")}

#: Deliberately ABRIDGED prose — a one-line summary rather than an enumeration.
#: Each must be a single line, or it is an enumeration pretending to be a summary.
_DOC_ABRIDGED = {
    (
        "docs/api.md",
        "ExternalFieldRef / ExternalTypeRef",
    ),  # "Field: class/name/type descriptors + `descriptor`."
    ("docs/api.md", "ResolvedCallSite"),  # "All `CallSite` fields plus `args`."
}


def _runtime_record_attrs():
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    from _records import assert_skips_are_optional, public_record_attrs

    recs, skipped = public_record_attrs()
    assert_skips_are_optional(skipped)
    out = {}
    for qual, attrs in recs.items():
        out.setdefault(qual.rsplit(".", 1)[1], set()).update(attrs)
    return out


def test_the_docs_enumerate_the_fields_a_record_actually_has():
    """dexllm#68/#69 follow-up: a prose field list is a claim, and it can rot.

    Two notations are audited — `docs/sdk.md`'s ``- **`Name`** `(a, b, c)` `` and
    `docs/api.md`'s ``### `Name` `` followed by a `| field |` table. Both are
    compared against the LIVE attribute set, so a rename or an added field that
    misses the doc fails here rather than in a user's editor.
    """
    import re

    runtime = _runtime_record_attrs()
    offenders, audited = [], 0

    def check(where, name, claimed, both_ways=True):
        """`both_ways` is False for PROSE: a sentence may legitimately name the
        record itself or cross-reference another API, so only a MISSING field is
        a defect there. A TABLE row is a field claim and is checked both ways."""
        nonlocal audited
        targets = _DOC_SHARED_HEADINGS.get(name, (name,))
        if not all(t in runtime for t in targets):
            return
        audited += 1
        actual = set().union(*(runtime[t] for t in targets))
        missing = actual - claimed
        extra = (claimed - actual) if both_ways else set()
        if missing or extra:
            offenders.append(
                f"{where} {name}: missing {sorted(missing)} extra {sorted(extra)}"
            )

    sdk = (REPO_ROOT / "docs/sdk.md").read_text(encoding="utf-8")
    for m in re.finditer(r"- \*\*`([\w /]+)`\*\*\s*`\(([^`]*)\)`", sdk):
        body = m.group(2).replace("\n", " ")
        if "..." in body:
            continue  # explicitly abridged
        claimed = {f.strip().rstrip("?") for f in body.split(",") if f.strip()}
        check("docs/sdk.md", m.group(1), claimed)

    api = (REPO_ROOT / "docs/api.md").read_text(encoding="utf-8")
    for sec in re.split(r"\n### ", api):
        m = re.match(r"`([\w /`]+)`", sec)
        if not m:
            continue
        name = m.group(1).replace("`", "").strip()
        if ("docs/api.md", name) in _DOC_ABRIDGED:
            continue
        body = sec.split("\n### ")[0]
        rows = re.findall(r"^\|\s*([^|]+?)\s*\|", body, re.M)
        claimed = {i for r in rows for i in re.findall(r"`(\w+)`", r)}
        if not claimed:
            # PROSE form — `field: type`, `field` (`type`), … A backticked word
            # that FOLLOWS an opening paren is the TYPE, not a field, which is
            # what separates `interface_descriptors` from the `(`list[str]`)`
            # after it. Without this branch the whole section is skipped, and
            # `CapabilityReport` — documented that way — sat two fields stale.
            first = body.split("\n\n")[0]
            claimed = {
                w for pre, w in re.findall(r"(.?)`(\w+)(?:`|:)", first) if pre != "("
            }
            if len(claimed) < 3:
                continue
            check("docs/api.md", name, claimed, both_ways=False)
            continue
        check("docs/api.md", name, claimed)

    assert audited >= 8, f"only {audited} documented records audited — the parse broke"
    assert (
        not offenders
    ), "documented field lists disagree with the runtime:\n  " + "\n  ".join(offenders)

    # the abridged exceptions must be EARNED: a real one-line summary, not an
    # enumeration that would otherwise fail.
    for doc, name in _DOC_ABRIDGED:
        sec = re.split(r"\n### ", (REPO_ROOT / doc).read_text(encoding="utf-8"))
        body = next(s for s in sec if s.startswith(f"`{name.split(' / ')[0]}`"))
        body = body.split("\n### ")[0].split("\n\n")[0]
        assert (
            "|" not in body
        ), f"{doc} {name} is listed as abridged but has a field TABLE"


def test_no_in_page_doc_link_is_dangling():
    """An invented anchor reads as a working cross-reference and is not one.

    Written after one was added by hand during the dexllm#69 audit — the exact
    defect the audit was looking for. GitHub's slug keeps `[A-Za-z0-9_]`, spaces
    and hyphens, lowercases, and maps EACH space to a hyphen (it does not collapse
    runs), so a heading with an em dash slugs with a `--` in it.
    """
    import re

    def slug(h):
        h = re.sub(r"<[^>]+>", "", h)
        h = re.sub(r"[^\w\s-]", "", h.lower())
        return h.strip().replace(" ", "-")

    docs = sorted(REPO_ROOT.glob("*.md")) + sorted((REPO_ROOT / "docs").glob("*.md"))
    assert len(docs) >= 12, f"only {len(docs)} md files found"
    total, bad = 0, []
    for f in docs:
        t = f.read_text(encoding="utf-8")
        anchors = {slug(h) for h in re.findall(r"^#{1,6} (.+)$", t, re.M)}
        anchors |= set(re.findall(r'<a name="([\w-]+)"', t))
        links = set(re.findall(r"\]\(#([\w-]+)\)", t))
        total += len(links)
        bad += [f"{f.name}#{a}" for a in sorted(links - anchors)]
    assert total >= 10, f"only {total} in-page links found — the scan broke"
    assert not bad, f"dangling in-page links: {bad}"


def test_the_documented_arg_kinds_are_the_ones_the_binding_emits():
    """A field's documented VALUE SET is a claim too, and it had rotted.

    `docs/api.md` advertised `'StringConst'` / `'IntConst'` / `'Field'` as
    `ResolvedArg.kind` values. The binding emits `ConstString` / `ConstInt` /
    `FieldRead` and has never emitted the other three, so a consumer branching on
    the documented spelling silently matched nothing. The field-NAME audit above
    cannot see it — `kind` is present and correctly named.

    The authority is `ArgKindName`'s switch in `dexkit_ext.cpp`, read from source
    so this holds with no corpus.
    """
    import re

    cpp = (REPO_ROOT / "native/core_ext/dexkit_ext.cpp").read_text(encoding="utf-8")
    body = cpp[cpp.index("const char* ArgKindName(") :]
    body = body[: body.index("\n}")]
    emitted = set(re.findall(r'return "(\w+)";', body))
    assert (
        len(emitted) >= 10
    ), f"only {len(emitted)} kinds parsed — re-anchor this guard"

    api = (REPO_ROOT / "docs/api.md").read_text(encoding="utf-8")
    # `| \`kind\` |` starts TWO rows — this one and the crossed_branch flavours
    # table, whose second column is `crossed_branch` rather than the type. Pick by
    # the type cell, and fail loudly if that stops being unique.
    rows = [ln for ln in api.split("\n") if ln.startswith("| `kind` | `str` |")]
    assert len(rows) == 1, f"expected one `kind`/`str` row, found {len(rows)}"
    row = rows[0]
    documented = set(re.findall(r"`'?(\w+)'?`", row)) - {"kind", "str"}
    assert documented == emitted, (
        f"documented-but-never-emitted {sorted(documented - emitted)} | "
        f"emitted-but-undocumented {sorted(emitted - documented)}"
    )
