"""The vendored DexKit tree is pinned to a recorded upstream baseline (dexllm#65).

`vendor/dexkit_core/UPSTREAM` names the fork point and
`vendor/dexkit_core/UPSTREAM.blobs` records, for each vendored file, the git blob
SHA it had THERE.  A file whose on-disk bytes hash to that SHA is byte-identical
to upstream; every other file is a divergence and must be catalogued in
`docs/dexkit-vendor-divergences.md`.

Why this is a test and not a convention.  Before dexllm#65 the only record of a
divergence was an in-source `dexllm` comment, and it undercounted three ways:

  * three files carried no marker token at all, so a `grep dexllm` census saw
    8 files where there are 11 -- and two further hunks inside an
    already-marked file (`ThreadPool.h`) were unmarked too, five hunks over
    four files in all;
  * a DELETION leaves nothing to grep for -- `GetInvokeMethodsFromCode`
    (dexllm#61) and upstream's `declared_synchronized` rewrite (dexllm#41) are
    both invisible in the current tree;
  * a new divergence in a file that already has a marker adds no marker of its
    own, and one such divergence (D13, `PutDeclaredClass`) had gone both
    unmarked and uncatalogued for three months.

A manifest comparison sees the first two.  It does not see the third, and this
file says so rather than implying otherwise: **the granularity here is the
FILE.**  What the catalogue checks below add is that a file cannot be catalogued
in name only -- every divergent path must be named in an ENTRY's `Where:`, every
entry must sit under one of the four treatment headings, and which treatment is
pinned here as a literal.

Corpus-independent -- it reads only committed bytes, so it runs in the
corpus-less CI leg and under any `$DEXLLM_TEST_APK` narrowing.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest
from conftest import REPO_ROOT

_VENDOR = REPO_ROOT / "vendor" / "dexkit_core"
_MANIFEST = _VENDOR / "UPSTREAM.blobs"
_PROVENANCE = _VENDOR / "UPSTREAM"
_CATALOGUE = REPO_ROOT / "docs" / "dexkit-vendor-divergences.md"

# Files that describe the baseline rather than being part of it.  Compared as
# RELATIVE PATHS, not basenames: a `Core/dexkit/UPSTREAM` would otherwise be
# invisible to the coverage check (a reviewer built exactly that and it passed).
_NOT_VENDORED = frozenset({"UPSTREAM", "UPSTREAM.blobs"})

# The fork point, pinned in THREE places on purpose: here, in UPSTREAM, and in
# the catalogue's own header.  Rebasing has to move all three, which is the
# one-mirror-updated-the-other-missed shape this repo keeps hitting.
_BASELINE = "dff66e8eff15512ac9a2d03cf3ef23de338bd167"

# sha256 over the manifest's sorted data lines.  Without this the manifest is a
# SELF-REFERENTIAL oracle: editing a pristine file and regenerating just its
# line keeps the divergent set at eleven and passes everything (a reviewer built
# that too, on the very file upstream fix 6ca92c3 would land in).  Regenerating
# the manifest is now a deliberate two-place edit.
_MANIFEST_SHA = "beb4ab3b4fd2f0c43f26fb24d2cf207304d153f30fb1c7f8426c096714a19e32"

# Every file that differs from the baseline, as a LITERAL.  Deriving this from
# the manifest or from the catalogue would make the guard blind to an edit of
# the very thing it guards, so a new divergence -- or a divergence that goes
# away on a rebase -- is a deliberate two-place edit here and in the catalogue.
_DIVERGENT = frozenset(
    {
        "Core/CMakeLists.txt",
        "Core/dexkit/dex_item.cpp",
        "Core/dexkit/dexkit.cpp",
        "Core/dexkit/include/dex_item.h",
        "Core/dexkit/include/dexkit.h",
        "Core/dexkit/include/zip_archive.h",
        "Core/third_party/slicer/common.cc",
        "Core/third_party/slicer/export/slicer/dex_format.h",
        "Core/third_party/slicer/export/slicer/dex_ir.h",
        "Core/third_party/slicer/reader.cc",
        "Core/third_party/thread_helper/ThreadPool.h",
    }
)

# Pinned so a manifest that trivially matched everything, or a vendored subset
# that quietly grew or shrank, fails instead of passing.
_VENDORED_FILES = 136

# Entry -> treatment.  A LITERAL, because the treatment is the registry's whole
# content: without this, moving every entry under `## U` (so `## C` is an empty
# heading) passed all 26 cases, which would silently un-say the change's own
# headline finding that D7 has CONVERGED with upstream.
_TREATMENT = {
    "D1": "U",
    "D2": "U",
    "D3": "U",
    "D4": "U",
    "D5": "U",
    "D6": "U",
    "D11": "U",
    "D13": "U",
    "D14": "U",
    "D7": "C",
    "D8": "P",
    "D9": "P",
    "D10": "P",
    "D12": "R",
}

_SECTION_TREATMENT = {
    "U — upstreamable": "U",
    "C — converged with upstream": "C",
    "P — permanent": "P",
    "R — reduction candidates": "R",
}

# Which entries' `Where:` must name each divergent file.  Pinned so a path
# cannot satisfy the catalogue by being mentioned in some UNRELATED entry.
_PATH_ENTRIES = {
    "Core/CMakeLists.txt": frozenset({"D10"}),
    "Core/dexkit/dex_item.cpp": frozenset(
        {"D4", "D5", "D6", "D7", "D9", "D11", "D12", "D14"}
    ),
    "Core/dexkit/dexkit.cpp": frozenset({"D4", "D13"}),
    "Core/dexkit/include/dex_item.h": frozenset({"D4", "D7", "D8", "D9", "D11"}),
    "Core/dexkit/include/dexkit.h": frozenset({"D4"}),
    "Core/dexkit/include/zip_archive.h": frozenset({"D2"}),
    "Core/third_party/slicer/common.cc": frozenset({"D1"}),
    "Core/third_party/slicer/export/slicer/dex_format.h": frozenset({"D6"}),
    "Core/third_party/slicer/export/slicer/dex_ir.h": frozenset({"D6"}),
    "Core/third_party/slicer/reader.cc": frozenset({"D6"}),
    "Core/third_party/thread_helper/ThreadPool.h": frozenset({"D3", "D10"}),
}


def _git_blob_sha(path: Path) -> str:
    """git's own object hash: sha1(b"blob <len>\\0" + bytes)."""
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _manifest() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        sha, path = line.split("  ", 1)
        assert path not in out, f"duplicate manifest entry: {path}"
        out[path] = sha
    return out


def _present() -> set[str]:
    """Every vendored file the BUILD can see: tracked, plus untracked-not-ignored.

    A plain filesystem walk reports a rebase's own `.orig`/`.rej` leftovers as an
    uncatalogued divergence -- RED on an environment fact, during exactly the
    operation this catalogue exists to enable, which is the trap
    `tests/conftest.py` states as a rule.  But TRACKED-only is not the answer
    either, and a reviewer proved it: `Core/CMakeLists.txt` builds the core from
    `file(GLOB_RECURSE ... dexkit/*.cpp)`, so an untracked `.cpp` dropped in
    there is COMPILED INTO THE PRODUCT while `git ls-files` cannot see it.
    "Not committed yet" is a fact about git, not about what ships.

    So: tracked union untracked-not-ignored.  The `.orig`/`.rej` half is handled
    where it belongs, in `.gitignore`.
    """

    def ls(*args: str) -> set[str]:
        try:
            out = subprocess.run(
                ["git", "ls-files", "-z", *args, "--", "vendor/dexkit_core"],
                cwd=REPO_ROOT,
                capture_output=True,
                check=True,
            ).stdout.decode()
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
            pytest.skip(f"not a git checkout, so there is no committed tree: {exc}")
        return {p[len("vendor/dexkit_core/") :] for p in out.split("\0") if p}

    rel = ls() | ls("--others", "--exclude-standard")
    return {p for p in rel if p not in _NOT_VENDORED}


def _entries() -> dict[str, tuple[str, str]]:
    """entry id -> (treatment letter or "", body).

    The body stops at the next `###`, and the section scan stops at the first
    `## ` that is not a treatment heading, so trailing prose (`## Not proposed`)
    cannot stand in for an entry.
    """
    out: dict[str, tuple[str, str]] = {}
    section = ""
    for block in re.split(
        r"^(?=#{2,3} )", _CATALOGUE.read_text(encoding="utf-8"), flags=re.M
    ):
        head = block.splitlines()[0] if block.strip() else ""
        if head.startswith("## "):
            section = _SECTION_TREATMENT.get(head[3:].strip(), "")
        elif head.startswith("### "):
            m = re.match(r"### (D\d+)\. ", head)
            if m:
                out[m.group(1)] = (section, block)
    return out


def _where(body: str) -> str:
    m = re.search(r"^- \*\*Where:\*\*(.*?)(?=^- \*\*|\Z)", body, re.M | re.S)
    return m.group(1) if m else ""


def test_the_manifest_covers_exactly_the_vendored_tree() -> None:
    """A file added to or removed from vendor/ is a divergence with no marker.

    This is the half a `grep dexllm` census structurally cannot do: an added
    file may carry no marker, and a removed one leaves nothing behind at all.
    """
    manifest = _manifest()
    disk = _present()

    assert (
        len(manifest) == _VENDORED_FILES
    ), f"manifest lists {len(manifest)} files, expected {_VENDORED_FILES}"
    assert disk - manifest.keys() == set(), (
        "file(s) under vendor/dexkit_core/ with no baseline entry (the core "
        "CMakeLists GLOBs *.cpp, so an untracked one still ships) -- "
        "either vendor an upstream file properly or record it as a dexllm "
        f"addition: {sorted(disk - manifest.keys())}"
    )
    assert manifest.keys() - disk == set(), (
        "baseline entr(ies) with no file -- a vendored file was "
        f"deleted: {sorted(manifest.keys() - disk)}"
    )
    # Tracked and absent from the working tree is the same divergence one step
    # earlier, and without this the hashing below dies with FileNotFoundError
    # instead of naming the cause.
    missing = sorted(p for p in manifest if not (_VENDOR / p).is_file())
    assert not missing, f"vendored file(s) tracked but not on disk: {missing}"


def test_the_manifest_itself_is_pinned() -> None:
    """The manifest is the oracle, so it cannot also be freely editable."""
    lines = sorted(
        ln
        for ln in _MANIFEST.read_text(encoding="utf-8").splitlines()
        if ln and not ln.startswith("#")
    )
    got = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    assert got == _MANIFEST_SHA, (
        "UPSTREAM.blobs changed. That is correct ONLY when the baseline itself "
        "moves (a rebase), in which case update _MANIFEST_SHA here in the same "
        f"change. Regenerating a single line to silence a divergence is what "
        f"this refuses.\n  got {got}\n  pin {_MANIFEST_SHA}"
    )


def test_the_divergent_set_is_exactly_what_is_catalogued() -> None:
    """Hash every vendored file; the set that differs must be the pinned set."""
    manifest = _manifest()
    divergent = {p for p, sha in manifest.items() if _git_blob_sha(_VENDOR / p) != sha}

    unexpected = divergent - _DIVERGENT
    assert not unexpected, (
        "vendored file(s) now differ from the upstream baseline with no entry "
        "in docs/dexkit-vendor-divergences.md: " + ", ".join(sorted(unexpected))
    )
    gone = _DIVERGENT - divergent
    assert not gone, (
        "file(s) catalogued as divergent are now byte-identical to upstream "
        "-- drop the entry (and this pin): " + ", ".join(sorted(gone))
    )

    # Non-vacuity in the other direction: most of the tree must still be
    # pristine, or the manifest has stopped meaning anything.
    identical = len(manifest) - len(divergent)
    assert identical == _VENDORED_FILES - len(_DIVERGENT) == 125, identical


@pytest.mark.parametrize("path", sorted(_DIVERGENT))
def test_every_divergent_file_carries_a_marker(path: str) -> None:
    """The in-source convention, as a checked invariant.

    Presence only, at FILE granularity -- this cannot tell a marker on the
    divergent hunk from a `dexllm` mention anywhere else in the file, and it
    cannot see a second divergence inside an already-marked file.  D13 is the
    standing proof that the second limit is real, not hypothetical.
    """
    text = (_VENDOR / path).read_text(encoding="utf-8", errors="replace")
    assert "dexllm" in text, (
        f"{path} diverges from upstream but carries no `dexllm` marker; "
        "mark the hunk so a reader of the file knows it is not upstream code"
    )


def test_no_pristine_file_carries_a_marker() -> None:
    """The other direction: a marker in a file the manifest calls pristine is
    either a stale marker or a divergence the manifest is not seeing."""
    manifest = _manifest()
    stray = sorted(
        p
        for p in manifest
        if p not in _DIVERGENT
        and "dexllm" in (_VENDOR / p).read_text(encoding="utf-8", errors="replace")
    )
    assert not stray, f"marker in a file with no divergence: {stray}"


@pytest.mark.parametrize("path", sorted(_DIVERGENT))
def test_every_divergent_file_is_named_in_its_own_entry(path: str) -> None:
    """In an ENTRY's `Where:`, and in the entries pinned for it.

    Three weaker versions of this were each defeated by a built mutant: `path in
    catalogue` is satisfied by the summary TABLE alone; `path in <entries
    section>` is satisfied by a bullet list under the first heading with every
    entry body deleted; and `path in any entry` lets a divergence be documented
    under an unrelated one.
    """
    entries = _entries()
    owners = {eid for eid, (_, body) in entries.items() if path in _where(body)}
    assert owners == _PATH_ENTRIES[path], (
        f"{path} is named in the `Where:` of {sorted(owners) or 'no entry'}, "
        f"expected {sorted(_PATH_ENTRIES[path])}"
    )


def test_every_entry_declares_a_where_and_a_treatment() -> None:
    """An entry with no `Where:` is a story; one under no treatment heading is a
    fact with nothing to be done about it.  Both passed before this check."""
    entries = _entries()
    assert set(entries) == set(
        _TREATMENT
    ), f"entries {sorted(set(entries) ^ set(_TREATMENT))} appear on one side only"
    for eid, (treatment, body) in sorted(entries.items()):
        assert treatment, f"{eid} is not under any of the four treatment headings"
        assert (
            treatment == _TREATMENT[eid]
        ), f"{eid} is under treatment {treatment}, pinned as {_TREATMENT[eid]}"
        assert _where(body).strip(), f"{eid} has no `- **Where:**` line"

    # All four treatments are used: an empty `## C` would erase this change's
    # own headline finding while leaving twelve entries and four headings.
    assert set(_TREATMENT.values()) == set(_SECTION_TREATMENT.values())


def test_the_catalogue_publishes_the_numbers_it_measures() -> None:
    """The headline census in the doc must be the one the manifest yields."""
    manifest = _manifest()
    divergent = {p for p, sha in manifest.items() if _git_blob_sha(_VENDOR / p) != sha}
    text = _CATALOGUE.read_text(encoding="utf-8")
    m = re.search(
        r"\*\*(\d+)\s+files:\s+(\d+)\s+byte-identical,\s+(\d+)\s+modified,"
        r"\s+(\d+)\s+added\*\*",
        text,
    )
    assert m, "the catalogue no longer states its own census"
    files, identical, modified, added = (int(g) for g in m.groups())
    assert files == len(manifest) == _VENDORED_FILES
    assert identical == len(manifest) - len(divergent)
    assert modified == len(divergent)
    assert added == 0
    # The line totals come from the fork-point tree, which is not in this repo,
    # so they are pinned rather than recomputed -- with the predicate stated.
    assert "**+1288 / -131 lines**" in text
    assert "git diff --numstat" in text


def test_the_baseline_is_pinned_the_same_way_everywhere() -> None:
    """UPSTREAM, the catalogue and this test must name one fork point."""
    provenance = _PROVENANCE.read_text(encoding="utf-8")
    assert _BASELINE in provenance, "UPSTREAM does not name the pinned baseline"

    short = _BASELINE[:7]
    assert short in _CATALOGUE.read_text(
        encoding="utf-8"
    ), "the catalogue does not name the pinned baseline"
    assert short in _MANIFEST.read_text(
        encoding="utf-8"
    ), "UPSTREAM.blobs does not name the baseline its SHAs came from"

    # The manifest is only meaningful next to a repo URL to re-derive it from.
    assert "github.com/LuckyPray/DexKit" in provenance


def test_upstream_cross_references_resolve() -> None:
    """UPSTREAM points at entries by id, and it pointed at the WRONG one.

    Its drift table said the converged revision matches "D6", which is the
    `encoded_value` entry -- classified U and documented as still diverging.
    Sending a reader to the opposite classification is worse than sending them
    nowhere, and nothing checked it.
    """
    provenance = _PROVENANCE.read_text(encoding="utf-8")
    entries = _entries()
    for eid in set(re.findall(r"\bD\d+\b", provenance)):
        assert eid in entries, f"UPSTREAM names {eid}, which is not an entry"
    assert (
        "CONVERGED with D7" in provenance
    ), "UPSTREAM must point the converged revision at the C entry"
    assert _TREATMENT["D7"] == "C"


def _table_rows() -> dict[str, tuple[int, ...]]:
    """The per-file census table: path -> (+, -, hunks, marked, marker lines)."""
    out: dict[str, tuple[int, ...]] = {}
    for m in re.finditer(
        r"^\| `([^`]+)` \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$",
        _CATALOGUE.read_text(encoding="utf-8"),
        re.M,
    ):
        out[m.group(1)] = tuple(int(g) for g in m.groups()[1:])
    return out


def test_the_summary_table_agrees_with_the_treatment_sections() -> None:
    """The catalogue states each treatment TWICE -- in the table and by section.

    A reviewer changed only the table (D7 listed under U, C left "(none)") and
    the whole file stayed green, so the change's own headline finding could be
    un-said in the summary a reader meets first.
    """
    text = _CATALOGUE.read_text(encoding="utf-8")
    listed: dict[str, set[str]] = {}
    for m in re.finditer(r"^\| \*\*([UCPR])\*\* \|[^|]*\|([^|]*)\|", text, re.M):
        listed[m.group(1)] = set(re.findall(r"\bD\d+\b", m.group(2)))
    assert set(listed) == set(
        _SECTION_TREATMENT.values()
    ), f"the treatment table lists {sorted(listed)}, expected U/C/P/R"
    for letter, ids in sorted(listed.items()):
        expected = {e for e, t in _TREATMENT.items() if t == letter}
        assert ids == expected, (
            f"the summary table puts {sorted(ids)} under {letter}; the sections "
            f"and the pin say {sorted(expected)}"
        )


def test_the_per_file_table_is_the_census_it_claims() -> None:
    """The table is five columns of numbers and nothing checked any of them.

    Two of the five are recomputable offline (the path set, and the marker-line
    count); the other three are pinned by having to sum to the totals the prose
    publishes.  A reviewer rewrote a whole row and flipped "7 not marked" to
    "0 not" with the file green.
    """
    rows = _table_rows()
    assert (
        set(rows) == _DIVERGENT
    ), f"the table covers {sorted(set(rows) ^ _DIVERGENT)} on one side only"

    text = _CATALOGUE.read_text(encoding="utf-8")
    plus = sum(r[0] for r in rows.values())
    minus = sum(r[1] for r in rows.values())
    assert (
        f"**+{plus} / -{minus} lines**" in text
    ), f"the table sums to +{plus}/-{minus}, which the prose does not publish"

    hunks = sum(r[2] for r in rows.values())
    marked = sum(r[3] for r in rows.values())
    assert f"{hunks} divergent hunks, {marked} marked, {hunks - marked} not" in text
    for path, r in sorted(rows.items()):
        assert r[3] <= r[2], f"{path}: more marked hunks than hunks"

    lines = sum(r[4] for r in rows.values())
    assert f"**{lines} marker lines" in text
    for path, r in sorted(rows.items()):
        # LINES, not occurrences: one comment line names the marker twice.
        body = (_VENDOR / path).read_text(encoding="utf-8", errors="replace")
        got = sum(1 for ln in body.splitlines() if "dexllm" in ln)
        assert got == r[4], f"{path}: table says {r[4]} marker lines, file has {got}"


def test_every_entry_says_what_it_is_for() -> None:
    """`Where:` alone is a path index, not a registry.

    The first fix for "the entry bodies can be deleted" required a `Where:`; a
    reviewer then reduced all 13 entries to a heading plus that one line (352
    lines -> 169) and the file stayed green, taking every `Upstream:`,
    `Divergence:` and `Why:` with it -- including D7's CONVERGED verdict, which
    is the finding this whole change turns on.  `Why` is the one other bullet
    all of them carry (`Why`, `Why permanent`, `Why permanent-ish`, `Why it is a
    reduction candidate`), so it is what can be required of all of them.
    """
    for eid, (_, body) in sorted(_entries().items()):
        assert re.search(
            r"^- \*\*Why", body, re.M
        ), f"{eid} says where it is but not what it is for"


def test_no_pristine_file_is_catalogued_as_divergent() -> None:
    """The mirror of `test_no_pristine_file_carries_a_marker`, on the doc side."""
    manifest = _manifest()
    entries = _entries()
    for path in sorted(set(manifest) - _DIVERGENT):
        owners = [e for e, (_, b) in entries.items() if f"`{path}`" in _where(b)]
        assert not owners, f"{path} is byte-identical to upstream but {owners} claim it"


def test_the_census_is_the_same_in_every_mirror() -> None:
    """Three documents publish it; a first-match check saw one.

    A reviewer left a correct sentence above a falsified heading and the guard
    read the correct one.  Every occurrence in every mirror must be right.
    """
    manifest = _manifest()
    divergent = {p for p, sha in manifest.items() if _git_blob_sha(_VENDOR / p) != sha}
    want = (len(manifest), len(manifest) - len(divergent), len(divergent), 0)

    pat = re.compile(
        r"(\d+)\s+(?:vendored\s+)?files[:,]\s+(\d+)\s+byte-identical"
        r"(?:\s+to\s+upstream)?,\s+(\d+)\s+modified,\s+(\d+)\s+added"
    )
    seen = 0
    for doc in (
        _CATALOGUE,
        REPO_ROOT / "CLAUDE.md",
        REPO_ROOT / "docs" / "architecture.md",
    ):
        text = doc.read_text(encoding="utf-8")
        found = [tuple(int(g) for g in m.groups()) for m in pat.finditer(text)]
        assert found, f"{doc.name} no longer states the census"
        for got in found:
            assert got == want, f"{doc.name} states {got}, measured {want}"
        seen += len(found)
    assert seen >= 3, seen
