"""The L4 analyzer's opcode enumeration is COMPLETE (dexllm#32).

``AnalyzeMethodInvokes``' ``default:`` clears no register, so every opcode that
WRITES one must appear in a non-default branch. Miss one and a stale origin
survives its own overwrite and is reported as an unconditional definite value —
the worst failure this API has, since it exists to answer "which string was passed
to ``Cipher.getInstance``" and a hole makes it answer confidently and wrongly.

That obligation was hand-maintained and had already been wrong twice (the
``*-int/lit8`` / ``lit16`` destination swap and the wide high half, both found in
the dexllm#16 review). These tests make it machine-checked instead, against
slicer's own instruction table — a source independent of the switch under audit.

The classification is stated as the small, closed set of opcodes that only READ
operand A; anything else with a register there must be handled. A new opcode is
therefore a FAILURE by default, which is the fail-closed direction: the cost of a
wrongly-listed reader is lost resolution, the cost of a missed writer is a wrong
answer.

These tests parse source files, so they need no corpus and no built extension.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_TABLE = (
    _ROOT
    / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_instruction_list.h"
)
_SRC = _ROOT / "vendor/dexkit_core/Core/dexkit/dex_item.cpp"

# Opcodes whose operand A is a register the instruction only READS. Everything else
# carrying kVerifyRegA / kVerifyRegAWide writes it. Matched on the slicer table's own
# opcode NAME so the list reads as the Dalvik spec rather than as numeric ranges that
# would drift with the switch it audits.
#
# `check-cast` is the subtle member: it is a *checked* read whose whole point is that
# the value is unchanged, so preserving the origin across `(String) x` is correct.
_READS_A_ONLY = (
    "return",
    "throw",
    "monitor-",
    "if-",
    "goto",
    "packed-switch",
    "sparse-switch",
    "aput",
    "sput",
    "iput",  # covers iput-*-quick
    "fill-array-data",
    "check-cast",
    "nop",
    # An invoke's operand A is the ARGUMENT COUNT, not a register (the table marks it
    # kVerifyVarArg, not kVerifyRegA) — listed only so the intent is explicit.
    "invoke-",
)

# The same list, pinned. `_READS_A_ONLY` is an EXCUSE list that lives in the same file
# as the assertion it feeds, so the cheapest way past a failure is to widen it — a
# review demonstrated that deleting `case 0x0D:` (move-exception) from the switch and
# adding "move-exception" here leaves the whole suite green while the analyzer reports
# a stale origin. Pinning does not make that impossible, but it makes it a deliberate
# edit in two places rather than a one-line "make the test pass".
_PINNED_READS_A_ONLY = (
    "aput",
    "check-cast",
    "fill-array-data",
    "goto",
    "if-",
    "invoke-",
    "iput",
    "monitor-",
    "nop",
    "packed-switch",
    "return",
    "sparse-switch",
    "sput",
    "throw",
)

_ROW = re.compile(
    r"\s*V\(0x([0-9A-Fa-f]{2}),\s*(\w+),\s*\"([^\"]*)\",\s*(\w+),\s*(\w+),"
    r"\s*([^,]+),\s*[^,]+,\s*([^)]*)\)"
)


def _slicer_table() -> dict[int, dict[str, str]]:
    """Every opcode slicer knows, with its name, format and verify flags."""
    rows: dict[int, dict[str, str]] = {}
    for line in _TABLE.read_text().splitlines():
        m = _ROW.match(line)
        if m:
            op, _enum, name, fmt, _idx, _flow, verify = m.groups()
            rows[int(op, 16)] = {"name": name, "fmt": fmt, "verify": verify.strip()}
    return rows


def _strip_comments(text: str) -> str:
    """Blank out `//` and `/* */` comments, preserving line structure.

    Without this the scan counts a `case 0xNN:` that a comment has DISABLED. A review
    reverted six of the seven fixed opcodes exactly that way — moving their labels
    into a `//` comment above the surviving one — with the whole suite green.

    A left-to-right scan, not two regex passes: this very file contains
    ``// ---- const-wide/* ----``, and a `/* ... */` regex applied first treats that
    `/*` as a block-comment opener and swallows everything up to the next `*/` some
    290 lines later — which silently shrinks the audit instead of failing it. String
    and char literals are tracked for the same reason.
    """
    out: list[str] = []
    i, n = 0, len(text)
    line_c = block_c = in_str = in_chr = False
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if line_c:
            if c == "\n":
                line_c = False
                out.append(c)
            i += 1
        elif block_c:
            if two == "*/":
                block_c = False
                i += 2
            else:
                out.append(c if c == "\n" else " ")
                i += 1
        elif in_str or in_chr:
            out.append(c)
            if c == "\\":
                if i + 1 < n:
                    out.append(text[i + 1])
                i += 2
                continue
            if (in_str and c == '"') or (in_chr and c == "'"):
                in_str = in_chr = False
            i += 1
        elif two == "//":
            line_c = True
            i += 2
        elif two == "/*":
            block_c = True
            i += 2
        else:
            if c == '"':
                in_str = True
            elif c == "'":
                in_chr = True
            out.append(c)
            i += 1
    return "".join(out)


def _handled_opcodes() -> set[int]:
    """Opcodes the analyzer's switch handles in a NON-default branch."""
    lines = _strip_comments(_SRC.read_text()).splitlines()
    starts = [i for i, ln in enumerate(lines) if "switch (op) {" in ln]
    assert starts, "the analyzer's opcode switch moved — update this test's locator"
    # The analyzer's switch is the one followed by a `default:` inside run_block.
    lo = starts[-1]
    hi = next(i for i in range(lo, len(lines)) if lines[i].strip() == "default:")
    handled: set[int] = set()
    for ln in lines[lo:hi]:
        handled |= {int(h, 16) for h in re.findall(r"case 0x([0-9A-Fa-f]{2}):", ln)}
    return handled


def _writes_a(row: dict[str, str]) -> bool:
    if "kVerifyRegA" not in row["verify"]:  # substring also covers kVerifyRegAWide
        return False
    return not row["name"].startswith(_READS_A_ONLY)


def test_the_slicer_table_and_the_switch_are_both_parsed() -> None:
    """Non-vacuity floor: neither side may silently parse to nothing.

    Both parsers key off source text, so a refactor that moved either one would
    otherwise turn every assertion below into a tautology over an empty set.
    """
    rows = _slicer_table()
    assert len(rows) == 256, f"slicer table parsed {len(rows)} opcodes, expected 256"
    handled = _handled_opcodes()
    assert len(handled) > 150, f"only {len(handled)} opcodes parsed out of the switch"
    writers = [op for op, r in rows.items() if _writes_a(r)]
    assert len(writers) > 150, f"only {len(writers)} register writers classified"


def test_every_register_writing_opcode_is_handled() -> None:
    """The completeness obligation `default:` rests on.

    An opcode that writes a register and reaches `default:` leaves the previous
    origin in place, so the analyzer reports a value the code overwrote.
    """
    rows = _slicer_table()
    handled = _handled_opcodes()
    missing = [
        f"0x{op:02X} {rows[op]['name']} (fmt={rows[op]['fmt']})"
        for op in sorted(rows)
        if _writes_a(rows[op]) and op not in handled
    ]
    assert not missing, (
        "these opcodes write a register but fall through to `default:`, which "
        "clears nothing — a stale origin would be reported as an unconditional "
        "value:\n  " + "\n  ".join(missing)
    )


def test_the_read_only_classification_is_pinned() -> None:
    """`_READS_A_ONLY` may not grow without a deliberate second edit.

    It is the predicate every other assertion here rests on, so widening it excuses
    an arbitrary writer. Compared as SORTED sets so a reordering is not a failure.
    """
    assert tuple(sorted(_READS_A_ONLY)) == _PINNED_READS_A_ONLY, (
        "the read-only-operand-A classification changed. Every entry excuses an "
        "opcode from the completeness check, so adding one must be deliberate: "
        "update _PINNED_READS_A_ONLY too, and say why in the commit."
    )


def test_a_commented_out_case_label_does_not_count_as_handled() -> None:
    """The scan must read code, not text.

    Self-check of `_strip_comments`, which is otherwise invisible: with it absent the
    completeness assertion passes for opcodes whose `case` label has been commented
    out, which is how a review reverted six of the seven fixed opcodes.
    """
    src = "switch (op) {\n// case 0xE3: case 0xE4:\ncase 0xE5:\n  x();\ndefault:\n}"
    stripped = _strip_comments(src)
    assert "0xE3" not in stripped and "0xE5" in stripped
    assert "0xF0" not in _strip_comments("a /* case 0xF0: */ b")
    # Line structure is preserved, so the switch/default locator still sees the same
    # line numbers after stripping.
    assert _strip_comments(src).count("\n") == src.count("\n")
    # A `//` comment containing `/*` must NOT open a block comment -- this file has
    # exactly that (`// ---- const-wide/* ----`), and getting it wrong silently
    # shrinks the audit rather than failing it.
    tricky = "// a /* b\ncase 0xE5:\n/* real */\ncase 0xE3:\n"
    assert "0xE5" in _strip_comments(tricky) and "0xE3" in _strip_comments(tricky)
    # A comment marker inside a string literal is not a comment.
    assert '"//"' in _strip_comments('x = "//"; case 0xE4:')


def test_the_quick_iget_family_is_handled() -> None:
    """The seven holes dexllm#32 found, pinned by number.

    Pinned as literals rather than derived from `_writes_a`, because a guard
    parametrised over the same predicate cannot catch that predicate being widened
    to excuse them (e.g. adding "iget-" to `_READS_A_ONLY`, which would silently
    re-open exactly this hole while leaving the test above green).
    """
    handled = _handled_opcodes()
    quick_igets = {0xE3, 0xE4, 0xE5, 0xEF, 0xF0, 0xF1, 0xF2}
    assert quick_igets <= handled, (
        "unhandled ART iget-*-quick opcodes: "
        f"{sorted(hex(o) for o in quick_igets - handled)}"
    )


def test_the_quick_iput_family_is_not_treated_as_a_writer() -> None:
    """The other half of the fix: iput-*-quick READS vA.

    Clearing there would be sound but lossy, and listing them beside their iget
    siblings is the easy mistake — they sit in the same 0xE3-0xF2 block.
    """
    rows = _slicer_table()
    for op in (0xE6, 0xE7, 0xE8, 0xEB, 0xEC, 0xED, 0xEE):
        assert rows[op]["name"].startswith("iput-"), f"0x{op:02X} is not an iput-quick"
        assert not _writes_a(rows[op]), f"0x{op:02X} misclassified as a writer"


@pytest.mark.parametrize(
    ("op", "name"),
    [
        (0x1F, "check-cast"),
        (0x4D, "aput-object"),
        (0x5B, "iput-object"),
        (0x69, "sput-object"),
        (0x1D, "monitor-enter"),
    ],
)
def test_a_read_only_operand_a_keeps_its_origin(op: int, name: str) -> None:
    """These carry a register in A and must NOT be cleared.

    Non-discriminating BY DESIGN against the dexllm#32 fix — it adds writers, it
    removes no reader. The guard is against a later "make `default:` fail closed"
    rewrite, which is the natural next idea and would cost real resolution: an
    `iput v0, ...` or `(String) v0` before a call is ordinary code, and clearing v0
    there loses the origin the API exists to report.
    """
    rows = _slicer_table()
    assert rows[op]["name"] == name, f"0x{op:02X} is {rows[op]['name']}, not {name}"
    assert "kVerifyRegA" in rows[op]["verify"]
    assert not _writes_a(rows[op])
