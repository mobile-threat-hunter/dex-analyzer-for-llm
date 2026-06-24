"""MANDATORY D-3 gate: condition / loop / switch HEADER lines must map.

This is the regression backstop for Finding A of the design review (dexllm#1):
the harvest hook is NOT a single site at the statement chokepoint. `if (…)`,
`while (…)`, `} while (…)` and `switch (…)` headers are emitted through
`visit_cond` / `Accept` (text) and `get_cond_block` (AST), which bypass the
statement path — so they need their own four hooks. Those header lines are
EXACTLY the short-circuit / multiple-anchor cases D-3 exists to map.

A statement-only test (test_pc_line_map.py) would stay green even if the
header hooks were dropped. This file fails in that case: it scans the corpus
until it has found and verified each header kind, including a short-circuit
compound condition. Skips only if no test APK is present (never silently
passes on missing coverage — a kind that is never found is a FAIL).
"""

import pytest
from conftest import smali_offsets

import dexllm


def _classify(stripped):
    if stripped.startswith(("if (", "if(")):
        return "if"
    if stripped.startswith(("while (", "while(")) and not stripped.startswith(
        "while(true)"
    ):
        return "while"
    if stripped.startswith("} while("):
        return "dowhile"
    if stripped.startswith("switch ("):
        return "switch"
    return None


@pytest.fixture(scope="module")
def header_coverage(loadable_apks):
    """Scan the corpus, collecting one verified example per header kind.

    For each kind we require: the header line has a pc_map entry AND its offset
    is a real instruction of that method. Additionally we require at least one
    short-circuit header (`&&`/`||`) to be covered — the headline D-3 case.
    """
    examples = {}  # kind -> (method, line, text, off)
    short_circuit = None  # (method, line, text, off)
    cap = 6000
    checked = 0

    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for cls in dk.list_classes():
            if (
                checked >= cap
                and examples.keys()
                >= {
                    "if",
                    "while",
                    "dowhile",
                    "switch",
                }
                and short_circuit
            ):
                break
            try:
                methods = dk.list_class_methods(cls)
            except Exception:
                continue
            for m in methods:
                try:
                    r = dk.decompile_method_java_with_pc(m)
                except Exception:
                    continue
                src = r["source"]
                if not src or src.startswith("// DECOMPILE ERROR"):
                    continue
                pcm = dict(r["pc_map"])
                if not pcm:
                    continue
                checked += 1
                valid = None
                for i, line in enumerate(src.split("\n"), 1):  # \n contract
                    s = line.strip()
                    kind = _classify(s)
                    if not kind:
                        continue
                    if i not in pcm:
                        continue
                    if valid is None:
                        valid = smali_offsets(dk, m)
                    off = pcm[i]
                    if off not in valid:
                        continue
                    if kind not in examples:
                        examples[kind] = (m, i, s, off)
                    if short_circuit is None and ("&&" in s or "||" in s):
                        short_circuit = (m, i, s, off)
            if (
                examples.keys() >= {"if", "while", "dowhile", "switch"}
                and short_circuit
            ):
                break
        if examples.keys() >= {"if", "while", "dowhile", "switch"} and short_circuit:
            break

    return examples, short_circuit


@pytest.mark.parametrize("kind", ["if", "while", "dowhile", "switch"])
def test_header_kind_is_mapped(header_coverage, kind):
    examples, _ = header_coverage
    assert kind in examples, (
        f"no {kind!r} header line with a valid pc_map entry was found in the "
        f"corpus — Finding A regression (header hook missing/broken)"
    )
    m, line, text, off = examples[kind]
    assert off != 0xFFFFFFFF
    # offset already validated against real instructions during the scan


def test_short_circuit_header_is_mapped(header_coverage):
    """The headline D-3 case: a compound `(a && b) || c` header maps to the
    offset of its condition's last if-test instruction."""
    _, short_circuit = header_coverage
    assert short_circuit is not None, (
        "no short-circuit (&&/||) header with a valid pc_map entry was found — "
        "Condition::get_ins() recovery for compound headers is broken"
    )
    m, line, text, off = short_circuit
    assert off != 0xFFFFFFFF
