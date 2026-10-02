#!/usr/bin/env python3
"""Regenerate the bundled component-base table, ``src/dexllm/data/component_bases.json``.

The framework half of an inheritance chain is never in an app's dex: a class
written ``extends android.service.media.MediaBrowserService`` is a Service
component, and nothing in the dex says so — the dex names the parent and stops.
``find_component_subclasses`` walks the dex half itself and needs this table for
the rest, which is aosp_data_set's layer 13 (``COMPONENT_BASES.md``, issue #7):
the transitive ``extends`` closure of the nine types an ``AndroidManifest.xml``
can name, with the attribute → base-type table that gives each root its meaning.

Three things are bundled, all MECHANICAL extraction (so, like ``perm_api.json``,
this file is NOT in the ``data_dir`` override channel — a fresher AOSP snapshot
is a re-run of this script):

  * ``roots``  — the 9 roots (8 classes + the ``ZygotePreload`` interface), each
    with its ``root_kind`` and the manifest attributes that name it;
  * ``bases``  — every class in the closure INCLUDING the roots (depth 0), keyed
    by Dalvik descriptor, with root / depth / direct_super / abstract /
    api_surface / has_public_noarg_ctor;
  * ``sdk_classes`` — every type in the SDK catalog (public + system + module-lib),
    as descriptors. This is what separates "the parent is a KNOWN SDK class that
    is not a component base" (resolved: not a candidate) from "the parent is in
    no loaded dex and not in the SDK" (UNRESOLVED: a hidden-API base, a
    ``uses-library`` class, a split-APK remnant — a candidate whose kind cannot
    be decided). Without it the two look identical.

FQN → descriptor needs the catalog to tell a nested class from a package:
``android.app.Notification.Builder`` is ``Landroid/app/Notification$Builder;``
because ``android.app.Notification`` is itself a class. The longest known-class
prefix decides, recursively.

Usage (point at an aosp_data_set checkout, or set $DEXLLM_AOSP_DATASET):
    python scripts/gen_component_data.py /path/to/aosp_data_set [output.json]

The optional second argument redirects the output (the reproduction guard writes
to a temporary file and compares, so a test run never touches the committed one).
"""

from __future__ import annotations

import csv
import json
import os
import pathlib
import sys

DATA = pathlib.Path(__file__).resolve().parent.parent / "src" / "dexllm" / "data"
OUT = DATA / "component_bases.json"

_ROOT_KINDS = {
    "activity",
    "service",
    "receiver",
    "provider",
    "application",
    "backup_agent",
    "instrumentation",
    "app_component_factory",
    "zygote_preload",
}


def _resolve_root(arg: str | None) -> pathlib.Path:
    root = arg or os.environ.get("DEXLLM_AOSP_DATASET") or ""
    if not root:
        sys.exit(
            "usage: gen_component_data.py <aosp_data_set dir>  (or $DEXLLM_AOSP_DATASET)"
        )
    p = pathlib.Path(root)
    for name in (
        "component_bases.tsv",
        "manifest_component_attrs.tsv",
        "aosp_class_names.txt",
    ):
        if not (p / name).is_file():
            sys.exit(
                f"{p / name} is missing — needs aosp_data_set at layer 13 (issue #7)"
            )
    return p


def make_descriptor(fqn: str, known: set[str]) -> str:
    """``android.app.Notification.Builder`` → ``Landroid/app/Notification$Builder;``.

    A dot separates a nested class from its outer class exactly when the prefix
    is itself a known type; the longest such prefix wins, recursively, so
    ``A.B.C`` with ``A.B`` known and ``A`` known becomes ``A$B$C``.
    """
    parts = fqn.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in known:
            outer = make_descriptor(prefix, known)[1:-1]  # strip L ... ;
            return "L" + outer + "$" + "$".join(parts[i:]) + ";"
    return "L" + fqn.replace(".", "/") + ";"


def _yes(v: str) -> bool:
    return v.strip().lower() == "yes"


def main() -> int:
    root = _resolve_root(sys.argv[1] if len(sys.argv) > 1 else None)
    out_path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else OUT
    known = {
        line.strip()
        for line in (root / "aosp_class_names.txt").read_text().splitlines()
        if line.strip()
    }

    bases: dict[str, dict] = {}
    roots: dict[str, dict] = {}
    with open(root / "component_bases.tsv", newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            fqn = row["fqn"]
            desc = make_descriptor(fqn, known)
            root_desc = make_descriptor(row["root"], known)
            kind = row["root_kind"]
            if kind not in _ROOT_KINDS:
                sys.exit(
                    f"unknown root_kind {kind!r} on {fqn} — extend _ROOT_KINDS deliberately"
                )
            depth = int(row["depth"])
            entry = {
                "root": root_desc,
                "root_kind": kind,
                "depth": depth,
                "direct_super": (
                    make_descriptor(row["direct_super"], known)
                    if row["direct_super"]
                    else ""
                ),
                "kind": row["kind"],
                "abstract": _yes(row["abstract"]),
                "api_surface": row["api_surface"],
                "has_public_noarg_ctor": _yes(row["has_public_noarg_ctor"]),
            }
            if desc in bases:
                sys.exit(f"duplicate base {desc}")
            bases[desc] = entry
            if depth == 0:
                if desc != root_desc:
                    sys.exit(f"depth-0 row {fqn} is not its own root")
                roots[desc] = {
                    "root_kind": kind,
                    "kind": row["kind"],
                    "manifest_attrs": (
                        [a for a in row["manifest_attrs"].split("> <") if a]
                        if row["manifest_attrs"]
                        else []
                    ),
                }
    # Re-join the manifest_attrs split above into clean "<element attr>" tokens.
    for r in roots.values():
        toks = []
        for a in r["manifest_attrs"]:
            a = a.strip()
            if not a.startswith("<"):
                a = "<" + a
            if not a.endswith(">"):
                a = a + ">"
            toks.append(a)
        r["manifest_attrs"] = toks

    # Every base's direct_super must be a base too (or "" at depth 0); every
    # chain must reach its root at exactly `depth` steps.
    for desc, e in bases.items():
        cur, steps = desc, 0
        while bases[cur]["depth"] > 0:
            cur = bases[cur]["direct_super"]
            steps += 1
            if cur not in bases:
                sys.exit(f"{desc}: direct_super chain leaves the table at {cur}")
        if cur != e["root"] or steps != e["depth"]:
            sys.exit(
                f"{desc}: chain reaches {cur} in {steps} steps, table says {e['root']} / {e['depth']}"
            )

    attrs = []
    with open(root / "manifest_component_attrs.tsv", newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            attrs.append(
                {
                    "element": row["element"],
                    "attribute": row["attribute"],
                    "value_kind": row["value_kind"],
                    "required_type": (
                        make_descriptor(row["required_type"], known)
                        if row["required_type"]
                        else ""
                    ),
                    "enforcement": row["enforcement"],
                    "scope": row["scope"],
                }
            )

    sdk_classes = sorted(make_descriptor(n, known) for n in known)

    out = {
        "source": {
            "dataset": "https://github.com/mobile-threat-hunter/aosp_data_set",
            "layer": "13 (COMPONENT_BASES.md, issue #7)",
            "generator": "scripts/gen_component_data.py",
        },
        "roots": dict(sorted(roots.items())),
        "bases": dict(sorted(bases.items())),
        "manifest_attrs": attrs,
        "sdk_classes": sdk_classes,
    }
    out_path.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n")
    n_pub = sum(
        1 for e in bases.values() if e["depth"] > 0 and e["api_surface"] == "public"
    )
    print(
        f"wrote {out_path} — {len(roots)} roots, {len(bases) - len(roots)} subclasses "
        f"({n_pub} public), {len(attrs)} manifest attrs, {len(sdk_classes)} sdk classes, "
        f"{out_path.stat().st_size:,} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
