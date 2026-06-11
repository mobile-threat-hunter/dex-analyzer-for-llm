#!/usr/bin/env python3
"""Decompile straight from a bare .dex file — no APK/zip needed.

DexKit sniffs the `dex\\n` magic and loads a raw .dex directly, so you can
point it at a single classes*.dex (e.g. one pulled from an app, a dump, or a
dynamically-loaded module) without repackaging it into a zip.

Usage:
    python examples/04_decompile_dex.py [path/to/classes.dex]

With no argument it extracts a classes.dex from the first APK under
../test_apk/APK/ into a temp file, so the example runs out of the box.
"""

import sys
import tempfile
import zipfile
from pathlib import Path

import dexllm


def resolve_dex() -> str:
    """Return a .dex path: CLI arg, else one extracted from a corpus APK."""
    if len(sys.argv) > 1:
        return sys.argv[1]
    root = Path(__file__).resolve().parents[1]
    for apk in sorted((root / "test_apk" / "APK").glob("*.apk")):
        with zipfile.ZipFile(apk) as z:
            dexes = [n for n in z.namelist() if n.endswith(".dex")]
            if not dexes:
                continue
            out = Path(tempfile.gettempdir()) / "dexllm_example.dex"
            out.write_bytes(z.read(dexes[0]))
            print(f"# no .dex given — extracted {dexes[0]} from {apk.name}")
            return str(out)
    sys.exit("No .dex given and no APK with a dex under test_apk/APK/.")


dex_path = resolve_dex()

# The whole point: a bare .dex loads directly, just like an .apk would.
dk = dexllm.DexKit(dex_path)
print(f"dex file   : {dex_path}")
print(f"dex_count  : {dk.dex_count()}")

classes = dk.list_classes()
print(f"classes    : {len(classes)}")
if not classes:
    sys.exit("This dex declares no classes.")

# Decompile the first class that actually has methods.
target = next((c for c in classes if dk.list_class_methods(c)), classes[0])
print(f"\n=== Java (whole class: {target}) ===\n")
print(dexllm.safe_decompile_class_java(dk, target, timeout=10.0))
