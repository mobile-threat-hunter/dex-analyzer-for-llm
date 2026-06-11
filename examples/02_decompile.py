#!/usr/bin/env python3
"""Decompile a method/class to Java, smali, and the structured AST.

Usage:
    python examples/02_decompile.py [path/to/app.apk | classes.dex]

Accepts a zip container (.apk/.jar/.zip) or a bare .dex file.
"""
import json

from _common import resolve_apk

import dexllm

apk = resolve_apk()
dk = dexllm.DexKit(apk)

# Pick the first internal class with at least one method.
target_cls = target_method = None
for cls in dk.list_classes():
    methods = dk.list_class_methods(cls)
    if methods:
        target_cls, target_method = cls, methods[0]
        break
if target_method is None:
    raise SystemExit("no decompilable method found")

print(f"# method : {target_method}\n")
print("=== Java (method) ===")
print(dk.decompile_method_java(target_method))

print("\n=== smali (method) ===")
print(dk.render_method_smali(target_method))

print("\n=== AST (method) — DAD dast.py nested form ===")
ast = dk.decompile_method_ast(target_method)  # includes Java `source` too
print("keys:", list(ast.keys()))
print(json.dumps(ast["ast"], indent=1)[:600], "...")

# AST-only is ~1.7x faster (skips the redundant text-emit pipeline).
ast_only = dk.decompile_method_ast(target_method, include_source=False)
assert ast_only["ast"] == ast["ast"] and ast_only["source"] == ""

print(f"\n=== Java (whole class: {target_cls}) — first 25 lines ===")
print("\n".join(dk.decompile_class_java(target_cls).splitlines()[:25]))
