#!/usr/bin/env python3
"""Load an APK and print a quick overview: scale, external APIs, capabilities.

Usage:
    python examples/01_overview.py [path/to/app.apk | classes.dex]
"""
from _common import resolve_apk

import dexllm

apk = resolve_apk()
dk = dexllm.DexKit(apk)

classes = dk.list_classes()
nmethods = sum(len(dk.list_class_methods(c)) for c in classes)
print(f"APK            : {apk}")
print(f"dex files      : {dk.dex_count()}")
print(f"classes        : {len(classes)}")
print(f"methods        : {nmethods}")

print("\nTop external framework APIs touched:")
for ref in dk.list_external_method_refs(framework_only=True)[:10]:
    print(f"  {ref.java_signature}")

# Capability summary (API → category: LOCATION / CRYPTO / REFLECTION / ...)
report = dexllm.summarize_capabilities(dk)
print(
    f"\nCapabilities ({report.matched_apis} APIs / {report.total_call_sites} call sites):"
)
for name, count in report.top_categories(10):
    print(f"  {name:16s} {count} call site(s)")
