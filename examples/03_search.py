#!/usr/bin/env python3
"""Search the APK: classes by name, methods using a string, API call sites.

Usage:
    python examples/03_search.py [path/to/app.apk | classes.dex]
"""
from _common import resolve_apk

import dexllm

apk = resolve_apk()
dk = dexllm.DexKit(apk)

print("== classes whose name contains 'Activity' ==")
for c in dk.find_classes_by_name("Activity", "contains")[:10]:
    print(f"  {c}")

print("\n== methods referencing the string 'http' ==")
for m in dk.find_methods_using_strings(["http"], "contains")[:10]:
    print(f"  {m}")

print("\n== call sites of Log.d(String, String) ==")
api = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
sites = dk.find_call_sites_to_api(api)
print(f"  {len(sites)} call site(s); first 5:")
for s in sites[:5]:
    print(f"    {s}")

print("\n== resolved argument origins at those call sites (dataflow) ==")
for rcs in dk.resolve_call_args(api)[:5]:
    print(f"    {rcs}")
