#!/usr/bin/env python3
"""Static C2 / network-IOC extraction — VirusTotal-style, no execution.

Recovers the URLs, IPs, domains, emails, and .onion addresses embedded in the
app's dex strings and ties each one back to the class/method that references it.

Usage:
    python examples/05_extract_iocs.py [path/to/app.apk | classes.dex]
"""

from _common import resolve_apk

import dexllm

apk = resolve_apk()
dk = dexllm.DexKit(apk)

iocs = dexllm.extract_iocs(dk, with_xref=True)

print("== STATIC C2 / IOC REPORT ==\n")
for category in dexllm.IOC_CATEGORIES:
    rows = iocs[category]
    if not rows:
        continue
    print(f"[{category.upper()}]  ({len(rows)})")
    for row in rows:
        print(f"  - {row['value']}")
        for method in row["methods"][:3]:
            print(f"      referenced by: {method}")
        # An indicator kept only as a `static final String` constant is loaded by no
        # code, so it has no call site — `declared_in` is then its only location.
        for cls in row["declared_in"][:3]:
            print(f"      declared in:   {cls}")
    print()

# The value-bearing string feed is also available for custom queries:
print(f"(total distinct value-strings in dex: {len(dk.list_value_strings())})")
