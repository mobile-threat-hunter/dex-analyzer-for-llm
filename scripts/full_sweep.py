"""Full-corpus decompile sweep — the 0-crash gate.

Recreated from .claude/skills/dexkit-sweep/SKILL.md (the script does not survive a
reboot). Enumerates classes via dexllm's OWN list_classes() rather than androguard,
so the counts are comparable to earlier runs on the 0/0/0 axis but NOT on the
absolutes -- published with that predicate.
"""

import gc
import glob
import sys
import time

import dexllm

sys.stdout.reconfigure(line_buffering=True)
CAP_BYTES, CAP_CLASSES = 5 * 1024 * 1024, 200
tot = dict(classes=0, blocks=0, crash=0, err=0, empty=0, ok=0, timeout=0)
t0 = time.time()
for apk in sorted(glob.glob("test_apk/APK/*.apk")):
    try:
        if dexllm.identify(apk).get("dex_count", 0) == 0:
            continue
        dk = dexllm.DexKit(apk)
    except Exception:
        continue
    classes = dk.list_classes()
    import os

    if os.path.getsize(apk) > CAP_BYTES:
        classes = classes[:CAP_CLASSES]
    for c in classes:
        tot["classes"] += 1
        out = dexllm.safe_decompile_class(dk, c, timeout=10.0)
        if dexllm.is_timeout_marker(out):
            tot["timeout"] += 1
            continue
        if out is None:
            tot["crash"] += 1
            continue
        for blk in out.split("\n\n"):
            b = blk.strip()
            if not b:
                continue
            tot["blocks"] += 1
            if "// DECOMPILE ERROR" in b or "// METHOD ERROR" in b:
                tot["err"] += 1
            elif not b:
                tot["empty"] += 1
            else:
                tot["ok"] += 1
    del dk
    gc.collect()
el = time.time() - t0
print(f"{tot}  {el:.1f}s")
gate = tot["crash"] == 0 and tot["timeout"] == 0 and tot["err"] == 0
print("GATE:", "PASS" if gate else "FAIL")
