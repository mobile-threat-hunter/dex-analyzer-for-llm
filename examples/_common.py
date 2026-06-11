"""Shared helper for the examples: resolve a DexKit-loadable path.

Order: CLI arg → $DEXLLM_TEST_APK → first APK under ../test_apk/APK/.
The CLI arg is passed through verbatim, so it may be a zip container
(.apk/.jar/.zip) or a bare .dex file — DexKit accepts both.
"""

import glob
import os
import sys
from pathlib import Path


def resolve_apk() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    env = os.environ.get("DEXLLM_TEST_APK")
    if env:
        return env
    root = Path(__file__).resolve().parents[1]
    hits = sorted(glob.glob(str(root / "test_apk" / "APK" / "*.apk")))
    if hits:
        return hits[0]
    sys.exit(
        "No APK given. Pass one as an argument, set $DEXLLM_TEST_APK, "
        "or drop an .apk under test_apk/APK/."
    )
