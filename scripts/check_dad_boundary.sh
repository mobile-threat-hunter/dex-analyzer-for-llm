#!/usr/bin/env bash
# check_dad_boundary.sh — guards the hexagonal boundary of the decompiler.
#
# native/dad_cpp/ is the DOMAIN CORE. It must depend only on:
#   - the C++ standard library
#   - its own headers (native/dad_cpp/include/)
#   - the slicer dex-format value types (slicer/dex_*.h) — the shared dex vocabulary
#   - the IDexCodeSource port (dex_code_source.h)
#
# It must NEVER include infrastructure / driving-adapter code: DexKit Core,
# FlatBuffers schema, the zip reader, core_ext adapters, or upstream analysis.
# Those are reachable ONLY through the IDexCodeSource port, so the domain stays
# testable in isolation (see MockCodeSource) and faithful to androguard DAD.
#
# Run from anywhere; exits non-zero on any boundary leak.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
DAD="$ROOT/native/dad_cpp"

# Infrastructure / adapter includes the domain core must not see.
FORBIDDEN='dexkit\.h|flatbuffers|zip_archive|core_ext|analyze\.h|schema/|dexitem_code_source'

# ...and EVERY public header of core_ext, BY BASENAME. `native/core_ext/include`
# is PUBLIC on dexkit_ext, which dexkit_dad links, so those headers are on every
# dad_cpp TU's include path and are included WITHOUT the string `core_ext` in the
# path — which the pattern above matches. That is a transitive route the script
# could not see, and a review CONSTRUCTED it (dexllm#80): a dad_cpp probe that
# named `dexkit::DexItem` compiled and linked, via a core_ext header that in turn
# included `dex_item.h`, while this script reported clean. Deriving the list at
# run time means a header added to core_ext is covered the day it appears.
for h in "$ROOT"/native/core_ext/include/*.h; do
    FORBIDDEN="${FORBIDDEN}|\"$(basename "$h")\""
done

leaks="$(grep -rnE "^[[:space:]]*#include.*(${FORBIDDEN})" "$DAD" || true)"
if [[ -n "$leaks" ]]; then
    echo "✗ dad_cpp boundary leak — the domain core must not include infrastructure:"
    echo "$leaks"
    echo
    echo "Route the dependency through the IDexCodeSource port instead."
    exit 1
fi

echo "✓ dad_cpp boundary clean — domain depends only on stdlib + own headers +"
echo "  slicer dex types + the IDexCodeSource port (no DexKit / zip / FlatBuffers)."
