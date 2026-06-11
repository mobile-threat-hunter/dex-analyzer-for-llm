#!/usr/bin/env bash
# Pack the project into a portable zip for moving to another machine.
#
# Excludes machine-specific build artifacts and regenerable caches so the
# archive rebuilds cleanly anywhere with `pip install -e .`. The vendored
# DexKit C++ core (vendor/dexkit_core) IS included — it is required to build.
#
# Usage:
#   scripts/make_portable_zip.sh [output.zip] [--no-apks]
#
#   output.zip   destination archive (default: ../<project>-portable.zip)
#   --no-apks    also exclude test_apk/ (~63 MB of sample APKs); examples and
#                tests then need an explicit APK/dex path instead of the
#                bundled corpus.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
proj="$(basename "$root")"

out=""
no_apks=0
for arg in "$@"; do
    if [ "$arg" = "--no-apks" ]; then
        no_apks=1
    else
        out="$arg"
    fi
done
out="${out:-$root/../${proj}-portable.zip}"

excludes=(
    "$proj/build/*"            # machine-specific CMakeCache (absolute paths)
    "$proj/.git/*"
    "*/__pycache__/*"
    "$proj/.mypy_cache/*"
    "$proj/.ruff_cache/*"
    "$proj/.pytest_cache/*"
    "*.so"                     # ABI-specific; rebuilt on target
    "$proj/.claude/settings.local.json"
)
[ "$no_apks" -eq 1 ] && excludes+=("$proj/test_apk/*")

rm -f "$out"
( cd "$root/.." && zip -r "$out" "$proj" -x "${excludes[@]}" >/dev/null )

echo "Wrote $out"
echo "Size:  $(du -h "$out" | cut -f1)"
echo
echo "On the target machine:"
echo "  unzip $(basename "$out") && cd $proj"
echo "  pip install -e \".[dev]\"     # builds the C++ core + reinstalls"
echo "  python -c 'import dexllm; print(\"ok\")'"
echo
echo "Prereqs there: C++20 compiler, Python 3.9+ dev headers (cmake/ninja are"
echo "pulled by scikit-build-core if missing)."
