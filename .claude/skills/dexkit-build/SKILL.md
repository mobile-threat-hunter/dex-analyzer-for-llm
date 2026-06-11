---
name: dexkit-build
description: Rebuild the DexKit C++ core via ninja and reinstall the editable Python wheel. Run this every time any C++ source under vendor/dexkit_core/Core/, native/binding/, native/dad_cpp/, or native/core_ext/ is modified — the in-memory pip extension does NOT pick up rebuilt .so files automatically.
---

DexKit develops natively (C++ static lib + pybind11 module) and Python wraps it. Two directories are involved:

- Build artifacts: `<repo>/build/<wheel_tag>` — scikit-build-core names this per platform/Python (e.g. `cp313-cp313-linux_x86_64` on Linux, `cp313-cp313-macosx_14_0_arm64` on macOS). Discover it; never hardcode the name.
- Package root (for editable install): `<repo>` (the directory with `pyproject.toml`)

A correct rebuild ALWAYS runs both steps in this order — running ninja from inside the build dir, then pip install from the package root. Skipping the second step leaves the installed extension stale.

## Execute

Run this single chained command (platform-agnostic — discovers the build dir by its `build.ninja`; if none exists yet, the `pip install` does a full configure+build):

```bash
R="$(git rev-parse --show-toplevel)" && B="$(find "$R/build" -maxdepth 2 -name build.ninja -exec dirname {} \; 2>/dev/null | head -1)" && { [ -n "$B" ] && cd "$B" && ninja 2>&1 | tail -5; } ; cd "$R" && pip install -e . --no-build-isolation 2>&1 | tail -3
```

Report success only when both `Linking CXX shared module _dexkit_core...so` and `Successfully installed dexllm-0.0.1` appear in output.

## Common pitfalls

- `pip install -e .` from the build directory FAILS with "does not appear to be a Python project" — always cd to the repo root (`git rev-parse --show-toplevel`) first.
- If compilation fails, do not retry blindly — read the error and fix the C++ source. Do not work around by reverting changes unless the user asks.
