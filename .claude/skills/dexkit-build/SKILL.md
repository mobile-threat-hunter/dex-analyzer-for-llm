---
name: dexkit-build
description: Rebuild the DexKit C++ core via ninja and reinstall the editable Python wheel. Run this every time any C++ source under vendor/dexkit_core/Core/, new_dexkit/binding/, new_dexkit/dad_cpp/, or new_dexkit/core_ext/ is modified — the in-memory pip extension does NOT pick up rebuilt .so files automatically.
---

DexKit develops natively (C++ static lib + pybind11 module) and Python wraps it. Two directories are involved:

- Build artifacts: `/home/nyahumi/Project/Dexkit/new_dexkit/build/cp313-cp313-linux_x86_64`
- Package root (for editable install): `/home/nyahumi/Project/Dexkit/new_dexkit`

A correct rebuild ALWAYS runs both steps in this order — running ninja from inside the build dir, then pip install from the package root. Skipping the second step leaves the installed extension stale.

## Execute

Run this single chained command:

```bash
cd /home/nyahumi/Project/Dexkit/new_dexkit/build/cp313-cp313-linux_x86_64 && ninja 2>&1 | tail -5 && cd /home/nyahumi/Project/Dexkit/new_dexkit && pip install -e . --no-build-isolation 2>&1 | tail -3
```

Report success only when both `Linking CXX shared module _dexkit_core...so` and `Successfully installed dexkit-py-0.0.1` appear in output.

## Common pitfalls

- `pip install -e .` from the build directory FAILS with "does not appear to be a Python project" — always cd to `/home/nyahumi/Project/Dexkit/new_dexkit` first.
- If compilation fails, do not retry blindly — read the error and fix the C++ source. Do not work around by reverting changes unless the user asks.
