---
name: dexkit-trace
description: |
  Reproduce, isolate, and capture a stack trace for crashes / hangs / wrong output in the DAD-aligned
  C++ pipeline. Bisects to the offending method, runs it under gdb (segfaults) or with timeout
  (infinite loops), and surfaces the failing pass + IR state. Use when a sweep run shows a
  `class_crash` entry or a method hangs indefinitely.
---

## Crash categories addressed

| Symptom | Likely cause | Tool |
|---|---|---|
| Python `RuntimeError` | C++ exception (slicer `SLICER_CHECK`, `std::runtime_error`) | exception message in stderr |
| Segfault, exit code 139 | null deref in IR / writer; bad `var_map` lookup; cycle in `get_used_vars`/`ToString` | gdb backtrace |
| `UnicodeDecodeError` in Python | MUTF-8 surrogate or non-ASCII in C++ output bypassing `SanitizeUtf8` | hex-dump of return value |
| Hang (no return) | infinite loop in `RegisterPropagation`, `ControlFlow`, or recursive IR traversal | py-spy / SIGINT to get traceback |
| Stack overflow → exit code 134 | unguarded recursion in IR (see `GetUsedVarsGuard` precedent) | gdb backtrace will show deep recursion |

## Execute

**Step 1 — bisect to class:**
```bash
python << 'EOF' 2>&1 | tail -5
import sys; sys.stdout.reconfigure(line_buffering=True)
from loguru import logger; logger.remove()
import dexllm
from androguard.misc import AnalyzeAPK
APK = "<resolved_apk_path>"
dk = dexllm.DexKit(APK)
_, d_list, _ = AnalyzeAPK(APK)
for dex in d_list:
    for cls in dex.get_classes():
        name = cls.get_name()
        print(f"trying {name}", flush=True)
        try: dk.decompile_class_java(name)
        except Exception as e: print(f"  EXC {type(e).__name__}: {e}", flush=True)
EOF
```

The last "trying ..." line before a crash names the offending class.

**Step 2 — bisect to method:**
```bash
python << 'EOF' 2>&1 | tail -10
import sys; sys.stdout.reconfigure(line_buffering=True)
from loguru import logger; logger.remove()
import dexllm
from androguard.misc import AnalyzeAPK
APK = "<resolved_apk_path>"
TARGET = "<class_descriptor_from_step1>"
dk = dexllm.DexKit(APK)
_, d_list, _ = AnalyzeAPK(APK)
for dex in d_list:
    for cls in dex.get_classes():
        if cls.get_name() != TARGET: continue
        for em in cls.get_methods():
            desc = f"{em.get_class_name()}->{em.get_name()}{em.get_descriptor()}"
            print(f"trying {desc}", flush=True)
            try: dk.decompile_method_java(desc)
            except Exception as e: print(f"  EXC {type(e).__name__}: {e}", flush=True)
EOF
```

**Step 3a — segfault / stack overflow: gdb backtrace**
```bash
gdb -batch -ex "set pagination off" -ex run -ex "thread apply all bt 20" -ex quit \
    --args python -c "
import dexllm
dk = dexllm.DexKit('<resolved_apk_path>')
dk.decompile_method_java('<method_descriptor>')
" 2>&1 | grep -E "^#|signal|Program received" | head -40
```

**Step 3b — hang: py-spy + SIGINT**
```bash
# Terminal 1: start the hanging method (will hang)
python -c "
import dexllm
dk = dexllm.DexKit('<resolved_apk_path>')
dk.decompile_method_java('<method_descriptor>')
" &
PID=$!

# Terminal 2: attach py-spy / gdb
sleep 3
sudo py-spy dump --pid $PID
# Or: gdb -batch -p $PID -ex "thread apply all bt 30" -ex detach -ex quit
kill $PID
```

## Common fix patterns (precedents)

- **Cycle in IR traversal (stack overflow)** — see `GetUsedVarsGuard` in
  [instruction.cpp:35](../../../dex_analyzer/dad_cpp/instruction.cpp#L35). RAII thread-local visited
  set, return `{}` on re-entry. Required for any `get_used_vars` / `ToString` / `has_side_effect`
  that recurses through `var_map`.
- **Null deref in `Interval::GetEnd`** — added null guard at
  [node.h](../../../dex_analyzer/dad_cpp/include/node.h). DAD bug-compatible: `end_` stays nullptr
  when ComputeEnd finds no external successors.
- **MUTF-8 surrogate** — `SanitizeUtf8` at
  [decompiler.cpp:22](../../../dex_analyzer/dad_cpp/decompiler.cpp#L22). Escape non-ASCII as `\uXXXX`
  before returning to Python's strict UTF-8 stdout.

## Reporting

After identifying the failing method + pass, ALWAYS check androguard DAD's behavior on the same
method via [/dexkit-diff](../dexkit-diff/SKILL.md). If DAD also crashes (RecursionError,
AttributeError, etc.), the port is faithful and the fix is a defensive guard, not a behavior
change. If DAD succeeds where DexKit crashes, the port has a genuine bug — find the diverging
pass.
