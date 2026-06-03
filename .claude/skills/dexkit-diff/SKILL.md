---
name: dexkit-diff
description: |
  Side-by-side parity diff between androguard DAD (Python reference) and DexKit-DAD (our C++ port)
  for a given method descriptor. Use when investigating output divergence — confirms whether a
  defect is a port bug or matches DAD's behavior (in which case it's DAD-faithful and out of scope).
---

## Usage

```
/dexkit-diff <method-descriptor> [from <apk-path>]
```

## When to use

When `dk.decompile_method_java(desc)` produces output that looks wrong, the first question is
"does DAD produce the same wrong output?" Three outcomes:

1. **DAD matches DexKit (both wrong the same way)** — DAD bug we haven't tackled yet. Check
   CLAUDE.md "Deferred DAD quirks" (bug-for-bug faithful by design) or consider promoting to
   "Upstream DAD bug fixes" with a dual-track parity entry.
2. **DAD wrong, DexKit correct** — we've already fixed it upstream-of-DAD. Look for a
   `*DADFaithful` sibling in `util.cpp` etc.; the mismatch is intentional and counts as
   improvement, not divergence.
3. **DAD correct, DexKit wrong** — port bug. Use the diverging output region to narrow down
   which pass introduced the regression.

## Execute

```bash
DESC='<method_descriptor>'
APK='<resolved_apk_path>'

# DexKit-DAD output
python << EOF > /tmp/dexkit.txt 2>&1
from loguru import logger; logger.remove()
import dexllm
dk = dexllm.DexKit("$APK")
print(dk.decompile_method_java("$DESC"))
EOF

# androguard DAD reference output
python << EOF > /tmp/dad.txt 2>&1
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompile import DvMethod
_a, _d, dx = AnalyzeAPK("$APK")
cls, _, name, proto = "$DESC".replace('->', '|').replace('(', '|(', 1).split('|', 2)
for m in dx.find_methods(classname=cls, methodname=name, descriptor=proto):
    if not m.is_external():
        dv = DvMethod(m); dv.process(); print(dv.get_source())
EOF

diff -u /tmp/dad.txt /tmp/dexkit.txt | head -80
```

## Interpreting results

- **No diff**: byte-identical → port is DAD-faithful. Any "defect" must be addressed at
  DAD's level (a DAD bug) — either deferred (add to CLAUDE.md "Deferred DAD quirks") or
  fixed in production (add to "Upstream DAD bug fixes" with a `*DADFaithful` sibling +
  dual-track parity test). Precedents: `GetType` (fixed), `ParseParamsType` (Writer-side
  alternative to DAD's `GetParamsType`).
- **Diff present, DexKit looks better**: we already fixed a DAD bug — confirm via
  CLAUDE.md "Upstream DAD bug fixes" section. Not a regression.
- **Diff present, DexKit looks wrong**: port bug. Use the diverging region to narrow down.
  Common classes: `decompile.cpp` (pass ordering), `writer.cpp` (Java text emission),
  `instruction.cpp` (IR semantics), `dataflow.cpp` (def-use / propagation), `control_flow.cpp`
  (structuring).

## Caveats

- DAD's output may include surrogate-half MUTF-8 bytes that crash Python's `print()` on
  strict-UTF-8 stdout. Pipe through `iconv -f UTF-8//IGNORE` if needed.
- ExternalMethod refs: DAD's `DvMethod.__init__` crashes; our port returns empty. The
  "no diff" check should skip external refs (the `is_external()` guard above does that).
