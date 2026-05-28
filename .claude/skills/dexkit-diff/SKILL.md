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
"does DAD produce the same wrong output?" If yes, the defect is in DAD's algorithm — we're
bug-compatible by design (see `CLAUDE.md` "Deferred DAD quirks" section). If no, it's a
port bug.

## Execute

```bash
DESC='<method_descriptor>'
APK='<resolved_apk_path>'

# DexKit-DAD output
python << EOF > /tmp/dexkit.txt 2>&1
from loguru import logger; logger.remove()
import dexkit_py
dk = dexkit_py.DexKit("$APK")
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
  DAD's level (upstream patch) or via a Writer-side correction (see `ParseParamsType`
  precedent in writer.cpp).
- **Diff present**: port bug. Use the location (which class/pass) to narrow down. Common
  classes: `decompile.cpp` (pass ordering), `writer.cpp` (Java text emission), `instruction.cpp`
  (IR semantics), `dataflow.cpp` (def-use / propagation), `control_flow.cpp` (structuring).

## Caveats

- DAD's output may include surrogate-half MUTF-8 bytes that crash Python's `print()` on
  strict-UTF-8 stdout. Pipe through `iconv -f UTF-8//IGNORE` if needed.
- ExternalMethod refs: DAD's `DvMethod.__init__` crashes; our port returns empty. The
  "no diff" check should skip external refs (the `is_external()` guard above does that).
