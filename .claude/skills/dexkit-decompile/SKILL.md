---
name: dexkit-decompile
description: |
  Decompile a single method (or class) via the DAD-aligned C++ pipeline and print the result.
  Argument is a Dalvik method descriptor (e.g. `LX/00D9;->equals(Ljava/lang/Object;)Z`) or a
  class descriptor (`LX/00D9;`), optionally followed by `from <apk_path>`.
---

## Usage

```
/dexkit-decompile <method-or-class-descriptor> [from <apk-path>]
```

If no APK is given, default to `com.example.android.tvleanback.apk` (~4135 classes, real-world
Android support library code — good coverage of if/else, try-catch, switch, synchronized).

## Execute

Single method:
```bash
python << 'EOF'
import dexkit_py
APK = "<resolved_apk_path>"
DESC = "<method_descriptor>"
dk = dexkit_py.DexKit(APK)
try:
    src = dk.decompile_method_java(DESC)
    print(src if src else "(empty — likely external method ref, no code in this dex)")
except RuntimeError as e:
    print(f"ERROR: {e}")
EOF
```

Whole class:
```bash
python << 'EOF'
import dexkit_py
dk = dexkit_py.DexKit("<resolved_apk_path>")
print(dk.decompile_class_java("<class_descriptor>"))
EOF
```

## Notes

- Descriptors with `$` for inner classes use Smali form (`LX/0F$Inner;`).
- Method protos use `(args)Ret` Dalvik shape.
- `<init>` and `<clinit>` are valid method names.
- Shell escaping: `$` may need `\$` if passed through bash; prefer Python heredoc.
- **External method refs** (entries in MethodIds without ClassData in this dex) return empty
  output — DAD-equivalent behavior, not a bug.
- Multi-dex APKs are fully supported; the descriptor is resolved across all dexes.
