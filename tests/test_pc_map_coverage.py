"""D-3 audit (dexllm#1): every emitted pc_map offset is a REAL instruction.

Acceptance-criterion #4: for a bounded corpus sample, walk both the text
`pc_map` and the AST `pc_map` and verify each offset corresponds to an actual
RawIns byte offset of that method (it appears as an `0xNN:` prefix in
render_method_smali). Catches an IR transform that silently rewrites a node to
a bogus offset, or an off-by-N in the harvest. Skips if no test APK.
"""

from conftest import smali_offsets

import dexllm


def test_offsets_land_on_real_instructions(loadable_apks):
    checked = 0
    cap = 2000
    for apk in loadable_apks:
        if checked >= cap:
            break
        dk = dexllm.DexKit(apk)
        for cls in dk.list_classes():
            if checked >= cap:
                break
            try:
                methods = dk.list_class_methods(cls)
            except Exception:
                continue
            for m in methods:
                if checked >= cap:
                    break
                try:
                    r = dk.decompile_method_java_with_pc(m)
                except Exception:
                    continue
                if not r["source"] or r["source"].startswith("// DECOMPILE ERROR"):
                    continue
                if not r["pc_map"]:
                    continue
                valid = smali_offsets(dk, m)
                if not valid:
                    continue
                checked += 1
                for ln, off in r["pc_map"]:
                    assert off in valid, (
                        f"{m}: text offset 0x{off:x} (line {ln}) not a real "
                        f"instruction"
                    )
                try:
                    d = dk.decompile_method_ast(m, include_source=False)
                except Exception:
                    continue
                for seq, off in d["pc_map"]:
                    assert off in valid, (
                        f"{m}: AST offset 0x{off:x} (seq {seq}) not a real "
                        f"instruction"
                    )
    assert checked > 0, "no method with a pc_map was sampled"
