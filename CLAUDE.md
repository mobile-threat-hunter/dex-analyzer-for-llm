# CLAUDE.md — DexKit pybind11 wrapper

Project: C++ DexKit Core + pybind11 wrapper (`dexllm`) with an embedded DAD-aligned Java decompiler. Develop in C++ (mostly `vendor/dexkit_core/Core/dexkit/dex_item.cpp`), test via Python.

## DAD-aligned development policy

Decompiler implementation lives in `native/dad_cpp/`. It is being built as a faithful C++ port of androguard's DAD. Reference source: a local androguard checkout's `androguard/decompiler/` directory — set `$DAD_REF` to point at it (defaults to `$HOME/androguard/androguard/decompiler`; override per-machine with `export DAD_REF=...`). Every function added MUST carry `// DAD: <file.py>:<lineno> <concept>` in both code comment and commit message. If no DAD analogue exists, do not implement — discuss first.

A `PreToolUse` hook injects this reminder when editing `vendor/dexkit_core/Core/**` or `native/binding/**` C++ sources.

### Port status — `native/dad_cpp/` (COMPLETE — end-to-end pipeline working)

All 12 DAD modules ported. `dk.decompile_method_java(descriptor)` returns DAD-quality Java text on real APKs. 26 parity suites pass (25 DAD-module + 1 verifier regression/fuzz; ~770+ cumulative checks), 0 regressions.

| C++ Module | DAD source | Status |
|---|---|---|
| util         | util.py (250 lines)          | **ported** — 8/10 (build_path + common_dom unblocked, in graph.cpp; merge_inner + create_png skipped). + `ParseParamsType` non-DAD helper for Writer multi-arg signature emission. Parity 17/17. |
| node         | node.py (166 lines)          | **ported** — LoopType/NodeType/Node/Interval (Interval::ComputeEnd implemented in graph.cpp). MakeProperties metaclass folded into explicit setters. Parity 35/35. |
| basic_blocks | basic_blocks.py (369 lines)  | **fully ported** — 11/11 classes + `build_node_from_block`. CondBlock::visit_cond, Condition::visit, Condition::Operand::visit_cond all wired. CondBlockOperand / ConditionOperand adapters added so DAD short-circuit pattern works in C++. Parity 52/52. |
| graph        | graph.py (560 lines)         | **fully ported** — Graph + GenInvokeRetName + Simplify + DomLt + SplitIfNodes + bfs/make_node folded into `Construct(MethodSnapshot)`. `Graph::MakeNode<T>` adds node-ownership for synthesised blocks. `UpdateAttributeWith` hoisted to NodeBase virtual. Parity 43/43. |
| instruction  | instruction.py (1397 lines)  | **fully ported** — 41/41 classes + CONDS + per-class `Accept(Visitor&)` (37 overrides). Cumulative parity 275/275 across 8 chunks. |
| opcode_ins   | opcode_ins.py (2023 lines)   | **fully ported** — 229 handlers + `kInstructionSet` 256-entry dispatch via `OpcodeKind` enum. C++ note: handler signatures differ per opcode, so the table maps to enum (not function pointers) and `DispatchInstruction` switches on the enum. Cumulative parity 220+43 across chunks A-F. |
| dataflow     | dataflow.py (500 lines)      | **fully ported** — 12/12. Also unlocked util's BuildPath + CommonDom. Parity 23/23. |
| control_flow | control_flow.py (442 lines)  | **fully ported** — 14/14 (intervals, derived_sequence, mark_loop, loop_type, loop_follow, loop_struct, if_struct, switch_struct, short_circuit_struct, while_block_struct, catch_struct, identify_structures, update_dom). TryBlock.try_follow added as scalar field (DAD overrides Node.follow dict, we keep both). Parity 13/13. |
| dast         | dast.py (766 lines)          | **fully ported** — `JSONWriter` ([dast.cpp](native/dad_cpp/dast.cpp)/[dast.h](native/dad_cpp/include/dast.h)) emits the full DAD nested-list AST. `decompile_method_ast(desc) → dict` now returns `{cls_name, name, proto, ret_type, params_type, access, source, found, ast}` where `ast` is the complete `get_ast()` dict `{triple, flags, ret, params, comments, body}` with all 50+ node types (Literal/BinaryInfix/MethodInvocation/IfStatement/SwitchStatement/TryStatement/...). `AstValue` JSON tree models DAD's nested lists/tuples; the binding converts it to native py objects (MUTF-8→UTF-8 decoded). `DvMethod::ProcessAst()` runs the same pipeline as `Process()` (graph build refactored into shared `BuildProcessedGraph()`) then emits via `JSONWriter` instead of `Writer`. e2e parity vs androguard DAD `dv.process(doAST=True)`: **90-95%** (residual = the same deferred IR-level buckets that limit the Writer text path — var-naming suffix, type inference, loop structuring — confirmed shared via `/tmp/dast_parity.py`, not dast-specific). C++ smoke test: `dast_parity_test.cpp` (25th parity suite). Known port-side approximation: float/double literals use `std::to_chars` shortest-round-trip + `.0` normalization to approximate Python's `str(float)`; exotic float reprs may diverge (rare — float/double constants are uncommon). |
| writer       | writer.py (782 lines)        | **fully ported** — Visitor-based with all 47 visit_X methods (DAD writer.py 1:1). DAD-faithful Java output including `if (cond) { } else { }`, `try { } catch (T _) { }`, `switch (x) { case N: ... }`, compound assigns (`x += 1`), inplace-if-possible patterns. |
| decompile    | decompile.py (627 lines)     | **ported (DvMethod + DvClass)** — full pipeline driver: Construct → BuildDefUse → SplitVariables → DCE → RegisterPropagation → PlaceDeclarations → SplitIfNodes → Simplify → IdentifyStructures → Writer. External method refs (no code in this dex) detected via empty access flags, return `""`. **DvClass.get_source ported** ([decompiler.cpp:151](native/dad_cpp/decompiler.cpp#L151)) — emits full Java class text (package + class header with access flags / extends / implements / interface keyword, field declarations with static-first/instance-second ordering and EncodedValue initializers, method bodies, closing brace). DvMachine still deferred — DexKit pybind11 handles APK-level enumeration. |
| decompiler   | decompiler.py (100 lines)    | **fully ported** — `Decompiler` facade with shared_mutex cache, exception-safe per-method decompilation, descriptor-string lookup via `IDexCodeSource::LocateMethod`. GIL released in pybind11 binding for true multi-thread decompile. |

### Snapshot ABI — `native/dad_cpp/include/method_snapshot.h` + `dex_code_source.h`

DexKit ↔ DAD boundary: `MethodSnapshotBuilder::Build(IDexCodeSource&, dex_id, method_idx) → unique_ptr<MethodSnapshot>`. Snapshot is immutable POD-ish DTO with:
- `MethodMeta` (cls/name/proto/access/lparams/triple)
- `RawIns[]` — pointer-stable, decoded `dex::Instruction` + pre-resolved `ConstRef` variant (String/Type/Method/Field) + pre-computed branch_target
- `RawBlock[]` — CFG (start_byte/end_byte/ins-span/childs/exception_handlers/payloads)
- `entry_block_id: optional<uint32_t>` (nullopt for native/abstract/external-ref)

Builder runs in 7 stages: decode → leaders → exception table → block split → CFG edges → payload attach. Strings come from DexItem (process-lifetime); snapshot lives shorter than DexItem.

**Malformed-dex safety — a load-time structural verifier is the single gate (see [native/core_ext/dex_verifier.h](native/core_ext/include/dex_verifier.h), THE safety contract):** `dexkit::ext::VerifyDex(bytes, size) → {ok, reason}` runs in `DexKitExt` *before* the core parses any dex — raw `.dex` before `AddImage`, each `classes*.dex` before feeding the core; a reject throws with a byte-level reason (siblings in an apk still load), surfaced via `dk.verify_report()`. It is a readable 1:1 port of AOSP ART `DexFileVerifier` (`art/libdexfile/dex/dex_file_verifier.cc`, `// ART :NNNN` anchors, AOSP as spec-reference not runtime dep): `CheckHeader`/`CheckMap`/`CheckIntraSection` (ids, string_data MUTF-8, type_list, class_def, class_data, code_item, encoded_array) / `CheckInterSection` (id ordering+uniqueness, descriptor-syntax + member-name validity, class_def semantics). **One deliberate divergence:** `VerifyInsns` (instruction-operand bounds — register/index/branch/switch/array-data targets) is NOT in ART's *structural* verifier (those live in the 6032-line runtime method_verifier we refuse to vendor); it is our bounded checker anchored to the Dalvik bytecode spec via the slicer's VerifyFlags/IndexType tables. **Out of scope** (stated in the contract): instruction dataflow semantics, annotations, call_site/method_handle, debug_info, adler32. **Validated:** clean corpus 0 false-reject, parity 26/26 (incl. verifier regression+fuzz suite), 400+ fuzz 0-crash, full sweep 0-crash, **ASan corpus + malformed-dex fuzz = 0 heap-overflow/UAF/SEGV** (was 66/120 SEGV pre-verifier). The earlier scattered in-decode guards (builder `SafeAt`-style clamps, dexitem `SafeAt`, branch/payload bounds) were **removed as redundant** once the verifier owns structural validity — the decode path now has a "VerifyDex-validated input" precondition. The few kept guards are NOT redundant and documented in the contract: API-boundary `if(idx>=table.size())` (caller-supplied indices), builder `SafeWidth` (safe-wrapper for OOB-by-design `GetWidthFromBytecode`), and [instruction.cpp:274](native/dad_cpp/instruction.cpp#L274) IR null-guard on move-result-without-invoke (dataflow — structurally unverifiable).

`safe.py` thread-isolation still guards *hangs* (not crashes); with the verifier crash-proofing the load+decode path, process isolation is no longer the planned crash-containment mechanism.

`DexItemCodeSource` (in `core_ext/`) wraps `dexkit::DexKit` — only file with both `dad_cpp/` and DexKit Core includes. `dad_cpp/` itself depends only on slicer headers, not DexKit internals.

This is a **hexagonal (ports & adapters)** boundary: `IDexCodeSource` is the port, `DexItemCodeSource` (prod) + `MockCodeSource` (test) are the adapters, and `dad_cpp/` is the domain core. Full map + role table in [docs/architecture.md](docs/architecture.md). The invariant — `dad_cpp/` must not `#include` DexKit / FlatBuffers / zip / core_ext — is enforced by [scripts/check_dad_boundary.sh](scripts/check_dad_boundary.sh) (run it after touching includes under `dad_cpp/`). Do **not** push hexagonal layering deeper into `dad_cpp/` internals: it would break the `// DAD:` 1:1 traceability and risk parity for no gain (pure transform pipeline, no internal I/O to isolate) — see the doc's rationale.

### Removed (no longer applicable)

- `data_provider.h` — old IDexDataProvider interface. Deleted. Replaced by `IDexCodeSource` + `MethodSnapshot`.
- `NullDataProvider` stub in `binding/module.cpp` — deleted.

### Fixed: non-deterministic ShortCircuitStruct hang — true root cause `90d0b79`

**Status: FIXED at the source (Graph::remove_node leaked stale edges/reverse_edges entries for removed nodes). The earlier mitigations (cap `6906cb7`, ShortCircuit local done-checks `a104e22`) were band-aids on the use site; the graph-side erase is the structural fix. Post-fix 30-iter sweep = 0/30 timeouts, 0/30 cap bails (vs 16.7% timeout rate pre-fix).** Keep using `safe_decompile_*` (see [safe.py](dexllm/safe.py)) in batch/automation code as belt-and-suspenders.

#### Original symptom (kept for context)

Repeated sweep runs (30+ iters) reproducibly exposed **non-deterministic hangs** in the C++ IR pipeline on a small set of classes:

| APK | Class | Hang frequency |
|---|---|---|
| `com.test.intent_filter.apk` | `Landroid/support/constraint/solver/widgets/Guideline;` (idx 197) | ~80% of hang events; appears every ~7 sweep iterations |
| `multiple_locale_appname_test.apk` | `Landroidx/appcompat/app/AppCompatDelegateImpl;` (idx 245) | seen |
| `multiple_locale_appname_test.apk` | `Landroidx/appcompat/app/WindowDecorActionBar;` (idx 276) | seen |

**Symptoms** ([/proc/PID/status](file:///proc/) capture during hang):
- `State: R (running)` — user-space tight loop, no syscall
- `wchan: 0` — single-thread spin
- Slow `VmRSS` growth (~150 KB/s during hang) — small ongoing allocation
- 100% of one CPU core
- Classes themselves are **deterministically fast** when decompiled standalone (Guideline = 0.06s/call, 30/30 OK). Hang only manifests in mid-sweep cumulative state and at a non-deterministic rate (~12-17% of sweep runs).

#### Confirmed root cause (P1b gdb backtraces + P1c in-memory merge log)

Two independent dumps both pinned the stack inside
`Graph::post_order` → `Graph::compute_rpo` → `ShortCircuitStruct` → `IdentifyStructures` → `DvMethod::Process`.
The outer `while (change)` loop in `ShortCircuitStruct` failed to reach a fixed point: Inside one inner-for iteration we merge `node` + `then_b`/`els_b`. The merged-away nodes are removed from `graph.nodes` and added to `done`, but `CondBlock::true_branch` / `false_branch` are raw pointers — when the next post_order entry has its branch still pointing at the just-removed node, the old code (only guarding `node` itself) merged on the stale pointer. `graph.remove_node(stale)` then no-ops (EraseFirst finds nothing) while `MakeNode<ShortCircuitBlock>` still fires → net +1 per iter forever. Specific trigger is process-local: whichever post_order order exposes the re-use. DAD Python omits the same guard but CPython dict iteration on n_map happens to give a benign order on the corpus.

#### Fix (final — commit `90d0b79`)

True root cause is in `Graph::remove_node` itself: it removed the node from `nodes` and `rpo` but **left the node's own entries in `edges` / `reverse_edges` intact**. Subsequent `graph.preds(removed)` / `graph.sucs(removed)` returned those stale lists, and `ShortCircuitStruct` used the size-1 predecessor count as its "is this still a valid merge target" gate — so the stale pointer passed the gate, MergeShortCircuit got called on a fully-removed node, the second remove_node no-oped, MakeNode still fired, net `+1` per iter forever.

The earlier a104e22 `done.count(then_b/els_b)` guards inside `ShortCircuitStruct` worked too but only blocked the *use*; this fix removes the *source* — the stale data — so any other pass that calls `graph.remove_node` benefits as well. The local ShortCircuit guards were reverted to keep that pass DAD-faithful at the algorithm level.

[graph.cpp:158](native/dad_cpp/graph.cpp#L158): after `EraseFirst(nodes, node)` / `EraseFirst(rpo, node)`, also `edges.erase(node)` / `reverse_edges.erase(node)` / `catch_edges.erase(node)` / `reverse_catch_edges.erase(node)`. Five extra lines, zero perf impact (single unordered_map erase per node-remove).

Post-fix verification: 30/30 sweeps → **0 timeouts, 0 cap bails, mean 12.05s** (no perf regression). 24 parity 100%, DvClass parity 90.4% unchanged.

DAD's `graph.remove_node` has the same leak; we deliberately diverge for the algorithmic-correctness reasons above. The earlier [control_flow.cpp:441](native/dad_cpp/control_flow.cpp#L441) max-iteration cap is retained as defense-in-depth — quiet on the bench corpus now, but still catches any future fixed-point regression.

#### Defense-in-depth: `safe_decompile_*` wrappers

`dexllm/safe.py` ([safe.py](dexllm/safe.py)) runs each call on a `daemon=True` thread with a wall-clock deadline (default 10s). If a future regression introduces another hang the cap above doesn't catch, the wrapper still keeps the caller alive — the hung thread leaks until process exit but the batch loop progresses. **Batch / CI / automation code MUST continue to use the safe wrapper.** Single-class interactive debugging from a REPL can use the raw binding (`dk.decompile_class_java(cls)`).

```python
from dexllm import safe_decompile_class_java, is_timeout_marker

out = safe_decompile_class_java(dk, cls, timeout=10.0)
if is_timeout_marker(out):
    # hit the safe deadline AND the IR cap didn't catch it — record and move on
```

Tools updated to use both the cap and the safe wrapper: `/tmp/full_sweep.py` (counts `class_timeout` separately from crashes), `tests/dvclass_parity.py` (per-APK + total `timeouts` column with warning footer).

### Upstream DAD bug fixes (production diverges from DAD, parity-faithful variant retained for tests)

Policy: now that the port reaches DAD parity, real DAD bugs with observable production impact get fixed in our production path. A `*DADFaithful` sibling is retained for byte-identical parity comparison against androguard DAD output. Dual-track parity tests assert **both** the fixed output (for production) and the buggy output (for DAD-compat).

- **`util.py:205 get_type`** — `atype[1:-1].lstrip('java/lang/')` is Python char-set strip, not prefix strip. DAD mangles `Ljava/lang/annotation/Foo;` → `otation.Foo` (and similar lowercase-leading subpackages). **Production `GetType` ([util.cpp:128](native/dad_cpp/util.cpp#L128)) now does proper `"java/lang/"` prefix strip** — emits `annotation.Foo`. DAD-faithful variant `GetTypeDADFaithful` ([util.cpp:174](native/dad_cpp/util.cpp#L174)) kept for parity test ([util_parity_test.cpp:88-92](tests/parity/util_parity_test.cpp#L88-L92)). Effect: 7,539-class scan across 3 APKs shows 102 spec-correct hits, 0 mangled residues; match-rate vs DAD unaffected on random-200/APK bench (mangle cases under-represented in random sample but always fixed when they occur).
- **`core/dex/__init__.py:1860 _getintvalue` for EncodedValue FLOAT/DOUBLE** — DAD reads `VALUE_FLOAT (0x10)` and `VALUE_DOUBLE (0x11)` payload bytes as little-endian unsigned int, then `DvClass.get_source` emits them as a Python int literal (invalid Java; androguard's own `# TODO: parse floats/doubles correctly`). **DexKit decodes IEEE754** ([dexitem_code_source.cpp:DecodeEncodedValueText](native/core_ext/dexitem_code_source.cpp)) — payload goes into LSB end of a 4/8-byte buffer, MSB end zero-padded ("zero-extended to the right"), then reinterpreted as `float`/`double`. Output uses `%.9gf` (binary32 round-trip) / `%.17g` (binary64 round-trip). NaN/Infinity emit as `Float.NaN` / `Float.POSITIVE_INFINITY` / `Double.NEGATIVE_INFINITY` etc. — valid Java literals. No `*DADFaithful` sibling because the decoder lives in core_ext (Dexkit-side) not dad_cpp; parity tests for this case are not byte-match-vs-DAD but smoke checks (e.g. `Float.MAX_VALUE` field emits `3.40282347e+38f`).
- **EncodedValue `VALUE_NULL (0x1e)` / `VALUE_BOOLEAN (0x1f)`** ([dexitem_code_source.cpp:DecodeEncodedValueText](native/core_ext/dexitem_code_source.cpp)) — DAD emits the **Python literals** `None` / `True` / `False` for null-reference and boolean static-field initializers (e.g. `public static final int[] FontFamily = None;`) — not valid Java. **DexKit emits spec-correct `null` / `true` / `false`.** Same core_ext / no-`*DADFaithful` precedent as the IEEE754 fix above. Found via a 2026-06-05 cross-tool comparison (614 `= None` lines on a single APK → 0). Sweep regression: 0-crash unchanged, 25 parity unchanged.

### Deferred DAD quirks (bug-compatible IR, Writer may diverge for correct Java)

The IR layer is bug-for-bug faithful (parity tests fail on divergence). For Writer's Java emission we sometimes split into a DAD-faithful IR helper + a corrected Writer-side helper so output is usable.

- **`util.py:227 get_params_type`** — `descriptor.split(')')[0][1:].split()` whitespace-splits a no-whitespace string → single-element list for multi-arg methods. `GetParamsType()` replicates the quirk for parity-test compatibility, but **all production call sites use non-DAD `ParseParamsType`** (`BuildMethodRef` in instruction_dispatch.cpp, `MethodMeta::params_type` in method_snapshot_builder.cpp, Writer signature emission). DAD's `get_params_type` only works correctly because androguard's `get_descriptor()` returns space-separated args like `(LA; LB;)V`; our internal proto is spaceless, so the quirk would drop args.
- **`basic_blocks.py:152 CondBlock.neg`** calls `self.ins[-1].neg()`. `ConditionalExpression::Neg()` and `ConditionalZExpression::Neg()` are implemented in our port (flip via CONDS table). `CondBlock::neg` dispatches via virtual `IRForm::Neg` — and we added a `virtual void Neg() {}` default on `IRForm` because C++ can't duck-type the `ins[-1].neg()` call DAD does. Side effect: in DAD, calling `.neg()` on a non-Conditional IRForm raises `AttributeError`; in our port it's a silent no-op. The call path is gated by `CondBlock::neg`'s `ins.size()==1` guard, so no observable difference on real input.
- **`basic_blocks.py:244 LoopBlock.visit_cond`** calls `self.cond.visit_cond(visitor)`. In DAD this is a `ShortCircuitBlock` (CondBlock subclass) that delegates to `cond.visit()` → `visit_short_circuit_condition`. Our `LoopBlock::visit_cond` ([basic_blocks.cpp:357](native/dad_cpp/basic_blocks.cpp#L357)) dispatches: `cond->visit(visitor)` for composite Condition, `cond_block->visit_cond(visitor)` for the single-CondBlock form. Without this, `while ((a < b) && (c == 0))` short-circuit loops emit empty `while () {}`.
- **`basic_blocks.py:247 LoopBlock.update_attribute_with`** calls `self.cond.update_attribute_with(n_map)` but `Condition` has no `update_attribute_with`. Same AttributeError pattern as line 244. Not implemented in our `LoopBlock` until a use site appears.
- **`basic_blocks.py:119 SwitchBlock.copy_from`** does `self.switch = node.switch[:]` which only works if the switch payload is list-like. DAD assumes it is; the actual payload is the raw fill-data object. Our port replicates as pointer-copy (DAD's slice on a non-list raises).
- **`basic_blocks.py:154/162 CondBlock.neg / visit_cond`** raise `RuntimeWarning` if `len(ins) != 1`. `raise RuntimeWarning(...)` IS a real raise in Python (RuntimeWarning is an Exception subclass) — the warning filter only affects `warnings.warn()` calls, not `raise`. So DAD would propagate the exception and `DvMethod.process` would die. Our port returns silently — divergent on this edge case, but the `len(ins) != 1` invariant is satisfied on every real method in the test corpus (159k methods, 0 trigger), so behavior matches in practice. If a future input violates the invariant, we'll see different output (we produce something; DAD crashes).
- **`writer.cpp:687 EmitIf swap null guard`** — our `EmitIf` swap (DAD `writer.py:319-326`) wraps the `cond.num > cond.true.num` comparison in `cond->true_branch != nullptr`. DAD would `AttributeError` on `None.num`; we skip the swap. Same invariant-driven non-trigger as above — no real-corpus difference.
- **`decompile.py:107 DvMethod.__init__` crashes on ExternalMethod** — `method.get_access_flags()` doesn't exist on ExternalMethod (only EncodedMethod). DAD relies on caller (DvClass) to catch AttributeError. Our port detects this case via empty `meta.access` (DexKit's adapter returns 0 access for external refs) and returns empty source string — **observable behavior matches DAD's effective output** (external refs disappear from class decompilation).

When DAD upstream fixes these, update util.cpp + util.h comments + parity tests in lockstep. When we fix one ahead of DAD, follow the dual-track pattern: production gets the spec-correct function, a `*DADFaithful` sibling is retained, and parity tests assert both.

### Root-cause fixes (replaces former masking guards)

Two earlier masking guards (`GetUsedVarsGuard` in instruction.cpp, thread-local visited in `Visitor::visit_ins`) hid a real port bug: `SplitVariables` was effectively a no-op, leaving un-split variables that `RegisterPropagation` then substituted into their own def chains → IR cycles → stack overflow.

Root cause was two `std::stoi("vN")` failures plus an incomplete `lvars` seed:

1. **`dataflow.cpp:345 GroupVariables`** — `in_lvars(s)` did `std::stoi(s)` where `s` is `"vN"` (e.g. `"v3"`). stoi raises `invalid_argument`, caught and returned false → every variable filtered out → `variables` map stayed empty → SplitVariables saw nothing to split. Fixed by stripping leading `'v'` before stoi.
2. **`dataflow.cpp:408 SplitVariables`** — same `std::stoi(var_str)` bug at the size-check fork. Same fix.
3. **`decompile.cpp:90 lvars construction`** — only seeded with `lparams_` (params). DAD seeds `var_to_name` with params, then `construct()` populates it with every register seen during CFG construction via `get_variables(vmap, reg)`. By the time `split_variables` runs, var_to_name covers all locals too. Mirror by walking the full `vmap_` and converting every `"vN"` key into its int form.

Two follow-up fixes after SplitVariables started actually running:

4. **`dataflow.cpp:577 PlaceDeclarations unreachable filter`** — `get_node_from_loc` returns nodes that are in the graph but unreachable from `entry` (so not in `post_order()`, no idom entry, `num=0`). Passing such a node to `CommonDom` would spin forever (no path to a common ancestor). Skip def_nodes whose idom is missing.
5. **`graph.cpp:730 CommonDom equal-num guard`** — defensive bail when `cur->num == pred->num && cur != pred`. With the filter in #4 this shouldn't trigger on normal input; kept as a belt-and-suspenders against any future malformed dominator tree (e.g. nodes with duplicate post-order numbers).

Result on the bench corpus: variable splits work (`v1_1`, `v0_3`, ...), match rate climbs from 73.8% → 82% on tvleanback-100, no regressions, ArgbEvaluator and previously-crashing methods all decompile cleanly. The two masking guards were removed.

### Later fixes (2026-05-28) — match 82% → 92.4%

After the SplitVariables root-cause fix, the remaining mismatch carrousel was attacked category-by-category:

| Fix | Where | Match Δ |
|---|---|---|
| Variable `Vid()` "v" prefix unified across SplitVariables | dataflow.cpp:431 | +2.2 |
| catch-all → Throwable default in `MoveException` | opcode_ins.cpp:160 | +1.0 |
| `const/high16` shift `<< 16` (slicer didn't auto-shift) | opcode_ins.cpp:181 | +0.8 |
| `super()` vs `this()` detection (ThisParam.super_flag) | writer.cpp:280 | +2.4 |
| `cmp` operator → real comparison op (BinaryCompExpression.set_op) | writer.cpp:455 | +1.2 |
| Switch-as-while: packed-switch as block leader + node_to_case wiring | method_snapshot_builder.cpp:301 + graph.cpp:619 | +0.8 |
| `fill-array-data` payload (add OP_FILL_ARRAY_DATA to IsBranchOpcode) | method_snapshot_builder.cpp:91 | +0.4 |
| `declared_synchronized` raw access flags (upstream DexKit patch) | vendor/dexkit_core/Core/dexkit/dex_item.cpp + dexitem_code_source.cpp | +0.4 |
| `// Both branches` comment form + else_diff visited check | writer.cpp:681 / 732 | +0.6 |
| String apostrophe escape (`\'`) | writer.cpp:35 | +0.6 |
| (var_to_declare insertion-ordered — no rate change, deterministic) | basic_blocks.cpp:90 | 0 |

Cumulative: 73.8% → **92.4%** (+18.6pp). Full sweep regression: **0 crash / 159,505 methods / 16,857 m/s** on the 22-APK corpus.

Deferred residual ~7.6%: see [[project-deferred-decompiler-tasks]] memory — dominated by `var_naming suffix off-by-N` (semantic-equivalent, 50%) and deep IR refactor (RegisterPropagation cascade order, type-inference policy, nested try/while CFG structuring) with very low ROI.

### Decompiler API surface (pybind11)

Exposed via `dexllm.DexKit(apk_path)`. The constructor identifies the file **by content, not extension** — a `dex\n` magic loads as a bare `.dex` via the core's `AddImage`; otherwise it must prove out as a real zip/apk container (PK signature + parseable central directory via `ZipArchive::Open`) and carry at least one sequential `classes*.dex`. A disguised `.apk` (renamed, wrong, or absent extension) therefore still loads; a non-dex/non-zip file or a zip with no `classes*.dex` now raises a clear `std::runtime_error` (the error reports whether `AndroidManifest.xml` was present) instead of the old silent 0-dex load. Detection lives in `DexKitExt::DexKitExt` ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)). Arg name stays `apk_path` for backward compatibility.

`dexllm.identify(path)` is the load-free probe behind the same logic — returns `{format: "dex"|"zip"|"unknown", is_apk, has_manifest, dex_count}` without constructing a `DexKit`. Use it to pre-filter resources-only containers (0-dex) before loading, e.g. in sweep harnesses (`dexkit_ext.cpp::Identify`, bound in [module.cpp](native/binding/module.cpp)).

| Method | Purpose |
|---|---|
| `decompile_method_java(desc)` | Java text decompile. **GIL released** during execution (parallel-safe). |
| `decompile_class_java(cls_desc)` | Full Java class text — `package`, class header (access + extends + implements), static→instance field declarations with compile-time initializers (EncodedValue decoded), then method bodies. Header+fields region is byte-identical to androguard `DvClass.get_source()`. |
| `decompile_method_ast(desc, include_source=True)` → dict | Signature components + Java `source` + full DAD `dast.py` nested-list `ast` (`{triple, flags, ret, params, comments, body}`). `include_source=False` skips the separate text-emit pipeline (AST and text emitters each mutate the graph, so they can't share one run) — ~1.7× faster for AST-only consumers. |
| `list_classes()` → list[str] | Every declared class descriptor across all loaded dexes. Replaces androguard's `AnalyzeAPK→get_classes` (100×+ faster). |
| `list_class_methods(cls_desc)` → list[str] | Every declared method's full Dalvik descriptor. |
| `identify(path)` → dict | Module-level. Content-based probe (no load): `{format, is_apk, has_manifest, dex_count}`. Proves a disguised `.apk` and pre-filters 0-dex containers. |
| `verify_report()` → list[dict] | Per-loaded-dex structural-verification verdict: `{dex_id, name, valid, reason}`. The malformed-dex gate (`VerifyDex`) runs at load; this exposes its results (a fully-rejected container raises at construction instead). |
| `decompiler_set_cache_capacity(n)` / `decompiler_cache_capacity()` | LRU cache cap (default 4096, 0 = unbounded). |
| `decompiler_clear_cache()` / `decompiler_cache_size()` | Cache lifecycle. |
| L1-L7 search family | Pre-existing find/match APIs (class/method/field by name/strings/annotation/etc). |

The class+method enumeration APIs let drivers (sweep, bench) drop the androguard dependency entirely. Last reference run: **full sweep 60s → 9.7s (6×)**, **DexKit vs androguard end-to-end 60× faster** (per-method decompile 6.3× faster, APK load 142× faster).

### Skills

`dexkit-build` is the production rebuild loop (ninja + pip install). Use `/dexkit-build` after any C++ change.

`.claude/skills/dexkit-{diff,decompile,sweep,trace,bench}/SKILL.md` are all active and aligned with the current `dad_cpp/` pipeline:

- `/dexkit-decompile <desc> [from <apk>]` — single method or whole class via the DAD pipeline
- `/dexkit-diff <desc> [from <apk>]` — side-by-side parity diff vs androguard DAD (with guidance on DAD-bug vs port-bug attribution)
- `/dexkit-sweep` — full-corpus regression (0-crash gate, ~16k m/s)
- `/dexkit-trace` — bisect crashes/hangs to method + capture stack trace
- `/dexkit-bench` — head-to-head perf benchmark with indent-normalized match rate

Bench output match rate normalization (`norm()` in the skill) strips leading whitespace per line — DAD emits class-context indent that DexKit's standalone-method output omits; without normalization match rate would read as 0%.

### Removed in 2026-05-26 audit — DO NOT REINTRODUCE

- **L6 entire decompiler subsystem** (~6033 lines) — Structurer class, ExprNode/IrStmt hierarchies, BuildCFG, CollectLeaders, BuildDomTree, BuildSsa, BuildStructuredIr, EmitStructured, RenderInstructionAsJava, etc. Not DAD-aligned, replaced by `dad_cpp/`.
- **Legacy expr-tree pipeline** (Phase 2a/2b/3/4/5/6/8e) — ~2450 lines.
- **`L6_NO_EXPR_TREE` / `L6_LEGACY_MODE` / `L6_SSA_MODE` / `L6_NO_POSTPASS` / `L6_SSA`** env flag gating.
- **Text-regex post-passes**: `PostInlineSingleUse`, `PostInlineShortExitTargets`, `PostStructureForwardGotos`, `PostEliminateDeadWrites`, `PostCollapseEmptyBlocks`, `PostSuppressUnusedLabels`, `PostSSARename`, `PostSuppressOrphanGotos` (Phase 22).

Structural defects must be fixed at the IR level (mirroring DAD's `control_flow.py` and `dataflow.py`), never via output text rewriting.

## Behavioral guidelines

Adopted from [karpathy-guidelines](.claude/skills/karpathy-guidelines/SKILL.md). Apply on every non-trivial task.

### 1. Think before coding
Surface assumptions. If multiple interpretations exist, present them — don't pick silently. If a simpler approach exists, say so. If unclear, ask.

### 2. Simplicity first
Minimum code that solves the problem. No abstractions for single-use code, no error handling for impossible scenarios, no speculative flexibility. If 200 lines could be 50, rewrite.

### 3. Surgical changes
Touch only what the task requires. Don't refactor adjacent code, don't reformat, don't delete unrelated dead code. Every changed line should trace to the user's request.

### 4. Goal-driven execution
State a brief plan with verification steps. For decompiler work, verification is **always** a sweep delta: counts before vs after the patch.

## Workflow defaults

- **Language**: Korean for user-facing responses. Code/comments in English.
- **Tools allowed**: in-process androguard, custom C++. **Forbidden**: jadx, any JVM/subprocess decompiler, prebuild of full APK.
- **Decompile model**: lazy per-class on-demand (JEB-style). Cache results.
- **Permissions**: `--dangerously-skip-permissions` is set — no pre-approval for tool calls.
- **Docs gate**: a `PreToolUse(Bash)` hook ([.claude/docs-precommit-check.sh](.claude/docs-precommit-check.sh)) blocks `git commit` / `git push` until the project docs (`README.md`, `CLAUDE.md`, `docs/*.md`) have been reviewed for drift against the change and any inaccuracies fixed in the same commit. After reviewing, re-run the same command prefixed with `DOCS_CHECKED=1` to bypass (e.g. `DOCS_CHECKED=1 git commit -m "..."`).

## C++ → Python rebuild loop

Every C++ change requires two atomic steps in this exact order:
1. `cd build/cp*-cp*-* && ninja` (scikit-build-core's platform build dir — name varies by OS/Python; don't hardcode `linux_x86_64`)
2. `pip install -e . --no-build-isolation` (from repo root)

A `PostToolUse` hook reminds when files under `vendor/dexkit_core/Core/` or `native/binding/` are edited. Run `/dexkit-build` to do both steps correctly.

## Memory safety — ASan checked (2026-05-28)

DexKit C++ side is ASan-clean. Build with:
```bash
cmake -B build/asan -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" .
ninja -C build/asan
```
Run with:
```bash
LD_PRELOAD="$(gcc -print-file-name=libstdc++.so.6) $(gcc -print-file-name=libasan.so)" \
    ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:abort_on_error=0:verify_asan_link_order=0" \
    LSAN_OPTIONS="suppressions=/tmp/lsan_suppress.txt" \
    python ...
```
Last run: 31,639 methods across 4 APKs — 0 leaks (DexKit code), 0 UAF, 0 invalid reads, 0 crashes. The library-order workaround (libstdc++ preloaded first) is needed because our `try/catch` around `std::stoi` exercises `__cxa_throw`. Background dependencies (lxml, cryptography, greenlet) leak some module-init memory; suppression filter at `/tmp/lsan_suppress.txt` filters those.

## Regression verification

Default success criterion for any decompiler change: **26 parity suites in `tests/parity/` must remain at 0 failures**, and end-to-end decompilation on `test_apk/APK/com.example.android.tvleanback.apk` must not crash.

Run parity sweep (build + run all 24 via CMake/CTest):
```bash
cd build/cp*-cp*-* && \
    ninja parity_tests && ctest --output-on-failure
```
Expected tail: `100% tests passed, 0 tests failed out of 24`.

End-to-end smoke check:
```bash
python -c "import dexllm; dk = dexllm.DexKit('test_apk/APK/com.example.android.tvleanback.apk'); print(dk.decompile_class_java('Landroid/support/v4/app/Fragment;'))" | head -50
```

For deeper validation, compare against androguard DAD on the same method:
```bash
python -c "
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompile import DvMethod
a,d,dx = AnalyzeAPK('test_apk/APK/com.example.android.tvleanback.apk')
for m in dx.find_methods(classname='Lcom/example/android/tvleanback/Utils;', methodname='getDisplaySize'):
    dv = DvMethod(m); dv.process(); print(dv.get_source())
"
```

## Test corpus

- Live corpus: `test_apk/APK/*.apk` (multi-APK)
- The old single `test.apk` no longer exists. Scripts that hardcode it must be updated.
- `capacity_large.apk` (555MB) loads but has 0 dex — skip.
- `lineageos_nexus5_framework-res.apk` — resources only, no dex.

## Skills available

- `/dexkit-build` — atomic ninja + pip install -e
- `/dexkit-sweep` — full-corpus regression sweep (crash/error/empty counts + throughput); primary success gate
- `/dexkit-decompile` — decompile one method or class via the DAD-aligned pipeline
- `/dexkit-diff` — side-by-side parity diff: androguard DAD (Python) vs DexKit-DAD (C++ port)
- `/dexkit-bench` — head-to-head perf benchmark + output parity rate
- `/dexkit-trace` — reproduce + bisect + capture stack trace for crashes / hangs (gdb / py-spy)
- `/karpathy-guidelines` — four behavioral principles (re-read when needed)

## Known structural patterns (don't re-derive)

- **Pipeline shape** (replaces the old L6 structurer + post-pass scheme):
  `descriptor → DexItemCodeSource → MethodSnapshotBuilder → DvMethod → Construct → BuildDefUse → SplitVariables → DeadCodeElimination → RegisterPropagation → PlaceDeclarations → SplitIfNodes → Simplify → IdentifyStructures → Writer.WriteMethod → Java text`. All passes mirror DAD's `decompile.py:DvMethod.process` step-by-step.
- **IR layer is DAD-faithful**: each instruction class has `Accept(Visitor&)` that mirrors DAD's `IR.visit(visitor)`. Writer (subclass of Visitor) implements all 47 `visit_X` methods 1:1 from DAD writer.py.
- **No more text post-passes**: structural defects must be fixed at the IR / structurer level (control_flow.py / dataflow.py mirrors), not in Writer output.
- **Slicer's `SLICER_CHECK` failures** are thrown as `std::runtime_error` (not aborts) so a single bad method doesn't kill the process. Don't revert.
- **External method refs** (entries in MethodIds without a ClassData in this dex) are detected via empty `access_flags` and produce empty Java output (matches DAD's effective behavior — DAD crashes on ExternalMethod, caller's try/except swallows).
