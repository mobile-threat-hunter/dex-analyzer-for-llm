# CLAUDE.md — DexKit pybind11 wrapper

Project: C++ DexKit Core + pybind11 wrapper (`dexllm`) with an embedded DAD-aligned Java decompiler. Develop in C++ (mostly `vendor/dexkit_core/Core/dexkit/dex_item.cpp`), test via Python.

## DAD-aligned development policy

Decompiler implementation lives in `native/dad_cpp/`. It is being built as a faithful C++ port of androguard's DAD. Reference source: a local androguard checkout's `androguard/decompiler/` directory — set `$DAD_REF` to point at it (defaults to `$HOME/androguard/androguard/decompiler`; override per-machine with `export DAD_REF=...`). Every function added MUST carry `// DAD: <file.py>:<lineno> <concept>` in both code comment and commit message. If no DAD analogue exists, do not implement — discuss first.

A `PreToolUse` hook injects this reminder when editing `vendor/dexkit_core/Core/**` or `native/binding/**` C++ sources.

### Port status — `native/dad_cpp/` (COMPLETE — end-to-end pipeline working)

All 12 DAD modules ported. `dk.decompile_method_java(descriptor)` returns DAD-quality Java text on real APKs. 27 parity suites pass (25 DAD-module + 1 verifier regression/fuzz + 1 return-literal beyond-DAD; ~790+ cumulative checks), 0 regressions.

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

### Construct only builds reachable blocks — `catch (char vN)` fix (2026-06-17)

`Graph::Construct` ([graph.cpp](native/dad_cpp/graph.cpp)) previously built a `BasicBlock` + IR for **every** RawBlock in the snapshot, in block_id order. DAD's `graph.py:502 construct()` does `for block in bfs(start_block): make_node(...)` — only **reachable** blocks, in **bfs order**. Both halves matter, because `BuildNodeFromBlock` runs the opcode handlers, which mutate the **shared** register `Variable` via `set_type()` (`get_variables` = `vmap.setdefault`) and bump `gen_ret`:
- **reachable-set:** an unreachable dead block (`invoke …()C` + `move-result v0`) after a `return-void` set register 0's type to `"C"`; built *after* the reachable `move-exception v0` (Throwable), char won → `catch (char v0)` + `char v0_5 = new …` (invalid Java).
- **bfs-order:** among reachable blocks the last `set_type` on a reused register wins, so build order must equal DAD's bfs (else the catch/decl type resolves to a different — but still plausible — type than DAD).

**Fix:** replace the block-id loop with DAD's bfs — FIFO queue from `*snap.entry_block_id`, enqueue `rb.exception_handlers[].handler_block_id` then `rb.childs[].target_block_id` (matching `bfs()`'s exception-then-childs yield order), build only dequeued blocks. `nodes[]` stays block_id-indexed (unreachable = nullptr; edge-wiring null-guarded). Repro now byte-identical to DAD (`Throwable v0_2`). **Measured (apples-to-apples, same samples):** obfuscated-corpus per-method catch-type match vs DAD **23.4% → 89.4%** (the prior block-id build forced near-uniform `Throwable`, which itself diverged from DAD's int/boolean/class mix); tvleanback 500-sample **89.4% → 90.6%**; parity 26/26, sweep 0-crash/159,305-method unchanged. Detail: [[project-type-inference-catch-bug]].

### Conditional child-edge order must match androguard — bfs/rpo fidelity (2026-06-17)

`ComputeChildEdges` ([method_snapshot_builder.cpp](native/dad_cpp/method_snapshot_builder.cpp)) emitted a conditional block's children as `[Branch(target), BranchFalse(fall-through)]`. androguard's `determineNext` for the `if` opcodes (0x32-0x3D) returns `[fall-through, branch-target]` (`core/dex/__init__.py: [cur_idx+length, off+cur_idx]`), and DAD consumes `node.childs` order for **both** `bfs()` construction (→ shared-vmap `set_type` winner + `gen_ret` tmp numbering) **and** `graph.sucs()` (→ `compute_rpo` post-order → ins numbering). The reversed order flipped the bfs traversal of every diamond's two arms, so reused registers unified to a different (still-plausible) type than DAD and post-order numbering drifted corpus-wide. **Fix:** emit `BranchFalse` (fall-through) before `Branch` (target). Kind tags still drive `true_branch`/`false_branch` wiring in Construct, so order is free to match androguard. **Measured (same samples, on top of the bfs fix above):** obfuscated-corpus catch-type multiset match vs DAD **94.7% → 100%** (94/94 methods); tvleanback 500-sample **90.6% → 97.0%**; parity 26/26, sweep 0-crash/159,305-method unchanged. The residual catch diffs are now purely catch-clause *emit order* (same type multiset) — a try-structuring axis, not type inference. switch (default-first) and goto/return edges already matched androguard, so only the `if` arm needed reordering.

### LoopBlock must wrap any header node — `while () {}` collapse fix (2026-06-17)

Endless loops whose header `SplitIfNodes` turned into a plain `StatementBlock` collapsed to an empty `while () {}` (no condition, no body) — ~6% of tvleanback classes, the largest structural-fidelity gap after the snapshot-boundary fixes. Two coupled C++-port divergences from DAD's duck-typed model:
1. **`LoopBlock` couldn't hold a non-cond header.** DAD's `LoopBlock(node.name, node)` wraps **any** node in `self.cond` and delegates `get_ins`/`visit_cond`/body-visit to it. Our port split the wrapped node into typed `cond` (`Condition*`) / `cond_block` (`CondBlock*`) fields; a `StatementBlock` header `dynamic_cast`'d to null in both → wrapped node lost → empty body. **Fix:** added `BasicBlock* cond_node` holding the header regardless of type; `WhileBlockStruct` passes the generic `BasicBlock*`; the Writer/JSONWriter endless+posttest body-visit and `loop_get_ins`/`loop_get_loc_with_ins` go through `cond_node` ([basic_blocks.h](native/dad_cpp/include/basic_blocks.h), [control_flow.cpp](native/dad_cpp/control_flow.cpp), [writer.cpp](native/dad_cpp/writer.cpp), [dast.cpp](native/dad_cpp/dast.cpp)).
2. **`LoopType` used RTTI instead of the `.type` flag.** DAD's `loop_type` branches on `start.type.is_cond` — a flag `copy_from()` copied from the wrapped header (so a statement-wrapped `LoopBlock` has `is_cond == false` → `endless`). Our port used `dynamic_cast<CondBlock*>(start)`, which is **always** non-null for a `LoopBlock` (it subclasses `CondBlock`) → forced `pretest` → empty `while ()`. **Fix:** `LoopType` now reads `node->type.is_cond()` (the copied flag) for both `start` and `end` ([control_flow.cpp:148](native/dad_cpp/control_flow.cpp#L148)). `Node::CopyFrom` already copied `type`, so no other change needed. General lesson: where DAD branches on a `.type.is_*` data flag, the port must read that flag, NOT C++ RTTI — they diverge for wrapper nodes (`LoopBlock`).

**Measured (apples-to-apples, tvleanback):** empty `while ()` **104 → 17**; parity 26/26, sweep 0-crash/159,305-method unchanged; tvleanback 500-sample exact-match flat at 97.0% (fixed loops go from catastrophically-empty to body-present but still differ from DAD on inner-`if`/`break` structuring — a separate, smaller residual).

**Follow-up — short-circuit do-while condition (same day):** the remaining 17 empty `while ()` were actually empty `} while ()` on **posttest** loops with a compound latch condition. The Writer emitted the latch via `dynamic_cast<CondBlock*>(latch)->get_ins().back()->Accept()`, which only handles a single-instruction `CondBlock`; a `ShortCircuitBlock` latch (`(a) && (b)` do-while condition) has empty `get_ins()` → `} while ()`. DAD does `loop.latch.visit_cond(self)` (writer.py:271). **Fix:** Writer posttest now calls `latch_cond->visit_cond(wi)` — virtual dispatch emits the single ins for a `CondBlock` and the whole `Condition` tree for a `ShortCircuitBlock` ([writer.cpp](native/dad_cpp/writer.cpp)). Result: empty `while ()` **17 → 0** (e.g. `SsaDecoder.parseHeader` now byte-identical to DAD: `} while ((v0 != null) && (!v0.startsWith("[Events]")))`). parity 26/26, sweep 0-crash unchanged.

**Follow-up — `SwitchBlock.default_case` not remapped after split (same day):** the empty `if ()` cases were a stale switch-default pointer. `split_if_nodes` splits a multi-ins cond node into `-pre` (statement) + `-cond`, removes the original, and `update_attribute_with(node_map)` remaps every reference. `SwitchBlock::UpdateAttributeWith` remapped `cases` and `node_to_case` but **NOT `default_case`** — so a switch whose default target got split kept pointing at the removed 2-ins original node. The Writer follows `default_case` directly (`VisitNode(sw->default_case)`), visited that stale node, and `CondBlock::visit_cond` emits nothing when `ins.size() != 1` → empty `if ()` + the pre-statement's declaration leaking into the condition. DAD avoids this because it derives `self.default` in `order_cases()` (which runs *after* split) from the already-remapped `cases`; our port sets `default_case` at Construct time and defers `order_cases`. **Fix:** remap `default_case` through `n_map` in `SwitchBlock::UpdateAttributeWith` ([basic_blocks.cpp](native/dad_cpp/basic_blocks.cpp)). Result: empty `if ()` **14 → 0**; `PlaybackTransportControlGlue.onKey` now byte-identical to DAD. parity 26/26, sweep 0-crash unchanged. **All empty `while ()`/`if ()` on tvleanback are now eliminated (104+14 → 0).**

### do-while/endless loop body truncated — wrapped-header edges erased (2026-06-17)

The Writer emits a posttest (do-while) or endless loop BODY via `VisitNode(loop->cond_node)`, where `cond_node` is the original loop header that `WhileBlockStruct` wrapped into the `LoopBlock` and then `remove_node`'d. `EmitStatement`/`EmitIf` walk the body by following `graph_->sucs(cond_node)`. DAD relies on its `remove_node` leaving the wrapped node's **stale successor edges** intact, so `graph.sucs(loop.cond)` still returns the body's first node. **Our `remove_node` erases the node's own edges** (the ShortCircuit hang fix — see [[the hang root-cause section]]), so `sucs(cond_node)` came back empty and the body **truncated at the header's own instructions** — dropping the rest of the loop body and leaving body-local vars undeclared (`} while (int v3 >= T[] v2.length)`, `while (true) { stmt; }` with the inner `if` gone). **Fix:** in `WhileBlockStruct`, after `remove_node(n)`, restore `n`'s FORWARD successor edges (`graph.add_edge(n, map(suc))`) so the Writer's body walk continues ([control_flow.cpp](native/dad_cpp/control_flow.cpp)). Safe because `n` is out of `nodes`/`rpo` (later passes ignore it); only the Writer's forward `sucs(n)` read uses them. Result: `GridLayoutManager.onFocusChanged` byte-identical to DAD (full `while(true){ ...; if(v1!=null){...break...} }`); `LocalBroadcastManager.executePendingBroadcasts` do-while body complete + no decl-leak. parity 26/26, sweep 0-crash/159,305 unchanged, tvleanback structural mismatches 9→8. (Residual on executePendingBroadcasts: a deeper outer-do-while vs inner-while partition difference — DAD's own structuring is convoluted there; deferred.)

**Follow-up — restored edge must be ONE-WAY for NESTED loops (2026-06-18):** the restoration above used `graph.add_edge(n, map(suc))`, which is **two-way** — it also re-inserts `n` into `reverse_edges[suc]`. For a **nested** loop (inner header is a successor of the outer header), when `WhileBlockStruct` later wraps and `remove_node`s the **inner** header, its pred-walk (`for pred in reverse_edges[inner]: edges[pred].remove(inner)`) finds the outer header `n` there and **erases the restored `n→inner` edge** — so the outer loop body truncated right back to the header's own instructions (e.g. gson `JsonReader.skipQuotedValue` lost its entire `do { ... if (v1_0 >= v2) {...} ... } while(!fillBuffer(1))` body, leaving `do { int v1_0=this.pos; int v2=this.limit; } while(!fillBuffer(1))` + a `this.pos = int v4;` decl-leak elsewhere). DAD never hits this because its `remove_node` leaves `edges[node]` populated while the reverse side was already cleaned — its stale forward edges are effectively **one-way** (invisible to later pred-walks). **Fix:** restore the edge by appending to `graph.edges[n]` directly (with a dedup check) instead of `add_edge` — i.e. one-way, mirroring DAD's stale-edge semantics ([control_flow.cpp](native/dad_cpp/control_flow.cpp) `WhileBlockStruct`). Result: `skipQuotedValue` now byte-identical to DAD (full nested body + inner `while (v1_0 < v2)`); OURS-only `= primtype vN;` assign decl-leaks on a 12-APK obfuscated sample **3+ → 0**. parity 26/26, sweep 0-crash/0-timeout/159,305, tvleanback 500-sample exact-match flat at 98.0% (no regression — nested-loop methods absent from that sample). Hang-safe: the one-way edges live only on already-removed, entry-unreachable nodes, so `ShortCircuitStruct`'s `post_order` walk and the `preds(...).size()==1` gate never see them.

### in_catch must be seeded only on first-reached-via-exception — mis-scoped try (2026-06-18)

DAD `graph.py:468 make_node` sets `exception_node.in_catch = True` **only when the handler node is created fresh** (`if exception_node is None`) — i.e. the exception edge is the FIRST reference to that block. A block reached by normal flow first (or first-enqueued via a child edge in the bfs) stays `in_catch=False`, even if a later exception edge also targets it. Our port set `handler->in_catch = true` **unconditionally** during edge-wiring, so a block that is **both** a normal-flow merge point **and** a catch target got over-marked. `IfStruct`'s in_catch follow filter (a764b85) then wrongly excluded such a node as an if-follow → the cond was left unresolved (`follow["if"] = null`) → `CatchStruct` set `try_follow = null` → the try mis-scoped to wrap the entire rest of the method, the if's body was dropped, and the short-circuit condition De-Morgan-flipped (`(a != null) && b` → `(a == null) || !b`). **Fix:** mirror DAD's seed — in the bfs build loop ([graph.cpp](native/dad_cpp/graph.cpp) `Construct`), record `catch_seed[h]` only when a block `h` is **first enqueued via an exception edge** (exceptions are enqueued before childs per block), and set `in_catch` from that seed at build time; the unconditional `handler->in_catch = true` at edge-wiring is removed. The in_catch *filter* in IfStruct is unchanged (genuine catch tails are still first-reached via exception → still marked → still excluded, so the a764b85 fix holds). Repro `Lcom/alivc/component/capture/b;->i(Z)V` now structurally matches DAD (`try { if ((v1_3 != null) && (this.l0)) { unregisterListener } } catch {}` then the rest **outside** the try, modulo the `catch (X _)` vs `catch (X)` cosmetic); obfuscated-corpus empty-negated-`equals`-if methods **4 → 3**. parity 26/26, sweep 0-crash/0-timeout/159,305, tvleanback 500-sample 98.0% with **identical mismatch set** (zero regression), EasyPermissions.g (the a764b85 repro) still matches DAD. General lesson: where DAD sets an attribute at lazy node-creation time gated on `is None`, the port must reproduce the same first-touch semantics — an unconditional later pass over-applies it.

### TryBlock.num must delegate to try_start.num — dropped try/catch if-body (2026-06-18)

DAD `basic_blocks.py:270` defines `TryBlock.num` as a **@property returning `self.try_start.num`** (live). C++ has no properties: our `TryBlock` carried the inherited `num` **field** (default 0) plus an unused `Num()` method, and every reader uses `->num` on the field — `EmitIf`'s backward-jump heuristic (`cond.num > cond.true.num`), `IfStruct`, `post_order`. So whenever an `if`'s **true-branch was a TryBlock** (created by `CatchStruct`, field num stayed 0), `cond.num > 0` always held → EmitIf spuriously **negated** the condition, emptied the then-body, and `is_else = !(follow in (true,false))` then suppressed the else → the entire try/catch body was **dropped**. Symptom: Kotlin `when(String)` (hashCode switch + `.equals()` chain) cases vanished as `if (!s.equals("X")) {}` (empty, negated). **Fix:** copy `try_start->num` into the inherited field in the `TryBlock` ctor ([basic_blocks.cpp](native/dad_cpp/basic_blocks.cpp)) — safe because `CatchStruct` (the only creator) runs after `compute_rpo`/`number_ins` and is the last structuring pass, so `try_start->num` is final; the static copy equals DAD's live property value at every read. Repro `Lcom/pedro/rtmp/rtmp/RtmpClient;->handleMessages()V` **122 → 256 lines, now byte-identical to DAD** (the `_error`/`onStatus` case bodies restored); obfuscated-sample OURS-only empty-negated-`equals`-if methods **5 → 4**. parity 26/26, sweep 0-crash/0-timeout/159,305, tvleanback 500-sample 98.0% with **identical mismatch set** (zero regression). General lesson (same family as `LoopType` RTTI / interval-end element): where DAD exposes a value via a **live @property**, the C++ port must reproduce that value at the field every reader touches — a parallel accessor method nobody calls is invisible to `->num`.

### Interval end = content MEMBER not successor — loop-latch corruption fix (2026-06-18)

`Interval::ComputeEnd` ([graph.cpp](native/dad_cpp/graph.cpp)) is DAD `node.py:149 compute_end`: `for node in self.content: for suc in graph.sucs(node): if suc not in self.content: self.end = node` then `self.end = self.end or self.head`. DAD assigns `end` = the **content member** that has an external successor (last such in set order), then `loop_struct`/`mark_loop` use `interval.get_end()` as the loop **latch**. Our port assigned `end_ = the successor` and maximized the **successor's** num — so for a nested loop it could pick a node **outside** the interval (e.g. inner-loop head `0x40`, the successor of member `0x3e`). A latch outside the loop body corrupts `mark_loop`'s `e_num` bound → wrong `loop_type` (posttest instead of endless) → the outer loop collapsed to a spurious truncated `do { ... } while (v9 >= v0_5)` with a body-local var (`v0_5`) leaking into the condition. **Fix:** assign `end_ = member`; among members with an external successor pick **max-num member** as a deterministic, ASLR-proof tiebreak (DAD's set-iteration order is itself non-deterministic — observed it pick member `0x3e` on one run and `0x11a` on another for the same interval, both valid members, both correct; max-num reproduces DAD's `0x3e` here). Added the missing `end_ or head_` fallback. Repro `ParallelFromPublisher$ParallelDispatcher.drainSync` now emits the correct `while(true){ ... while(v9_0 < v0_5){...} }` endless structure, no `v0_5` decl-leak. parity 26/26, sweep 0-crash/159,305 unchanged, tvleanback 500-sample exact-match flat at 98.0% with **identical mismatch set** (the fix targets nested-loop methods absent from that sample — zero regression, the broken case was invalid Java not a matched line). General lesson (same family as the `LoopType` RTTI fix): where DAD assigns an attribute to the iterated **element**, the port must assign the element, not a derived value.

### Output determinism — pointer-keyed map iteration (2026-06-17, partial)

Python dicts/sets iterate in insertion order (deterministic); C++ `unordered_map`/`unordered_set` keyed by `NodeBase*` iterate in **pointer-hash** order, which **varies per process** (ASLR randomizes addresses). Where DAD relies on a dict's insertion order, our pointer-keyed equivalent made structuring — and thus decompiled output — non-deterministic across runs (within a process it's stable; a fresh `python` invocation can differ). In rare ASLR layouts this produced malformed output (e.g. an undeclared var leaking its type into a short-circuit cond: `(int v7 != 0) && (int v8 != 0)`). **Fixes (control_flow.cpp / node.cpp):** (1) `CatchStruct` — sort the `reverse_catch_edges` key collection by post-order `num` before structuring; (2) `Intervals` — iterate the interval `edges` map in interval-creation order (`owned_intervals`), matching DAD's dict insertion order, so the interval graph → `compute_rpo` → loop detection is stable; (3) `Node::UpdateAttributeWith` — sort `loop_nodes` by `num` after the dedup-set rebuild. Result: the frequent non-determinism is gone (an obfuscated APK that varied per run is now byte-identical across 20+ processes; `catch(primitive)` decl-leak eliminated). parity 26/26, sweep 0-crash. **(4) ROOT CAUSE — `MergeShortCircuit`** ([control_flow.cpp](native/dad_cpp/control_flow.cpp)): the rare residual (a short-circuit cond with flipped De-Morgan polarity, `(a==0)||(b==0)` vs `(a!=0)&&(b!=0)`) was bisected — via per-pass graph-signature hashing across 50 processes — to ShortCircuitStruct's merge. `MergeShortCircuit` collected a merged node's preds/dests into `unordered_set<NodeBase*>` (`lpreds`/`ldests`) and iterated them to `add_edge`, wiring the new node's edge vectors in **pointer-hash order**. That order seeds the next `post_order()` the merge loop walks → which short-circuits merge, and with what polarity, changes → fully non-deterministic output (DAD's Python `set` has the identical flaw; we diverge to be reproducible). **Fix:** sort `lpreds`/`ldests` by post-order `num` (ties → block name) before the `add_edge` loops. Verified: 3 obfuscated APKs that varied across runs are now byte-identical across 12–24 processes each; the previously-divergent reactivex/gson classes stable across 40. parity 26/26, sweep 0-crash. Output determinism is now complete on the tested corpus.

### Robustness — if-follow must match the cond's exception context (2026-06-17)

On exception-heavy obfuscated methods, `IfStruct` could select a **catch-handler tail** as an if's `follow`. Its candidate filter is `node is idom[n] AND len(reverse_edges[n]) > 1`, then `max num`. For an `if` inside a *try* block, a node reachable only through the catch handlers (`in_catch`) is dominated by the try entry (dominators use `all_sucs`, incl. catch edges) and often has the **max num**, so it won out over the real normal-flow merge. The Writer then emitted the catch body *inside the try* with the catch variable undeclared → uncompilable `android.util.Log.e("..", Object[] v7_9, InvocationTargetException v6_1)`. **Fix** ([control_flow.cpp](native/dad_cpp/control_flow.cpp) IfStruct): skip a candidate `n` when `n.in_catch && !cond.in_catch` — an if's follow is the branch merge, which lives in the cond's own exception context; a catch-only-reachable node is never a valid structured-if follow (DAD's graph/num state never picks it; we exclude it explicitly, keeping in_catch follows legal when the cond itself is in_catch). Result: `EasyPermissions.g` now byte-matches DAD; obfuscated array-in-condition decl-leaks halved (8→4 on a 50-APK sample); **clean tvleanback exact-match unchanged at 96.8%**, parity 26/26, sweep 0-crash. Remaining decl-leaks (~15 lines / 195k classes) have other deep try/loop-structuring roots — deferred.

### Production fix — invalid `catch (primitive)`/`catch (Object[])` → Throwable (2026-06-17)

On obfuscated dex, type inference sometimes lands a primitive (`I`/`Z`/…) or array (`[…`) descriptor on a move-exception (catch) variable, producing **uncompilable** `catch (int v)` / `catch (Object[] v)`. DAD emits these verbatim; we deliberately diverge (a real Dalvik catch target is always a Throwable subclass, so a non-`Lcls;` descriptor there is a type-inference artifact). **Fix:** in `visit_move_exception` ([writer.cpp](native/dad_cpp/writer.cpp)), if the catch variable's descriptor isn't a reference type (`Lcls;`), prefer the actual catch-handler type carried on the `MoveExceptionExpression`, else `Ljava/lang/Throwable;`. Measured on an obfuscated APK: `catch(primitive)` + `catch(array)` **→ 0** (was thousands corpus-wide); valid class catches (`catch (IOException v)` etc.) untouched (4444 preserved). parity 26/26, sweep 0-crash. This is a beyond-DAD production divergence (no `*DADFaithful` sibling needed — the parity suites don't assert catch emission, and DvClass e2e parity *improves* where DAD was invalid).

### Production fix — return-type-mismatched integer constants (Z/ref/F/D) (2026-06-18)

Every `const*` opcode builds the value as an **integer-typed** `Constant` (DAD `opcode_ins.py:263+` — `Constant(val, 'I'/'J')`); the boolean/reference/float/double-ness comes only from the **declared return type**. DAD emits the raw int verbatim, which is wrong (uncompilable, or wrong-valued) whenever the method returns a non-int type. **All four corrected in `visit_return` ([writer.cpp](native/dad_cpp/writer.cpp)), gated on the operand being a genuine integer Constant** (`get_type()` ∈ {I,J,B,S,C,Z} — so a typed reference constant like const-class `Ljava/lang/Class;` or const-string is NOT touched and emits its literal):

- **`Z` (boolean):** `return 0`/`1` → `return false`/`true` (no int→boolean coercion in Java). Repro `JobSchedulerServiceV.a()Z`.
- **reference / array (`L…;` / `[…`):** an integer `0` in an object register is the null reference → `return null` (no int→reference coercion). 5,892 occurrences on a 12-APK obfuscated sample → 0. **Guard is essential:** a const-class return (`Ljava/lang/Class;`, e.g. `Foo.class`) has `get_int_value()==0` but type `Ljava/lang/Class;` — without the integer-type gate it would be wrongly rewritten to `null` (caught in regression: tvleanback `getResourceClass()` dropped its `BitmapDrawable` literal → restored by the gate).
- **`F` (float):** the int holds the raw IEEE-754 binary32 bits → reinterpret + `%.9gf` (e.g. `return 1065353216;` → `return 1f;` for `1.0f`; widening would otherwise give the wrong value `1.07e9`). NaN/±Inf → `Float.NaN`/`Float.POSITIVE_INFINITY`/…
- **`D` (double):** the long holds raw binary64 bits → reinterpret + `%.17g` (`getMAX_VALUE()D` → `1.7976931348623157e+308`, `getMIN_VALUE()D` → `4.9406564584124654e-324`, `getNEGATIVE_INFINITY()D` → `Double.NEGATIVE_INFINITY`). Whole-number doubles (0.0/1.0) render as `0`/`1` — valid & correctly-valued via int→double widening.

Float/double literal formatting mirrors the core_ext EncodedValue IEEE754 helper (`FormatFloatLiteral`/`FormatDoubleLiteral`). Beyond-DAD divergence, catch-clamp precedent (no `*DADFaithful` sibling — parity suites don't assert return emission; e2e *improves* where DAD was invalid). The **AST path** (`decompile_method_ast`, dast.cpp `ins_to_stmt` ReturnInstruction) applies the identical correction (same integer-constant guard; NaN/±Inf via `LiteralFloatChecked`/`LiteralDoubleChecked` so the AST emits `Double.NEGATIVE_INFINITY` not `to_chars`'s invalid `-inf`) so the text and AST APIs agree. The const\*/high16 pre-shift uses the well-defined unsigned-shift idiom (negative `bbbb` left-shift is UB pre-C++20, and the F/D reinterpret consumes those bits). Locked in by **`tests/parity/return_literal_parity_test.cpp`** (27th suite, 24 checks: text+AST × Z/ref/F/D, NaN/±Inf, high16 negative shift, and regression guards that int/char returns stay numeric) — the fast, APK-free, deterministic gate. The through-the-binding end-to-end backstop is **`tests/test_return_literals.py`** (pytest; scans ~41k methods of the bundled corpus, asserts 0 type-mismatch violations, reaches the real `Float.NaN`/`Double.NaN` returns in `multiple_locale_appname_test.apk`, and checks text/AST agree). parity 27/27, sweep 0-crash/0-timeout/159,305. tvleanback byte-match-vs-DAD dips 98.0%→96.8% (methods now emit valid `false`/`null`/float-literal where DAD emits invalid `0`/`1`/raw-bits — a metric artifact of being more correct than the reference, not a regression; verified the new mismatches are all this divergence, and 2480 genuine `null` / 783 string / 48 class-literal returns are preserved).

### Production fix — float/double constants as raw IEEE bits in expressions (2026-06-18)

Same const-typed-int root as the return fix, but in **non-return positions**: a `const-wide` loads a double as type `"J"` (raw bits), and DAD emits the raw int wherever it's used — `p2 *= 4611686018427387904` (should be `*= 2.0`), `if (p9 < 4607182418800017408)` (`< 1.0`), `Math.pow(x, 1065353216)` (`, 1f`). Invalid VALUE (Java widens the long, giving e.g. 4.6e18 instead of 2.0). **Sound localized fix without IR type inference:** in a Dalvik float/double op BOTH operands are the same F/D type, so an integer-Constant operand beside an F/D-typed sibling (or in an F/D-typed slot) is definitionally the raw IEEE bits — reinterpret it (`emit_fp_const_typed`, [writer.cpp](native/dad_cpp/writer.cpp); `visit_expr_fp_typed`, [dast.cpp](native/dad_cpp/dast.cpp)). Wired into every position where the F/D context is reliably known: **binary expr, comparison, compound-assign, method-arg (via `InvokeInstruction::ptype()`), plain-assign (lhs type), array-store (element type), field-store (`visit_put_*` field type)** — text and AST both. Same integer-constant guard as the return fix (typed-reference constants untouched). **Measured (bundled corpus, canonical double bit-patterns):** ~hundreds → ~6; the residual is purely **type-inference-limited** — a variable (or array-load result) that holds a double but was not inferred as `D`, so no F/D context is visible at any position (the deferred type-inference bucket; e.g. `if (v9_25 < <1.0 bits>)`). Every position where the F/D context IS known is now covered. Beyond-DAD, catch-clamp precedent. parity 27/27, sweep 0-crash/0-timeout/159,305; tvleanback byte-match-vs-DAD dips further (new mismatches all verified OURS-more-correct, e.g. `* 100f` vs DAD's wrong `* 1120403456`). Guarded by `test_double_bit_patterns_largely_eliminated` in [tests/test_return_literals.py](tests/test_return_literals.py).

### Writer constant/keyword nits — string `"true"` + `while(true)` (2026-06-17)

Two text-Writer divergences surfaced by a same-line-count DAD differential:
- **String constant `"true"`/`"false"` lost its quotes.** `Constant::Accept` routed BOTH the boolean (`type=="Z"`) case and real String constants through `visit_constant_string`, and the Writer used a value heuristic (`if value=="true"||"false" → emit unquoted`). A `const-string "true"` (e.g. `Boolean.parseBoolean("true")`) is a String literal and got emitted as bare `true`. **Fix:** added `visit_constant_bool` (Z → unquoted `true`/`false`); `Constant::Accept` routes `type=="Z"` there; `visit_constant_string` now ALWAYS escapes/quotes (DAD `string()`). dast (JSONWriter) already discriminated by type (LiteralBool vs LiteralString) — unaffected.
- **`while(true)` spacing.** DAD emits the endless-loop keyword as `while(true)` (no space), unlike pretest `while (cond)`. We emitted `while (true)`. Fixed to match.

tvleanback 500-sample exact-match 96.6%→96.8%, bench 97.2%→97.6%; parity 26/26, sweep 0-crash unchanged.

**Follow-up — posttest do-while latch spacing (2026-06-18):** DAD writer.py:269 emits the posttest latch as `} while(` WITHOUT a space (same as endless `while(true)`; only pretest `while (` keeps the space). We emitted `} while (`. Fixed to `} while(` ([writer.cpp](native/dad_cpp/writer.cpp) `EmitLoop` posttest path). `JsonReader.skipQuotedValue` now byte-identical to DAD. parity 26/26, sweep 0-crash, tvleanback 500-sample 98.0% identical mismatch set (no posttest do-while loops in that sample's diff lines).

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
