# CLAUDE.md — DexKit pybind11 wrapper

Project: C++ DexKit Core + pybind11 wrapper (`dexllm`) with an embedded DAD-aligned Java decompiler. Develop in C++ (mostly `vendor/dexkit_core/Core/dexkit/dex_item.cpp`), test via Python.

## Development policy — DAD as reference, correctness first (relaxed 2026-07-04)

Decompiler implementation lives in `native/dad_cpp/`. It was **built** as a faithful 1:1 C++ port of androguard's DAD, and most of it still is — the port is the foundation and the `// DAD: <file.py>:<lineno> <concept>` anchors on ported code are kept for traceability. Reference source: a local androguard checkout's `androguard/decompiler/` directory — set `$DAD_REF` to point at it (defaults to `$HOME/androguard/androguard/decompiler`; override per-machine with `export DAD_REF=...`).

**DAD 1:1 fidelity is NO LONGER a hard constraint (user decision, 2026-07-04).** DAD is a weak-in-places reference (its `GroupVariables` last-write typing, its lack of a real type-inference / SSA pass), and the project already carries many **beyond-DAD** production divergences for correctness (the type-inference cascade/mirror/use-bound passes, return-literals, catch-clamp, `this`-materialise, void-invoke IR fix, …). New work now **optimizes for output correctness / quality (jadx-level), free to diverge from DAD** where DAD is wrong or absent — including replacing/superseding ported dataflow (e.g. splitting the genuine `has_ref && has_prim` merges that DAD's `GroupVariables` conflates, which a jadx-style SSA split resolves). A new function no longer requires a `// DAD:` analogue; a beyond-DAD one should say so in its comment.

**What actually protects quality now (these are the REAL gates, DAD-fidelity was never one of them):**
- **a/b snapshot 0-regression** over the whole corpus (bundled + obfuscated), measured OFF vs ON with the SAME script (never reuse another run's baseline).
- **determinism** — multi-process byte-identical output.
- **repeated 0-crash / 0-hang sweeps** (a non-deterministic hang can pass a single run — cf. the historical ShortCircuitStruct hang).
- **≥2 independent adversarial reviewers** (the mandatory review gate) + the HACK self-check (root-cause at the IR/dataflow layer, not Writer output masking).

**The 28 parity suites are now REGRESSION tests, not a blocker.** They verify the still-ported modules match DAD (useful — a large surface is unchanged), but a deliberate beyond-DAD divergence that changes a ported module's output is allowed: update or split the affected parity assertion (the `*DADFaithful` dual-track pattern) rather than treating a parity failure as a hard stop. Do not casually break parity — it's a valuable regression signal — but correctness wins when they conflict.

A `PreToolUse` hook injects a DAD reminder when editing `vendor/dexkit_core/Core/**` or `native/binding/**` C++ sources; treat it as context, not a mandate.

### Port status — `native/dad_cpp/` (COMPLETE — end-to-end pipeline working)

All 12 DAD modules ported. `dk.decompile_method(descriptor)` returns DAD-quality Java text on real APKs. 28 parity suites pass (25 DAD-module + 1 verifier regression/fuzz + 1 return-literal beyond-DAD + 1 MUTF-8 decoder differential-vs-ART; ~790+ cumulative checks), 0 regressions. `ctest` reports **29** — the 29th is `thread_pool_selfdestruct_test`, a concurrency regression (dexllm#50), not a parity suite.

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
| dast         | dast.py (766 lines)          | **fully ported** — `JSONWriter` ([dast.cpp](native/dad_cpp/dast.cpp)/[dast.h](native/dad_cpp/include/dast.h)) emits the full DAD nested-list AST. `decompile_method_ast(desc) → dict` returns `{class_descriptor, name, proto, return_type, param_types, access_flags, source, found, ast}` (four of those keys were `cls_name` / `ret_type` / `params_type` / `access` until dexllm#69) where `ast` is the complete `get_ast()` dict `{triple, flags, ret, params, comments, body}` with all 50+ node types (Literal/BinaryInfix/MethodInvocation/IfStatement/SwitchStatement/TryStatement/...). `AstValue` JSON tree models DAD's nested lists/tuples; the binding converts it to native py objects (MUTF-8→UTF-8 decoded). `DvMethod::ProcessAst()` runs the same pipeline as `Process()` (graph build refactored into shared `BuildProcessedGraph()`) then emits via `JSONWriter` instead of `Writer`. e2e parity vs androguard DAD `dv.process(doAST=True)`: **90-95%** (residual = the same deferred IR-level buckets that limit the Writer text path — var-naming suffix, type inference, loop structuring — confirmed shared via `/tmp/dast_parity.py`, not dast-specific). C++ smoke test: `dast_parity_test.cpp` (25th parity suite). Known port-side approximation: float/double literals use `std::to_chars` shortest-round-trip + `.0` normalization to approximate Python's `str(float)`; exotic float reprs may diverge (rare — float/double constants are uncommon). |
| writer       | writer.py (782 lines)        | **fully ported** — Visitor-based with all 47 visit_X methods (DAD writer.py 1:1). DAD-faithful Java output including `if (cond) { } else { }`, `try { } catch (T _) { }`, `switch (x) { case N: ... }`, compound assigns (`x += 1`), inplace-if-possible patterns. |
| decompile    | decompile.py (627 lines)     | **ported (DvMethod + DvClass)** — full pipeline driver: Construct → BuildDefUse → SplitVariables → DCE → RegisterPropagation → PlaceDeclarations → SplitIfNodes → Simplify → IdentifyStructures → Writer. External method refs (no code in this dex) detected via empty access flags, return `""`. **DvClass.get_source ported** ([decompiler.cpp:151](native/dad_cpp/decompiler.cpp#L151)) — emits full Java class text (package + class header with access flags / extends / implements / interface keyword, field declarations with static-first/instance-second ordering and EncodedValue initializers, method bodies, closing brace). DvMachine still deferred — DexKit pybind11 handles APK-level enumeration. |
| decompiler   | decompiler.py (100 lines)    | **fully ported** — `Decompiler` facade with shared_mutex cache, exception-safe per-method decompilation, descriptor-string lookup via `IDexCodeSource::LocateMethod`. GIL released in pybind11 binding for true multi-thread decompile. |

### Snapshot ABI — `native/dad_cpp/include/method_snapshot.h` + `dex_code_source.h`

DexKit ↔ DAD boundary: `MethodSnapshotBuilder::Build(IDexCodeSource&, dex_id, method_idx) → unique_ptr<MethodSnapshot>`. Snapshot is immutable POD-ish DTO with:
- `MethodMeta` (cls/name/proto/access/lparams/triple)
- `RawIns[]` — pointer-stable, decoded `dex::Instruction` + pre-resolved `ConstRef` variant (String/Type/Method/Field) + pre-computed branch_target
- `RawBlock[]` — CFG (start_byte/end_byte/ins-span/childs/exception_handlers/payloads)
- `entry_block_id: optional<uint32_t>` — nullopt ⟺ `ins_storage` is empty: no CFG
  to build (native/abstract/external-ref, or a code item with no decodable
  instruction — `insns_size == 0`, or payloads only). NOT keyed on `blocks`, which
  a try-range leader makes non-empty even with zero instructions. A value is the
  id of the block that CONTAINS the first decodable instruction — NOT necessarily
  block 0, whose span is the lowest LEADER and can hold no instruction at all
  (dexllm#75). It PROMISES `blocks[value]` exists; `Construct` consumes it six
  times unguarded and THROWS if a producer ever breaks it (dexllm#73)
- `entry_not_at_offset_zero: bool` — the first decodable instruction is not at
  byte 0, i.e. the body starts with a payload and what is decompiled is a
  REINTERPRETATION of a method no VM can enter. Both emitters mark it
  (dexllm#75)

Builder runs in 7 stages: decode → leaders → exception table → block split → CFG edges → payload attach. Strings come from DexItem (process-lifetime); snapshot lives shorter than DexItem.

**Malformed-dex safety — a load-time structural verifier is the single gate (see [native/core_ext/dex_verifier.h](native/core_ext/include/dex_verifier.h), THE safety contract):** `dexkit::ext::VerifyDex(image, size, check_insns, header_off) → {ok, reason}` runs in `DexKitExt` *before* the core parses any dex — raw `.dex` before `AddImage`, each `classes*.dex` before feeding the core; a reject throws with a byte-level reason (siblings in an apk still load), surfaced via `dk.verify_report()`. **Once per LOGICAL dex, not per file (dexllm#25, 2026-08-08):** `AddImage` runs `ParseLogicalDexOffsets`, which splits ONE image into a `DexItem` per embedded `dex\n` header, so verifying the image once at offset 0 let every later logical dex reach the core UNVERIFIED — a crafted concatenation made `find_classes_by_name` SEGV on a file `verify_report()` called `valid: True` (the `DexItem` ctor throws inside AddImage's ThreadPool lambda, the exception is swallowed, and the core's search loops deref the null). `DexKitExt::CollectImage` now verifies every slice (`LogicalDexSlices` mirrors the core's split rule; `AssertLoadedDexesWereVerified` refuses the load if the mirror and the core ever disagree, or if any `DexItem` came back null). All-verified → the image is handed over WHOLE (no copy, byte-identical to before); some-rejected → the survivors are copied into images of their own (`image_origin_.base_offset` keeps `extract_dex()["offset"]` reporting the position in the ORIGINAL container). A v41 CONTAINER slice is not salvageable that way (its offsets address the container) so it is rejected alongside its sibling. `VerifyDex`'s span is now ART's `DexFile::GetDataRange` (`dex_file.cc:240`): a standard dex is bounded by its own `file_size` (ART's rule — the previous whole-image bound is what let a concatenated tail's sections roam), a **v41 container** dex is based at the container and bounded by `container_size` (siblings SHARE a data section, so its `string_ids_off` legitimately sits past its own `file_size`); ART's v41 header self-consistency block (`dex_file_verifier.cc:670`) is ported too. Verified against AOSP's own `art/test/dexdump/multidex-container.dex`: both dexes verify and load (HEAD verified only the first, loosely). **Two review-driven additions, both CONFIRMED by BOTH reviewers with a running SEGV:** (1) **`kMaxLoadedDexes` (65536)** — `AssertLoadedDexesWereVerified`'s null-item scan did `GetDexItem(static_cast<uint16_t>(i))`, and the core's dex_id plumbing is uint16_t throughout, so index 65536 WRAPPED to 0: the scan inspected dex 0 twice and a null `DexItem` at any id ≥ 65536 was never seen. Reproduced with 65536 valid dexes + one that `VerifyDex` accepts but the slicer rejects (`link_size`/`link_off`, outside every structural check) → `verify_report()` all-valid → `find_classes_by_name` → SIGSEGV; boundary pinned exactly (poison at 65535 throws, at 65536 escapes). Fixed by REFUSING the excess in `EmitSliceVerdicts` — a **session-total** running limit on `next_dex_id_`, not per-image (a reviewer's explicit follow-up: many small sources exceed it in aggregate too), so an unaddressable id is never handed out; `AssertLoadedDexesWereVerified` re-checks the bound rather than assuming it. (2) **an inflated v41 `container_size` is REJECTED, not clamped** — ART clamps (`min(size, container->End() - data)`), but the slicer's own `ValidateHeader` (`SLICER_CHECK_LE(ContainerSize() - ContainerOff(), size)`) does not, so clamping let `verify()` call a dex loadable that the loader then threw on — a break of the documented `verify()` ≡ `verify_report()` equality (reproduced with `container_size = 0xFFFFFF00`). A deliberate divergence from ART, catalogued in [docs/aosp-oob-divergences.md](docs/aosp-oob-divergences.md) A3/A4. **Measured:** a/b over 37 corpus sources × {identify, verify strict+lenient, load, dex_count, per-dex class hash, extract provenance + bytes} = **0 diff** (0 false-reject), load time 200.2ms → 195.2ms (noise), parity 28/28, sweep 25,309-class / 213,374-method 0-crash 0-timeout, pytest 261, determinism 3 processes byte-identical. Guards: [tests/test_verifier_logical_dex.py](tests/test_verifier_logical_dex.py) (9 of 11 verified to FAIL against a pre-fix rebuild; the 2 that pass are declared non-discriminating by design — the fixture sanity check and the corpus-wide row↔dex_id invariant, which must hold on both sides). **Known conservative limitation:** a v41 container whose sibling fails verification is rejected WHOLE (a container dex cannot be salvaged apart from the data section it shares), so recoverable dexes are dropped rather than risk cross-reading. It is a readable 1:1 port of AOSP ART `DexFileVerifier` (`art/libdexfile/dex/dex_file_verifier.cc`, `// ART :NNNN` anchors, AOSP as spec-reference not runtime dep): `CheckHeader`/`CheckMap`/`CheckIntraSection` (ids, string_data MUTF-8, type_list, class_def, class_data, code_item, encoded_array) / `CheckInterSection` (id ordering+uniqueness, descriptor-syntax for **every** `type_id` — `CheckInterTypeIdItem`, added for dexllm#23 — as well as the field/method/class_def references to one, member-name validity, class_def semantics). **One deliberate divergence:** `VerifyInsns` (instruction-operand bounds — register/index/branch/switch/array-data targets) is NOT in ART's *structural* verifier (those live in the 6032-line runtime method_verifier we refuse to vendor); it is our bounded checker anchored to the Dalvik bytecode spec via the slicer's VerifyFlags/IndexType tables. **Out of scope** (stated in the contract): instruction dataflow semantics, call_site CONTENTS, debug_info, adler32, and ART's `offset_to_type_map_` (`CheckOffsetToTypeMap`) — the port is REFERENCE-driven where ART is MAP-driven, so the equivalent guarantee is per-structure and what is lost is type-confusion as a category. **`annotations` left that list in dexllm#56 (2026-08-18)** — see the section below; the short version is that "the core lazy-parses it" was the wrong test, and combined with the missing type map it was a SIGSEGV on a dex `verify()` called valid. **Validated:** clean corpus 0 false-reject, parity 26/26 (incl. verifier regression+fuzz suite), 400+ fuzz 0-crash, full sweep 0-crash, **ASan corpus + malformed-dex fuzz = 0 heap-overflow/UAF/SEGV** (was 66/120 SEGV pre-verifier). The earlier scattered in-decode guards (builder `SafeAt`-style clamps, dexitem `SafeAt`, branch/payload bounds) were **removed as redundant** once the verifier owns structural validity — the decode path now has a "VerifyDex-validated input" precondition. The few kept guards are NOT redundant and documented in the contract: API-boundary `if(idx>=table.size())` (caller-supplied indices), builder `SafeWidth` (safe-wrapper for OOB-by-design `GetWidthFromBytecode`), and [instruction.cpp:274](native/dad_cpp/instruction.cpp#L274) IR null-guard on move-result-without-invoke (dataflow — structurally unverifiable).

**Adversarial-review hardening (2026-06-21):** a multi-agent code review found two crafted-input OOBs that random byte-flip fuzz never reached (now fixed + ASan-verified with the exact triggers; regression in `tests/test_verifier_oob.py`), plus a deep-recursion crash: (1) **`CheckHeader` ID-table span** — the section-bound check passed each table's element COUNT to `CheckValidOffsetAndSize`, which validates a BYTE size, so a dex whose `class_defs_size` fits as bytes but whose `count*sizeof(ClassDef=32)` overruns the file OOB-read *inside the verifier* (uncatchable by its try/catch). Fixed by also bounding the byte span with the overflow-safe `CheckListSize` for all six id tables ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp) `CheckHeader`). (2) **payload parsers** — `ParsePackedSwitch/SparseSwitch/FillArrayPayload` ([method_snapshot_builder.cpp](native/dad_cpp/method_snapshot_builder.cpp)) trusted the payload's declared `size` ("fits by construction") but `VerifyInsns` only bounds a switch/fill-array *target* in-range, not that it points at a correctly-sized payload — a crafted target to a fabricated marker drove an unbounded heap-overread. Fixed by clamping each size-driven read to `end` (no-op on valid input; sweep 0-crash unchanged). (3) **emit-walk stack overflow** — the graph DFS/post_order passes were iterativized to survive large CFGs, but the structural emit walk (`Writer::VisitNode` / `JSONWriter::visit_node`) stayed recursive, so a crafted method with thousands of nested if/follow blocks overflows the native stack (an uncatchable SIGSEGV the per-method try/catch and `safe.py`'s hang-only wrapper can't contain). Fixed with a recursion-depth guard (cap 2000; throws → the existing catch yields an empty decompile; real methods never approach it — 0 hits across 25,309 classes, and the throw→catch path was verified by temporarily lowering the cap). All three fixes are DAD-parity-neutral (parity 28/28).

`safe.py` thread-isolation still guards *hangs* (not crashes); with the verifier crash-proofing the load+decode path, process isolation is no longer the planned crash-containment mechanism.

`DexItemCodeSource` (in `core_ext/`) wraps `dexkit::DexKit` — only file with both `dad_cpp/` and DexKit Core includes. `dad_cpp/` itself depends only on slicer headers, not DexKit internals.

This is a **hexagonal (ports & adapters)** boundary: `IDexCodeSource` is the port, `DexItemCodeSource` (prod) + `MockCodeSource` (test) are the adapters, and `dad_cpp/` is the domain core. Full map + role table in [docs/architecture.md](docs/architecture.md). The invariant — `dad_cpp/` must not `#include` DexKit / FlatBuffers / zip / core_ext — is enforced by [scripts/check_dad_boundary.sh](scripts/check_dad_boundary.sh) (run it after touching includes under `dad_cpp/`). Do **not** push hexagonal layering deeper into `dad_cpp/` internals: it would break the `// DAD:` 1:1 traceability and risk parity for no gain (pure transform pipeline, no internal I/O to isolate) — see the doc's rationale.

### Removed (no longer applicable)

- `data_provider.h` — old IDexDataProvider interface. Deleted. Replaced by `IDexCodeSource` + `MethodSnapshot`.
- `NullDataProvider` stub in `binding/module.cpp` — deleted.

### Fixed: non-deterministic ShortCircuitStruct hang — true root cause `90d0b79`

**Status: FIXED at the source (Graph::remove_node leaked stale edges/reverse_edges entries for removed nodes). The earlier mitigations (cap `6906cb7`, ShortCircuit local done-checks `a104e22`) were band-aids on the use site; the graph-side erase is the structural fix. Post-fix 30-iter sweep = 0/30 timeouts, 0/30 cap bails (vs 16.7% timeout rate pre-fix).** Keep using `safe_decompile_*` (see [safe.py](src/dexllm/safe.py)) in batch/automation code as belt-and-suspenders.

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

`src/dexllm/safe.py` ([safe.py](src/dexllm/safe.py)) runs each call on a `daemon=True` thread with a wall-clock deadline (default 10s). If a future regression introduces another hang the cap above doesn't catch, the wrapper still keeps the caller alive — the hung thread leaks until process exit but the batch loop progresses. **Batch / CI / automation code MUST continue to use the safe wrapper.** Single-class interactive debugging from a REPL can use the raw binding (`dk.decompile_class(cls)`).

```python
from dexllm import safe_decompile_class, is_timeout_marker

out = safe_decompile_class(dk, cls, timeout=10.0)
if is_timeout_marker(out):
    # hit the safe deadline AND the IR cap didn't catch it — record and move on
```

Tools updated to use both the cap and the safe wrapper: `/tmp/full_sweep.py` (counts `class_timeout` separately from crashes), `tests/dvclass_parity.py` (per-APK + total `timeouts` column with warning footer).

### Upstream DAD bug fixes (production diverges from DAD, parity-faithful variant retained for tests)

Policy: now that the port reaches DAD parity, real DAD bugs with observable production impact get fixed in our production path. A `*DADFaithful` sibling is retained for byte-identical parity comparison against androguard DAD output. Dual-track parity tests assert **both** the fixed output (for production) and the buggy output (for DAD-compat).

- **`util.py:205 get_type`** — `atype[1:-1].lstrip('java/lang/')` is Python char-set strip, not prefix strip. DAD mangles `Ljava/lang/annotation/Foo;` → `otation.Foo` (and similar lowercase-leading subpackages). **Production `GetType` ([util.cpp:128](native/dad_cpp/util.cpp#L128)) now does proper `"java/lang/"` prefix strip** — emits `annotation.Foo`. DAD-faithful variant `GetTypeDADFaithful` ([util.cpp:174](native/dad_cpp/util.cpp#L174)) kept for parity test ([util_parity_test.cpp:88-92](tests/parity/util_parity_test.cpp#L88-L92)). Effect: 7,539-class scan across 3 APKs shows 102 spec-correct hits, 0 mangled residues; match-rate vs DAD unaffected on random-200/APK bench (mangle cases under-represented in random sample but always fixed when they occur).
- **`core/dex/__init__.py:1860 _getintvalue` for EncodedValue FLOAT/DOUBLE** — DAD reads `VALUE_FLOAT (0x10)` and `VALUE_DOUBLE (0x11)` payload bytes as little-endian unsigned int, then `DvClass.get_source` emits them as a Python int literal (invalid Java; androguard's own `# TODO: parse floats/doubles correctly`). **DexKit decodes IEEE754** ([dexitem_code_source.cpp:DecodeEncodedValueText](native/core_ext/dexitem_code_source.cpp)) — the payload's stored bytes are the MOST significant ones ("zero-extended to the right", ART's `fill_on_right`), so they go to the MSB end of a 4/8-byte buffer and the LOW end is zero-padded, then reinterpreted as `float`/`double`. Output uses `%.9gf` (binary32 round-trip) / `%.17g` (binary64 round-trip). NaN/Infinity emit as `Float.NaN` / `Float.POSITIVE_INFINITY` / `Double.NEGATIVE_INFINITY` etc. — valid Java literals. No `*DADFaithful` sibling because the decoder lives in core_ext (Dexkit-side) not dad_cpp; parity tests for this case are not byte-match-vs-DAD but smoke checks (e.g. `Float.MAX_VALUE` field emits `3.40282347e+38f`). **This paragraph asserted the OPPOSITE rule until dexllm#70** — "payload goes into LSB end … MSB end zero-padded" — and the code matched the prose, so the two corroborated each other for a year; and the "smoke check" it names is not a test that exists anywhere in the repo (the `Float.MAX_VALUE` rendering is real, the assertion of it was never written) — the property it gestures at, that a FULL-WIDTH encoding is the one width where both readings agree, is pinned by dexllm#70's `test_a_full_width_float_still_renders`. See the dexllm#70 section below.
- **EncodedValue `VALUE_NULL (0x1e)` / `VALUE_BOOLEAN (0x1f)`** ([dexitem_code_source.cpp:DecodeEncodedValueText](native/core_ext/dexitem_code_source.cpp)) — DAD emits the **Python literals** `None` / `True` / `False` for null-reference and boolean static-field initializers (e.g. `public static final int[] FontFamily = None;`) — not valid Java. **DexKit emits spec-correct `null` / `true` / `false`.** Same core_ext / no-`*DADFaithful` precedent as the IEEE754 fix above. Found via a 2026-06-05 cross-tool comparison (614 `= None` lines on a single APK → 0). Sweep regression: 0-crash unchanged, 25 parity unchanged.
- **`writer.py:167` static initializer rendered as `static <ClassName>()` (2026-07)** — a `<clinit>` carries `ACC_CONSTRUCTOR` in dex (like `<init>`), so DAD's `write_method` (and our 1:1 port) takes the constructor branch and emits the class simple name + `()` → **`static l()`** (invalid Java) with a trailing **`return;`** (a compile error inside an initializer, JLS §8.7 — verified with javac). **Production `WriteMethod` ([writer.cpp](native/dad_cpp/writer.cpp)) detects `m.name == "<clinit>"` and emits a `static { }` block** — exactly the `static` keyword with NO name / return type / parameters, and NO other access modifier (a `<clinit>` may carry `ACC_PUBLIC` etc. in obfuscated dex, but `public static { }` is also invalid Java — code-review-hardening, 19/3137 bundled). The trailing `return-void` is dropped in `visit_return_void`, but **only when it is in TAIL POSITION** — nothing executes after it on any path, so fall-through is equivalent. Tail position is tracked STRUCTURALLY through the Emit* recursion (a `tail_pos_` flag, NOT the render indent): true through the top-level statement chain and into `if`/`else` branches whose `if` has no follow (the if is itself the tail — so `if (c){…return}else{…return}` at method end drops BOTH), and false inside loops / switch / try and non-tail branches. A genuinely-early return (code runs after it — e.g. Kotlin `PlatformImplementationsKt.<clinit>`'s `IMPL = x; return;` before outer code, or a `try{…return}catch{…}` whose catch would otherwise run) has `tail_pos_ == false` and is KEPT DAD-faithful (uncompilable but not wrong; fully fixing early returns needs if/else restructuring, deferred). `tail_pos_` is only READ when `is_clinit_`, so **non-`<clinit>` output is byte-identical** (verified 0 diffs / 188,065 bundled methods). This replaced an earlier `indent_ == clinit_base_indent_` proxy (a rendering-counter hack, flagged in review) with the real structural property — strictly cleaner and drops more (e.g. `ICUCompatIcs.<clinit>` 3→1 returns): bundled 4 + obfuscated 34 clinits improved, 0 regressions / 0 body corruption. **Safety PROVEN by an independent sound oracle** (`tests/test_clinit_tail_oracle.py`): the oracle recomputes tail position structurally from the AST (whose emitter is untouched by the drop and carries EVERY return node) — a return is tail iff it is the LAST statement of its block and that block is tail (if/else branches inherit the if's tail; try/loop/switch bodies non-tail), which is the correct structural notion (NOT the flawed `follow==null`). Across **19,582 `<clinit>` (3,137 bundled + 16,445 obfuscated)** the Writer dropped **0** returns the oracle marks non-tail, with **0** oracle undercount (it finds every AST return-void, so the check isn't vacuous) — e.g. `ICUCompatIcs` (2 tail dropped / 1 catch non-tail kept) and `PlatformImplementationsKt` (1 tail / 2 early non-tail kept) both verified. Two review agents initially disagreed (one flagged a `zzfiq.<clinit>` "regression" — REFUTED: the empty `if(v0_13==null){}` is a PRE-EXISTING DAD structuring artifact present in pure DAD at 4e83f14, and the dropped return was the safe trailing one, confirmed via the AST return position); the oracle settled it. The **AST path is unchanged**: `decompile_method_ast` carries the raw `<clinit>` name + a faithful return node (it's language-neutral structural data — a consumer applies Java rules), so it never produced `static l()`. No `*DADFaithful` sibling (parity suites don't assert method signatures — return-literal / catch-clamp precedent). **Measured (bundled corpus):** 3,137 `<clinit>` → 0 `static <ClassName>()` headers; 3,047 fully-valid `static { }` (no leftover return), 90 header-fixed with a kept nested return; `<init>` constructors unaffected (still `ClassName()`); 0 semantic changes, parity 28/28, sweep 188,065/0-crash. Guard: `tests/test_clinit.py` (header, outermost-return-drop, nested-return-preserved semantic guard, constructor-unaffected).
- **`dataflow.py:382 split_variables` — split version type from its own def (2026-06-25)** — DAD copies the original register's type to **every** split version (`new_version.type = orig_var.type`). When a register is reused across types — `const v0,#1` → `new-instance v0,LFoo;` → `iget v0,…:I` — `orig_var.type` is the **last** write (`I`), so the object version is mistyped **`int v0_x = new Foo()`** (invalid Java; the exact symptom dexllm#1/D-3 was built to surface). **Production `SplitVariables` ([dataflow.cpp:484](native/dad_cpp/dataflow.cpp#L484)) types each version from its DEFINING instruction's rhs** (`ins->get_rhs()[0]->get_type()` — the value actually assigned; new-instance → the class). Multi-def disagreement prefers a reference/array over a primitive (the bug direction); empty/absent rhs or a param version (dmin<0) keeps `orig_type`. **Move-source caveat (adversarial-review hardening):** a `vDst = move vSrc` def's rhs is the live, SHARED source `Variable`, whose `get_type()` reflects vSrc's LAST mutation — stale if vSrc is reused across types after the move. The dangerous direction is a stale primitive making an object version look primitive (the very bug), so a move source (`is_ident` rhs) is trusted only for a REFERENCE/array type (can only make the version more object-like, never wrongly primitive); an intrinsically-typed rhs (new-instance/const/field/invoke/cast — non-ident) is always trusted. No `*DADFaithful` sibling (a deep-pipeline transform, not a leaf emitter; the parity suites assert def/use chains and version COUNT, not version type — so they're unaffected and the change is beyond-DAD-correct; same "parity suites don't assert this axis" precedent as the return-literal/catch-clamp fixes). **Measured (before→after, master-revert+rebuild):** direct `prim v = new Ref();` bugs drop **5,408→92 on an obfuscated 4-APK / 10,618-method sample (−98.3%)**, **35,005→530 on an independent 30-APK / 274,948-method obfuscated sample (−98.5%, 0-crash, no new invalid-Java classes — catch/empty-if/empty-rhs all flat)**, and **1,490→31 on the bundled tvleanback corpus (−97.9%)** — the clean corpus carried the same DAD bug (the move-source ref-trust recovers a few extra correct move-defined declarations). Unit guard: `split-type` checks in `dataflow_parity_test.cpp` (object version typed `LFoo;`, int stays `I`, exactly-2-versions, + a move-source-ref case for the trust rule; fails without the fix). parity 28/28, sweep 0-crash, 0 new invalid-Java patterns. **Follow-up — `<init>`-result type fix (`FixInitResultTypes`, 2026-06-25):** the residual after the split-rhs fix was the `new-instance + invoke-direct <init>` pattern. DAD models it as `vRes = vBase.<init>()` (`opcode_ins.cpp` InvokeDirect, `returned = base`), and `InvokeInstruction::get_type()` for `<init>` returns the **live base (receiver) `Variable`'s type** (`instruction.cpp`). split_variables reads that to type the `<init>`-result version `vRes`, but `vBase`'s own version is finalized only in a **later** split iteration (vRes has the lower index) — so at read time `vBase` still resolves to the shared register carrying a STALE last-written type (e.g. a trailing `int` reuse) → `vRes` mistyped `int`; RegisterPropagation then faithfully inlines `new Foo()` into it, surfacing `int vRes = new Foo()` (RP is NOT the root). **A first attempt — typing `<init>` results inline from the static class (`cls()`) inside split_variables — regressed the clean corpus +12** by perturbing the multi-def derivation of object-or-null *conflated* merge variables; reverted. **Correct fix:** a separate pass `FixInitResultTypes` ([dataflow.cpp](native/dad_cpp/dataflow.cpp)) run AFTER split_variables (all bases finalized → `<init>` get_type() now correct) and BEFORE register_propagation (the `<init>` node still intact): re-read each `<init>` result's finalized base type and apply it only when the result is currently non-reference. It does NOT touch the split-time type derivation, so conflated merges are untouched. **Measured (master-revert+rebuild):** direct `prim v = new Ref();` drops **530→2 on the 30-APK / 274,948-method obfuscated sample** and **31→6 on the bundled corpus with ZERO new regressions** (25 fixed; the residual 6 are a different sub-pattern). Unit guard: `init-result` checks in `dataflow_parity_test.cpp`. parity 28/28, sweep 188,065/0-crash. **Follow-up — conflated object-or-null merges (new-array / range-`<init>` + `= null`, 2026-06-25):** the residual 6 were all the SAME shape — a SINGLE-version (unsplit) register holding `new X()` in one branch and `0`/null in another (`try { v = new byte[n] } catch { v = 0 }`); split_variables `continue`s on single-version registers, so they keep DAD's last-write type (int). Two coupled fixes: **(1)** `FixInitResultTypes` extended beyond `<init>` to also re-type a direct **new-instance** and **new-array** result (`v = new byte[]` → the static `[B`), plus a `cls()` fallback for `invoke-direct/range` `<init>` (`InvokeRangeInstruction` sets no `base_`, so its `<init>` get_type() returns the `"V"` rtype — use the constructed class). **(2)** beyond-DAD `= null`: a genuine integer `Constant 0` assigned to a now-correctly-REFERENCE lhs is the Dalvik null reference, so `write_inplace_if_possible` (writer.cpp / dast.cpp) emits `lhs = null` not the uncompilable `lhs = 0` (same integer-constant guard as the return-literal null fix; text + AST agree). A **`ThisParam` lhs is excluded** (adversarial-review hardening) — `this = 0` is the pre-existing DAD this-slot-reuse corruption (assignment to `this`, already invalid), kept DAD-faithful rather than silently diverging to `this = null`. Without #2, #1 just trades `int v = new byte[]` for `byte[] v = 0`. **Measured (bundled corpus):** direct `prim = new` **6→3** (new-array conflated fixed), invalid `refvar = 0` **134→0** (a pre-existing null-render bug surfaced + fixed corpus-wide), 0 new anomaly classes, parity 28/28, sweep 188,065/0-crash. Unit guard: `init-result: new-array re-typed [B`. **Follow-up — move-from-ALLOCATION target (the residual 3, 2026-06-25):** the 3 residuals (`Flow.measureChainWrap`) tracked to a `move-object vDst, vSrc` where `vSrc` is a new-instance (`new-instance v10` → `move-object v0, v10` → `invoke-direct/range {v0..v7} <init>`). The `<init>` results were already correctly typed (instrumentation confirmed); the mistyped variable was the **move TARGET** (`int v0_5 = new Flow$WidgetsList(...)` — id `v43`, type `I`). split_variables' move-source ref-trust read a STALE primitive for `vSrc` (its reference version finalized in a LATER split iteration than `vDst`), so it didn't trust it → `vDst` kept `orig_type` (int); RP then inlined `new X()` into it. **Fix:** `FixInitResultTypes` re-types a `vDst = move vSrc` target when `vSrc`'s single defining instruction is an **allocation** (new-instance / new-array) and `vDst` is non-reference. **The restriction to an allocation source is essential, found by adversarial expanded-sample review:** a first attempt that promoted ANY ref-typed move source mistyped genuinely-conflated int/ref registers (DAD reuses one Dalvik register for both) — uncompilable `String v = -1`, `SolverVariable v = 6`, an `int` loop counter typed as a reference then used in `arr[v]` / `v++` (19 regressions on a 14-APK obfuscated sample). A def-based "skip versions with a genuine-primitive def" guard cut that to 2 but couldn't reach 0 (the residual 2 were use-side-only conflation). An **allocation source carries no such ambiguity** — a register receiving `move newobj` IS that object — so the narrowed rule is **provably regression-free**: 0 prim→ref-misused regressions on bundled (188,065) + obfuscated (108,726), parity 28/28, sweep 0-crash. **Measured:** the 3 Flow residuals → correct `Flow$WidgetsList v = new Flow$WidgetsList(...)` (10 bundled lines, 2 obfuscated), 0 new anomalies. The broader move-from-method-result/catch correction (`int v = startService()` → `ComponentName v = …`) is **deliberately NOT attempted** here — separating a stale-typed reference from a genuine int/ref conflation needs a real type-inference pass (the large deferred work), not a heuristic post-pass. Unit guards: `init-result: move-from-alloc re-typed` + `move-from-nonalloc untouched`. Direct `prim = new` on the bundled corpus is now **0** (the 2 grep hits are `new X().getValue()` / `new BigDecimal().doubleValue()` chains whose result is a primitive — valid Java). **Follow-up — catch-Throwable conflation, single-def authoritative ref-override (2026-07):** the prior `FixInitResultTypes` guard only corrected a **non-reference** (int) result of `new`. But register conflation also produces a **WRONG-reference** result: a slot reused as a `catch (Throwable v)` variable makes split_variables type an `<init>` / new-instance result `Throwable`, surfacing invalid `Throwable v = new java.io.FileInputStream(...)` then `v.getChannel()` (root cause pinned on a real 7days sample — the `<init>` result v15 typed `Throwable`, `!is_ref` gate left it). **Fix:** for a **SINGLE-def AUTHORITATIVE** result (direct new-instance / new-array, or an `<init>` whose base resolves to the class — the constructed type is definitionally known), FixInitResultTypes now overrides even a reference when it DIFFERS from the constructed class (`fix = !is_ref(cur) || (authoritative && cur != bt && !multi_def.count(lid) && !ThisParam)`). A **move source is NOT authoritative** (kept non-ref-only, PR#7). **Multi-def is excluded** — a genuinely-conflated int/ref register typed as a supertype merge must keep its type. A **`ThisParam` lhs is excluded** (review-hardening): `super()`/`this()` via `invoke-direct/range` keeps `returned = base` (InvokeDirectRange has no ThisParam guard, unlike InvokeDirect which nulls the LHS), so the `<init>` result can be `this` with `cls()` = the SUPERCLASS — re-typing would corrupt `this` and flip the writer's super-vs-this detection (the multi_def guard happened to block the 6 in-corpus cases, but that's data-dependent; the exclusion makes it structural). **Measured (adversarial before/after, 34 APK / ~66k classes):** 756 type-declaration corrections, **0 structural changes, 0 wrong-type overrides, 0 valid→invalid, 0 crashes**; the catch-conflation bug signature (`ExceptionType v = new NonException()`) drops **bundled 4→2, obfuscated 206→65 (−68%)** — the residual are **multi-def** conflated registers (need a real version-level type-inference pass, the large deferred work, excluded here for safety). Side effect: a valid `List v = new ArrayList()` upcast narrows to the exact `ArrayList v = …` (always assignment-compatible, arguably more informative). No `*DADFaithful` sibling (same beyond-DAD emit precedent). Unit guards: `init-result: wrong-ref Throwable overridden to class` + `ThisParam not re-typed (this preserved)`. parity 28/28, sweep 188,065/0-crash, hexagonal-boundary-clean. **Follow-up — move-chain type CASCADE re-typing (2026-07):** the multi-def residual deferred above turned out to be dominated NOT by genuine int/ref merges but by a **type cascade**. A Phase 3 investigation (instrumenting `GroupVariables`, which is a standard SSA phi-web where two defs share a version only through a common use) classified each ref-typed multi-def version by its **transitive ground-truth producers** (resolving `move`s to their ultimate source): the large majority (≈275–308/obfuscated-APK) are **cascade** — ref-typed but with NO ground-truth reference producer, because a `move` copied a stale reference type off a sibling conflated register; the value is really a primitive flag → uncompilable `ArrayList v = 1;`. Genuine merges (a real allocation AND a real primitive both reaching a null-check) are far fewer (≈0–57/APK). So the dominant invalid-Java is a **typing** bug fixable with NO control-flow surgery. **Fix:** `FixInitResultTypes`' second pass re-types a cascade version to its (resolved-width) primitive descriptor when its transitive ground-truth producers are all primitive/null (NO new-instance/new-array/method-ref/field-ref/cast/exception anywhere in the def closure) AND the version is never used as an object (receiver of `v.m()`, owner of `v.f`/`v.f=…`). **def-anchored + use-corroborated**; the ground-truth classifier is SAFETY-FIRST (`'P'` primitive only when the producer's OWN type is a genuine primitive descriptor, `'R'` whenever the type is a reference, else `'U'`/`'M'` uncertain) so a real object is NEVER mislabeled primitive. **Adversarial-review hardening (2 independent reviewers):** re-type ONLY when EVERY def is definitively primitive/null — **any UNRESOLVED def (a move-cycle `'M'`, or a producer whose type we cannot determine `'U'` — e.g. an empty-typed `aget-object` off a mistyped array, or a `move` whose source chain doesn't bottom out in a definitive producer) BLOCKS the re-type** (it might be a hidden reference). This makes the reviewers' constructible-but-unconfirmed holes (incomplete object-use guard covering only receiver/field; `gt()` hiding a reference behind a move-cycle/no-def fallback) structurally unreachable: a genuine object always yields `'R'` or resolves to `'U'`/`'M'`, all of which block. The re-type width is the RESOLVED descriptor (`'I'`/`'J'`/…) so a `long`/`double` cascade is not narrowed to uncompilable `int v = <out-of-range>`. A version with BOTH a real allocation and a real primitive forcer is a **genuine** conflation (needs a version split — the next cut) and is left untouched. **Measured (reference-declared-nonzero-int invalid lines, before→after, hardened):** aggregate **422→26 (−94%)** on a 13-APK a/b (obfuscated APKs e.g. 61→1, 14→4; clean tvleanback 41→4); **0 regression on every axis** — `prim = new`, `prim.member`, `throw prim`, `prim[]` all byte-identical OFF→ON (the ~20 cases the hardening leaves vs the aggressive variant are provably-uncertain move-chains, correctly untouched). parity 28/28, sweep 0-crash / 51k-class, hexagonal-clean. Guard: `tests/test_cascade_type.py` (0 `prim = new`; a `prim`-used-as-object ceiling over the pre-existing Shape-B baseline; a bounded `RefType v = <nonzero int>` residual). No `*DADFaithful` sibling (same beyond-DAD emit precedent). Detail: [docs/type-inference-design.md](docs/type-inference-design.md). **Follow-up — the MIRROR direction (prim→ref, 2026-07):** the same cascade also occurs reversed — a **PRIMITIVE-typed** version whose ground-truth producers are a reference + null, mistyped `int` by DAD's last-write (the `= 0` def won). E.g. `int v9 = ObjectAnimator.ofFloat(...); … v9 = 0; … v9.addListener(); return v9;` — invalid (`int` used as an object / returned as `Animator`). This is the bigger population (Shape B: a primitive used AS an object — bundled ~349). The classifier `gt()` now carries the resolved concrete descriptor for `'R'` too, and `FixInitResultTypes` runs a **two-phase classify-then-apply** (reads only pre-mutation types so the two directions can't interfere) that re-types a primitive version to the (agreeing) reference class when its producers are a reference + null with NO genuine primitive forcer, no unresolved def, and no disagreeing references — the `= 0` then renders `= null`. The `!has_prim` guard keeps a genuine int/ref merge untouched (the PR#7 direction). **Sound by the same valid-Dalvik argument** (an all-reference value can't be used as an int, so a `!has_prim` version is genuinely a reference). **Measured (a/b, mirror on vs off, 7 APKs):** `prim`-used-as-object **249→111 (−138)**, with **0 new `ref = int` and 0 new `ref`-used-as-int** (`v+1`/`v<n`/`arr[v]`/`v++` all delta 0), cascade `ref_int` unchanged (26→26), `prim = new` 0. parity 28/28, sweep 0-crash / 51k-class, hexagonal-clean. **Adversarial-review hardening of the mirror (2 independent reviewers, gate-enforced):** the initial mirror was UNSOUND on register-conflated obfuscated dex — a CONFIRMED regression (`Ld/u/e;->l(...)`): a Dalvik register holding an `int` limit AND a `String` param, split into a single version whose defs are `[N:const-0, R:String-param]` (the primitive nature only in the USES), was re-typed `String` → uncompilable `String v6; v6 <= null; v6 - 1`. Two coupled fixes: **(1) `gt()` move-source no longer short-circuits on the first `'R'`** — it aggregates ALL sibling defs and returns `'U'` (block) when a source mixes a reference and a primitive (the short-circuit had INVERTED safety polarity for prim→ref: it swallowed the primitive sibling so a genuine merge looked pure-reference). **(2) USE-CORROBORATION for prim→ref (symmetric to the ref→prim `object_vids`):** an `int_use_vids` set (arithmetic operand, array index, ORDERED comparison `< <= > >=` operand — `==`/`!=` excluded as valid ref/null checks) blocks the mirror on any version used as an int. Both make the pass sound for lenient/unverified dex, not only verifier-guaranteed input. Plus the allocation `'R'` branch guards `type_out` with `is_ref` (consistency). **Verified (a/b mirror on vs off):** the `v6` case → correct `int v6`; **0 new `v <op> null` / ref-used-as-int on bundled (delta 0) and obfuscated (80→80)** — a residual ~109 `v <op> null` on bundled is PRE-EXISTING (a separate split_variables/init-result typing bug, present mirror-off, out of scope); Shape B still fixed (prim-used-as-object deduped ~262→60). parity 28/28, sweep 0-crash. Regression tests added: `test_mirror_does_not_flood_ref_used_as_int` (bounded `v <op> null`) + deduped `test_primitive_used_as_object_bounded`. The mirror's `!has_prim`-only guard was proven insufficient by the review — an int-used version can look all-reference on its defs when the reference arm is a moved-in param. **Follow-up — single-def method-result mistypes (ref→prim, use-corroborated, 2026-07):** investigating the pre-existing `v <op> null` residual surfaced a larger bug — a lone **primitive-returning method** typed a REFERENCE by register conflation, then used as an int (`String v2_6 = p10.indexOf(44); if (v2_6 >= null) …; v2_6 + 1` — uncompilable). The cascade previously **skipped single-def versions** (`dvec.size() < 2 continue`); the pass now processes them, re-typing a single-def ref version to its resolved primitive when it is **int-USE-corroborated** (used as an arithmetic operand / array index / ordered comparison) — width-correct (`Long.parseLong` → `long v2_1`, `indexOf` → `int v2_6`). A single-def version never used as an int is ambiguous (`String v = indexOf(); return v`) → left untouched. The prim→ref mirror stays **multi-def only** (conservative). Two adversarial-review nits fixed: (1) `instanceof` (a `BinaryExpression` whose arg1 is the tested OBJECT) is excluded from `int_use_vids` (precision); (2) a `boolean` (Z) def reaching an int use is a genuine boolean/int conflation neither type resolves (`boolean v; v + 1` invalid, `int v = booleanMethod()` invalid) → left untouched (B/S/C stay re-typed — `byte v; v + 1` is valid via numeric promotion). **Verified (adversarial review, 1155 re-types / 6 obfuscated apks, 0 valid→invalid regressions; a/b HEAD vs change):** ref-declared-used-as-int **239→66** (−72%), `v <op> null` **109→53**, boolean-arith **18→18 (delta 0, pre-existing)**, `prim = new` 0, prim-used-as-object flat (60→55), parity 28/28, sweep 0-crash / 58k classes. The residual `v <op> null` (~53) is a genuine int/ref merge (a ref DEF + int use) needing a version split. Regression test `test_ref_used_as_int_bounded` (bounded `v <op> null`). **Follow-up — vs-zero comparison int-use (the "version splitting" residual was a GAP, 2026-07):** investigating the `v <op> null` residual as a version-split candidate revealed it was NOT a genuine merge but a MISSING int-use pattern: `Object v0_2 = this.zza(p3); if (v0_2 < null); this.zzpka.get(v0_2)` (zza returns an int search index). The `v0_2 < null` is an `if-ltz` (compare-vs-zero) = a **`ConditionalZExpression`** (single operand), which `int_use_vids` only covered for the two-operand `ConditionalExpression`. Adding the ordered vs-zero forms (`if-ltz/lez/gtz/gez` → `<`/`<=`/`>`/`>=`; `if-eqz/nez` = the reference null-check, excluded) completes it — `Object v0_2 = zza()` → `int v0_2`, `v0_2 < null` → `v0_2 < 0`. **Measured:** `v <op> null` **53 → 11**, ref-declared-used-as-int **66 → 35**, 0 regression (prim=new 0, boolean-arith 18→18), parity 28/28, sweep 0-crash / 68k classes. **Two independent adversarial reviewers: SOUND / 0 findings** — the `==`/`!=` exclusion is negation-stable (`ConditionalZExpression::Neg` flips via a `CondsTable` with disjoint `{==↔!=}` / `{<↔>=,<=↔>}` partitions, so a null-check can't be structured into an ordered op), and the blast radius is bounded (int_use only unlocks the already-primitive-looking single-def cascade / conservatively blocks the mirror — never re-types a def-proven reference). **Lesson: the requested "version splitting" was mostly a use-corroboration gap; a simple symmetric fix beat a risky control-flow transform.** Test ceiling `test_ref_used_as_int_bounded` tightened (~11). **A separate PRE-EXISTING bug remains deferred:** split_variables/init-result typing an ordered-compared variable as a reference (the residual is that, not this pass), plus the true genuine-merge (`has_ref && has_prim`, ~11 `v <op> null`) that would need an actual version split. **Follow-up — width-resolved use-driven ref→prim (the "version splitting" residual, 2026-07):** the user asked to attempt genuine version splitting for this residual. Analysis showed splitting is the WRONG tool: `GroupVariables` merges defs only through a shared use, so a genuine merge always has a phi point (no clean split), BUT the residual was PROVEN to have **0 real reference uses** — the values are primitives (`Object v0_2 = zza(); if (v0_2 < 0); list.get(v0_2)`, zza returns int) mistyped a reference by register conflation. In valid Dalvik an ordered-compare / arithmetic operand cannot be a reference (verifier), so a reference type on an int-used version is a spurious conflation artifact. The fix is a USE-DRIVEN ref→prim branch (before the def-only guards): a `cur_ref` version that is int-used (`int_use_vids`) and not object-used is re-typed to the **width resolved from its def closure** (`resolve_prim_width` walks moves to the first genuine primitive descriptor, skipping spurious references), so a `long`/`float`/`double` keeps its width (**not** narrowed to int). **Data that shaped it:** of 8119 candidate IR versions, 6599 are int but 885 float / 308 long / 139 double — a naive "force int" would truncate 1332, so width resolution is essential. **Adversarial-review hardening (finding #1, HIGH):** the branch bypasses the `has_ref && has_prim` genuine-merge guard, and `object_vids` covers only receiver/field-owner (misses `return v` / `throw v` / `aput-object` / ref-cast / ref-ARG) — so a GENUINE object+int conflation whose object-use is a blind spot could be wrongly re-typed. Fixed by requiring **EVERY def to resolve to an AGREEING primitive width**: any genuine reference producer (allocation / reference method → `resolve_prim_width` returns "") or width disagreement (I vs J) → left untouched (a real object+int or mixed-width merge that genuinely needs a version split). **Measured (a/b HEAD vs change):** ref-declared-used-as-int **35→20** (−43%), `v <op> null` **11→3**, `int v = <wide method>` truncation **2→2 (0 new — pre-existing separate `cur_prim` int→long bug)**, prim-used-as-object flat (60), `prim = new` 0, parity 28/28, sweep 0-crash / 46k-class. **Two adversarial reviewers** (correctness: sound/0 findings; adversarial: finding #1 fixed as above). The genuine object+int merges + mixed-width conflations that remain DO need a real version split (control-flow) — deferred; this fix handles the spurious-reference majority soundly without any control-flow surgery. **Follow-up — prim→WIDER-prim (int→long/float/double narrowing, 2026-07):** a separate pre-existing bug — `int v = System.currentTimeMillis()` / `int v = Long.parseLong(s)` (a `long`/`float`/`double` value returned into a wide register whose split version DAD mistyped `int`; `int v = <long>` is an uncompilable narrowing). A `cur_prim` version is re-typed to the def width when EVERY def resolves (via `resolve_prim_width`) to the SAME primitive `w` that is WIDER than the current type (`rank(w) > rank(cur)`, ranks `{Z,B,C,S,I}=1 < J=2 < F=3 < D=4` — an assignment `cur v = w` that would be an invalid narrowing). Guarded by an `int_required_vids` set (a use where a wide type is invalid: array index `arr[v]`, `switch(v)`, array-creation size `new int[v]`) — NOT all int uses, since ordinary arithmetic / comparison on a wide value is valid (unlike the mirror). **Two adversarial reviewers** (correctness: sound/0; adversarial: 2 structural gaps fixed — (1) `int_required_vids` extended from array-index-only to also cover switch-selector + array-creation-size, (2) `resolve_prim_width`'s move-source walk now AGGREGATES sibling defs and returns "" on width disagreement, symmetric to `gt()`, so a move-hidden I/J conflation is not false-widened). **Measured (a/b):** `int v = <wide method>` narrowing **2→0**, ref-used-as-int unchanged (20), wide-var-used-as-array-index/switch 10→10 (0 new), parity 28/28, sweep 0-crash / 50k. byte/short narrowing (`short v = <int>`) is intentionally NOT fixed (conservative — {B,S,C,I} share rank 1). Test `test_no_wide_value_narrowed_to_int`. **Follow-up — single-def prim→ref mirror (object-use corroborated, 2026-07):** a broad invalid-Java scan (after ruling out a false-positive "duplicate declaration" bucket — the regex had matched `return v` as a decl; real dup-decls = 0) found the dominant remaining bucket was `int v2 = getChildViewHolderInt(...); v2.isRemoved(); v2.itemView` — a lone **reference-returning method typed `int`** by register conflation, used as an OBJECT. The mirror previously required `dvec.size() >= 2` (multi-def); extended to fire for a SINGLE-def version when USE-corroborated as an object (`object_vids` — invoke receiver / iget-owner / iput-owner), re-typing to the def's resolved `ref_type` (symmetric to the single-def ref→prim cascade's int-use proof: in valid Dalvik an invoke-virtual receiver / field owner IS a reference). The `int_use_vids` skip is kept (a version used as BOTH object AND int is a genuine merge → left). **Two adversarial reviewers** (correctness: sound/0; adversarial: 1 LOW lenient-dex garbage-in cosmetic, no crash/regression — key attacks structurally excluded: `ref_type` is the def's producer type = self-consistent with the receiver-use, and `this`/`<init>`-base is always cur_ref so the `cur_prim` gate excludes it, PLUS a belt-and-suspenders `!ThisParam` guard now makes that structural). **Measured (a/b):** prim-used-as-object deduped **181→35 (−146, −81%)**, ref-used-as-int 20→20 (0 new), `<op>null` 3→3, parity 28/28, sweep 0-crash / 37k. Verified: `int v0;` → `SafeIterableMap$Entry v0 = this.get(...)`. Test ceiling `test_primitive_used_as_object_bounded` tightened (~35). The remaining separate pre-existing bug (split_variables typing an ordered-compared variable as a reference) and the true genuine object+int / mixed-width merges (a real object def AND a real int def, need control-flow version splitting) stay deferred. **Follow-up — `v == <nonzero int const>` int-use (the "ordered-compare typed reference" residual, 2026-07):** the deferred pre-existing residual above was largely NOT a genuine merge but another MISSING int-use pattern. `==`/`!=` were excluded from `int_use_vids` because `== null` (Constant 0) is a valid reference null-check — but `v == <NONZERO int const>` (e.g. `v == 5`) proves `v` is a **primitive** (a reference is `==` only to null or another reference, never a nonzero literal). Because `defs_of` is built incrementally, the `==`/`!=` ConditionalExpression operand PAIRS are recorded during collection and resolved in a POST-PASS: if one operand `is_nonzero_int_const` (has a nonzero-int Constant def), the OTHER joins `int_use_vids` (blocking the prim→ref mirror + unlocking the single-def ref→prim cascade). **Adversarial-review hardening (path-robustness):** `is_nonzero_int_const(v)` returns true only when `v` is UNAMBIGUOUSLY a primitive — a nonzero-int const def AND **no reference def anywhere** in its def set; a genuinely int/ref-conflated `v` (nonzero-int on one arm, a reference on another) would path-insensitively veto its reference-arm partner's mirror (`int v = someObject()`), so requiring no-reference-def makes the proof path-independent. The pass runs pre-RegisterPropagation (the compared const is still a distinct `const` def), a documented ordering dependency (a safe no-op if that order ever changed). **Measured (a/b, bundled corpus, pass off vs on):** `RefType v = …; v == <nonzero>` residual **100 → 8** (the residual 8 are genuine int/ref-conflated versions the path-robust proof deliberately skips — they need a real version split); prim-used-as-object flat (mirror not flooded), `v <op> null` 0 (no ref-used-as-int flood), parity 28/28, sweep 0-crash / 25,309-class. Regression test `test_ref_equals_nonzero_int_bounded`. **Two adversarial reviewers** (correctness: 0 findings; adversarial: 4 REFUTED + 1 PLAUSIBLE-deferred): the const-string/const-class attack is REFUTED by the `is_prim_desc` + `is_ref` type gates (a typed reference constant is not a nonzero-int Constant), the wide-narrowing interaction is REFUTED (the prim→WIDER branch reads `int_required_vids`, never written here), and the genuine-merge / mirror-veto attack is the case the path-robust safening explicitly declines (conservative — leaves DAD's type, no new bad output). The one PLAUSIBLE (conf 45) is a **pre-existing, lenient-only** gap this change *widens the reachability of* but does not create: the USE-DRIVEN ref→prim branch's `object_vids` guard covers only invoke-receiver / field-owner, NOT `return v` / `throw v` / ref-arg positions, so on a crafted **lenient** (`check_insns=false`) dump a purely-primitive-def register used as `return-object v` could be forced to `int`. On verified dex this is unreachable (`if-eq int-vs-ref` is rejected), and the gap is ALREADY reachable pre-change via any arithmetic int-use (`v + 1` → `note_int` BinaryExpression → same `int_use_vids` → same line-818 consumer), so eq/ne adds no new *kind* of hole. Closing it properly (extend object-use corroboration to reference-typed return/throw/ref-arg) is a separate change with its own blast radius + a/b — **deferred** [[project-deferred-type-conflation]]. **Follow-up — move-CYCLE resolution in `gt()` (2026-07-04):** the residual ref-declared-int / prim-used-as-object was dominated NOT by genuine merges (a classification-first census: bundled ref-int 26 = 100% cascade-gap / 0 genuine, op-null 3 = 0 genuine) but by a `gt()` RESOLUTION gap: a version whose all-primitive/null defs reconverge through a **move-diamond / cycle** (e.g. a boolean `equals()`/`onItemRangeMoved()` result `1`/`null` moved v1→v2→`return`) hit a move back-edge that `gt()` reported as `'M'` and the aggregator treated as `sib_u` → `'U'` (BLOCK) → the version kept DAD's reference type (`String v1_0 = 1`). **Fix ([dataflow.cpp](native/dad_cpp/dataflow.cpp) `gt`):** a genuine cycle back-edge `'M'` is now **NEUTRAL** (it targets an ancestor frame that already owns and resolves the cycle member's real defs — it carries no new ground truth; a reference entering the cycle is still aggregated on some member's non-move def on its first visit, so a reference can NEVER be hidden — adversarial-review REFUTED every `int v = <ref>` / `ref v = <prim>` construction). To make `'M'`-neutral SOUND, cycle detection is now **per-path**: `seen` is a backtracked DFS ancestor stack (each frame pops its own id via an RAII guard on exit), so a move-DIAMOND (two paths converging on one node) is not mistaken for a cycle — O(1) per node, not the O(depth) copy a naive per-sibling `seen` clone needs (which regressed a deep linear chain to O(N²)). A pure move-cycle with no ground producer → `'U'` (the new `!sib_any` guard). **Adversarial-review HIGH (perf) FIXED:** the per-path re-exploration is O(2^N) on a crafted nested-move-diamond chain (an uncatchable CPU-spin hang, same family as the emit-walk / ShortCircuitStruct caps) → bounded by a **`gt_budget` work cap** (2M gt() calls/pass; on exhaustion returns the conservative `'U'`; verified 0 output change vs uncapped over 43,399 corpus classes, so it bites ONLY crafted input). **Measured (a/b off→on):** ref-declared-int **bundled 26→6, obf 13→4**; prim-used-as-object **bundled 33→17, obf 77→61**; **`prim = new` FLAT 2/2, 9/9** (the critical no-`int v=new` axis) and `boolean v = <int>` FLAT 340/340 (a PRE-EXISTING writer gap, not this change). Backtracking is output-identical to the reviewed per-path-copy version (snapshot diff 0). parity 28/28, sweep 25,309/0-crash. Reviewers: correctness 0-bugs (one comment nit fixed); adversarial soundness REFUTED + 1 HIGH perf (the cap, FIXED) + delta re-review of the cap/backtracking. Ceilings tightened (`test_cascade_type.py`: prim-obj ≤30, ref-int ≤15). No `*DADFaithful` sibling (parity suites don't assert version type — cascade precedent). **Follow-up — reference-ARGUMENT use corroboration (2026-07-04):** a broad invalid-Java census found the biggest remaining bucket was `T v = varOfOtherKind` (a register conflated across a prim and a ref, moved: bundled 117) — dominated by `int v3 = findViewById(); if(v3!=0) removeView(v3)` where `v3` is a prim-typed version that is really a reference, used ONLY as a reference ARGUMENT (`removeView(View)`). The prim→ref MIRROR's single-def object-use corroboration (`object_vids`) covered only invoke-RECEIVER / iget-owner / iput-owner, MISSING a reference-argument position — the documented deferred gap. **Fix ([dataflow.cpp](native/dad_cpp/dataflow.cpp) `note_obj`):** for an `InvokeInstruction`, also add every argument `args()[i]` whose parameter type `ptype()[i]` is a reference (`is_ref`), guarded by `args().size()==ptype().size()`. Sound: in valid Dalvik a value at a reference-parameter position IS a reference (the verifier rejects passing an int there); `args()` is params-only (the receiver is `base()`, separate — verified for BOTH non-range and range invokes where `InvokeRangeInstruction` peels `args.front()` as base), a wide `J`/`D` param is ONE arg entry aligned 1:1 with ptype (via `GetArgs`+`GetTypeSize`), and `ptype` is `ParseParamsType` (correct multi-element). `object_vids` only *widens*: the mirror re-types more single-def **reference-def** versions (never a genuine int — `has_ref` comes solely from the DEF-side `gt()`, not from `object_vids`), and the ref→prim cascade becomes more conservative (a missed fix, never invalid output). **Measured (a/b off→on):** `T v = varOfOtherKind` **bundled 117→107, obf 287→278**; `int v3` → `View v3 = v2; removeView(v3)` (valid); **prim=new / ref-int / prim-obj / `v<op>null` / eq-nonzero / ref-used-as-int (arith+index, bundled 15 / obf 58) ALL UNCHANGED** (0 regression). parity 28/28, sweep 25,309/0-crash. Reviewers: correctness 0-findings (args↔ptype alignment traced clean incl. range/wide/DAD-quirk); adversarial genuine-int→ref REFUTED (`object_vids` never establishes `has_ref`) + 1 LOW **PLAUSIBLE lenient-only** (a reference-def value used at a `note_int`-blind int-sink — `return v` / aput-object / int-arg — could over-fire the widened single-def mirror; unreachable on VERIFIED dex, 0 a/b manifestation, PRE-EXISTING gap this widens but does not create — same eq/ne deferred precedent [[project-deferred-type-conflation]]). Test `test_prim_ref_mismatch_var_assign_bounded`. The residual 107/278 = genuine object+int merges + reference uses in still-uncovered positions (return/throw/aput-object), needing a version split.

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
| `declared_synchronized` raw access flags (upstream DexKit patch; the second-copy vector it added was later retired — see the RAW-dex-bits section, behaviour unchanged) | vendor/dexkit_core/Core/dexkit/dex_item.cpp + dexitem_code_source.cpp | +0.4 |
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

Same const-typed-int root as the return fix, but in **non-return positions**: a `const-wide` loads a double as type `"J"` (raw bits), and DAD emits the raw int wherever it's used — `p2 *= 4611686018427387904` (should be `*= 2.0`), `if (p9 < 4607182418800017408)` (`< 1.0`), `Math.pow(x, 1065353216)` (`, 1f`). Invalid VALUE (Java widens the long, giving e.g. 4.6e18 instead of 2.0). **Sound fix without an IR type-inference pass — use the OPERATION's type.** Each `const*` opcode types its value int, but every float/double *operation* (`mul-double`, `cmp-double`, …) builds its `BinaryExpression`/`BinaryCompExpression` with type `"D"`/`"F"` (`opcode_ins.cpp`), the field/array/param/return slots carry their declared type, so the F/D context is recoverable at emission even when an operand *variable* was never inferred as `D`. An integer-Constant in such a context is definitionally the raw IEEE bits → reinterpret it (`emit_fp_const_typed`, [writer.cpp](native/dad_cpp/writer.cpp); `visit_expr_fp_typed`, [dast.cpp](native/dad_cpp/dast.cpp)), same integer-constant guard as the return fix (typed-reference constants untouched). Wired into **every** position, text and AST: binary expr / comparison / compound-assign (the **expression's own `get_type()`**, threaded through `visit_binary_expression`/`visit_cond_expression`), method-arg (`InvokeInstruction::ptype()`), plain-assign (lhs type), array-store (element type), field-store (`visit_put_*` field type). Using the expression type (not the sibling operand's type) is what closes the type-inference gap — `if (v9_25 < <1.0 bits>)` becomes `< 1.0` even though `v9_25` was not typed `D`. **Measured (bundled corpus, canonical double bit-patterns): ~hundreds → 0.** Beyond-DAD, catch-clamp precedent. parity 27/27, sweep 0-crash/0-timeout/159,305; tvleanback byte-match-vs-DAD dips further (new mismatches all verified OURS-more-correct, e.g. `* 100f` vs DAD's wrong `* 1120403456`). Guarded by `test_double_bit_patterns_largely_eliminated` in [tests/test_return_literals.py](tests/test_return_literals.py).

### Production fix — boolean assignment/declaration literal (`boolean v = 0` → `false`, 2026-07-04)

Same const-typed-int root as the return / fp-const fixes, in the **assignment** position: a `const*` opcode builds an integer-typed value, so a `boolean` (Z) local assigned it renders the uncompilable **`boolean v = 0;`** (a Z register holds only the boolean 0/1). DAD emits the raw int; this surfaced corpus-wide (bundled 340) once the type passes correctly type such locals `Z`, and was WIDENED into visibility by the move-cycle cascade resolution. **Fix:** in `write_inplace_if_possible` ([writer.cpp](native/dad_cpp/writer.cpp)) — parallel to the existing reference-lhs `= 0 → null` branch — a `Z` lhs assigned an integer `Constant` 0/1 emits `= false` / `= true` (same integer-constant guard: a typed-reference constant is untouched; a value ≠ 0/1 is a genuine int/boolean conflation left as-is, no-worse). **AST path (the subtle part, adversarial-review MEDIUM):** the text emits a first-assignment DECLARATION inline through `write_inplace`, but the AST DECLARATION path (`ins_to_stmt`, [dast.cpp](native/dad_cpp/dast.cpp)) **bypasses `write_inplace`** and rendered the init by the Constant's OWN type (`'I'` → `LiteralInt(0)`), so the AST said `boolean v = 0` while the text said `= false` — a text/AST divergence on 317 methods. Fixed by a shared **`typed_rhs_expr(lhs, rhs)`** helper (Z→bool / ref→null / F-D reinterpret) used by BOTH `write_inplace_if_possible` (reassignment) and the `ins_to_stmt` declaration path, so declarations agree too (it also closes the same latent gap for the reference→null and fp-const declaration forms). **Measured (a/b off→on):** `boolean v = <int>` **bundled 340→3, obf 93→0** (337+94 now `false`/`true`; the residual 3 are `boolean v = 17`-style genuine conflations, correctly left); text/AST agree on 298/298 boolean-decl methods, 0 mismatch. Beyond-DAD (return-literal/catch-clamp precedent — no `*DADFaithful`; parity suites don't assert assignment/decl literal form). parity 28/28, sweep 25,309/0-crash, AST smoke 133,647-method/0-crash. Reviewers: correctness 0-bug; adversarial soundness REFUTED (typed-reference-constant / value-range / branch-disjointness all guarded) + 1 MEDIUM (the AST decl-path divergence, FIXED). Tests: `test_boolean_assign_literals` (text) + `test_boolean_decl_text_ast_agree` (AST) in [tests/test_return_literals.py](tests/test_return_literals.py). **Sibling fix (separate pre-existing inversion, adversarial-surfaced):** dast.cpp's standalone Z-typed-Constant render was INVERTED — `LiteralBool(get_int_value() == 0)` maps value 0→`true`, disagreeing with the text path (`visit_constant_bool(i != 0)`) and the sibling AST paths (`visit_cond` `iv != 0`, the Z-lhs assign `v == 1`). Fixed to `!= 0` (0=false, nonzero=true). A probe confirmed the branch is **reached 0× on the bundled corpus** (a `Constant` is essentially never type `'Z'` — `const*` builds `'I'`-typed constants; the live boolean renders go through write_inplace / return-literal / visit_cond), so the fix is **output-neutral / defensive** — it makes an unreachable branch consistent and correct rather than fixing an observable bug. parity 28/28 (dast_parity does not cover the unreached case).

### Production fix — use-bound prim→ref typing from a reference ARGUMENT (design §3 Phase 2a, 2026-07-04)

The first cut of the real version-level **type-inference** pass the accreted cascade/mirror patches were leading toward ([docs/type-inference-design.md](docs/type-inference-design.md) §3 "use corroboration" / Phase 2a) — the first that uses a use as a TYPE SOURCE, not merely a boolean int/object GATE. A primitive-typed version with NO reference DEF (`!has_ref`, so the existing prim→ref mirror — which needs a ref def — cannot fire), NEVER used as an int (`!int_use_vids`), and passed at a REFERENCE-argument position is re-typed to that param's type. The canonical shape is a Kotlin `$default` bridge: a Dalvik register shared between a reference param and a scratch local leaves the version typed `int` (DAD last-write), the reference lost from **every** def (a move off the conflated register reports type `I`), present ONLY at the ref-arg call — DAD emits **`int v4 = p10(Function1); actor(…, v4, …)`** (invalid). **Sound on verified Dalvik** (the verifier rejects an int at a reference-param position, so a version never int-used with no genuine int producer cannot really be an int — its primitive type is a conflation artifact). Two support pieces in `InferCascadeTypes` ([dataflow.cpp](native/dad_cpp/dataflow.cpp)): a **`ref_arg_type`** map (vid → the ref param type, recorded in `note_obj`; exact-match — `ref_arg_conflict` skips a vid passed at two DIFFERENT ref-param types rather than compute an LUB), and **`has_prim_producer`** — a transitive move-resolving check that BLOCKS the re-type if any def's closure contains a genuine primitive producer (nonzero const / arithmetic / prim-invoke / prim-field), while a move to a PARAM (no def) is NOT a producer. **Resolving moves is what distinguishes `v4 = p10(param)` (fixable) from `v = move vR; vR = x.intValue()` (blocked)** — a form-only check misses the int producer hidden behind the move (caught in adversarial-review a/b as a `String v = intValue()` / `Object v = onNestedFling()` regression, then fixed by the move resolution). `has_prim_producer` carries its own **work budget (2M, mirrors gt_budget)** so its O(2^N) per-path backtracking cannot hang on a crafted nested move-diamond (adversarial-review — the defense was otherwise only emergent via gt() exhausting its budget first on the same closure; the cap is output-neutral vs uncapped). The `= 0` default then renders `= null` via the existing reference-lhs null render, in text and AST (the Variable's type is read by both emitters — a root-cause IR/dataflow re-type, NOT a Writer mask). **Measured (a/b off vs on, 0 regression on every axis):** bundled 252 lines improved (≈14 versions re-typed prim→ref + the cascade `= 0`→`= null` null-renders — e.g. `Function1 v4`, `List v8 = p27`, `Throwable v3_0` in Kotlin coroutines); obfuscated 15-APK sample 130 lines; parity 28/28, determinism (multi-process 0-diff), 0-crash. Reviewers: correctness 0-bug (sound); adversarial 2 findings — the `has_prim_producer` budget cap (FIXED) + a lenient-dex GIGO (`RefType v = intParam` on `check_insns=false`, verifier-unreachable on strict dex, low/suppressed, matches the use-corroborated-re-type precedent and is NOT cheaply closable — a move-to-param reads the conflated register type `I`, indistinguishable from a real int param). Beyond-DAD (return-literal/catch-clamp precedent — no `*DADFaithful`; parity suites don't assert declaration types). Guard: `test_use_bound_prim_to_ref_typing` in [tests/test_cascade_type.py](tests/test_cascade_type.py). **Follow-up — field-store + throw sources, two-tier resolver (Phase 2b, 2026-07):** extended the use-bound type source beyond the ref-argument to a FIELD STORE (`obj.f = v` iput → field type `atype`; `Cls.f = v` sput → `ftype`) and a THROW (`throw v` → `Ljava/lang/Throwable;`, cast to `ThrowExpression` specifically so the sibling `MoveExceptionExpression` catch-DEF is not misread as a use). To keep them ADDITIVE, the single map became a **TWO-TIER resolver**: PRIMARY = the reference argument (a param type is exact), FALLBACK = field-store/throw (only when no ref-arg pins the vid) — so a field store to an unrelated type can never revert a ref-arg re-type (the first single-map attempt HAD exactly that regression, `p3 = null → p3 = 0`). A present-but-CONFLICTED primary returns EMPTY (skip), NOT descending to the fallback — a vid at two different ref-param types is a genuine LUB case no exact-match tier can satisfy, and descending could emit `Runnable v` passed at `m(List v)` (both reviewers converged; fix output-neutral on the corpus, shape constructible-only). **Measured (a/b, strictly additive vs the committed ref-arg version, 0 regression):** bundled +19 null-render lines, obfuscated (15-APK) +28; parity 28/28, determinism (2 fresh processes byte-identical), 0-crash. Reviewers: correctness sound; adversarial 5/6 REFUTED + 1 (conflicted-primary fall-through, FIXED). **Follow-up — return source (Phase 2c, 2026-07):** added the RETURN position (`return v` → the method's declared return type) as a FALLBACK-tier source. Needed the return type threaded into the pass: `FixInitResultTypes`/`InferCascadeTypes` gained a `const std::string& ret_type` param (from `m.ret_type` at the decompile.cpp call site; header default `= {}` keeps the unit-parity-test callers behaviour-neutral, `is_ref("")` false). A `return-object` at a reference-return method proves the value is a reference, so it pins the vid to the return type (fallback tier — a return type can be a supertype, so a ref-arg wins). **Measured (a/b, strictly additive, 0 regression):** bundled +110 lines (50 null-renders + `Long`/`Animator`/`SyncQueueItem` re-typed decls) — the largest single-source payoff yet (a conflated register RETURNED as a reference is a common shape). parity 28/28, determinism (2 fresh processes byte-identical), 0-crash. Reviewers: correctness sound, adversarial 6/6 REFUTED (0 findings). **array-store (aput-object) stays TODO** — the ArrayStoreInstruction carries only a category MARKER (`"O"`), not the element type descriptor, so the element type would have to be derived from the array variable's (possibly-conflated) type — fragile, low payoff, deferred. Genuine `has_ref && has_prim` merges still need a version split (Phase 3).

### Production fix — genuine ref+int conflation → `Object` + explicit casts (Phase 3, LLM-comprehension, 2026-07-05)

The residual `has_ref && has_prim` genuine merges — a Dalvik register reused across a REFERENCE and a NONZERO-INT LITERAL that MERGE at a phi-use (the value is genuinely int-OR-reference, which Java cannot express as one type). DAD types it from the last write → misleading `FontCallback v8 = -3` (asserts a type it doesn't hold on the int path). Enabled by the **DAD-1:1 relaxation** (user decision, 2026-07-04 — see top policy section); the output is consumed by an **LLM (not javac)**, so the goal is comprehension, and the fix follows **jadx's Object+cast model** (its `FixTypesVisitor` splits/casts un-typeable SSA vars) rather than SSA phi surgery (a clean rename-split fires on ZERO — every genuine merge has the phi-use by GroupVariables construction). **`SplitConflatedVersion`** ([dataflow.cpp](native/dad_cpp/dataflow.cpp), in `SplitVariables`) detects the conflation PRECISELY from DIRECT def types — `region_of`: a ref / ref-move → `'R'`, a NONZERO int const → `'P'`, const-0 → `'N'`, a non-const prim / method-result / arithmetic → `'U'` **bail** (so an arithmetic or false-`'R'` register is NOT flagged — the over-fire that would degrade a clean primitive; the gt-based `has_ref && has_prim` over-includes those and must NOT act). Where the two regions' USES are disjoint (reaching-def via `ud`) it SPLITS by rename; where they merge at a phi it types the register **`Object`** (the honest common type — `Object v = <int>` autoboxes; params excluded, their type is the signature). The Writer ([writer.cpp](native/dad_cpp/writer.cpp) `visit_invoke`) then emits an explicit **`(Type)` cast** wherever an Object-typed variable is passed at a more-specific reference ARG (`m(…, (T) v, …)`) or used as a RECEIVER (`((DeclClass) v).m()`, DeclClass = `invokeInstr->cls()`) — so the LLM sees the real type at each use; no-op `((Object) x)` casts and `this`/super/`<init>` are excluded. **Measured (a/b, 25,309 bundled + 15-APK obfuscated, HEAD vs change):** `FontCallback v8 = -3` → honest `Object v8 = -3`; **108 bundled / 249 obf explicit casts added**; pre-existing `Object v; v.m()` invalids FIXED by the receiver cast (bundled 39→12, obf 24→6); **net invalid-Java UNCHANGED (ref/Object=nonzero-int 4→4, prim=new 2→2)**, 0 new no-op casts; the split also fixed some unrelated `int↔boolean` cascades as a bonus (`boolean v = 17` → `int v = 17`). parity 28/28, determinism (3 processes byte-identical), 0-crash/0-timeout. Reviewers: correctness sound (0 bugs); adversarial 4/6 REFUTED + 2 LOW (a move-source stale-ref `'R'` could in principle Object-type a clean primitive — the SAME accepted move-source trust the split-time typing uses, did NOT fire on the corpus; a lenient-dex receiver cast is cosmetic-only, no worse than the `Object v; v.m()` it replaces). Beyond-DAD (no `*DADFaithful` — parity suites don't assert this). Guards: `test_conflated_register_typed_object_with_casts` + `test_object_typed_use_gets_explicit_cast` in [tests/test_cascade_type.py](tests/test_cascade_type.py). **Follow-up — FIELD-access owner cast (2026-07-05):** extended the Object-var cast beyond invoke arg/receiver to FIELD access — `((OwnerClass) v).field` for an iget/iput whose owner (`InstanceExpression`/`InstanceInstruction::cls()`, the field's declaring class) is a specific reference and the base is Object-typed. Factored the invoke-receiver cast into a shared `emit_base_maybe_cast(base, target)` helper (guards `!ThisParam`, `get_type()=="Ljava/lang/Object;"`, target specific-non-Object) and threaded the owner into `visit_get_instance`/`visit_put_instance` (a new `owner` param, default `{}`; only `WriterImpl` overrides them — dast handles iget/iput via its own AST path, unaffected). Dominant case: a Kotlin coroutine state machine reuses a register as the `Continuation` and accesses `.label` / `.L$0` (`Object v; v.label` → `((StateMachine) v).label`). **Measured (a/b):** `Object v; v.<field>` invalid **bundled 12→1, obfuscated 6→0** (165 obf field casts added); parity 28/28, determinism, 0-crash. Reviewers: correctness sound (0 bugs); adversarial all attacks REFUTED + 1 LOW (redundant-but-valid cast on a param whose signature is specific but Variable is Object — same accepted case as the invoke cast, valid→valid-noisy). Guard: `test_object_typed_field_access_gets_owner_cast`. **Follow-up — ARRAY-use-driven typing (root-cause, not a cast, 2026-07-05):** the array case (`Object v; v[i]` / `v.length`) is NOT fixed by a per-use cast but at the ROOT — a version USED AS AN ARRAY BASE (`array_use_vids` = the `array_id()` of an aget `ArrayLoadExpression` / aput `ArrayStoreInstruction` / `ArrayLengthExpression`) that is typed a NON-array is re-typed to the array descriptor recovered from its def(s) via **`resolve_array_type`** ([dataflow.cpp](native/dad_cpp/dataflow.cpp) `InferCascadeTypes`) — every def must produce an array (a rhs type starting with `[`: a check-cast to an array, a move off an array var, an array-returning method) or be the null const (array-compatible); a non-array-non-null / unresolved / two-disagreeing-arrays def → bail (a genuine conflation, left as-is). The branch runs FIRST in the retype loop and `continue`s (an array-typed version is fully determined). Fixing the TYPE makes every array use valid at once — cleaner than casting each `((T[]) v)`. e.g. `Object v1_0 = getSpans(); v1_0.length; v1_0[i]` → `Object[] v1_0` (a lost move-source array type); also recovers `int v = arr` → `int[]`, `Path v = varargs` → `CopyOption[]`. **Measured (a/b):** bundled 9 vars re-typed, obfuscated 3 (`String[]`/`Class[]`/`Type[]`), `Object v; v[i]` 2→1 (the residual = a circular move `v = v2; v2 = v` that `resolve_array_type` can't resolve without gt-style transitive move-resolution — deferred, 1 case); parity 28/28, determinism, 0-crash, strictly improves the writer's array-store fp-const element typing. Sound: an array operand IS an array in valid Dalvik (the use-side invariant); the def-side is conservative (bails on any ambiguity). Reviewers: correctness sound (0 bugs); adversarial all 6 attacks REFUTED (stale-move-source only bails-or-agrees, never mis-forces non-array→array; null-const gate admits only `const 0`; no ref+prim conflation passes the every-def-array guard). Guards: `test_array_used_variable_typed_as_array` + `test_array_used_not_typed_object_bounded`. **Follow-up — MIXED-version conflation (2026-07-05):** `SplitConflatedVersion`'s Object-typing initially fired only in the size==1 pre-pass (an UNSPLIT register). A register split into ≥2 versions can still have ONE version that is itself a genuine ref+nonzero-int conflation (a real reference def AND a real int-literal def merging at a phi WITHIN that version) — the multi-def ref-preference typed it a reference → misleading `zzj v = 1`. Extended: the SplitVariables rename loop now calls `SplitConflatedVersion` per split version and Object-types a phi-conflated one too (the size==1 pre-pass covers the unsplit case; this covers the split case). Safe mid-rename — the `conflated` flag is decided purely from DIRECT def rhs types (the preceding def-loop's `replace_lhs` touches only the LHS, not the rhs `region_of` reads, and the version's `ud` use-keys are still intact, re-keyed only in the later uses-loop). **Measured (a/b):** `RefType v = <nonzero int>` bundled 5→3, obfuscated 6→1; Object-receiver invalid 0→0; parity 28/28, determinism, 0-crash. Reviewers: correctness sound (0 bugs); adversarial 6/6 attacks REFUTED (state-mutation-at-call-time and clean-ref-degradation both fail — `region_of` reads rhs untouched by `replace_lhs`, and `has_p` requires a genuine nonzero-int Constant a clean reference never has). Guard: `test_reftype_eq_nonzero_int_bounded_mixed_version`. Residual (later cut): the circular-move array (~1) + genuine multi-type `this` merges. Detail: [docs/type-inference-design.md](docs/type-inference-design.md) Phase 3.

### Production fix — move-OPCODE ground-truth typing (`int v = ViewMove` → correct, 2026-07-05)

The largest remaining invalid-Java bucket after the Object+cast work was **`T v = wN` where one of {T, decl-type-of w} is a primitive and the other a reference** (an obfuscated register reused across a prim and a ref, connected by a `move`; census: bundled 108, obf 55) — DAD's last-write typed ONE of the two split versions wrong, e.g. `OnPrepareListViewListener v4 = v1` (v1 is an int index) or `int v3 = v24` (v24 is a View). **These are all int↔reference mismatches, which Java has NO cast for** (`(int) someView` / `(View) intVar` are both invalid and misleading), so the Object+cast model does not apply — the fix is to CORRECT the mistyped version. **The ground truth is the Dalvik move OPCODE**, which the IR was discarding: DAD (and our port's `MoveImpl`) collapsed `move` / `move-wide` / `move-object` into one `MoveExpression`. On verified Dalvik the opcode fixes the moved value's KIND (`move-object` copies a reference, `move` a 32-bit primitive, `move-wide` a 64-bit primitive). **Fix:** thread the opcode kind onto `MoveExpression` (`MoveKind::{Object,Plain,Wide,Unknown}`, set in the [opcode_ins.cpp](native/dad_cpp/opcode_ins.cpp) move handlers; `MoveResultExpression` stays `Unknown` → inert), then a **bounded-fixpoint post-pass in `InferCascadeTypes`** ([dataflow.cpp](native/dad_cpp/dataflow.cpp), run AFTER the cascade/mirror `retypes` are applied so it reads FINAL types) re-types a SINGLE-def move-DEST whose declared type contradicts its move opcode: `move-object` dest declared primitive → the source's reference type; `move`/`move-wide` dest declared reference → the source's primitive type. **ANTI-CONFLATION GUARDS:** the version must NOT also be used as the contradicting kind — a direct use (`object_vids`, which covers receiver/field-owner/ref-arg/return/throw/ref-field-store via `record` / `int_use_vids`) OR a move-SOURCE of the contradicting opcode (`moveobj_src_vids` / `moveprim_src_vids`); a move-object DEST that is also a plain-move SOURCE is a GENUINE prim+ref conflation (no single Java type) and is LEFT (needs a version split). **Kind-consistency is structurally enforced** by reading the source's FINAL type (`is_ref(st)` / `is_prim_desc(st)`) — the original in-loop attempt read the source's PRE-mutation type and a review found it could emit `ref v = primSrc` at a source independently re-typed by the cascade, or leave `int v2 = LFoo v1` at a two-hop `move-object` chain; the post-pass + FIXPOINT closes both (round 1 fixes the first link, round 2 the second). **Termination is guaranteed** by monotonicity — a version's def has ONE fixed opcode kind so it fires AT MOST ONCE (move-object → the →ref branch needs cur_prim, and once flipped cur is a reference; symmetric for →prim) — so a move-cycle re-types nothing (no oscillation); the `round < 32` cap is a crafted-input WORK backstop (real chains are ≤3 links, measured 0 added lines), documented-GIGO on a crafted >32-link chain (deterministic, no crash, no worse than DAD). **This is a root-cause IR/dataflow re-type** (the Variable's type is read by BOTH the text Writer and the AST — verified text/AST agree; `int v4_0 = v1_1` in both), NOT a Writer mask. **Measured (a/b OFF vs ON, SAME script):** `T v = wN` kind-mismatch **bundled 108 → 36, obfuscated 55 → 31**; an OFF/ON line-set diff on BOTH corpora shows **72 / 24 removed, 0 ADDED** (no new mismatch — the fixpoint + final-type read + guards prevent any move-chain-boundary cascade); all other invalid axes flat (`prim_used_as_object` obf 5→3); parity 28/28, determinism (multi-process byte-identical, 2 APKs), 0-crash/0-hang (2 full sweeps × 25,309 classes), AST smoke 159k/0-exceptions. Reviewers (initial + delta after the fix): correctness 0 confirmed bugs (finding CLOSED — fixpoint terminates, no oscillation, reads final types, single-def guard protects multi-def conflations); adversarial the confirmed chain finding REFUTED post-fix + all other attacks REFUTED + 1 PLAUSIBLE crafted-only >32-link cap escape (documented GIGO). Beyond-DAD (no `*DADFaithful` — parity suites don't assert declaration types; return-literal/catch-clamp precedent). Guards: `move-kind` fixtures in [dataflow_parity_test.cpp](tests/parity/dataflow_parity_test.cpp) (→ref single-def, two-hop chain fixpoint, anti-conflation-left) + the tightened `test_prim_ref_mismatch_var_assign_bounded` (≤48) in [tests/test_cascade_type.py](tests/test_cascade_type.py). **Residual:** genuine object+int merges (a real ref def AND a real prim def on one register that MERGE) still need a version split.

### Production fix — reused `this` register materialised as a local (`this = X` → valid, 2026-07-03)

When a method reuses its receiver register p0 (`this`) as a scratch local — reads `this` early, overwrites it (`move-result` / `const`), reads the new value later, the two merging at a shared use (e.g. `return`) — `GroupVariables` binds the param-def and reuse-defs into ONE version (they share the merge use), so `SplitVariables` leaves it unsplit and it keeps its `ThisParam` identity. DAD (and our 1:1 port) then emit **`this = <value>`** — always invalid Java (you cannot assign to `this`). **Confirmed identical bug in androguard DAD**, so this is a beyond-DAD production divergence. Dominant real-corpus invalid-Java bucket (269 occurrences bundled, above every other). **Fix — `MaterializeReusedThis` ([dataflow.cpp](native/dad_cpp/dataflow.cpp), declared in [dataflow.h](native/dad_cpp/include/dataflow.h)), runs AFTER SplitVariables and BEFORE the chain consumers:** allocate a fresh local `vX`, rewrite every graph reference to the receiver → `vX`, and inject `vX = this` at the entry block head — the sole remaining `this` is that copy's rhs → `<Ret> vX = this; … vX = …; return vX;` (valid). `findFragmentByWho` (the canonical repro) becomes byte-valid: `Fragment v7 = this; if(!p2.equals(this.mWho)){ if(this.mChildFragmentManager==null){ v7 = null; } else { v7 = this.mChildFragmentManager.findFragmentByWho(p2); } } return v7;` (reads stay `this.mWho` because RP propagates the entry copy for uses it dominates; `v7 = 0` renders `null` via the existing reference-lhs null-render). **Type safety (two adversarial-review rounds, 4 reviewers):** `vX` is typed as the method **RETURN type** — the one assignability anchor valid Dalvik gives (everything reaching a `return` is assignable to it). The pass is a **validate-then-mutate** (atomic — Phase A reads only, so every early bail leaves the graph pristine) that fires ONLY when (a) the return type is a reference, (b) the receiver is RETURNED, and (c) every reassignment rhs is a reference whose type **EXACTLY equals** ret_type, or the narrow-integer constant 0 (null). Exact equality (not just `is_ref`) is REQUIRED: the unsplit phi-web can bind a def reaching only an intermediate use (never the return) with an unrelated type — `vX = getBar()` where `Bar ⊄ Foo` (adversarial CONFIRMED) — the merge-point-assignability property does NOT hold per-def, and there is no type hierarchy to check assignability. A **void-invoke artifact** (`this = super.onDraw()` — a void call DAD wrongly models as defining the receiver; DAD keeps the `this` name so its later `this.getScrollX()` reads accidentally render correctly, and renaming would EXPOSE the artifact as `v.getScrollX()` on a void result — strictly worse), a non-reference return, a non-returned reuse, a genuine primitive (`this = 5`), or a non-exact reference reuse all bail → left as DAD's (invalid but **no-worse**) `this = X`. The receiver's ThisParam type is CORRUPTED during Construct (each `this = X` AssignExpression ctor does `this_param.set_type(X.get_type())`) so it is restored to the class before seeding the copy. On a `true` return the caller `number_ins()` + recomputes `BuildDefUse` (the injected copy + renumbered locs) before DCE/RP/PlaceDeclarations; `FixInitResultTypes` runs between (graph-only, no chain access, safe). Excludes `<init>` (super()/this() uses the receiver specially). **Measured (a/b off vs on, bundled corpus):** `this =` **269 → 218** (51 genuine reuses materialised valid; residual 218 = void-invoke artifacts + non-provable reuses, correctly left), **90 valid `<Ref> vX = this;` seeds**; **ALL other invalid-Java buckets byte-unchanged** (prim-used-as-object 55, ref-declared-int 23, `v<op>null` 3, `prim=new` 2), the pre-existing separate `void v=this` move-into-conflated-local bug **40→40 unchanged**, parity 28/28, 0-crash/25,309-class. No `*DADFaithful` sibling (parity suites don't assert method bodies — return-literal/catch-clamp precedent). Remaining (deferred, no-worse-than-DAD): the void-invoke-defines-receiver DAD bug itself, and genuine multi-type phi-web merges (need a real version split). Regression test `tests/test_this_reuse.py` (materialisation valid + active + the Fragment repro).

**Follow-up — generalised use-sink ANCHOR + injected class-hierarchy oracle (2026-07-04):** the return-only anchor left the biggest residual = a receiver reused as `cond ? this : null` then passed as an ARGUMENT (`m(this)`), never returned (e.g. `ActionProviderWrapperJB.setVisibilityListener`). The anchor is now any TYPED SINK the receiver flows to: `return this` (return type) OR a reference argument (the callee's parameter type at that position — the invoke is the AssignExpression rhs; args↔ptype 1:1 via ParseParamsType). A single consistent reference sink is required (two differing → bail). **The soundness gap two reviewers CONFIRMED for the exact-match version — `<anchor> vX = this` needs `cls <: anchor`, but an arg sink only pins the *value* at the call, not that the entry `this` reaches it — is closed by proving `cls <: anchor` via EITHER (a) an injected `is_assignable(sub, super)` class-hierarchy oracle (new `IDexCodeSource::IsAssignable`, a bounded dex superclass/interface BFS in [dexitem_code_source.cpp](native/core_ext/dexitem_code_source.cpp); default = exact-equality so the hierarchy-free core / test Mock stays conservative; threaded core-ward as a `std::function` callback so [dad_cpp](native/dad_cpp/) stays DexKit-free — hexagonal-clean), OR (b) the entry `this` REACHING an anchor sink through a reassignment-free CFG path (a reassign block consumes the entry value → stops the walk; the verifier then proves the up-cast, covering framework-transitive chains the dex-only oracle can't see). Every reassignment must likewise be `is_assignable` to the anchor (subtype ok) or null. The pre-existing `returned` return-anchor behaviour is kept as-is (0-manifest theoretical gap, 4-reviewer-accepted) so the sound additions never REGRESS an already-emitted valid materialisation.** **Measured (a/b, bundled + 6 obfuscated, sound-arg on vs off):** `this =` **637 → 577** (60 arg cases materialised valid), **0 regression** (prim=new 0, `<prim/void> v=this` 115 pre-existing, ref-declared-int 49 — all unchanged), parity 28/28, deterministic (3 processes identical), 0-crash. The `is_assignable` oracle is a PARTIAL sound oracle (a framework-transitive subtype it can't see returns false = "unknown, be conservative", never a false positive) and is the reusable foundation for replacing the type-inference passes' exact-match conservatism with real assignability. Test `test_arg_sink_materialization_valid`. **Follow-up — DEF-anchor for `this = new C` (no use-sink, 2026-07-04):** the dominant remaining `this =` bucket (120/187 sampled = 64%) was `this = new C` where the receiver is a pure scratch for an allocation that is then thrown/discarded — NO `return this` / arg-`this` use-sink, so the use-sink anchor was empty and the pass bailed (e.g. `ActionBar.setHideOffset`: `this = new UnsupportedOperationException(); this.<init>(msg); throw this`). `MaterializeReusedThis` now falls back to a DEF-anchor when `anchor.empty()`: if EVERY receiver reassignment is a `new C` (new-instance / new-array) of the SAME class C AND the entry `this` value is never read (`entry_this_read()==false`), it sets vX = C and injects NO `vX = this` seed (it would be dead) — so soundness needs no cls<:C up-cast proof: the entry value provably reaches no use, and vX is fully defined by its `new C` def(s) with PlaceDeclarations placing the declaration at the common dominator. **`entry_this_read()`** BFSes from entry, stops propagation at reassign blocks (their successors carry the reassigned value, not entry), and within a reached block scans instructions in order — a `this` use in a non-reassign block, or BEFORE the reassignment in a reassign block, is an entry read → disqualify. It is SOUND: `false` ⟺ no entry→use path avoids a reassignment ⟺ every vX use is dominated-through-reassignment (adversarial-review-hardened — the rhs `get_used_vars()` is checked BEFORE the LHS break so a self-referential `this = new C[this]` array-size read, reachable only on lenient/unverified dex, correctly disqualifies instead of emitting `C[] vX = new C[vX]`; invoke-base reads ARE in `get_used_vars` so a `this.m()` receiver read blocks it). **Measured (a/b off vs on, bundled + 6 obfuscated, 323,083 methods):** `this =` methods **156 → 51** (105 fixed — 103 `throw new X(...)`, 0 undeclared/use-before-def, 0 new `this =`), the 51 untouched methods BYTE-IDENTICAL, `prim v = new` 63 → 63 (no new primitive `= new`). Two independent reviewers (correctness: 5/5 attack points REFUTED; adversarial: 1 LOW lenient-only soundness-claim hole, FIXED as above, 3 attacks REFUTED). parity 28/28, sweep 188,065/0-crash, `test_this_reuse.py::test_def_anchor_throw_new`. No `*DADFaithful` sibling (return-literal/catch-clamp precedent). **Follow-up — DEF-anchor takes PRIORITY over a use-sink anchor (framework-transitive `new C; return this`, 2026-07-04):** the DEF-anchor was gated on `anchor.empty()` (fired only with NO use-sink), leaving a residual = `this = new C; … ; return this` where `C <: return-type` holds only through a **framework** class the dex-only `is_assignable` oracle cannot see (e.g. `generateDefaultLayoutParams`: `this = new ViewGroup$MarginLayoutParams; return this` returning `ViewGroup$LayoutParams`). The use-sink path's reassign-assignability check `assignable(new C, ret)` fails on that transitive chain and bails → invalid `this = new C`. **Fix:** the DEF-anchor now fires **whenever its conditions hold** (every reassignment `new C` of one class C AND the entry `this` never read), EVEN when a use-sink exists — the value genuinely IS a C, so every use (incl. the return/arg sink) is exactly what the verified bytecode did with a `new C` register → valid for a `C vX` variable with no transitive subtype proof; the dead seed's cls<:anchor up-cast is never emitted. Types `vX = C` exactly (more precise than the use-sink supertype). **Adversarial-review HIGH finding FIXED — catch-handler soundness:** the priority change converts a clean use-sink-path bail into an active rewrite, exposing that `entry_this_read()` walked `graph.sucs()` (NORMAL edges) while the materialisation rewrite walks `graph.rpo` (built via `all_sucs`, incl. **exception** edges) — so a `catch` handler that still reads the entry `this` (`this.onError()`) was rewritten to `vX.onError()` (invalid + use-before-def on the exception path) yet never counted as an entry read. `entry_this_read()` now also closes over the EXCEPTION-reachable set (seed from every `in_catch` handler, follow `all_sucs`; a catch observes the register at the throw point = entry `this` when the exception fires before the reassignment completes), scanning those blocks fully → a catch this-read disqualifies the DEF-anchor. The shape is 0 in a 12-APK / 48k-class obfuscated search (constructible-but-corpus-absent, defensive per the soundness-first precedent). A LOW lenient-only finding (a `sink(this)` with an unrelated param type under `lenient=True` emits `C vX = new C(); sink(vX)`) is documented as uncompilable-in/uncompilable-out (no worse than DAD, cannot crash); its suggested `assignable(alloc_type, sink_anchor)` gate is deliberately NOT applied — it would re-block the exact framework-transitive case this fix targets. **Measured (a/b off vs on):** obfuscated `this =` **111 → 100** (11 framework-transitive `new C; return this` materialised valid, e.g. `generateDefaultLayoutParams` → `return new ViewGroup$MarginLayoutParams(-1, -2)`); bundled `this =` 3 → 3 (the residual = genuine multi-type protobuf `zza` conflations, correctly untouched — need a real version-split); **ALL other invalid-Java buckets byte-unchanged** (prim=new, ref-int, `<op>null`, eq-nonzero, prim-object) on bundled + obfuscated; parity 28/28, sweep 25,309/0-crash. Reviewers: correctness 0-findings; adversarial 1 HIGH (catch-handler, FIXED) + 1 MEDIUM (same root, pre-existing, closed by the same fix) + 1 LOW (lenient-only, documented). Regression test `test_this_reuse.py::test_def_anchor_priority_over_return_sink` (bundled `ViewPager.generateDefaultLayoutParams` guards the priority path). No `*DADFaithful` sibling (return-literal/catch-clamp precedent).

### Production fix — void invoke on the receiver (`this = super.m()` → `super.m();`, 2026-07-03)

The residual after the reused-`this` materialisation was dominated by a **second, distinct** DAD bug (218 bundled): a **void** `invoke-super/range` or `invoke-direct/range` on the receiver rendered as **`this = super.onListItemClick(...)`** (assignment to `this`, invalid Java). **Root cause — at the IR builder:** DAD's RANGE invoke handlers set `returned = base` for a void call — `invokesuperrange`/`invokedirectrange` ([opcode_ins.cpp](native/dad_cpp/opcode_ins.cpp) `InvokeSuperRange`/`InvokeDirectRange`) did `if ret_type != 'V': returned = ret.new() else: returned = base; ret.set_to(base)` — **unlike** the NON-range `invokesuper` (nulls `returned` for void) and `invokedirect` (nulls it when `base` is a `ThisParam`). So a void range invoke on `this` builds `AssignExpression(this, void_invoke)`. Confirmed identical bug in androguard DAD, so beyond-DAD. **Fix (IR builder — make the range handlers consistent with the non-range ones, NOT a Writer-side mask):** `InvokeSuperRange` now nulls `returned` for void (invoke-super is never `<init>`, so the receiver never needs to be the result); `InvokeDirectRange` now nulls `returned` for a void call when `base` is a `ThisParam` (a `this.<init>()`/`super()` delegation or a void `this.privateMethod()`), else keeps `returned = base` + `ret.set_to` (the `newObj = new X()` constructor pattern). A void invoke then builds `AssignExpression(None, invoke)` → renders the bare call `super.onListItemClick(...);` in **BOTH the text AND the AST** — the earlier iteration masked this in the Writer's `visit_assign` (dropping the LHS), which fixed the text but left `dast`/AST carrying `this = voidcall`; the root-cause IR fix corrects both and is the principled layer (CLAUDE.md: "structural defects must be fixed at the IR level, not in Writer output"). Removing `ret.set_to(base)` for void super-range is safe — no `move-result` follows a void call, so the `gen_ret` chain is unread. **This is a beyond-DAD IR divergence** (our AST now differs from androguard DAD's for these methods — DAD's AST has the bug); the 28 parity suites do NOT assert the range-invoke void `returned=base` case (only static/range `None` and direct-`<init>` `base` are unit-tested), so **parity 28/28 is unbroken** with no `*DADFaithful` sibling needed. **Measured (a/b, bundled):** `this =` **218 → 11** (207 void cases fixed; the 11 residual all non-void — `this = 0` / `this = new X()` / `this = method()` — the deferred genuine multi-type phi-web merges, correctly untouched), **text AND AST both carry the bare call**, ALL other invalid-Java buckets byte-unchanged (prim-used-as-object 55, ref-declared-int 23, `v<op>null` 3, `prim=new` 2), constructor patterns intact (super() 4714 + `newObj = new X()` 12120 corpus-wide, 0 broken `<init>`), parity 28/28, 0-crash/25,309. Combined with the materialisation fix, the `this =` bucket is **269 → 11** (258 fixed). Regression tests in `tests/test_this_reuse.py` (`this = super.` = 0, the onListItemClick repro renders `super.onListItemClick(...)`).

### The IR models `invoke-custom`, so its bootstrap chain is reconstructed (dexllm#67, 2026-08-22)

The residue dexllm#60 left, pinned there by a guard saying a future change should
delete it. **Two failure modes, and the LOUD one was the smaller half.** 5 of
`invoke-custom.dex`'s 144 methods emitted `// DECOMPILE ERROR` (a `move-result`
after an unmodelled invoke, the documented null-guard at
[instruction.cpp:274](native/dad_cpp/instruction.cpp#L274)). Another **6 lost the
call SILENTLY** — a void or unconsumed `invoke-custom` produced a `NopExpression`
and simply vanished, and in `TestLinkerUnrelatedBSM` the following `move-result`
then bound to an EARLIER, unrelated temp, so the method read
`assertEquals(2.5f, vtmp1)` with `vtmp1` a `getName()` String. A confident wrong
answer with no error anywhere, and nothing in the issue predicted it.

**The issue's decision #1 dissolved: no vendor change.** It assumed the one missing
piece was `Reader::CallSiteIds()` in the vendored slicer. It is not — the section is
a `u4` array found through the map, and `core_ext/dexitem_code_source.cpp` already
reads raw sections that way (`BuildProto`'s `type_list`, the `static_values` walk).
`GetCallSite` is implemented there, so the pile dexllm#65 records as uncataloguable
gains nothing. What it DOES gain is a reader of UNVERIFIED bytes: `VerifyDex` bounds
the `call_site_id` section's EXTENT (dexllm#57's `CheckMap`) and nothing else — ART's
`CheckInterCallSiteIdItem` is not ported — so `data_off`, every element type code and
every index inside are bounded at the reader, which is the tier the safety contract
permits (dexllm#66's precedent).

**Decision #2, the IR representation, was escalated to the user, who chose jadx
parity** (CLAUDE.md already names jadx the reference oracle). An `invoke-custom`
names a call SITE: at runtime the VM calls the site's BOOTSTRAP once with a
`Lookup`, the target NAME and the call's METHOD TYPE (plus the site's extra
arguments) and invokes the `CallSite` it returns with the instruction's registers.
Every synthesized node is one of those steps, so nothing is invented — but it IS a
reconstruction rather than instructions the dex contains, which is what the trailing
**`/* invoke-custom */`** marker says (jadx marks it for the same reason). Built from
EXISTING IR node types, so the AST schema is unchanged and both emitters read the same
nodes. (**"agree by construction" was FALSE as first written** — see the float/double
finding below; it is true now, and it was not.)

```java
TestLinkerMethodMinimalArguments.assertEquals((p4 + p5),
    TestLinkerMethodMinimalArguments.linkerMethod(invoke.MethodHandles.lookup(), "_add",
        invoke.MethodType.methodType(Integer.TYPE, Integer.TYPE, Integer.TYPE))
    .dynamicInvoker().invoke(p4, p5) /* invoke-custom */);
```

**Two deliberate differences from jadx, both to stay consistent with THIS writer:**
a class name goes through `GetType`, so `java.lang.invoke.X` prints as `invoke.X` —
which is what every existing `invoke.CallSite` / `invoke.MethodHandles$Lookup` in the
same file already reads (a pre-existing repo-wide rendering, not a new one); and
`MethodHandle.invoke` is typed from the CALL SITE rather than as `Object` plus a cast
at each use, the same call-site-over-declaration choice dexllm#60 made for 0xFA (it is
also what makes the two float registers render `2f, 0.5f` instead of raw bits).

**One IR mechanism was needed and it is INERT unless used:** `IRForm::set_synthetic_vid`.
An IRForm keys its `var_map` by each child's `Vid()`, and the natural ids collide for
exactly this shape — an invoke's id is `""` (unique as the single BASE, not as two
ARGUMENTS, and `bsm(lookup(), name, methodType(…))` has two), while a Constant's is
VALUE-derived, so a `String "2"` and the int `2` are both `c2`. Nothing the opcode
handlers build ever sets it, so every existing id is exactly what it was.
`InvokeInstruction::call_site_marker` is the same: one bool, false everywhere else.

**A `MethodHandle` bootstrap argument has no Java literal at all**, and it is the
COMMON shape in real invoke-dynamic (`LambdaMetafactory.metafactory` takes one), so
refusing it would have made the fix useless for the one real-world case. It renders as
the method reference it is — `Cls::name`, `Cls::new`, and `Cls.name` for the four FIELD
kinds, which method-reference syntax cannot express — as a `BaseClass` node rather than
a Constant, because that is what BOTH emitters render as a bare NAME (the Writer writes
it unquoted; dast maps a descriptor-less one to `Local`). A String-typed Constant reads
as `"Cls::name"`, a literal it is not.

**An UNRESOLVED call site emits NOTHING** — the pre-dexllm#67 behaviour — rather than
fabricating output for input we could not read, and `GetCallSite` returns a PRISTINE
result on every failure path. That second half is not tidiness: the bootstrap is
resolved BEFORE the name is checked, so returning the half-filled record hands a
consumer a real bootstrap beside an empty name and an empty call type, which renders
as a plausible and entirely fabricated `bsm(lookup(), "", methodType(Void.TYPE))`.
**The mutation matrix found that** — the first guard crafted a site whose result is
CONSUMED, where an unresolved site reads as void and the null-guard error reappears
either way, so the bail looked unguarded until a VOID site was crafted too.

**Measured (a/b OFF=`d277837c` vs ON=`39135671`, SAME script, both `.so` md5-verified
and the ON build bit-reproducing its md5 after the halves were swapped back):** 60
sources — the whole bundled corpus, the committed fixtures, every
`art/test/dexdump/*.dex` and every `tools/dexter/testdata/*.dex` — x {both verify
verdicts, class list, the whole decompiled Java, the whole smali, every method's AST,
the `DECOMPILE ERROR` count} = **2 records changed, and they are the SAME FILE at two
paths** (the committed fixture and its AOSP original). **smali, verify and class counts
are identical on every source**, so dexllm#66's listing is untouched. A LINE-LEVEL diff
over that file resolves the change exactly: **14 removed / 101 added**, the 14 being 5
`DECOMPILE ERROR` lines plus 9 lines of the silent-loss kind, and **46 of the added
lines carry the marker** — one per call site the fixture has. The bundled corpus carries
**0** invoke-custom sites, so a flat corpus result is required and the fixtures are the
only thing that can show the mechanism firing [[ab-must-prove-the-mechanism-fires]].

**Measured (a/b OFF=`d277837c` vs ON=`413ff1bf`, SAME script, both `.so` md5-verified
and the ON build bit-reproducing its md5 after every mutant):** 60 sources — the whole
bundled corpus, the committed fixtures, every `art/test/dexdump/*.dex` and every
`tools/dexter/testdata/*.dex` — x {both verify verdicts, load, class list, the whole
decompiled Java, the whole smali, every method's AST, the `DECOMPILE ERROR` count} =
**2 records changed, and they are the SAME FILE at two paths** (the committed fixture
and its AOSP original). **smali, verify, load and class counts are identical on every
source**, so dexllm#66's listing is untouched. A LINE-LEVEL diff over that file resolves
it exactly: **14 removed / 101 added**, the 14 being 5 `DECOMPILE ERROR` lines plus 9
lines of the silent-loss kind, and **46 of the added lines carry the marker** — one per
call site the fixture has. The bundled corpus carries **0** invoke-custom sites, so a
flat corpus result is REQUIRED and the fixtures are the only thing that can show the
mechanism firing [[ab-must-prove-the-mechanism-fires]]. A correctness reviewer
re-derived every number of this table independently and got the same values.

parity **29/29**, pytest **821 passed / 10 skipped**, TRUE corpus-less (`test_apk` MOVED
aside) **415 passed / 416 skipped / 0 failed**, narrowed to `tests/data/multidex.apk`
**724 passed**, the guard files green narrowed to **each of the 34 bundled samples one at
a time**, sweep **26,938-class / 186,367 method-block 0-crash 0-timeout 0-error**,
determinism 3 processes x 3 `PYTHONHASHSEED`s -> one digest, lint trio clean (CI scope;
the two pre-existing unformatted `scripts/` files untouched), doc fences 78,
`scripts/check_dad_boundary.sh` clean.

## What the two reviewers found — 2 real code defects, and 7 load-bearing lines with no guard

**BOTH reviewers independently CONFIRMED the same bug, each against jadx as the oracle:
a `CHAR` bootstrap argument was SIGN-extended and then masked.** CHAR is the one
UNSIGNED member of the encoded_value integer family (ART reads it with
`ReadUnsignedInt`; BYTE/SHORT/INT use `ReadSignedInt`), and a mask cannot undo a
sign-extension — a one-byte `0x80` came out **65408** where ART reads **128**. **Not
crafted-only**: d8 emits any char in 128..255 as exactly one byte, so this is reachable
from an ordinarily compiled dex. Fixed by zero-extending; verified 0x41/0x7F/0x80/0xFF
-> 65/127/128/255, matching jadx on the identical bytes.

**A correctness reviewer CONFIRMED a second one, with a measurement I had not made:
`SpanOf`'s base is wrong for a v41 CONTAINER slice.** The slicer's ctor sets
`header_ = ptr<Header>(0)` — the SLICE — and only THEN `ValidateHeader` does
`image_ -= header_->ContainerOff()`, so the header address is slice-relative while every
offset it resolves is container-relative. On AOSP's own `multidex-container.dex` the
second slice sits at +564 with `map_off` 1332 in a 1468-byte container, so a
slice-based span rejects its own map and `GetCallSite` silently returns `{}` for every
call site in a later slice; for a geometry where the sum lands back in range it would
read ANOTHER slice's bytes and could fabricate a chain out of them. Fixed by
subtracting `ContainerOff()` — which is the slicer's own `image_`. My comment there had
asserted the opposite of the truth, in the sentence the reviewer disproved.

**And the change's own claim about float/double was false.** `CallSiteArgToIr` builds
`Constant(double, "F"/"D")`, whose Writer path is `%g` — six significant figures — while
the AST renders the same node through `PyFloatRepr`. So `Double.MAX_VALUE` printed
`1.79769e+308` in the text beside `1.7976931348623157e+308` in the AST: "the text and the
AST agree by construction" was FALSE for exactly the values only this change can produce.
The `%g` path was UNREACHABLE before it — every `const*` opcode builds an INTEGER-typed
Constant — so the Writer now uses the round-trip `FormatFloatLiteral` / `FormatDoubleLiteral`
it already had (which also render NaN/±Inf as valid Java instead of `nan`), reached
through a new `Visitor::visit_constant_float` that DEFAULTS to the double path so no other
implementer changed. The corpus a/b is byte-identical across that edit, which is the
unreachability restated as a measurement.

**Five of these guards lost their channel to dexllm#72** and are recorded in its
section: the `{?}` array demotion and its annotation twin, the `idx > UINT32_MAX`
width clause, and the two unresolvable-handle crafts all rested on the gate NOT
bounding the `0x16` index. Two were INVERTED into rejections, two became SOURCE
pins, and one was re-based onto the call_site route, where the contents are still
deliberately out of scope. The `idx > UINT32_MAX` clause this section added is
DEAD on its own route now (the gate caps `arg <= 3`), and the comment justifying
it said the opposite until a correctness reviewer read it. dexllm#74 carried the
clause into `ParseCallSiteArg`, where it IS live, and what was genuinely shared
all along is the bound one level down, inside
`ResolveMethodHandle`.

**One PLAUSIBLE was worth fixing rather than documenting:** a crafted call-site proto can
declare more parameters than the instruction has registers, and `BuildInvokeRegs` always
yields a 5-slot window with empty names, so `GetArgs` materialised `unknownType v`
arguments no register holds. The window is truncated to `vA` now, so `GetArgs` bails and
renders none — refusing beats inventing, the same rule the unresolved-site path follows.
It WIDENED a pre-existing shape (dexllm#60 feeds `ptype` from an equally unverified proto
operand) rather than creating one; the pre-existing half is not touched here.

**And the standing rule bound this commit for the fourth time**
[[a-rule-you-wrote-binds-your-next-commit]]: `dex_verifier.h` and `dex_verifier.cpp` both
still said `call_site` is "not dereferenced by the core … nothing reads its contents",
which `ResolveConstRef`'s new arm and `GetCallSite` make false. Both are rewritten to say
what is now true and where the bound lives (at the READER, which the rule permits, and in
`GetCallSite` rather than in `VerifyInsns` because the section is OPTIONAL — a dex with no
invoke-custom has no `call_site_ids` at all).

**Everything else they attacked, they REFUTED — with their own instruments.** Memory
safety: **7,000+ and 500+ crafted inputs** across the two reviews, judged by SUBPROCESS
EXIT STATUS (a `try/except` cannot see a SIGSEGV) — `data_off` at/past the end, a
`0xFFFFFFFF` uleb count, truncated arrays, an 8-byte handle index, every id past its
table, 3,000 append-and-repoint iterations, a 64 MB pad — **0 signals, 0 hangs, 0
unbounded allocations**, and the extent bound proven EXACT (one-past-fit rejected,
exactly-fits accepted). The reconstruction shape matches jadx 1.5.0 byte for byte modulo
the documented `invoke.X` prefix; `set_synthetic_vid` is provably inert; the AST schema
gains no node type; the chain survives RegisterPropagation / DCE / PlaceDeclarations; the
CONCATENATED-source case (dexllm#25) was verified rather than assumed; and every headline
a/b number re-derives.

**Guards** (31 cases in [tests/test_invoke_custom_ir.py](tests/test_invoke_custom_ir.py),
ALL on committed fixtures — corpus-less and narrowing-proof). dexllm#60's boundary test
was DELETED as its own docstring instructed, and `ParseCallSiteArg` — the FOURTH
encoded_value decoder — joined dexllm#63's parametrised desync guard rather than the
case-per-type one: it implements the kinds a call site may LEGALLY carry, so its
`default:` ADVANCES instead of enumerating all 18. Crafted IN PLACE and
length-preserving for the four shapes the fixture does not have: **0xFD**
(`invoke-custom/range`, **zero** sites in the fixture — retyped from 0xFC, both 3 code
units, registers rewritten to a range that fits and the craft asserted to still verify);
a **MethodHandle bootstrap argument** (zero — every handle there is element 0); a
**short-encoded float** (every float there is full width, where a left- and a
right-justified read AGREE — the last element of a site is shortened in place, and the
two bytes it stops using are simply not read); and an **unresolvable** site in both the
consumed and the void form.

**24 mutants, each BUILT and RUN with a distinct `.so` md5, each killed by its intended
guard**, and the matrix asserts a pinned control md5 before it starts AND after it ends.
Fifteen from the diff: pre-fix, 0xFC dropped, 0xFD dropped, the `!info.ok` bail removed,
the half-filled result, the invoke synthetic vids, the argument synthetic vid, the
marker, the call-site `ptype`, the `methodType` return type moved LAST,
`Integer.TYPE`->`int`, the float payload left-justified, the method reference quoted,
`dynamicInvoker()` dropped, and `ParseCallSiteArg`'s advancing `default:`. Nine more for
the review-driven fixes: CHAR sign-extended again, the container base reverted to the
slice base, the register window untruncated, element 0 unchecked, element 2 unchecked,
a handle always `::`, a constructor never `new`, the double back to `%g`, and a float
through the double formatter. **M9 escaped the first matrix** — every `methodType` the fixture
produces is HOMOGENEOUS (`(II)I` is three `Integer.TYPE`), so reordering is invisible
there; it is now pinned on two deliberately MIXED signatures, `(I)V` and
`(ILString;LDouble;)I`. **The reviewers found SEVEN more holes of the same shape**, each
by building a mutant that passed the whole file: the element-0 and element-2 kind checks
(only the middle one was guarded), the CHAR path (the fixture encodes every char argument
as an INT, which is how its bug shipped), the field-handle `.` and constructor `::new`
arms (**all 32 handles in all three committed fixtures are kind 4 or 5**, so two of the
three rendering arms were dead by construction), the float/double precision, and the
truncated register window. A guard of mine was also literally dead — `assert X or True` —
and one parametrised case, `methodType(Integer.TYPE)`, passed against the PRE-FIX build
because the fixture's own Java contains that call; every such assertion is scoped to the
RECONSTRUCTED lines now. **The container-base fix is pinned at SOURCE level and says
why**: no v41 container carrying a `call_site_ids` section exists in reach, and rebasing
one is not a length-preserving craft, so its runtime sibling is an explicit
non-discriminating floor while a reviewer's mutant is killed by the source pin
[[pinned-literals-guard-only-the-constant-half]]. **The harness itself had to be rebuilt**: a timed-out foreground
run left a mutant in the tree, a second run then snapshotted THAT as its baseline, and
two leftover mutations (`(void)ReadIntLE` and `call_site_marker = false`) had to be
found by diffing against a known-good copy — [[mutation-harness-restore-pitfalls]] with
a new variant, two racing instances. The harness now asserts a pinned control md5
before it starts and after it ends.

**Adjacent, found while implementing this and deliberately NOT fixed here:**
`DecodeEncodedValueText` — the SIBLING decoder in the same file — LEFT-justified a
float/double payload, where the dex spec and ART (`ReadUnsignedInt(..., fill_on_right)`)
put the stored bytes at the MSB end. Corpus-manifest:
`FloatingActionButtonImpl.SHOW_SCALE` read **`2.27795078e-41f`** where AOSP declares
`1f`, and **382** static float/double initializers across the corpus are short-encoded.
It was a defect of its own with its own blast radius and its own a/b; this change's
decoder was written correctly rather than bug-compatibly, and says so at the site.
**FIXED in dexllm#70** (below), which shares these very helpers — so `SHOW_SCALE` reads
`1f` now. A correctness reviewer had to point this paragraph out: dexllm#70 deleted its
TWIN from the C++ comment, citing [[a-rule-you-wrote-binds-your-next-commit]], and left
this one standing in the present tense — the one-mirror-updated-the-other-missed pattern
this file records elsewhere.

**Still not modelled, and now the list is short:** nothing in the `invoke-custom`
family. `EnumerateInvokeSites` and the caller index still exclude 0xFC/0xFD on purpose
(dexllm#61's truth set is derived from the operand's INDEX KIND, and a call-site index
is not a method reference) — cross-referencing a call site to its bootstrap is a
different capability, not a gap in this one.

### The `0x16` method_handle index is capped and bounded at the gate (dexllm#72, 2026-08-23)

The last piece of the method_handle boundary. `VerifyEncodedValue`'s `case 0x16`
was `skip(arg + 1)` — it consumed the payload and checked neither half of what
ART checks: `:1204` rejects `value_arg > 3` ("Bad encoded_value method handle
size") and `:1212` bounds the decoded index against `NumMethodHandles()`. Every
OTHER index-bearing arm got the width cap for free from the shared `idx` lambda,
so **0x16 was the one arm where an EIGHT-byte "index" was gate-legal** — the
asymmetry dexllm#71's lockstep guard had to be parametrised around.

**Fix:** the arm becomes
`case 0x16: return idx(method_handle_count_, "encoded method_handle idx");`, so
both ART checks arrive together. `method_handle_count_` is ART's
`NumMethodHandles()` — the count lives ONLY in the map (it is not a header
field), so `CheckMap` carries it forward, which is why this had to wait for
dexllm#59 to put the section itself in scope; the ORDER of the two passes is
load-bearing (`CheckMap` runs before `CheckIntraSection`, where encoded values
are walked). It is 0 when the dex declares no method_handle section, which is
exactly ART (`dex_file.cc` :159 zero-inits `num_method_handles_`, :290 assigns it
only from a `kDexTypeMethodHandleItem` map entry) — both anchors read against the
local AOSP checkout, not inferred.

**The residual was never an OOB**, and each reader already bounded the index
itself — a THROW through the slicer's `ArrayView`, an EMPTY RESULT through
`DecodeEncodedValueText` (dexllm#64), and dexllm#67's own bound in
`ParseCallSiteArg`. What porting buys is a load-time rejection with a byte-level
reason, and "`VerifyDex` is the single gate" restored for the last part of this
section. **method_handle now leaves the out-of-scope list entirely**, after four
commits: EXTENT (dexllm#57), ALIGN (dexllm#62), CONTENTS (dexllm#59), and the
index into it (this one).

## It RETIRED a test vehicle, and there is no third one — that is the cost of record

`tests/test_cache_init_failure.py` (dexllm#55, 10 cases) crafted exactly this
value: one byte, an annotation element retyped to `0x16` on a **section-less**
dex, where the index is out of range by construction. That file and this one both
called the channel one *"no future verifier improvement can take away, because
closing it at the gate would be a false-reject"* — **false, and dexllm#59
measured why**: `NumMethodHandles()` is 0 there, so ART rejects the same bytes.
Closing it is ART parity.

The issue's plan assumed a third vehicle existed. **None was found, and the
search is a measurement rather than a shrug — but state it as what it is: a
negative universal supported by a sample, not a proof.** Cache init dereferences three
things — the instruction stream (DexKit's own walk, bounded), the annotations
subtree, and the id tables — and the verifier now covers all three per-structure:

| probe (against the pre-#72 build) | verified | threw in cache init |
|---|---:|---:|
| every bare corpus dex x all 32 `encoded_value` type codes, width-preserving | 32 | **2 — both `0x16`** |
| …the same sweep after the fix | 30 | **0** |
| 500 random mutations in the annotation sections | 100 | 0 |
| 1,200 random mutations across every map section | 217 | 0 |
| 120 `lenient=True` instruction-stream mutations | 11 | 0 |
| `RLIMIT_NPROC` | n/a | raises, but from the pool **CONSTRUCTOR** |

The retype sweep is the strongest row and also the thinnest — 2 craftable bare
dexes x 32 codes, retyping the FIRST element of the FIRST annotated class — so
it is a census of the encoded_value SWITCH, not of every reachable shape. A
correctness reviewer ran an independent 900-mutation fuzz across the annotation
structures and `lenient=True` and got 89 verified / 0 thrown / 0 signals, which
agrees without widening the claim.

The RLIMIT row is the one that decides the shape of the replacement: the throw
comes out of `InitDexCache` directly ("Resource temporarily unavailable"), so it
never reaches `AbortInitCache` / `WaitInitCache` — it exercises the ctor/enqueue
recovery path, not the publish-on-failure machinery the 6 core guards pinned.
**The scope call was escalated to the user (CLAUDE.md rule 5) with this evidence,
who chose "port + retire the guards with a record".**

What replaced them is what this repo already does wherever a load-bearing line is
unreachable from any input (dexllm#63's advancing `default:`, dexllm#71's four
index bounds, dexllm#70's shared-helper call): **SOURCE-level pins**, on
`AbortInitCache` (record AND retire AND notify, never an empty reason),
`WaitInitCache` (wait on `ready | failed`, throw keyed on the FLAG),
`BeginInitCache` (exclude an already-failed flag), the task's own `catch` +
`RetireInitClaims` + `ReleaseInitClaims`, and `EnterQueryExecution`'s catch
(clear `warmup_inflight`, dequeue the admission ticket, notify), and the two
CALL SITES — `FinishInitCache` and `WaitInitCache`. A source pin is WEAKER than a
behavioural one — it cannot see a line that is present and wrong — and saying so
is part of the record. **13 source mutants, each applied and run without a
rebuild, each killed**, including "the fix survives only as a COMMENT" (the
stripper is scanned left-to-right and self-checked, the trap dexllm#32 and
dexllm#57 each paid for).

**Two reviewers turned that admission into measurements, one on each side.** A
correctness review deleted `dex_item->WaitInitCache(init_flags);` — the line that
makes anyone READ the verdict the state machine publishes — and the whole suite
passed at the published 1040, because the pins covered `WaitInitCache`'s BODY and
not its CALL SITE (the retired behavioural guards killed it with 9 errors, all
"warm_analysis_caches never returned"); that hole is the 13th mutant and is
closed. An adversarial review then built the one no source pin can EVER catch:
keep every pinned string verbatim in `AbortInitCache` and undo the effect one
line later (`init_cache_failed_flags &= ~failed_flags;`) — 9 passed. The first is
a defect; the second is the technique's ceiling, and the honest thing to do with
it is publish it rather than let the pins read as equivalent to what they
replaced.

**Measured (a/b OFF=`256a70cb01465af7156dc4346f3f1099` vs ON, SAME script, both
`.so` md5-verified — and the OFF build BIT-REPRODUCES the recorded HEAD md5,
which is the diff's functional content stated as a measurement):** 112 sources —
the whole bundled corpus, every committed fixture, every `art/test/dexdump/*.dex`,
every `tools/dexter/testdata/*.dex`, **every ART fuzzer-corpus dex**, and 20
crafts — x {strict verify, lenient verify, load, `dex_count`, class list, a smali
digest, a decompile digest, `warm_analysis_caches`} = **805 axis records, 8
changed, ALL crafted, 0 REAL**. The 805 is re-derivable rather than a harness
number: 90 sources load and carry all 8 axes, 21 are rejected on both halves and
carry 4, and 1 SIGNALS and carries only that — 8x90 + 4x21 + 1
[[published-counts-need-the-repos-own-predicate]]. The boundary is EXACT: index `count - 1`
accepted, `count` rejected; widths 0..3 untouched, 4..7 flip to `encoded_value
bad index size`; and the `0x15 METHOD_TYPE` / `0x04 INT` controls at the same
widths are unchanged on both halves, so the change is not "the lambda rejects
more". The bundled corpus carries **0** `0x16` values, so a corpus-only a/b is
byte-identical BY CONSTRUCTION and the crafts are the only thing that can show
the mechanism firing [[ab-must-prove-the-mechanism-fires]].

**Independent census, and it is what bounds the false-reject risk:** a raw
map-list parser that never asks the code under test — every `.dex`/`.apk`/`.jar`/
`.zip`/`.oat`/`.odex` under the repo and the local AOSP tree — finds **12**
carrying a method_handle section, and all 12 are in the a/b. (The 12 is stable —
two reviewers' independent scanners reproduced the same twelve files; the file
and logical-dex TOTALS they were drawn from are not, at 8,718 / 1,421 against
8,712 / 1,424 and 8,706 / 1,417, which is what a count with no shared predicate
is worth, so only the carrier list is published.) **One of the twelve does carry
a `0x16` value** — `art/tools/fuzzer/class-verifier-corpus/b365807384.dex`, an
annotation element whose index is 0 against a 2-entry section, so it is ACCEPTED
on both halves. An earlier draft said none did, which an adversarial reviewer
refuted with a raw parser; the direction is favourable (a real file exercises the
accept path) and the sentence was still wrong. None carries a `0x16` encoded_value at all, which is why the
accept direction had to be crafted on the committed fixture rather than found.

**Guards** (12 new cases in
[tests/test_encoded_value_method_types.py](tests/test_encoded_value_method_types.py),
the file that already owns the `0x16` subject; every craft is on the COMMITTED
`tests/data/invoke-custom.dex`, so they run in the corpus-less CI leg and under
any `$DEXLLM_TEST_APK` narrowing). The width cap is parametrised over `value_arg`
0..7 and asserts BOTH sides of the cut — a bound that rejected every width
satisfies the reject half on its own, and `value_arg == 3` is what says it does
not. The index bound is pinned at the boundary in both directions and in BOTH
verify modes (`check_insns_` gates `VerifyInsns` and nothing else, and a packer
dump is the population most likely to carry one). A third guard is the
no-false-reject floor over the three committed carriers. The `value_arg >= 4`
half needs a craft the in-place retype structurally cannot produce (it preserves
the element's WIDTH), so it appends a fresh `encoded_array` at EOF and repoints
`static_values_off` — trading length-preservation for reach and paying for it by
asserting the verdict [[one-byte-crafts-cannot-prove-width]].

**The HIGH an adversarial review confirmed was in the GUARDS, and it was the
change's own headline property.** `u4 method_handle_count_ = 0;` — the default
that makes "0 for a dex with no such section" ART parity — had no test at all: a
one-token mutant, `= 0xFFFFFFFFu`, restores the pre-#72 behaviour EXACTLY and
passed the whole corpus-less suite twice. The `count == 0` guard described above
does not see it, because it reaches count 0 by ZEROING the fixture's map item,
i.e. through `CheckMap`'s ASSIGNMENT, which overwrites whatever the member was
initialised to. Only a dex with **no method_handle map item at all** exercises
the initializer. `tests/data/multidex.apk` is one and it is COMMITTED, so
`test_a_dex_with_no_method_handle_section_at_all_rejects_index_zero` appends a
`0x16 idx=0` static value to it and runs everywhere; index 0 because it is in
range for every nonzero count. Post-fix the mutant fails 2 cases corpus-less.
**Two guards for what looked like one property, and the difference between them
is which line of C++ they reach.**

**A SECOND finding in the same fixture, from the same review:** with the corpus
present that mutant failed as *"the #57 fixture can no longer be built"* — a
product regression reported as a missing corpus shape, which is the trap
`tests/test_cache_init_failure.py` already carries a three-outcome fixture to
avoid. `_crafted` now separates them: no bare `.dex` SKIPS, no craftable shape
goes through `require_corpus_shape`, and a craftable shape whose VERDICT moved
FAILS with a message that says so.

**Two inherited guards were INVERTED rather than deleted**, the dexllm#22 /
dexllm#29 / dexllm#45 precedent: `test_a_method_handle_value_no_longer_fails_as_
an_unknown_type` asserted the section-less craft LOADED and threw, and is now
`test_an_unresolvable_method_handle_index_is_rejected_at_the_gate`; its fixture
takes an explicit `expect_valid=False`, because a fixture that only looked for
"verifies" would silently fall through every candidate and report a deliberate
change as a missing corpus shape. And dexllm#71's lockstep guard lost `0x16` from
its `_UNCAPPED` set — the pinned pair count `compared == 64` becomes **60**,
which is exactly the "a deliberate change to an arm's accepted args has to bump
this by hand" the assertion's own comment predicted.

**9 mutants, each BUILT and RUN with a distinct `.so` md5, each killed:** the
pre-fix arm (9 fail), the bound retargeted at `method_ids` (2), `CheckMap` never
recording the count (14 — everything is rejected, which is the accept direction
earning its place), the arm gated on `check_insns_` (2, killed only by the
lenient leg), **width cap ONLY with the index unbounded (10)**, **index bound ONLY
with the width uncapped (7)**, an off-by-one accepting `index == count` (4), and
— added after a correctness review — the arm SKIPPED when the dex declares no
section at all (2), which nothing saw until the `count == 0` guard below existed.
The two half-fixes are the ones worth having: both ART checks arrive through one
lambda, so nothing else would notice if only one of them did.

**The `count == 0` case needed a guard of its own, and it is the change's own
headline property.** The inverted guard that drives a genuinely section-less dex
is corpus-GATED and skips in the CI leg, so until a reviewer said so the only
behavioural coverage was `count == 29`. A committed-fixture craft that zeroes the
method_handle map item's own count (one `u4`, length-preserving) reaches the same
state everywhere, with index 0 as the payload — in range for ANY nonzero count,
so it is the sharpest case a `>`-instead-of-`>=` or a skip-when-absent would let
through. Both mutants above were invisible without it.

**It cost a SECOND set of guards, which the issue did not anticipate either.**
dexllm#64's five method_handle guards in
[tests/test_static_initializer_rendering.py](tests/test_static_initializer_rendering.py)
all rested on the same "the gate does not bound this index" premise:

| guard | what happened |
|---|---|
| unresolvable handle renders nothing | **INVERTED** — the craft is rejected at the gate now, with an in-range control so the rejection is not "0x16 stopped working" |
| an 8-byte handle index is refused, not wrapped | **INVERTED** — the encoding is refused at load (ART :1204) |
| `{?}` array demotion + `\|\| el.text.empty()` | **SOURCE pin** — no dex that verifies can make `DecodeEncodedValueText` return empty text any more (`IsValidMemberName` rejects the empty-name route too), so the channel is closed rather than moved |
| the annotation `?` twin | **SOURCE pin**, same reason |
| the reader's own `mh_idx >= handles.size()` | **RE-BASED, still behavioural** — a call_site's CONTENTS stay out of the gate's scope, so a crafted bootstrap-handle index reaches it; the guard moved to [tests/test_invoke_custom_ir.py](tests/test_invoke_custom_ir.py) and drives a VOID site, because on a site whose result is CONSUMED both readings end in a `// DECOMPILE ERROR` and differ only in the message |

That re-base is the one worth reading twice: the FIRST cut of it used the
consumed-result site and did NOT kill the mutant (both readings lack the marker),
which only a built-and-run mutant showed. The void site turns it into "the class
renders complete, minus one `/* invoke-custom */`, with no `SLICER_CHECK` in it".

**Adjacent, found while re-basing that guard and NOT fixed here:**
`ParseCallSiteArg`'s own 0x16 arm truncated `idx` to `uint32_t` with **no
`idx > UINT32_MAX` clause** — the exact defence dexllm#64's review added to the
SIBLING arm in the same file. A call_site's contents are not gate-read, so an
8-byte index there is legal and `2**32` fabricates handle 0 for a value naming
none. Its `0x15` / `0x17` / `0x18` siblings narrowed the same way, so the fix is
an arm FAMILY rather than one case. Pre-existing, unchanged by this commit, and
made the ONLY route to that shape by it — **dexllm#74**, fixed in the section
below.

**A process lesson worth more than any single finding.** The two reviewers ran
CONCURRENTLY on one worktree, and the adversarial one's first baseline measured
the OTHER reviewer's pre-fix mutant: 8 spurious failures, with the `.so` md5
silently flipped from the change's to HEAD's mid-run. It caught this by checking
the md5 [[verify-build-identity-before-measuring]], retracted the reading, and
re-ran everything in an isolated copy of the tree with its own venv and build
dir. **Concurrent reviewers need isolated worktrees, not just discipline about
restoring** [[reviewer-agents-swap-the-worktree]] — and the only reason the
retraction was possible is that it was asserting build identity in the first
place.

**Adjacent, found by this a/b and deliberately NOT fixed here:**
`art/tools/fuzzer/class-verifier-corpus/b391844326.dex` — an UNMODIFIED AOSP file
— verifies valid in BOTH modes, loads, renders smali, warms its caches, and then
**SIGSEGVs in `dexkit::dad::Construct`** on `decompile_method`. Identical on OFF
and ON, so it is pre-existing and this change neither caused nor closed it; it is
a crash on a `verify()`-valid input, i.e. the defect class the verifier project
exists to prevent, and it is in the IR builder rather than the gate —
**dexllm#73**.

parity **29/29**, pytest **1044 passed / 24 skipped**, TRUE corpus-less
(`test_apk` MOVED aside) **644 passed / 424 skipped / 0 failed** — every one of
the new cases runs in the CI leg, since every craft is on a committed fixture
(`tests/data/invoke-custom.dex` for the section, `tests/data/multidex.apk` for
the absence of one) — narrowed to `tests/data/multidex.apk` **945 passed**, the
five touched guard files green narrowed to **each of the 34 bundled samples one
at a time**, sweep **25,309-class / 213,374 method-block 0-crash 0-timeout
0-error, GATE: PASS**, determinism 3 `PYTHONHASHSEED`s -> one digest, lint trio
clean, doc fences 78, `scripts/check_dad_boundary.sh` clean. The a/b was
RE-CAPTURED on the shipped binary after every review fix and is identical on all
112 sources to the capture taken before them, so the record covers what is
committed and not a predecessor [[verify-build-identity-before-measuring]].

### A code item can carry no instruction, and `entry_block_id` promised otherwise (dexllm#73, 2026-08-23)

`decompile_method` **SIGSEGV'd in `dad::Construct`** on an UNMODIFIED AOSP file —
`art/tools/fuzzer/class-verifier-corpus/b391844326.dex`, 1,240 bytes — that
`verify()` calls valid in BOTH modes, which loads, lists its classes, renders its
smali and warms its caches. A signal unwinds nothing, so no `catch (...)` and no
`safe.py` deadline can contain it, and it breaks the two properties README and
CLAUDE.md both market: *"a load-time structural verifier is the single gate"* and
0-crash on malformed dex.

**The issue asked which of two branches it was, and it is the second.**
`LMain;->throwsIfParamIsZero(I)V` has a real code item (`code_off=512`,
`registers=4`) whose **`insns_size` is 0** — established by a raw `class_data`
walk that never asks dexllm anything, and reproduced independently by both
reviewers. ART's **structural** verifier accepts that: `CheckIntraCodeItem`
(`dex_file_verifier.cc:1726`) bounds the insns span with `CheckListSize` (`:1754`,
which returns true for count 0) and, with `tries_size == 0`, returns. What rejects
a zero-opcode code item is the **runtime** `method_verifier`
(`method_verifier.cc:1734`, *"code item has no opcode"*) — the 6032-line pass this
project deliberately does not vendor. So the gate behaved exactly as documented
and the defect was in the IR builder, where the issue's second branch predicted it.

**`entry_block_id` is a PROMISE and the builder made it unconditionally.**
`MethodSnapshotBuilder::Build` set `entry_block_id = 0` for every method with a
code item at all, and **six** accesses consume that id with no bound of their own
— `seen[]`, `snap.blocks[bid]` (the bfs seed), `exception_type_for[bid]`,
`catch_seed[bid]`, `nodes[*entry]`, and `nodes[bid] = raw`, **which is a heap
pointer WRITE**. On an empty vector that is a null deref; on a short one it is an
out-of-range write, which a correctness reviewer demonstrated by building it. A
half-guard on the adjacent `seen[...]` write made the function *look* tolerant; it
was not, and it is gone.

**The predicate is `ins_storage`, not `blocks` — and BOTH reviewers independently
CONFIRMED that, each by constructing the input.** The first cut guarded on
`blocks.empty()`, justified as "no instruction → no leader → no block". That is
true only when `tries_size == 0`: stage 3 seeds a leader per try-range START and
per handler address, so a payload-only body **with a try table** produces blocks —
every one with an empty `ins` span — and rendered an empty `try { } catch { }` (or
`while(true) { }`) for a method carrying no instruction at all, which is exactly
the fabrication this path exists to refuse. It also made the rule written on the
field false. `blocks.empty()` implies `ins_storage.empty()` but not the reverse,
so the weaker predicate is the one that matches the documented contract, and it is
what shipped. Pinned by a `[payload+try]` case in C++ and a crafted one in Python;
the mutant that keys on `blocks` fails both.

**Fix at the builder — one condition:** the id is set only `if (!snap->ins_storage.empty())`.
`DvMethod::BuildProcessedGraph` then returns false (`decompile.cpp:89` already
tests `!graph_->entry`) and the method falls to the signature-only path
abstract/native methods take, in text and AST alike, with `ast.body == null`.
Refusing beats inventing — an empty `{ }` would assert the method does nothing,
which is a fabrication (falling off the end of a Dalvik method is not a return).

**And it SAYS it refused.** Both reviewers pointed out that the bare signature is
separated from an abstract or native method only by the ABSENCE of a modifier, on
the primary LLM-facing surface, so a body-less declaration is marked:

```java
public void throwsIfParamIsZero(int p3);  // no instructions
```

beyond-DAD, the same *"say that you could not render it"* choice dexllm#64 made
for an unrenderable static initializer, and driven by a snapshot flag
(`code_without_instructions`) so it cannot spread to a WELL-FORMED abstract or
native method, which has no code item at all — that has its own guard, on a
fixture that actually contains such methods. A CRAFTED method that is both
abstract and code-bearing does carry the marker, and for it "no instructions" is
simply true; that is pinned too, so it stays a decision. The AST carries the same distinction structurally (`body: null`
plus `flags` without `abstract`/`native`), and `decompile_method_ast()["source"]`
runs the same Writer, so text and AST cannot disagree.

**And the promise is bounded at the READER, where it now THROWS.** `Construct`'s
`nullopt` case still returns an empty graph — that is a legitimate no-CFG shape —
but an id naming no block is an internal invariant violation, not an input shape,
so it raises and the per-method catch reports it rather than silently emitting a
method that reads as abstract. Same choice as the `MoveExpression` null-operand
guard (divergences C2): *a segfault would be the divergence*.

**Deliberately NOT fixed at the gate.** Rejecting `insns_size == 0` would refuse
the WHOLE dex over one method, where the IR fix keeps every other method
analysable and makes the one without a body say so. (An earlier draft also argued
"an added check can only fail in the direction ART cannot" — an adversarial
reviewer correctly refuted the framing: `VerifyInsns` is exactly such a check and
this project ships it deliberately. The whole-dex-versus-per-method argument is
the one that decides it.)

**Measured (a/b OFF=`e411eb0941e22563227b3c76a9cb0172` vs
ON=`bbbbcd569aa15726628df2d9b3f16a48`, SAME script, both `.so` md5-verified — and
the OFF build BIT-REPRODUCES the recorded HEAD md5, which is the diff's functional
content stated as a measurement):** 92 sources — the whole bundled corpus, every
committed fixture, every `art/test/dexdump/*.dex`, every
`tools/dexter/testdata/*.dex` and **all four ART fuzzer corpora** — x {strict
verify, lenient verify, load, `dex_count`, class list, a smali digest, a
whole-decompile digest, decompiled line count, `// DECOMPILE ERROR` count, an AST
digest, `warm_analysis_caches`, and the subprocess EXIT STATUS} = **861 axis
records PRESENT** (not a product — a source that fails to load carries only the
axes it reached), **6 changed, all on `b391844326.dex`**, over 3,038,784 decompiled lines.
Each source runs in a SUBPROCESS whose axes are FLUSHED one per line, so the
crashing half still reports what it computed before dying — which is what makes
the attribution exact: on that file `verify`, `verify_lenient`, `load`,
`dex_count`, `classes` and `smali` are **byte-identical**, and the six that move
are `java` / `ast` / `java_lines` / `decompile_errors` / `warm` (nothing → a
value) plus `_EXIT` (**-11 → 0**). Judging by exit status is not a detail: a
`try/except` cannot observe a SIGSEGV. **0 other source changed on any axis.** The
a/b was RE-CAPTURED on the shipped binary after every review fix and is identical
on all 92 sources to the capture taken before them, so the record covers what is
committed and not a predecessor [[verify-build-identity-before-measuring]].

**Independent census — the population is ONE, and only the CONCLUSION re-derives.**
Three raw `class_data` parsers written independently (mine and both reviewers')
agree exactly: **one** code item with no decodable instruction — the reported one
— and **zero** payload-only bodies, with every source a parser could not walk
being gate-rejected in both modes. Their totals do NOT agree (89 sources /
263,941 methods; 92 enumerated, 81 walked / 263,833; 80 / 240,657) because each
counts a different predicate, so the totals are published as what they are rather
than as one number [[published-counts-need-the-repos-own-predicate]].

parity **29/29** (the count is unchanged — the new cases went into the existing
`construct_parity_test`, which grows from **16** checks to **32**), pytest
**1061 passed / 24 skipped**, TRUE corpus-less (`test_apk` MOVED aside) **661
passed / 424 skipped / 0 failed** — every one of the 17 new cases runs in the CI
leg — narrowed to `tests/data/multidex.apk` **962 passed**, the guard file green
narrowed to **each of the 34 bundled samples one at a time**, sweep
**25,309-class / 213,374 method-block 0-crash 0-timeout 0-error, GATE: PASS**,
determinism 3 processes x 3 `PYTHONHASHSEED`s -> one digest, lint trio clean, doc
fences 78, `scripts/check_dad_boundary.sh` clean.

**Guards, in TWO layers, and the matrix is what proves they are complementary.**
[tests/test_empty_code_item.py](tests/test_empty_code_item.py) (17 cases) crafts
both shapes IN PLACE on the committed `tests/data/multidex.apk` — one `u4` for
shape A, the instruction words for shape B, length-preserving to the byte, with
the craft's verify verdict ASSERTED rather than assumed (a rejected dex never
reaches the IR builder, so a guard that skipped this could pass for the wrong
reason) — plus the payload+try shape on `tests/data/invoke-custom.dex`, the only
committed fixture with try blocks. **No decompile of a CRAFTED dex runs in
the pytest process**: an adversarial reviewer showed the first cut ran 7 of its
10 cases in-process on the crafted dex, so against a regression `pytest tests/` **aborted
the session at this alphabetically-early file** instead of reporting — the
published matrix cell "FF" was only the prefix before the crash. It also pins that
the sibling method is byte-unchanged (without which a build that renders EVERY
method as a signature would satisfy the rest), that the marker does not spread to
abstract/native, and that the uncrafted target HAS a body (non-vacuity;
non-discriminating BY DESIGN and says so). Six cases in
[tests/parity/construct_parity_test.cpp](tests/parity/construct_parity_test.cpp)
pin the C++ side: the three no-instruction shapes leave `entry_block_id`
**nullopt**, two hand-built snapshots with a broken promise are REFUSED, and a
self-loop pins that the entry is SEEDED so a back edge cannot build it twice.

**9 mutants, each BUILT and RUN with a distinct `.so` md5, each killed — and the
two layers do NOT overlap:**

| mutant | pytest | ctest[construct] |
|---|---|---|
| M0 pre-fix — a TRUE revert of all four sources (md5 = the OFF build's, exactly) | 11 failed | FAIL |
| M1 builder guard removed, reader side kept | 7 failed | FAIL |
| M2 reader side removed, builder fix kept | **14 passed** | FAIL |
| M3 builder guard keyed on `insns_size == 0` | 3 failed | FAIL |
| M4 builder guard keyed on `blocks.empty()` (the reviewers' shape) | 1 failed | FAIL |
| M5 broken promise returns an empty graph instead of throwing | **14 passed** | FAIL |
| M6 bound weakened to `blocks.empty()` | **14 passed** | FAIL |
| M7 the `// no instructions` marker removed | 5 failed | pass |
| M8 the marker emitted unconditionally | 1 failed | pass |

M2, M5 and M6 are invisible at the Python surface: with the reader side in place
an unbuilt promise yields an empty graph and the pipeline renders the same
signature, so **the two guards mask each other end-to-end**
[[mutants-can-mask-each-other]] and the ABI contract is observable only from C++.
That is the argument for the C++ layer stated as a measurement.

**M6 is the one worth reading twice.** An adversarial reviewer built it —
`*entry >= blocks.size()` weakened to `blocks.empty()`, a plausible
simplification, since under the documented producer the two agree — and it
survived the whole suite, because the only fixture set `blocks` EMPTY, the single
state where the two predicates coincide. A one-block snapshot with `entry = 7`
separates them; that fixture is also where `nodes[bid] = raw` is a genuine
out-of-range WRITE rather than a null deref. **And the first version of that
fixture still did not kill it**: asserting merely that *something* threw accepted
a throw raised from the garbage read one frame later, so the case asserts the
rejection MESSAGE.

**M8 is the second one worth reading twice, and it is a hole I created answering
review.** The marker guard I first wrote scoped itself to the crafted class — and
`tests/data/multidex.apk` has **no abstract or native method at all**, so it was
VACUOUS: a mutant emitting the marker unconditionally (which would append
`// no instructions` to every interface method in every APK) passed the whole
file. It is driven on `tests/data/method_handles.dex` now, with a floor requiring
it to actually REACH abstract methods
[[a-guard-can-pass-having-exercised-nothing]] — the pattern this repo keeps
recording, where the defect is in the RESPONSE to a review rather than in the
design [[review-responses-are-the-weak-spot]].


**Follow-up — the DELTA review of the shipped commit found a regression IT
introduced, and two lines nothing was holding (2026-08-24).** The two reviews
above ran on a PRE-response cut, so the `ins_storage` predicate, the throw, the
marker and the subprocess restructure shipped unreviewed — this project's own
record says that is where defects concentrate
[[review-responses-are-the-weak-spot]]. A third adversarial pass, aimed only at
those:

* **CONFIRMED, and the shipped change created the route: a package-private
  body-less method VANISHED from `decompile_class`.** `DvMethod::Process` uses
  `meta.access.empty()` as a proxy for *"external reference — emit nothing"*,
  and a package-private member has access flags 0, i.e. an empty vector too.
  That was unreachable while every method with a code item got a graph. The
  method came back as the empty string: no declaration, no marker, no error —
  the exact outcome `test_the_class_still_decompiles_whole`'s own docstring
  forbids. Every fixture method AND the real AOSP exemplar are `public`, so no
  corpus a/b could reach it. Fixed by `access.empty() &&
  !code_without_instructions`: the flag is set only when a code item EXISTS,
  which an external reference never has, so it separates the two exactly.
* **CONFIRMED — a line this change REWROTE was unguarded.** The diff simplified
  `if (*entry < seen.size()) seen[*entry] = 1;` to a bare `seen[*entry] = 1;`.
  The comment explains the line's BOUND; its PURPOSE is the seed — without it a
  child edge back to the entry re-enqueues it and the block is BUILT TWICE.
  Deleting it survived ctest, the corpus-less suite and a narrowed run, while
  changing decompiled output on two unmodified AOSP dexes (`checkers.dex`, and
  `large.dex` at 601,885 → 601,884 lines, i.e. structural). Not an equivalent
  mutant. Pinned by a `[self-loop]` case: `const/4 v0,#0 ; goto -1` is the
  smallest input with the shape, and the graph must carry exactly one node.
* **CONFIRMED (LOW) — `static;  // no instructions` is not Java.** A `<clinit>`
  reaching the signature-only branch has already emitted the bare `static`
  keyword. With no instruction nothing executes, so the empty initializer block
  is both valid AND true — the one shape where `{ }` is not the fabrication the
  marker exists to refuse. Scoped to the no-instruction case, so a code-less
  `<clinit>`'s pre-existing rendering is untouched.
* **CONFIRMED (LOW) — the marker CAN reach an abstract or native declaration**
  on crafted input (the flag follows the code item, not the modifiers, and
  member access-flag validation is out of the gate's scope). The claim above was
  false as written and is narrowed; the crafted case is pinned rather than
  suppressed, because for such a method "no instructions" is true.
* Two prose defects: the adjacent finding's root cause is ANY leader before the
  first instruction — a plain branch target does it with no try table — and
  "92 sources x 12 axes = 861 axis records" reads as a product (92 x 12 = 1104;
  861 is the count PRESENT). Both corrected above.

**REFUTED with its own instruments**, and worth recording: the throw cannot
escape (every reachable surface — text, class, AST at both `include_source`
values, pc-map, both smali renderers, `safe_decompile_*`, the SDK adapter —
returns `// DECOMPILE ERROR`, exit 0, no signal, no inconsistent cache);
`ins_storage` is exhaustive (no third shape where it is non-empty and the
promise breaks, and nothing real is lost when it is empty); **1,400 subprocess
runs over 700 crafted dexes → 0 signals, 0 hangs**, with a positive control
reporting -11 on the OFF build; and the census, the exemplar's facts, the ART
anchors, the check counts and the corpus-less total all re-derive independently.
One mutant the reviewer PREDICTED would survive (the marker swallowing the
trailing newline) is killed by the existing whole-class guard.

**Measured (a/b OFF=`bbbbcd569aa15726628df2d9b3f16a48` — the SHIPPED `692cfc8`,
bit-reproduced — vs ON=`ccee6d9887b7cd0022c00e1352e25dc7`):** the same 92
sources x 12 axes = **860 axis records present, 0 changed**, over 3,038,784
decompiled lines. A follow-up that fixes three crafted-only shapes MUST be a
no-op on every real input, and this is that stated as a measurement. **3 mutants,
each BUILT and RUN, each killed by its intended guard**: the package-private
proxy restored (1 pytest), the `<clinit>` back to a bare `;` (1 pytest), and the
entry seed deleted (ctest only — invisible to all 17 Python cases, which is the
two-layer complementarity again).

**Adjacent, found by the adversarial review and deliberately NOT fixed here.** A
crafted body whose FIRST code units are a payload, with real code after it and a
try range starting at byte 0, makes block 0 the empty payload block — so
`entry_block_id = 0` names it, it has no child edges, and the real body is
**silently dropped** (`while(true) { }`); a nearby variant is contained by the
existing emit-depth cap as `// DECOMPILE ERROR`. Both are **identical OFF and ON**
(pre-existing, neither caused nor closed here), crafted-only (0 in the census),
and not crashes — but the builder's `// first block is entry (lowest byte_off)`
assumption is wrong whenever ANY leader precedes the first instruction — a try
or handler leader, and (a delta reviewer's addition) a plain BRANCH TARGET with
no try table at all — and that is a wrong-ANSWER defect with its own blast radius
and its own a/b. Filed as **dexllm#75** and FIXED there — see its section
below, where the branch-target route turns out to be the wider of the two.

### A call_site index arm bounds what it indexes (dexllm#74, 2026-08-24)

`ParseCallSiteArg` ([dexitem_code_source.cpp](native/core_ext/dexitem_code_source.cpp))
reads `value_arg + 1` bytes — up to **eight** — into a `uint64_t` and then
indexes a table with a `uint32_t`. Four arms did that: `0x15 METHOD_TYPE`,
`0x16 METHOD_HANDLE`, `0x17 STRING`, `0x18 TYPE`. `2**32` narrows to **0**, a
real entry, so the reader answered with a fully-formed value built from an
operand the dex does not contain.

**Reachable because a call_site's CONTENTS are deliberately out of the gate's
scope.** `VerifyEncodedValue` caps `value_arg` at 3 for every index type it
walks — dexllm#72 brought `0x16` into that lambda — but `VerifyEncodedArrayAt`
has exactly ONE caller (`class_def.static_values_off`), so a call_site's
`encoded_array` is never walked; those bytes are bounded at the READER
(dexllm#67). dexllm#72 is what made this the ONLY remaining route: the SIBLING
arm in the same file has refused since dexllm#64, and its clause is now dead on
its own route while these are live. The standing rule bound the commit for at
least the **seventh** time — that sibling's comment said this arm "narrows an
8-byte index instead: dexllm#74, recorded rather than fixed here", which this
change makes false [[a-rule-you-wrote-binds-your-next-commit]].

**A wrong ANSWER, not an OOB, and both reviewers verified it rather than
accepting it:** `GetString` / `GetTypeName` / `GetProtoCached` /
`ResolveMethodHandle` each bound the NARROWED index against a real table (and
one of them proved those bounds are themselves guarded — deleting `GetString`'s
SIGSEGVs an existing test). What came out was a plausible bootstrap chain handed
to an analyst or an LLM with no marker — the "confidently wrong" shape dexllm#67
designed its unresolved-site bail to avoid, reached through the operands it did
not check. On the pre-fix build a `wide_*` craft's whole-decompile digest is
**byte-identical** to its in-range control, which is that claim at digest level.

**Fix — refuse, do not clamp:** `if (idx > UINT32_MAX) return false;` in the
`0x15` / `0x16` / `0x18` arms, which abandons the whole call site so it renders
nothing. Clamping is not a weaker fix but *the same binary*: `idx &= 0xFFFFFFFF`
before a `uint32_t` cast is a no-op the compiler folds, and the mutant that does
it reproduces the pre-fix `.so` md5 exactly (both reviewers built it).

**`0x17` bounds the INDEX instead, and the reason the first cut gave for not
doing so was FALSE.** That cut kept the width clause and left the arm returning
`true` for an out-of-range index, arguing the fix "needs either a size accessor
or a different lookup path" because `""` is a legal String constant and
emptiness cannot separate the two. **Both reviewers refuted it independently**:
`ParseCallSiteArg` already takes `const DexItem& item`, `GetStrings()` is public,
and the sibling decoder 470 lines up in the same file does exactly this. The
correct discriminator was never emptiness — it is the RANGE, which the ambiguity
does not obstruct. And the residual was not merely untidy: an adversarial
reviewer reached, on a `verify()`-valid dex with a **four-byte** craft (shorter
than the eight-byte one the width clause closes), exactly
`bsm(lookup(), "", methodType(Void.TYPE))` — verbatim the string `GetCallSite`'s
own comment names as what its pristine-result rule exists to prevent — while the
same out-of-range index abandoned the site on all three sibling arms. The range
bound also SUBSUMES the width clause (`size()` cannot reach 2**32), so it
replaces rather than joins it, and it makes an existing claim in
[dex_verifier.h](native/core_ext/include/dex_verifier.h) true: the safety
contract already said *"every offset, element kind and index inside is bounded
[at the reader]"*, and that sentence had been false for this one arm.

**The read goes through the BOUNDED accessor even so.** A raw `strings[idx]`
after the check makes the check memory-safety-critical, and the mutation matrix
showed the difference concretely: with the raw subscript, removing the check
CRASHED the suite; with `src.GetString`, it merely fails two cases. A later edit
to that line should be a wrong answer, not a SEGV.

**Measured (a/b OFF=`ccee6d9887b7cd0022c00e1352e25dc7` — HEAD, bit-reproduced by
the true pre-fix mutant — vs ON=`238911494b43c603829140b2820f5f63`, SAME script,
both `.so` md5-verified):** 108 sources — the whole bundled corpus, every
committed fixture, every `art/test/dexdump/*.dex`, every
`tools/dexter/testdata/*.dex`, all four ART fuzzer corpora, and **16 crafted** —
x {strict verify, lenient verify, load, class list, a smali digest, a
whole-decompile digest, the `/* invoke-custom */` marker count, the
`DECOMPILE ERROR` count, an AST digest, `warm_analysis_caches`, exit status} =
**947 axis records present, 15 changed, ALL of them crafts, 0 REAL source changed
on any axis**. The five that move are the four `wide_*` (the width fix) and
`oob_17` (the range fix), each **46 → 45** markers. The **four `wideok_*`** — an
in-range index at eight bytes — are unchanged on both halves, and so are
`oob_15` / `oob_16` / `oob_18`, which the pre-fix build already refused: that
asymmetry IS the 0x17 residual, stated as a measurement rather than as prose.
The bundled corpus carries **0** invoke-custom sites (an independent raw
map-list census agrees), so a corpus-only a/b is byte-identical by construction
and the crafts are the only thing that can show either mechanism firing
[[ab-must-prove-the-mechanism-fires]].

parity **29/29**, pytest **1079 passed / 24 skipped**, TRUE corpus-less
(`test_apk` MOVED aside) **679 passed / 424 skipped / 0 failed** — every new case
runs in the CI leg, since every craft is built from the committed
`tests/data/invoke-custom.dex` — narrowed to `tests/data/multidex.apk` **980
passed**, the guard file green narrowed to **each of the 34 bundled samples one
at a time**, sweep **25,309-class / 213,374 method-block 0-crash 0-timeout
0-error, GATE: PASS**, determinism 3 processes x 3 `PYTHONHASHSEED`s -> one
digest, lint trio clean, doc fences 78,
`scripts/check_dad_boundary.sh` clean.

**Guards** (18 new cases in
[tests/test_invoke_custom_ir.py](tests/test_invoke_custom_ir.py), the file that
already owns call-site crafting; 32 -> 50). The craft has to LENGTHEN an element,
so it cannot be length-preserving: it APPENDS a fresh `encoded_array` at EOF
(4-aligned), repoints ONE `call_site_id` at it, and grows `file_size` /
`data_size` — the shape [tests/test_encoded_value_lockstep.py](tests/test_encoded_value_lockstep.py)
uses for the same reason [[one-byte-crafts-cannot-prove-width]]. It pays for the
lost length-preservation by ASSERTING the dex still verifies, and it rebuilds
site 0's own element values so the chain stays resolvable and the only variable
is the one under test. Four families, each parametrised over all four arms:
natural (the control), **wide-but-in-range**, over-2**32, and in-`uint32`-but-
out-of-table. Plus a legitimately EMPTY string element, and a premise test.

**9 mutants, each BUILT and RUN with a distinct `.so` md5, each killed — and
FOUR of them were CONSTRUCTED BY THE REVIEWERS, each having passed the whole file
as it then stood:**

| mutant | outcome |
|---|---|
| M0 true pre-fix, the whole file at HEAD (md5 = the OFF build's, exactly) | 5 failed |
| M0b the three width clauses removed | 3 failed (not 4 — the 0x17 range bound subsumes its width clause) |
| M1 / M2 / M3 each arm's width clause alone (three distinct md5s) | 1 failed each |
| M4 the 0x17 range bound removed | 2 failed |
| **G1 `return true;` on the 0x18 + 0x15 arms** | 2 failed |
| **G2 the 0x17 range bound swapped back for an emptiness proxy** | 2 failed |
| **G3 `nbytes > 4` — refuse by WIDTH instead of by VALUE** | 3 failed |
| **G4 `>=` instead of `>`** | **49 passed — EQUIVALENT, not an escape** |

**G3 is the one worth reading twice, and BOTH reviewers built it independently.**
The clause is on the VALUE; the plausible alternative is on the WIDTH — which is
what this section's own first title said. A non-minimal `value_arg` is legal, the
array is gate-unchecked, so an in-range index at eight bytes must still resolve —
and the first cut tested only widths 4 and 8, with width 8 used ONLY for the
out-of-range value, so the two axes were confounded in every case and the mutant
passed all 40. The `wideok_*` family separates them.

**G1 and G2 are the same shape one level down:** the ONLY range bound the `0x18`
and `0x15` arms have is their resolver returning empty, and the ONLY thing
distinguishing the 0x17 range bound from an emptiness proxy is a legitimately
empty string — neither of which anything tested. The `oob_*` family and the
empty-name craft close them. **G4 is a genuine EQUIVALENT mutant** rather than an
escape: `0xFFFFFFFF` is out of range for every table in reach, so `>` and `>=`
refuse the same inputs by different routes; recorded rather than papered over.

**Adjacent, stated rather than discovered (adversarial review), NOT fixed here:**
the sibling VALUE arms of the same switch narrow or mis-read a wide payload too —
an 8-byte `0x04 INT` renders `1099511627775`, `0x03 CHAR` truncates to 16 bits,
an 8-byte `0x10 FLOAT` takes the LOW four bytes (the opposite of the
right-justification rule dexllm#70 established), and `0x1F BOOLEAN` with
`value_arg = 2` renders `false` where ART's reader gives true. Same function,
same gate-legality, but a different defect family (value arms, not index arms)
with its own blast radius and its own a/b.

### The entry block is the one holding the first instruction, not block 0 (dexllm#75, 2026-08-24)

The wrong-ANSWER defect dexllm#73's adversarial review found and that issue
deliberately left alone. **Pre-existing** — identical on
`e411eb0941e22563227b3c76a9cb0172` (pre-#73) and
`bbbbcd569aa15726628df2d9b3f16a48` (post-#73), so neither caused nor closed by
it.

```cpp
snap->entry_block_id = 0;  // first block is entry (lowest byte_off)
```

The ordering half is right and the conclusion is not. Block 0's span starts at
the lowest **LEADER**, and a leader is seeded per BRANCH TARGET (stage 2) and per
try-range START / handler address (stage 3) as well as at the first instruction.
When the code item opens with a switch/fill-array payload — which
`DecodeAllInsns` skips — and any of those lands inside it, **block 0 is a span
with no instruction in it**. `ComputeChildEdges` skips a block with no last
instruction, so it gets no successor, the graph is one empty block, and the whole
body is dropped: `decompile_method` renders `{ }` for a method whose
`render_method_smali` lists real instructions. **The two views of one method
disagree**, and the Java one — the primary LLM-facing surface — is the confident
wrong answer.

**Two routes, and only one of them needs a try table.** The issue's repro uses the
try-range start; a delta reviewer of dexllm#73 added the second, and it is the
wider one: `VerifyInsns` bounds a branch target's RANGE and does not require it
to be an instruction boundary, so an `if-eqz` targeting code unit 0 is gate-legal
with no try table anywhere in the method. Both are `verify()`-valid in BOTH
modes.

**The new rule is provably a no-op wherever the old one was right, and the
argument is exact rather than empirical:** `ins_storage.front().byte_off` is
ITSELF a leader, so `leaders[0] <= it`; block 0 holds the first instruction iff
`leaders[0] == it`; therefore **block 0 is non-empty iff it IS the block the new
rule looks up**. The a/b below is that restated as a measurement.

## The policy question the issue left open, and the answer

The issue listed three: reinterpret from the first instruction, refuse, or reject
at the gate. **Escalated to the user (CLAUDE.md rule 5), who chose reinterpret
AND MARK.**

* **Not the gate.** It refuses the whole dex over one method — the same
  trade-off dexllm#73 declined for `insns_size == 0`.
* **Not refuse.** `// DECOMPILE ERROR` is loud, but it throws away a body the
  smali view renders correctly, so the two views stay in disagreement with only
  the direction reversed. The realistic source is a packer dump — the population
  `lenient=True` exists for — and that is exactly where an analyst wants the
  body.
* **Reinterpret, and say so.** Starting at the first decodable instruction is
  NOT what would execute: a VM starts at `insns[0]`, so such a method cannot run
  at all (ART's runtime `method_verifier` rejects it; the STRUCTURAL verifier
  this port mirrors does not, which is why it loads). Both emitters mark it —
  the same "say what you could not do straight" choice dexllm#73 made for
  `// no instructions` and dexllm#64 for `// = ...`.

**The marker's predicate is the WEAKER one** — `ins_storage.front().byte_off != 0`,
not "the entry moved". The second implies the first and not the reverse: a
leading payload with NOTHING seeded inside it leaves block 0 holding the first
instruction, so the entry choice was already right there and the body always
rendered — but it is still a method whose first code unit is not an instruction,
i.e. still a reinterpretation, and it was already a silent one before this
change. That case is the `payload_only` craft, and it is what separates the
MARKER from the FIX.

```java
public static Object autofuzz(com.code_intelligence.jazzer.api.FuzzedDataProvider p2, com.code_intelligence.jazzer.api.Function1 p3)  // entry is not at offset 0
{
    try {
        return;
    } catch (Throwable _) {
    } catch (com.code_intelligence.jazzer.api.AutofuzzInvocationException _) {
    }
}
```

**The AST carries the identical string in its `comments` array**, which is a
beyond-DAD divergence: DAD's `dast.py` `get_ast()` reserves that field and never
fills it. Without it an AST-only consumer (`include_source=False`) has no way to
see the reinterpretation — the text/AST divergence the dexllm#63 review found for
`boolean v = 0` is the cost of marking one emitter and not the other. The
marker's text is FIXED; no attacker-controlled bytes reach it.

The two markers are **mutually exclusive by construction**:
`code_without_instructions` needs an EMPTY `ins_storage`, this one a non-empty
`front()`. A `<clinit>` renders `static  // entry is not at offset 0` then its
block — the marker ends the DECLARATION line in every shape, which is the only
safe place for a line comment and is guarded as such.

**The builder bounds its own lookup.** `FindBlockIdForByteOff` returns
`UINT32_MAX` for an offset that starts no block; storing it would publish
`entry_block_id = 0xFFFFFFFF`, reported one layer down by dexllm#73's bound as a
malformed SNAPSHOT rather than as the producer bug it is. Unreachable from any
input (the first instruction's offset is always a leader), so it is pinned at
SOURCE level — weaker than a behavioural guard, and the test says so.

**Measured (a/b OFF=`238911494b43c603829140b2820f5f63` — HEAD, bit-reproduced by
the pre-fix mutant — vs ON=`9f1baa1247b5b2796d7458f615c00033`, SAME script, both
`.so` md5-verified):** 96 sources — the whole bundled corpus (37), every
committed fixture (6), every `art/test/dexdump/*.dex` (10), every
`tools/dexter/testdata/*.dex` (11), **all four ART fuzzer corpora** (28) and 4
CRAFTED — x {strict verify, lenient verify, load, `dex_count`, class list, a
smali digest, a whole-decompile digest, decompiled line count, `// DECOMPILE
ERROR` count, marker count, an AST digest, `warm_analysis_caches`, and the
subprocess EXIT STATUS} = **1077 axis records present, 11 changed, ALL of them
crafts, 0 REAL source changed on any axis**, over 3,043,732 decompiled lines.
The 1077 is re-derivable rather than a harness number: 77 sources load and carry
all 13 axes, 19 are rejected and carry 4 — 13x77 + 4x19
[[published-counts-need-the-repos-own-predicate]]. Each source runs in a
SUBPROCESS whose axes are FLUSHED one per line, and all 96 exit 0 on both halves.

The bundled corpus carries **0** methods whose first code units are a payload
(the dexllm#73 census: three independently written raw-dex parsers over the
corpus, the fixtures, `art/test/dexdump`, `tools/dexter/testdata` and all four
fuzzer corpora), so a corpus-only a/b is byte-identical BY CONSTRUCTION and the
crafts are the only thing that can show the mechanism firing
[[ab-must-prove-the-mechanism-fires]]. The four are chosen to SEPARATE the two
halves of the change:

| craft | axes that move | what it isolates |
|---|---|---|
| `craft_try` — a try-range start at 0 | `java`, `java_lines` +1, `entry_markers` 0->1, `ast` | the FIX, reached through stage 3 |
| `craft_branch` — an `if-eqz` targeting unit 0, no try table | `java`, `java_lines` +4, `entry_markers` 0->1, `ast` | the FIX, reached through stage 2 |
| `craft_payload_only` — a leading payload with nothing inside it | `java`, `entry_markers` 0->1, `ast` — and **NOT `java_lines`** | the MARKER alone; the entry choice does not move here |
| `craft_no_payload` — the same body rewrite, no payload | **nothing** | the control: same method, same rewrite discipline, entry at 0 |

Pre-fix, `craft_branch` renders `{ }` and `craft_try` renders an empty
`try { } catch { } catch { }` — the try geometry decides which of the two you
get, and neither is the body.

parity **29/29** (the count is unchanged — the new cases went into the existing
`construct_parity_test`, which grows by 19 checks, 32 -> 51), pytest **1100 passed / 24
skipped**, TRUE corpus-less (`test_apk` MOVED aside) **700 passed / 424 skipped /
0 failed** — all 21 of the new cases run in the CI leg, since every craft is on a
committed fixture — narrowed to `tests/data/multidex.apk` **1001 passed**, the
guard file green narrowed to **each of the 34 bundled samples one at a time**
plus the committed one, sweep **25,309-class / 213,374 method-block 0-crash
0-timeout 0-error, GATE: PASS**, determinism 3 processes x 3 `PYTHONHASHSEED`s ->
one digest, lint trio clean, doc fences 78,
`scripts/check_dad_boundary.sh` clean.

**Guards, in TWO layers, and the matrix is what proves they are complementary.**
[tests/test_entry_block.py](tests/test_entry_block.py) (21 cases) crafts all five
shapes IN PLACE on the committed `tests/data/method_handles.dex` — the only
fixture that offers BOTH a try starting at 0 and a try-free method with room —
rewriting only code units inside one code item's `insns`, so it is
length-preserving to the byte and the craft's verify verdict is ASSERTED in both
modes rather than assumed (a rejected dex never reaches the IR builder, so a
guard that skipped this could pass for the wrong reason). **No decompile of a
CRAFTED dex runs in the pytest process** — this file sorts early, and a
regression that faulted in the builder would abort the whole session here rather
than report. 19 checks in
[tests/parity/construct_parity_test.cpp](tests/parity/construct_parity_test.cpp)
pin the ABI contract no Python assertion can see: both routes reach the same
entry, block 0 is empty, the entry block HAS instructions, and the
payload-with-no-leader case keeps entry 0 while STILL being marked.

**11 mutants, each BUILT and RUN with a distinct `.so` md5, each killed** (the
table is the FINAL 21-case guard file; an earlier run against a 15-case cut
published M0 as 11 failures, which a correctness reviewer could not re-derive —
it was a stale count, not a stale conclusion):

| mutant | pytest | ctest[construct] |
|---|---|---|
| M0 pre-fix — all five files at HEAD (md5 = the OFF build's, exactly) | 18 failed | N/A — HEAD's own cases |
| M1 entry reverted to block 0, marker kept | 5 failed | FAIL 7 |
| M2 the marker flag never set | 13 failed | FAIL 3 |
| M3 the Writer marker dropped | 13 failed | pass |
| M4 the AST marker dropped | 4 failed | pass |
| M5 the marker keyed on `entry != 0` instead of on offset 0 | 7 failed | FAIL 1 |
| M6 the marker ASSIGNED unconditionally | 3 failed | FAIL 1 |
| M7 entry looked up at byte offset 0 | 11 failed | **SIGNAL 6** |
| M8 the `UINT32_MAX` sentinel stored instead of refused | 1 failed | pass |
| M9 the marker moved INSIDE the body | 7 failed | pass |
| M10 the flag's DEFAULT flipped to `true` | 2 failed | pass |

M3, M4, M8, M9 and M10 are invisible to the C++ layer, and M1's seven C++
failures are what the Python cases largely miss — the two-layer argument stated
as a measurement. **M10 is a reviewer's mutant**: it flips the field's
INITIALISER rather than the assignment, so it also fires on a snapshot that never
reaches the assignment (an empty `ins_storage`, whose Writer path has no graph),
and only the AST can see it. It was killed by ONE assertion until the pristine
sweep was extended to walk every method's AST as well as its text. **M0 cannot be built with the new C++ cases in the tree at all** —
they reference a member the pre-fix ABI does not have — so that compile failure
is its own kill and the ctest column for it is N/A.

**M9 is the one worth reading twice, and it ESCAPED the first cut.** The marker
guards asserted `MARKER in text`, which says nothing about WHERE. Moved three
statements later — after `{` is emitted and before the body — a line comment
prefixes the first body statement and silently comments it out, and all 12 cases
then passed. `test_the_marker_ends_the_declaration_line` closes it by asserting
the marker ENDS its line and that the next line is the body's `{`, parametrised
over all four marked shapes including a `<clinit>`, where the line it ends is the
bare `static` keyword dexllm#73 emits.

**M8 is killed by a SOURCE pin and nothing else, necessarily.** The first
instruction's offset is always a leader, so the lookup cannot miss from any
input; the pin says so and says that it is weaker than a behavioural guard.

**Cost:** one extra `FindBlockIdForByteOff` per method, a linear scan over
`blocks`. `ComputeChildEdges` already loops every block and calls the same helper
for each one that ENDS IN A BRANCH, so the pre-existing pass is O(N) at best and
O(N^2) whenever branches are dense — either way one more O(N) scan cannot
dominate it. (An adversarial reviewer corrected the first version of this
sentence, which claimed O(N^2) unconditionally: that loop `continue`s on a block
with no instructions, so a method of many EMPTY blocks is O(N). The conclusion
survives, the reason did not.) Measured cold-cache, interleaved OFF/ON/OFF/ON on
`a2dp.Vol_137.apk`: 2570 / 2569 / 2525 / 2563 cls/s, and sweep throughput is
unchanged.

**Adjacent, stated rather than discovered:** a leading payload is the ONLY way to
reach either shape, because every other leader source is bounded below by 0 and
the first instruction is at 0 unless something before it is skipped. And the
`payload_only` case shows the residual honestly: the body there was always
rendered correctly, so what the marker adds is the statement that it is a
reinterpretation — the entry defect and the reinterpretation are different sets,
and only the larger one is marked.

## What the two reviewers found — 0 in the production code, 1 CONFIRMED consequence of it, and 6 in the guards and the prose

**The change is correct and both reviewers say so with their own instruments.** A
correctness review re-derived the exactness argument from `ComputeLeaders` and
`SplitIntoBlocks` rather than accepting it (`ins_idx_by_byte` is written ONLY at
instruction offsets, so any leader strictly below the first instruction yields
`SIZE_MAX` and an empty span; `leader_byte_offs` is a `std::set` and
`SplitIntoBlocks` emits exactly one block per leader, so the lookup can neither
miss nor be ambiguous — **the `UINT32_MAX` throw is provably dead, which is what
makes the source pin the right instrument rather than a cop-out**), confirmed the
bfs order cannot move on any well-formed input, and traced text/AST agreement to
`DecompileMethodAst` assigning `ast.source = DecompileMethod(descriptor)` — the
same call. An adversarial review fuzzed ~3,600 crafted code items over ~7,100
subprocess runs in both modes. Both re-derived the a/b to the digit (1077 records
/ 11 changed / all crafts; 3,043,732 lines; the `payload_only` separation).

## The CONFIRMED finding: this change WIDENS a pre-existing crash

An adversarial reviewer built a **strict-`verify()`-valid** dex — a
length-preserving rewrite of one code item of `tests/data/method_handles.dex`,
eight non-zero code units — on which `decompile_method` SIGSEGVs with this change
and returns normally without it. **Reproduced here independently, on builds whose
md5 was asserted at every step.** The mechanism is unbounded self-recursion in
`BinaryExpression::get_used_vars()` — an IR cycle, the family CLAUDE.md's
"Root-cause fixes" section already records — and no `catch (...)`, no `safe.py`
deadline and no SDK wrapper can contain a signal.

**The ablation is what makes the attribution exact**, and each row was built and
run on both halves:

| crafted body (all strict-valid in BOTH modes) | OFF = HEAD | ON |
|---|---|---|
| leading payload + branch INTO it + self-referential `shl-int/lit8 v1,v1,#-1` + back edge | **exit 0** | **SIGSEGV** |
| the same minus the payload and the branch into it | **SIGSEGV** | **SIGSEGV** |
| the same minus the self-referential `shl` | 0 | 0 |
| the same minus the back edge | 0 | 0 |

So **the crash is PRE-EXISTING and independently reachable on master today**: the
second row needs no payload, no leader below the first instruction, and nothing
this change touches. What this change supplies is REACHABILITY — on HEAD a
#75-shaped method had its body DROPPED, and that incidentally prevented the
pipeline from ever building the cyclic IR. Fixing the wrong answer runs the body,
and every latent body-level defect in that newly-reachable class of methods now
runs with it.

**This breaks two properties this project markets** — 0-crash on malformed dex,
and `VerifyDex` as the single gate — and it is stated here rather than left to be
discovered, because **the second row of that table means master already breaks
them**. Holding this change would not protect the property; it would only keep a
wrong answer. **Escalated to the user (CLAUDE.md rule 5) with exactly this
evidence, who chose to ship the fix and file the crash as its own issue** —
dexllm#76, **FIXED in the section below**: the root is a definition that reaches
its own use, which `RegisterPropagation` then substituted into its own
computation. Bolting a depth guard onto `get_used_vars` here was NOT done and is
the reason the escalation happened: CLAUDE.md's own record is that a
`GetUsedVarsGuard` in that exact function was REMOVED because it MASKED a real
port bug, so the root belongs at the dataflow layer with its own a/b, not in this
commit.

**Why nothing in this change could have seen it:** every craft in the a/b and in
all 21 guards has a two- or three-instruction body, so none exercises a
newly-reachable body large enough to form a cycle. "11 changed records, all
crafts" is fully consistent with the widening — a lesson about what a
0-regression a/b does NOT cover [[ab-must-prove-the-mechanism-fires]] one level
up: it shows the mechanism firing, and says nothing about what the mechanism now
makes reachable.

## Adjacent, pre-existing, identical on both halves, NOT fixed here

**A mid-body leader inside a payload silently truncates the body.** Same root one
position over: `SplitIntoBlocks` reads `ins_idx_by_byte[start]` at the block START
only, so a block whose start is not an instruction offset gets an empty `ins`
span even when instructions lie INSIDE its span. Built by a reviewer
(`const/4` → `if-eqz` targeting a mid-body payload → payload → `const/4` →
`return-void`): verifies valid in both modes, Java renders `if (1 != 0) { }`,
smali lists the instructions after it — **byte-identical OFF and ON**. This change
addresses only the ENTRY. Filed with the crash.

## The six in the guards, the docs and the counts — every one fixed here

* **A C++ check labelled "the body survives" could not fail.** `[entry try]`
  asserted `g->size() > 0` where its 7a sibling asserts `> 1`; `Construct` always
  builds the entry node, and in 7b the empty block 0 carries an exception edge,
  so the graph is size 2 even pre-fix. A reviewer built the entry-reverted mutant
  and watched this check report `got=1 want=1` — passing against precisely the
  defect its label names. Now `> 1`, with 7a's `entry block HAS instructions`
  counterpart added.
* **`test_the_java_view_no_longer_contradicts_the_smali_view[try]` passed against
  the defect.** Its oracle was `_body(text)` truthiness, and the pre-fix `try`
  rendering is `try { } catch { } catch { }` — non-empty. Measured on M0: only
  `[branch]` failed. It counts executable STATEMENTS now.
* **`assert got["ast_body"]` was vacuous** — `["BlockStatement", null, []]` is
  truthy, so the AST side of the headline test was dead weight on both halves.
  Both the text and the AST now assert the craft's OWN `return-void`, which is
  the one instruction in it that survives DCE.
* **The AST marker's own justification was unguarded.** Its stated reason is that
  an `include_source=False` consumer can see the reinterpretation, and no test
  called it that way; `ast["source"]` was only checked for containing the marker,
  never for equality with `decompile_method`. Both are asserted now.
* **`docs/api.md` said something false.** "no method in … or the four ART fuzzer
  corpora has either" — the unmodified
  `art/tools/fuzzer/class-verifier-corpus/b391844326.dex` carries a
  `// no instructions` method, and it is the file CLAUDE.md's own dexllm#73
  section names as its exemplar. CLAUDE.md was correctly scoped; only the api.md
  mirror overstated, which is the one-mirror-updated pattern this file keeps
  recording. Narrowed to the dexllm#75 marker, with the counter-example named.
* **Two published counts did not re-derive**: the C++ additions are **19** checks
  (32 → 51 at runtime), not 23; and M0 kills **18** of the 21 cases, not the 11 a
  15-case run had produced. Both corrected, and the whole matrix re-run against
  the final guard file [[published-counts-need-the-repos-own-predicate]].

**Two process notes.** A reviewer's brief named one worktree while its cwd was
another, and it found a concurrent process flipping files underneath it — it
moved to a private copy and said so, which is the only reason its numbers are
usable [[reviewer-agents-swap-the-worktree]]. And three of my own ad-hoc a/b
scripts measured the ON build twice while reporting an OFF half, because the C++
guard file references a member the pre-fix ABI lacks, so the OFF build FAILED TO
COMPILE and ninja left the previous `.so` in place — a mutant that does not
compile is not a mutant, and the md5 assertion is what caught it every time
[[mutation-harness-restore-pitfalls]].

### A definition is never propagated into itself (dexllm#76, 2026-08-25)

`RegisterPropagation` ([dataflow.cpp](native/dad_cpp/dataflow.cpp), DAD
`dataflow.py:190`) substitutes a uniquely-reaching definition into its use. It
read the reaching-definition chain without asking WHERE that definition is, and
`ud[{var, i}] == {i}` is a legal answer: a loop back edge carries `i`'s own
definition to `i`'s own use, and when no other definition reaches — i.e. the
register is **read before it is ever written** — that self-definition is the
ONLY one, so `locs.size() != 1` does not filter it out.

Substituting a value into its own computation is meaningless, and mechanically
it splices the instruction's own rhs underneath itself. `IRForm::var_map` is a
per-node child map, so `BinaryExpression::replace`'s `var_map[old_v] = new_node`
makes the node **its own operand**. The IR is then CYCLIC, and every recursive
walk over it runs away: an **uncatchable SIGSEGV** — a signal unwinds nothing,
so the per-method `catch (...)`, `safe.py`'s deadline and the SDK wrapper all
miss it, which is what dexllm#75's review verified across every decompile
surface.

**Which walker dies is a property of the input, not of the defect**, and the
first draft of this section said `get_used_vars` as though it were the whole
surface. Measured under gdb: the issue's repro and every crafted shape here
bottom out in the respective `get_used_vars` (`BinaryExpression`'s,
`UnaryExpression`'s, `ArrayLengthExpression`'s, `ArrayLoadExpression`'s — and
MUTUALLY between two of them when two IR classes alternate around the cycle),
while the adversarial review's own fuzz found inputs that die inside
**`replace`** instead (`UnaryExpression::replace` ↔ `BinaryExpression::replace`).
That widening matters because it strengthens the case against the masking
alternative below: a depth cap on one walker leaves the others.

It breaks the two properties this project markets — 0-crash on malformed dex,
and `VerifyDex` as the single gate — on a dex that verifies **strict**-valid, so
`lenient=True` was never the boundary. **Pre-existing**: it reproduces on
`238911494b43c603829140b2820f5f63` with nothing from dexllm#75 involved; that
change made it reachable through one more shape (a body whose first code units
are a payload used to have its body DROPPED, which incidentally prevented the
pipeline from ever building the cyclic IR) and was shipped after an escalation
that filed this separately. It is also the residual of a family this file
already records: the "Root-cause fixes" section above documents
`RegisterPropagation` substituting un-split variables "into their own def chains
→ IR cycles → stack overflow", and the two masking guards that hid it being
REMOVED.

**Fix — one condition, at the root:** `if (loc == i) continue;`. The value used
at `i` is defined by `i` itself; there is nothing to propagate. The instruction
then stays as the bytecode wrote it and renders honestly — the issue's own repro
becomes `do { int v1 <<= -1; } while(v0 == null);`, which is exactly what the
smali view lists, so the two views of one method agree.

**Confirmed upstream, by running it:** androguard DAD hits the identical defect
on the identical bytes (with the adler32 corrected — that check is out of THIS
gate's documented scope), recursing in `instruction.py:1095
BinaryExpression.get_used_vars` until `RecursionError`; a correctness reviewer
reproduced it with a second overload of the same method as a built-in control
that decompiles fine. Upstream goes from `if loc < 0: continue` (:219) straight
to `get_ins_from_loc(loc)` (:221) — a first draft of the C++ comment cited
`:214`, which is the sibling `len(locs) != 1` check one position early. Python
turns the same defect into a catchable exception and C++ into a signal. So the
guard is a **beyond-DAD** production divergence on the return-literal /
catch-clamp precedent — no `*DADFaithful` sibling, since the parity suites do
not assert propagation of a self-definition. **Parity passes on BOTH halves**
(29/29 pre-fix and post-fix, a reviewer's measurement), which is the statement
that no suite asserts the changed behaviour.

## Two alternatives were rejected, and one of them by measurement

**A recursion-depth cap on `get_used_vars` is the MASK, not the fix**, and the
issue says why: CLAUDE.md's own record is that a `GetUsedVarsGuard` in that exact
function was REMOVED because it hid a real port bug. Built as mutant M4 and RUN,
it is worse on three separate axes — it leaves the self-substituted expression in
the output (`do { }`, the statement gone), it takes the guard file from **27 s to
907 s**, and **it does not even contain the crash**: a reviewer's fuzz inputs and
the non-`BinaryExpression` shapes below still SIGSEGV under it, because the cycle
is still built and the OTHER walkers still run away. 18 of 32 cases fail.

**The gate is the wrong place.** This is instruction DATAFLOW semantics, which
`dex_verifier.h` scopes out explicitly and which ART itself only checks in the
6032-line runtime `method_verifier` this port refuses to vendor — and rejecting
the whole dex over one method is the trade-off dexllm#73 already declined.

## The condition was MEASURED, not argued — twice, independently

An instrumented build logged (a) `loc == i` and (b) a **definitive** path-based
cycle detector run over `ins` after every splice — a node that reappears on the
CURRENT ancestor path, so a shared subtree (a DAG) does not count. An earlier,
coarser probe asked whether `rhs` was already reachable from `ins` and fired
**1,145 times on one ordinary APK**; it was measuring DAGs, and replacing it was
the difference between a number and a fact.

| population | classes | cycles | of which `loc != i` |
|---|---:|---:|---:|
| 93 sources — bundled corpus, every committed fixture, `art/test/dexdump`, `tools/dexter/testdata`, all four ART fuzzer corpora | 33,853 | **0** | 0 |
| 600 structured fuzz bodies (valid encodings, random registers/literals, random back edge) — **600/600 verify strict+lenient** | — | **12** | **0** |
| 4 hand-built mutual-recursion shapes | — | 3 | 0 |

On the fuzz the cycle detector and the SIGSEGV correspond **1:1** (12 and 12),
which is the mechanism confirmed from both ends. And the mutual shapes are the
natural objection to a `loc == i` guard — they build the cycle through two and
three instructions — yet every one of them reports `same=1`: the ud/du
bookkeeping rewrites the chain onto the surviving instruction FIRST, so the step
that actually creates the cycle is always a self-definition.

**An adversarial reviewer re-derived this with its own instrument and got the
same answer at ten times the scale** — an ITERATIVE colour DFS (mine is
recursive; it terminates because it stops at the first repeat, but a reviewer
correctly noted that a recursive detector over a deep chain can lose its own log,
and it misread one run that way before rewriting it): **4,881 bodies / 371,194
propagation steps / 932 cycles, every one `same=1`, zero `same=0`**. With the
guard ON: **600 sources / 40,383 classes → 0 cycles**, and 2,002 bodies from the
generator that kills 65-in-336 without the guard → 0 cycles, 0 crashes. It also
found the structural reason: a non-const rhs is `du.size() > 1 → continue`
guarded and therefore ALWAYS `remove_ins(loc)`-ed after its single splice, so an
A→B, B→A pair cannot form; and a const rhs is leaf/ident, which the parent's
`replace` does not descend into.

## Measured

**a/b OFF=`a15d1644ef85c315e9f3f140462ce1c2` vs
ON=`08104afea5da1252dfe91168d274e3fa`, SAME script, both `.so` md5-verified
BEFORE and AFTER each capture — and the OFF build BIT-REPRODUCES the recorded
HEAD md5**, which is the diff's functional content stated as a measurement (the
pre-fix mutant M0 reproduces it too, from the other direction; a reviewer
additionally built a statement-only variant with the comment block deleted and
got a binary bit-identical to the fix, so the 29-line diff is one statement).
119 sources — 93 real plus **26 crafted** — x {strict verify verdicts + reasons,
lenient verify, load, `dex_count`, class list, a smali digest, a whole-decompile
digest, decompiled line count, `// DECOMPILE ERROR` count, an AST digest over
every method, `warm_analysis_caches`, and the subprocess EXIT STATUS} = **1268
axis records, 132 changed, 23 sources changed — ALL crafted, 0 REAL**.

Each source runs in a SUBPROCESS whose axes are FLUSHED one per line, so the
crashing half still reports what it computed before dying (OFF carries 1163 of
the 1268 records for exactly that reason); judging by EXIT STATUS is not a
detail, because a `try/except` cannot observe a SIGSEGV. The 23 split cleanly:

* **21 are `_EXIT` -11 → 0** plus the five axes they never reached (`java`,
  `java_lines`, `decompile_errors`, `ast`, `warm`), with `decompile_errors`
  **0** — the methods RENDER rather than being reported as errors.
* **2 never crashed on either half and change only their rendering** —
  `move v1, v1` and `move-object v1, v1`, a self-assignment. Pre-fix the
  propagation produced DAD's `// Both branches of the condition point to the
  same code.` form; with the guard the loop body is empty in the TEXT while the
  AST still carries a `LocalDeclarationStatement` for the register. Found by an
  adversarial reviewer, on a shape that was in NEITHER the guard file nor the
  a/b craft set — so the a/b was widened to hold it rather than only the crashes.
  Recorded, not repaired: chasing the `Dummy` initializer is a separate defect
  on a read-before-write register with its own blast radius.

The three non-crashing ablation crafts (`no_self_def`, `no_back_edge`,
`mutual2_no_back_edge`) are unchanged, which is the ablation stated as a
measurement: both ingredients are necessary.

The bundled corpus carries **0** instances of the condition, so a corpus-only
a/b is byte-identical BY CONSTRUCTION and proves 0-regression and nothing about
the mechanism; the crafts are in the same measurement for exactly that reason
[[ab-must-prove-the-mechanism-fires]].

parity **29/29**, pytest **1159 passed / 24 skipped**, TRUE corpus-less (`test_apk` MOVED
aside) **755 passed / 428 skipped / 0 failed**, narrowed to `tests/data/multidex.apk` **1059 passed**, the
guard file green narrowed to **each of the 34 bundled samples one at a time**
plus the committed one, sweep **25,309-class / 213,374 method-block 0-crash
0-timeout, GATE: PASS**, determinism 3 processes x 3 `PYTHONHASHSEED`s -> one
digest, lint trio clean, doc fences **81**,
`scripts/check_dad_boundary.sh` clean.

## Guards

32 cases in [tests/test_self_propagation.py](tests/test_self_propagation.py),
ALL corpus-independent — every craft rewrites code units INSIDE one code item of
the committed `tests/data/method_handles.dex`, length-preserving to the byte, so
no offset and no section size moves and nothing but the intended words can be
what changed. Each craft's verify verdict is ASSERTED in BOTH modes rather than
assumed: a rejected dex never reaches the IR builder, so a guard that skipped
this could pass for the wrong reason. **No decompile of a crafted dex runs in
the pytest process** — the defect is an uncatchable signal, so an in-process
assertion cannot survive the thing it asserts about; one child gathers the
observations and the tests assert on its JSON and its EXIT STATUS. (A reviewer
verified the isolation holds: against the pre-fix build the file reports clean
assertion failures naming `exited -11 (SIGNAL)` instead of aborting the session.)

Nine cycle shapes, two non-crashing shapes and three controls, plus text/AST
agreement parametrised over ALL eleven, the whole class surviving, and TWO
anti-vacuity anchors — a sibling method in the SAME crafted file still renders
`return this.pickValue(p5.toArray());`, which is only possible because a
temporary was PROPAGATED into it. Without that, every test here passes against a
build whose `RegisterPropagation` does nothing at all.

**The loop BODY is pinned as a literal per shape**, and that is what three
survivors forced — two found by the matrix, one by an adversarial reviewer:

* **`loc >= i`** also suppresses legitimate loop-carried (backward)
  propagation. Measured against the fix: **0 REAL sources move, 3 crafts do** —
  `mutual2` renders under the other register and `mutual3` never folds — so only
  a crafted body can state the difference.
* **`break` instead of `continue`** abandons the instruction's REMAINING
  variables. `v1 = v1 + v2` is circular in `v1` and perfectly ordinary in `v2`;
  the fix renders `int v1 += 3;` and `break` renders `int v2 = 3; int v1 += v2;`
  — a real loss on a shape the fix is supposed to leave alone.
* **the guard 1059 passed to a `BinaryExpression` rhs** — the finding that mattered
  most, and it is [[fixture-dead-branches-hide-guards]] again. The original six
  shapes encoded three different opcodes and built **one IR class**, so a
  plausible tidy-up (`loc == i && dynamic_cast<BinaryExpression*>(rhs.get())`)
  passed all 17 cases AND the whole 1141-test suite while leaving SIX shapes
  SIGSEGVing. Verified here on a pre-fix build: `neg-int` / `not-int` /
  `int-to-long` (`UnaryExpression`), `array-length` (`ArrayLengthExpression`),
  `aget` (`ArrayLoadExpression`) and `check-cast` (`CastExpression`) each fault
  on their own, each in their OWN `get_used_vars`. Three of them are shapes now,
  and the mutant fails 8.

**9 mutants, each BUILT and RUN with a distinct `.so` md5, each rebuilt to the
control (md5 ASSERTED) before the next, with the control asserted again at the
end — 7 killed, 2 PROVEN equivalent rather than waved away:**

| mutant | outcome |
|---|---|
| M0 pre-fix, the guard removed (md5 = the OFF build's, exactly) | **26 fail** |
| M1 `loc <= i` — kills forward propagation | 8 fail |
| M2 `loc >= i` — kills backward propagation | 2 fail (the pinned bodies, and nothing else) |
| M3 the guard moved AFTER the splice | 24 fail |
| M4 MASK: a depth cap in `get_used_vars` | 18 fail, 27 s → **907 s**, and it still crashes |
| M5 `break` instead of `continue` | 2 fail (the sibling craft, and nothing else) |
| **MA the guard narrowed to a `BinaryExpression` rhs** (reviewer-built) | **8 fail** |
| M6 the guard placed inside the non-const branch | **EQUIVALENT** — 0 of 1268 axis records move |
| M7 `orig_ins.get() == ins.get()` instead of `loc == i` | **EQUIVALENT** — 0 of 1268 axis records move |

M6's equivalence has an argument as well as a measurement, and the argument is
the interesting half: a const rhs with a non-empty `get_used_vars` exists only
as a `Cast`/`CheckCastExpression` over a `Param` (`Variable::is_const` is the
inherited `false`; only `Param` overrides it), and a `Param` always carries its
own entry definition at a negative loc — a SECOND reaching def, so
`locs.size() != 1` skips before the guard is ever consulted. Both reviewers
reproduced the equivalence independently, and it was re-measured on the
WIDENED craft set after the review rather than carried over.

## What the reviewers established that I had not

Beyond the two findings above, a correctness review re-derived every headline
number from its own builds (33,853 classes / 0 probe hits; 25,309-class sweep;
42-changed a/b on the pre-widening craft set; the corpus-less and narrowed
totals) and verified every falsifiable claim in the C++ comment — that ART's
runtime verifier hard-fails a read-before-write register
(`method_verifier.cc:1010` / `:2963`), that `var_map[old_v] = new_node` is the
branch it names, and that a thread deadline cannot survive a process-killing
signal. It also established the DECISIVE narrowness case by construction: a
register initialized before the loop gives `ud` two locs, so `locs.size() != 1`
skips first and the guard **fires 0 times** — `int v1 = 5; do { v1 <<= -1; }` is
rendered with the guard never consulted. And it noted the guard makes
`remove_ins(i)` — deleting the instruction currently being iterated —
unreachable, which is a narrowing rather than a new state.

## What the harnesses got wrong, three times

The first cycle probe measured DAGs (above). The a/b keyed each source on its
BASENAME, so `invoke-custom.dex` at two paths collided and the run reported
**90 sources where there are 103** — the same shape dexllm#61's diff harness hit,
in the same repository [[ab-harness-must-itself-be-deterministic]]. And a
background matrix run was read as finished when the notification was for the
`nohup` wrapper shell rather than the matrix, so a tree still holding M4 looked
like a restore failure; the fix is the control-md5 assertion at both ends, which
is what said the tree was fine.

**Both reviewers hit the same environment trap, independently, and it is worth
recording:** in a fresh venv `pip install -e . --no-build-isolation` fails with
`BackendUnavailable: Cannot import 'scikit_build_core'` and **silently leaves the
stale `.so`** — under `set -e` inside a harness it was swallowed, and only the
md5 assertion caught it. One of them also hit stale `__pycache__` carried by a
tree copy, whose `co_filename` made its tracebacks print the ORIGINAL repo's
paths, i.e. a reviewer's output looked like it came from the author's tree.

## Adjacent, filed with the issue and FIXED in the section below

A **mid-body** leader inside a payload silently truncates the body:
`SplitIntoBlocks` reads `ins_idx_by_byte[start]` at the block START only, so a
block whose start is not an instruction offset gets an empty `ins` span even
when instructions lie INSIDE it. Verifies valid in both modes, renders
`if (1 != 0) { }` while smali lists the instructions after it, and is
byte-identical on HEAD and with dexllm#75. A wrong ANSWER, not a crash, with its
own blast radius and its own a/b — dexllm#75 addressed only the ENTRY.
**dexllm#77**, and it turned out to be one of TWO shapes rather than the whole
condition: a payload is only half the way a leader lands off a boundary.

### A block reads the instructions inside its own span (dexllm#77, 2026-08-31)

The shape dexllm#76 filed as adjacent and left alone. Two measurements widened
it before a line was written and two reviews widened it again after: **a payload
is only half of the condition, a dead end is only half of the loss, and the
fix's own first cut introduced a regression of the same class.**

A basic-block **LEADER only has to be an in-range BYTE OFFSET.** `VerifyInsns`
bounds a branch/switch target and a try-range start and requires nothing more,
and ART's *structural* verifier does not either (opcode and dataflow legality
live in the 6032-line runtime `method_verifier` this port refuses to vendor). So
a leader can point **into a switch/fill-array payload**, which `DecodeAllInsns`
skips, or **into the TAIL of a multi-unit instruction** — no payload anywhere.
Both are `verify()`-valid in BOTH modes, so `lenient=True` was never the
boundary.

`SplitIntoBlocks` located a block's instruction span through
`ins_idx_by_byte[start]` — **at the block START alone**. When `start` is not an
instruction offset that lookup misses, so `blk.ins` came back EMPTY **even when
instructions lie inside `[start, end)`**, and those instructions then belonged
to NO BLOCK AT ALL; `ComputeChildEdges` in turn `continue`d on every empty
block, leaving it with **no successor**:

| | what is dropped |
|---|---|
| **(a)** the empty block is a **dead end** | everything reachable only through it |
| **(b)** the empty block's **own span** is dropped | the real instructions inside it |

`render_method_smali` still listed every instruction in both cases, so the two
views of one method disagreed and **the Java one — the primary LLM-facing
surface — was the wrong one**, silently.

## Four rules, and each one is a finding rather than a design flourish

**(H1) the span is read from its FIRST instruction at or after `start`, bounded
by `end`** (`std::lower_bound`; `ins_storage` is filled by a linear decode so it
is sorted by `byte_off` and the search is exact). **(H2) a block that is STILL
empty falls through** to the next block, so what follows stays reachable.
Neither alone closes it and the matrix shows they fail DIFFERENT cases: with H2
only, `midbody_lost` renders its `if` and stops (the fall-through sends control
*past* the instructions inside the empty block's own span); with H1 only,
`midbody_empty` is still a dead end.

**(H3) the fall-through must go FORWARD** (`end_byte > start_byte`). A leader
equal to `insns_byte_size` makes a block whose span is empty in both directions,
and `FindBlockIdForByteOff(blocks, blk.end_byte)` then finds **ITSELF** — an
unguarded self-edge, which the writer renders as a **`while(true) { }` the
bytecode does not contain**. Reachable under `lenient=True` (strict `VerifyInsns`
bounds a target below `insns_size`, but `ComputeLeaders` inserts it with no bound
of its own), i.e. in the packer-dump mode.

**(H4) an empty block that is an exception-HANDLER entry does NOT fall
through.** Control reaches a handler on a THROW; the fall-through models LINEAR
flow, and a handler address landing in a payload would otherwise "continue" into
the region it protects, whose catch edge leads straight back to it. That cycle
is one the structured emit walk cannot terminate on — see the CONFIRMED HIGH
below.

**UNREACHED on a well-formed dex, structurally rather than by measurement:**
every leader `ComputeLeaders` seeds is either `pass.ins[i].byte_off` (the
fall-through / terminator-successor / switch-successor rules) or a target a
compiler emitted at a boundary, so the START lookup hits and H1's branch is
never entered. A correctness review re-derived that from the source — exactly
nine `leader_byte_offs.insert` call sites, no missed leader source — which is
what makes the corpus a/b byte-identical by construction rather than merely
measured so.

## The marker says only what happened, and getting there took two corrections

Reinterpret-and-mark is dexllm#75's answer to the same three options, for the
same reasons: rejecting at the gate refuses the whole dex over one method, and
refusing (`// DECOMPILE ERROR`) throws away a body the smali view renders
correctly, leaving the two views in disagreement with only the direction
reversed. No VM enters at a non-instruction offset, so both emitters say so:

```java
public Object pickValue(java.util.Collection p5)  // control enters at a non-instruction offset
```

**The first cut said `// control falls through a payload`, which is a FALSE
STATEMENT on a method with no payload in it.** The `mid_insn` craft — an
`if-eqz` whose target is code unit 2 **of the if-eqz itself** — reaches the
identical shape with no payload anywhere, and carried the payload wording. Found
by building the craft, not by reading the code.

**And the second cut claimed a reinterpretation that never happened.** An
adversarial review CONFIRMED that an off-boundary leader in DEAD code set the
flag while `Construct`'s bfs never builds that block, so the rendering is
byte-identical to a boundary-aligned control and the marker is the only
difference. The flag is therefore **qualified by bfs reachability**: the
snapshot carries the raw per-block fact `RawBlock::starts_off_instruction`, and
`Graph::control_enters_non_instruction` — set only for a block the bfs actually
BUILDS — is what both emitters read.

That qualification immediately corrected an INHERITED expectation: dexllm#75's
`try` craft (a try-range start at byte 0, inside the leading payload) had been
updated to expect BOTH markers, and it earns only #75's — nothing branches to
byte 0 and no handler names it, so the block is never built. `branch`, whose
`if-eqz` targets code unit 0, earns both. **That contrast is the sharper one**:
it separates "a leader exists off a boundary" from "control actually enters
there".

## What the two reviewers found — 1 CONFIRMED HIGH the change itself created

**An adversarial review built a STRICT-`verify()`-valid dex that HEAD renders
and the first cut turned into `// DECOMPILE ERROR: structured emit recursion too
deep`, with `ast = None`.** The fall-through CLOSES a cycle that was previously
open — an empty block that is a catch handler falls into the region it protects
— and `Writer::VisitNode`'s `visited_` guard exempts return nodes, so a cycle
through one does not stop the recursion. The `depth_ > 2000` cap contains it (no
crash on the shipped configuration); with the cap raised to 200000 the same
input **SIGSEGVs**, while HEAD renders it at either cap. Reproduced here on the
shipped binary, then bisected by building H1-only and H2-only: **H2 is the
cause**, and H4 closes it.

**A correctness review then built the mutant that survived everything.** H1 has
two independent halves — WHICH instruction and the span bound — and only the
second was pinned: taking the **LAST** instruction in the span instead of the
first passed all 54 cases of both guard files while silently dropping every
instruction between, which is the defect class this issue exists to close,
reached through its own fix. `midbody_lost` cannot see it (the one instruction
it would lose is a dead `const/4` that DCE removes either way). The
`midbody_pair` craft makes it observable — the first recovered instruction
defines what the second returns, so the correct reading renders `return 3` and
the mutant returns an undefined register.

Both reviews independently confirmed the change is otherwise sound, each with
its own instruments: **2,000+ crafted inputs judged by SUBPROCESS EXIT STATUS —
0 signals, 0 hangs**; span inversion structurally impossible (`lower_bound` is
indexed only after `it != end()`, and `last_idx >= first_idx`); no instruction
in two blocks or in none (leaders are a sorted set and block spans are
half-open and disjoint); dexllm#75's entry promise unbreakable (the first
instruction's offset is itself a leader, and the `< end` bound stops a lower
block from claiming it); `ins_storage` sortedness proven from `DecodeAllInsns`;
and an **independent leader oracle that never asks the code under test** —
instruction offsets from `render_class_smali`, branch targets from its text,
switch/try/handler addresses from raw bytes — reporting **0 off-boundary leaders
across 227,166 methods / 550,827 leader sources**, with a non-vacuity check that
it does find the crafted ones.

Two further findings are accepted rather than fixed, both crafted-only and both
now stated in the source: **`AttachExceptionHandlers` keys try coverage on
`blk.start_byte`**, so a block that begins off a boundary can hold instructions
outside the try range its start falls in — over-attachment only (the try start
is always a leader, so coverage cannot be LOST), and strictly better than those
instructions not existing at all; and the residual below.

## The residual dissolved under inspection — 0 regressions

Over **800 random gate-legal crafts** (the adversarial reviewer's generator,
fixed seed), OFF vs the shipped ON, with each craft's error classified by
MESSAGE rather than counted: **NEW = 1, GONE = 0, and the 1 is not a
regression.**

It is `malformed bytecode: null operand to MoveExpression` — the PRE-EXISTING,
documented null-guard at [instruction.cpp:274](native/dad_cpp/instruction.cpp#L274)
— and that message class **already occurs on the OFF half** (1 -> 2), so it is
not a new failure MODE but one more instance of a guard that already fires. The
craft has a `move-result` following a fill-array PAYLOAD with no invoke before
it, which is why it is strict-INVALID and loads only under `lenient=True`. On
OFF that method rendered **6 body lines for 20 smali instructions** — HEAD had
SILENTLY DROPPED the whole tail from `0x3c` on, which is the exact defect this
issue closes. The fix includes those instructions, and the guard then reports
that they are malformed. **HEAD was quiet because it was hiding them.**

It was 7 of 761 (two of them STRICT) before H4, and every one of those was the
emit-recursion class the HIGH describes.

**The population also measures the fix working in the intended direction:** of
the 777 crafts that render on both halves, the body **GREW on 394** and shrank
on 9 — and all 9 were diffed by hand and **lose no statement**. Each is an
empty-arm collapse (`if (X) { } else { Y }` -> `if (!X) { Y }`, because the
empty block the then-arm pointed at now falls through and merges) or a
short-circuit merge of two real conditions; three render a `while (X) { }` where
the reinterpreted control flow genuinely loops back. `body_lines` is a POOR
proxy and saying so is part of the record: fewer lines here means a tighter
rendering, not less content, which is why the 9 were resolved by reading the
diffs rather than by the counter.

Marker false positives fell 743 -> 583 over the same population, which is the
reachability qualification removing them.

## Measured

**a/b OFF=`08104afea5da1252dfe91168d274e3fa` vs
ON=`b3219432ae8318f2ba1e8fd8a66fd06c`, SAME script, both `.so` md5-verified
BEFORE and AFTER each capture — and the OFF build BIT-REPRODUCES the recorded
HEAD md5.** **98 sources** — the whole bundled corpus, every committed fixture,
every `art/test/dexdump/*.dex`, every `tools/dexter/testdata/*.dex`, all four
ART fuzzer corpora and **6 crafted** — x up to 14 axes (both verify verdicts +
reasons, load, `dex_count`, class list, a smali digest, a whole-decompile
digest, decompiled line count, `// DECOMPILE ERROR` count, BOTH marker counts,
an AST digest over every method, `warm_analysis_caches`, and the subprocess EXIT
STATUS) = **1182 axis records, 20 changed on 5 sources, ALL CRAFTED, 0 REAL**,
over 3,046,176 decompiled lines. The 1182 is re-derivable rather than a harness
number: 79 sources load and carry all 14 axes, 19 are rejected and carry 4 —
14x79 + 4x19 [[published-counts-need-the-repos-own-predicate]]. Every source
runs in a SUBPROCESS whose axes are FLUSHED one per line; all 98 exit 0 on both
halves.

**`smali`, `verify`, `load`, `dex_count` and the class lists are identical on
every source** — the "two views disagree" point stated as a measurement: only
the Java view moves. The five crafts that move do so on exactly `java` /
`java_lines` / `ast` / `markers_77`, and the **`control` craft — the same
instructions and the same branch, landing on a real boundary — is unchanged on
both halves**, which separates this fix from "every block got a fall-through
edge".

**The census is the a/b's own axis, measured with the product's own predicate:
`markers_77` over the 92 REAL sources is 0 on BOTH halves**, so a corpus-only
a/b is byte-identical BY CONSTRUCTION and the crafts are the only thing that can
show the mechanism firing [[ab-must-prove-the-mechanism-fires]].
**Cross-checked on a DIFFERENT surface**, because a census taken with the flag
under test is the same claim twice: a parser reading instruction offsets and
relative branch operands out of `render_method_smali` — the smali view, which
this change leaves byte-identical — finds **0 off-boundary targets out of
244,977** across 71 loadable sources / 239,179 methods, and the correctness
reviewer's independent oracle (which also resolves switch, try and handler
addresses from raw bytes) reports 0 out of 550,827 leader sources over 227,166
methods. **My first version of that parser reported 201,105 off-boundary
targets**, a confident false answer from a regex that required the line to END
at the operand and so matched almost no instruction, leaving the offset set
nearly empty — killed by reading ONE real smali listing against it
[[ab-harness-must-itself-be-deterministic]].

parity **29/29** (the count is unchanged — the new cases went into the existing
`construct_parity_test`, which grows from **51** checks to **74**), pytest
**1199 passed / 24 skipped**, TRUE corpus-less (`test_apk` MOVED aside) **795
passed / 428 skipped / 0 failed** — +40 over HEAD, i.e. every one of the new
Python cases runs in the CI leg — narrowed to `tests/data/multidex.apk` **1099
passed**, the three touched guard files green narrowed to **each of the 34
bundled samples one at a time** plus the committed one, determinism 3 processes
x 3 `PYTHONHASHSEED`s -> one digest, lint trio clean (CI scope), doc fences
**81**, `scripts/check_dad_boundary.sh` clean.

**Sweep: 21,374-class / 180,879 method-block, 0-crash 0-timeout 0-error, GATE:
PASS** — published with its predicate rather than against the earlier entries':
`/tmp/full_sweep.py` does not survive a reboot, so the harness was RECREATED
from `.claude/skills/dexkit-sweep/SKILL.md` and enumerates classes through
`list_classes()` instead of androguard. Its 0/0/0 is comparable to every earlier
run; its absolute counts are not
[[published-counts-need-the-repos-own-predicate]].

## Guards, in TWO layers, and the matrix is what proves they are complementary

**40 cases** in [tests/test_payload_leader.py](tests/test_payload_leader.py),
ALL corpus-independent — every craft rewrites code units INSIDE one code item's
`insns` of the committed `tests/data/method_handles.dex` (and
`tests/data/invoke-custom.dex` for the one shape that needs try blocks),
length-preserving to the byte, with each craft's verify verdict ASSERTED in
**both** modes (`check_insns_` gates `VerifyInsns` and nothing else, and a leader
off a boundary is exactly what `VerifyInsns` is asked about, so a craft that
only verified leniently would prove a weaker claim than the issue makes). **No
decompile of a crafted dex runs in the pytest process** — this file sorts early
and a regression that faulted in the IR builder would abort the whole session
here rather than report.

Six shapes, each earning its place: `midbody_empty` (the dead end),
`midbody_lost` (instructions inside the empty span), **`midbody_pair`** (the
span read from its FIRST instruction), `mid_insn` (**no payload at all** — the
shape that refutes a payload-worded predicate), `steal_cond` (below) and
`control` (unmarked, body renders).

**23 checks in
[tests/parity/construct_parity_test.cpp](tests/parity/construct_parity_test.cpp)**
pin what no Python assertion can see, which is where two of the fix's four rules
live: the off-boundary span holds BOTH its instructions and is read from the
first; a wholly-empty block gets EXACTLY ONE forward fall-through; a
handler-entry empty block gets NONE; a block at `insns_byte_size` gets no
self-edge; the graph flag is set for a REACHED off-boundary block and NOT for a
dead-code one; and the control has neither. dexllm#73 and dexllm#75 both added
cases here for the same reason.

## 13 mutants, each BUILT and RUN with a distinct `.so` md5

The harness restores from a pristine snapshot, `touch`es it (`cp` preserves
mtime and ninja would SKIP), rebuilds to the control before every mutant and
ASSERTS the control md5 there and again when it ends; an anchor that does not
match exactly once is reported as **NOT A MUTANT**.

| mutant | pytest | construct |
|---|---:|---|
| M0 pre-fix — all six files at HEAD | — | **cannot BUILD** |
| M1 forward scan removed (H1) | 4 | FAIL |
| M2 fall-through removed (H2) | 7 | FAIL |
| **M3 scan takes the LAST instruction** | **1** | FAIL |
| M4 scan ignores the span END | 1 | FAIL |
| M5 per-block flag never set | 18 | FAIL |
| M6 flag set even with no instructions | **0** | **PASS — EQUIVALENT** |
| M7 marker not qualified by bfs reachability | 2 | FAIL |
| **M8 handler-entry blocks fall through too** | **0** | **FAIL** |
| **M9 the forward-only guard removed** | **0** | **FAIL** |
| M10 Writer marker dropped | 17 | PASS |
| M11 AST marker dropped | 6 | PASS |
| M12 graph flag DEFAULT true | 15 | FAIL |

**M8 and M9 are invisible to every Python case** — they are H4 and H3, whose
whole effect is an edge that is or is not in the snapshot — so the C++ layer is
not decoration, it is the only thing holding two of the four rules. **M0 cannot
be built at all** with the new C++ cases in the tree (they reference a member
the pre-fix ABI lacks), so that compile failure is its own kill, exactly as
dexllm#75 records for its own M0. **M6 is a PROVEN EQUIVALENT rather than an
escape**: with the marker qualified by reachability, a method with no
instruction builds no graph and cannot be marked whatever the per-block flag
says — the `ins_storage` condition survives only so that
`starts_off_instruction` is not VACUOUSLY true on every block of such a method,
and the source says so.

## Two process lessons, both paid for here

**A `cd` into a reviewer's private copy silently redirected five source edits.**
After `cd /tmp/adv77` the relative-path edits landed in the REVIEWER's tree, the
`(cd build/... && ninja)` that followed built a tree whose `CMAKE_HOME_DIRECTORY`
still pointed at the original, and the guards then passed against a binary that
did not contain the change. Caught only by `git status` showing the files
unmodified while the build had succeeded. **Isolating the reviewers is not
enough — every command has to state its own directory**
[[reviewer-agents-swap-the-worktree]].

**And a reviewer's `pip install -e .` in a `cp -a` copy repointed the ORIGINAL
venv** at `/tmp/cor77/src`, because the copied `pip` shebang and `.pth` still
addressed the original. It restored it and said so; the durable form is that a
copy is not isolated until its `pyvenv.cfg` and shebangs are rewritten too.

### A static float/double initializer is zero-extended to the RIGHT (dexllm#70, 2026-08-22)

`DecodeEncodedValueText` — the decoder behind `decompile_class`'s static-field
initializers — filled a `VALUE_FLOAT` / `VALUE_DOUBLE` payload from the **LSB**
end. The dex spec says the stored bytes are the **MOST** significant ones
("zero-extended to the right") and ART reads them that way
(`dex_file.cc`: `ReadUnsignedInt(ptr_, value_arg, /*fill_on_right=*/true)`), so
every SHORT encoding rendered as a **denormal**: two bytes `80 3F` became the
`0x00003F80` denormal rather than `0x3F800000` = `1.0f`.

**The rule was documented wrong, in the same words as the code** — the bullet
above asserted "payload goes into LSB end … MSB end zero-padded" while calling it
"zero-extended to the right", so prose and implementation corroborated each other
and neither was ever the thing being checked. Found while implementing dexllm#67
(whose `DecodeEncodedFloat` / `DecodeEncodedDouble` are written correctly and say
so at the site) and CONFIRMED independently by that change's correctness reviewer.

**Fix:** the two arms SHARE dexllm#67's helpers rather than adding a fifth reading
of the same spec sentence (this file holds four `encoded_value` decoders; the
other three were already right — `ScanEncodedValueStrings` reads only strings,
`Reader::ParseEncodedValue` hands raw bits to the IR, `ParseCallSiteArg` fills on
the right). The helpers moved above their new caller and their comment lost the
"KNOWN DIVERGENCE, deliberate" paragraph that described exactly this defect
[[a-rule-you-wrote-binds-your-next-commit]]. `ReadIntLE` replaces the hand-rolled
byte loop, which also deletes an unreachable excess-byte clamp: the gate
(`VerifyEncodedValue`) rejects `value_arg > 3` for 0x10, so `nbytes` is 1..4 there
and 1..8 for 0x11, and consumption is byte-for-byte what it was.

**Not cosmetic.** README and CLAUDE.md both market IEEE754 round-trip precision on
this path as a deliberate divergence from DAD (which emits the raw integer). The
FORMATTING was round-trip; the VALUE fed to it was wrong, so the claim did not
hold for a short encoding — and the output was a confident wrong constant, not a
visibly broken one. The sharpest case is self-refuting: Kotlin's
`FloatCompanionObject` field literally NAMED **`NaN`** rendered a finite
`4.5828065e-41f`, and `POSITIVE_INFINITY` / `NEGATIVE_INFINITY` likewise — 6 such
constants across the corpus, because the non-finite branches only fire once the
bits are read correctly.

| field | stored | before | after (ART / spec / AOSP) |
|---|---|---|---|
| `AutoScrollHelper.DEFAULT_RELATIVE_VELOCITY` | `80 3f` | `2.27795078e-41f` | `1f` |
| `CircleImageView.SHADOW_RADIUS` | `60 40` | `2.30933987e-41f` | `3.5f` |
| `ColorUtils.XYZ_WHITE_REFERENCE_Y` | `59 40` | `8.1387433839428543e-320` | `100` |
| `RatingCompat.RATING_NOT_RATED` | `80 bf` | `6.86972559e-41f` | `-1f` |
| `FloatCompanionObject.NaN` | `c0 7f` | `4.5828065e-41f` | `Float.NaN` |

**Measured (a/b OFF=`f9486e9` `413ff1bf…` vs ON `c723499f…`, SAME script, both
`.so` md5-verified and each build bit-reproducing its md5 after the halves were
swapped back):** 42 sources — the whole bundled corpus plus every committed
fixture — x {strict verify, load, class count, class list, a hash over EVERY
static-field declaration line, the whole decompile, the whole smali} = **269 axis
records present** (5 of the 42 never load — two resources-only APKs, a `.der`, a
`.pem`, `framework-res` — so they carry 2 axes each rather than 7; 42 x 7 = 294 is
the nominal product, which an earlier draft published), **10 sources changed, and
only on the two decompile axes**. **Verify, load,
class lists and smali are identical on every source.** A LINE-LEVEL diff over the
**2,180,703 lines** of decompiled text those 10 sources produce resolves it
exactly: **332 differing, 0 added, 0 removed** (312 float, 20 double), every one a
static-field declaration, and **positionally 1:1** — the same 332 slots, so no
value shifted and nothing desynced.

**Independent oracle, and it is what makes the 332 a fact rather than a diff
count** [[published-counts-need-the-repos-own-predicate]]: a raw-bytes
`class_defs` -> `static_values` parser that never asks the decoder under test what
a payload means reports **754** float/double static values, **382** short-encoded,
**50** of those encoding zero (which reads alike either way) and **332** where the
two readings genuinely differ — and on all **332/332** the value dexllm now
renders equals the RIGHT-justified reading, with **0** still rendering the left
one. That answers the issue's open question about a second source: the four AOSP
constants above are checked by name, and the whole population is checked against
the bytes. **Both reviewers re-derived every one of those four numbers
independently**, and the correctness reviewer's oracle is FIELD-PRECISE where the
shipped one does a whole-class substring match — 332/332 correct field, 0 wrong,
0 missing — so the shipped check is not hiding a right-value-wrong-field case.
The adversarial reviewer separately rebuilt both halves and reproduced the a/b to
the digit (10 changed sources, 332 differing / 0 added / 0 removed, 312 float / 20
double, 2,180,703 lines), and found **0 signals across 1,200 crafted dexes** on
BOTH builds, each judged by subprocess exit status.

The shift arithmetic itself was checked against **ART's own `ReadUnsignedInt` /
`ReadUnsignedLong`, copied verbatim from the local AOSP checkout**: exhaustive
over every 1- and 2-byte payload plus 2,000,000 random per wider width, **float
4,065,792 cases and double 12,065,792 cases, 0 mismatches**, cursor advance exact
in every one. The float arm's new routing of the bits through `double` and back is
**bit-exact over all 2^32 patterns** (0 differences, 0 isnan/isinf reclassifications,
with a non-vacuity control counting 16,777,214 NaN patterns). And the removed
excess-byte clamp is confirmed unreachable in BOTH modes — 16 crafts through
`dexllm.verify` show `value_arg > 3` rejected for 0x10 strict AND lenient, and
`check_insns_` gates only `VerifyInsns`.

parity 29/29, pytest **853 passed / 10 skipped**, TRUE corpus-less (`test_apk`
MOVED aside) **445 passed / 418 skipped / 0 failed** — **30 of the 32 new cases**
are crafted on committed fixtures and run there — narrowed to
`tests/data/multidex.apk` **754**, the guard file green narrowed to **each of the
34 bundled samples one at a time**, sweep (`/tmp/full_sweep.py`, the recorded harness, whose
block rule is its own — an ad-hoc regex in an earlier draft produced a
method-block figure that re-derived under no source list, which a correctness
reviewer caught) **25,309-class / 213,374 method-block, 0-crash 0-timeout
0-error, GATE: PASS**, determinism 3 processes x 3 `PYTHONHASHSEED`s -> one
digest, lint trio clean, doc fences 78, `scripts/check_dad_boundary.sh` clean.

**Guards** (32 cases in
[tests/test_static_float_justification.py](tests/test_static_float_justification.py)).
Every craft SHORTENS, because a full-width payload is exactly where the two
readings agree — which is why every pre-existing float/double assertion in the
suite was blind to this, and why `test_a_full_width_float_still_renders` is
declared non-discriminating BY DESIGN and kept anyway (it catches a fix that
over-shifts). Each craft re-lays the EIGHT bytes of `invoke-custom.dex`'s
`LTestLinkerMethodMinimalArguments` static_values and nothing else: a payload of
N bytes takes 1 + N, so the array's count drops to `1 + (7 - N) // 2`, the
surviving one-byte INTs follow, and the leftover byte or two are never read — no
offset, no section size and no neighbouring structure moves. Those survivors are
a **desync oracle**: a decoder consuming a fixed 4 or 8 bytes for a short payload
walks into them and their values shift. The field's declared type is deliberately
left `int`: the decoder dispatches on the encoded_value type code and never
consults it.

**ONE byte is not enough, and a correctness reviewer had to build the mutant that
shows it.** The fix IS the width-dependence of the shift, and at N = 1 the
exponent `8 * (4 - nbytes)` is the constant 24 — so a decoder that HARDCODES the
shift renders every one-byte case correctly and **passed the whole file in the
corpus-less leg**, which is precisely the leg this change advertises as the one
where the crafts carry it. The short cases are parametrised over N = 1, 2 and 3
for both types now (width 4 is the full-width case; width 8 does not fit in the
array and is covered by the corpus oracle), and the two- and three-byte rows
reproduce, on a committed fixture, two of the real AOSP constants the corpus
manifests — `1f` from `80 3f` and `100` from `59 40`.

Two corpus-gated cases carry evidence the crafts structurally cannot: a
**byte-level oracle** over every short-encoded static value the corpus holds
(the fixture's elements are one byte, and one byte cannot encode NaN or Infinity
— the exponent needs bits a single top byte cannot supply alongside a mantissa),
and the Kotlin `NaN` / `+-Infinity` case. Both SKIP rather than fail without a
corpus (issue #46), and the oracle carries a floor so a scan that collapsed to one
value cannot satisfy its own equality.

**A SOURCE-level guard states the invariant the issue's scope note asks for**: the
0x10 / 0x11 arms must CALL the shared helper. A correct-but-DUPLICATED inline body
passes every behavioural test here and drifts on the first edit — the shape the
`_callers.py` identity guard pins for the app-only prefix list — and it is exactly
what "add a fifth reading of the same rule" would look like. It strips comments
with a left-to-right scanner (a `/* */` regex pass swallows this file's own
`// ---- const-wide/* ----`, the trap dexllm#32 and dexllm#57 each paid for), and
the scanner has its own self-check.

**13 mutants, each BUILT and RUN with a distinct `.so` md5, each killed IN BOTH
LEGS** — with the corpus AND corpus-less, which is the discipline ADV-1 forced:
pre-fix (17 fail, and its md5 **reproduces the OFF build exactly**, which is the
diff's functional content stated as a measurement), float-only left, double-only
left, each shared helper left-justified, a **width-independent shift**
(`raw << 24` / `<< 56`), each arm over-consuming a fixed width, each of the three
non-finite branches deleted, the float format widened to `%.17gf`, and a correct
INLINE duplicate (**killed by the source guard ALONE**, 1 failure in both legs —
nothing behavioural can see it). Plus a control asserting the pinned md5 before
and after. **Five of the thirteen were CONSTRUCTED BY THE REVIEWERS**, and each
passed the file as it then stood.

**The two adversarial findings were both in the corpus-less leg, and one of them
was created by my fix for the correctness finding** [[review-responses-are-the-weak-spot]].
(1) The three **non-finite branches** — the very branches that produce the
change's headline case — were exercised by nothing CI can run: every finite craft
is blind to them, and the file justified leaving them to the corpus by saying a
one-byte payload cannot encode NaN or Infinity. That was TRUE and stopped
governing the moment the width fix replaced `_craft` with one that takes 1..4
bytes; the reviewer deleted each branch and all three survived corpus-less and
under every narrowing. Six two-byte crafts close it, using the Kotlin companion
objects' OWN bytes — so the fixture now carries the case and the corpus test
carries only the real-world EVIDENCE. (2) The float arm's **`%.9gf`** is the
other load-bearing half of that line and was guarded by nothing in the
repository: widening it to `%.17gf` passed the entire suite, because every
literal pinned here is exactly representable AND the corpus is biased the same
way (a short encoding puts few significant bits in the top bytes, so the values
come out round). The DOUBLE side was already covered by accident —
`3.0517578125e-05` needs the wider format. One craft with a non-representable
value (`cd 4c 3e` -> `0.200000763f`) pins the precision and width 3 at once.
[[pinned-literals-guard-only-the-constant-half]] one level up: the pinned line
covers the VALUE, and the format that renders it is a second constant.

**Known gap, stated rather than discovered:** a full-width DOUBLE (width 8) is
reachable only through the corpus oracle — nine bytes do not fit in the fixture
array's eight, and lengthening it would push past 29649, which is where this
fixture's `call_site_id[0]` target begins (all 46 invoke-custom bootstrap arrays
live in 29649..30255, i.e. exactly the bytes dexllm#67 reads). So the double
helper's `nbytes >= 8` fast path is invisible to the corpus-less leg; closing it
needs a fixture class with a larger `static_values` array. Two smaller ones: the
source guard's `f"{helper}(" in body` is a SUBSTRING test, so a correct duplicate
deliberately named `MyDecodeEncodedFloat` would satisfy it (not a live hole — any
INCORRECT duplicate dies behaviourally, and a correct one is what the guard is
for); and the byte-level oracle's nested ARRAY / ANNOTATION branches are
spec-correct but INERT (0 nested values across all 42 sources), so a bug there
would undercount silently.

**Adjacent, found by the over-consume mutants and deliberately NOT fixed here:** a
desync in this decoder is a **CRASH** surface, not merely a wrong answer. The
0x17 / 0x18 / 0x19 / 0x1b arms index `strings[idx]` / `type_names[idx]` on the
gate's promise ("idx validated in-range by VerifyEncodedValue"), and that promise
only holds while the decoder walks the array in lockstep with the gate — a
desynced reader reads different bytes and gets an unvalidated index. Reproduced:
M7 SIGSEGVs on `decompile_class` over an ordinary corpus APK. A correctness reviewer reproduced it on THREE
corpus APKs and proved the MECHANISM by construction rather than by argument: the
same mutant with an `idx >= size()` check added to those four arms gives 25 APKs
and **0 signals**. Unreachable today — `nbytes` is derived from the header exactly
as the gate derives it, this change leaves consumption byte-for-byte identical,
and a lockstep model of the two switches over **400,000 fuzzed byte streams** finds
**0 consumption mismatches** among 153,489 gate-accepted ones. But it means
**dexllm#63's "wrong-answer only" conclusion for the same function was not merely
incomplete, it was WRONG**: the reviewer rebuilt a pre-#63-shaped decoder (0x15 /
0x16 consuming only the header byte) and it **SIGSEGVs on 16 of 23 `verify()`-VALID
crafted dexes**, where both the OFF and ON builds give 0/23. Defence in depth
there — bounding the four index arms, and pinning the consumed WIDTH rather than
only the CASE SET in dexllm#63's own invariant test — was filed as **dexllm#71**
and is **DONE**; see its section below.

### Writer constant/keyword nits — string `"true"` + `while(true)` (2026-06-17)

Two text-Writer divergences surfaced by a same-line-count DAD differential:
- **String constant `"true"`/`"false"` lost its quotes.** `Constant::Accept` routed BOTH the boolean (`type=="Z"`) case and real String constants through `visit_constant_string`, and the Writer used a value heuristic (`if value=="true"||"false" → emit unquoted`). A `const-string "true"` (e.g. `Boolean.parseBoolean("true")`) is a String literal and got emitted as bare `true`. **Fix:** added `visit_constant_bool` (Z → unquoted `true`/`false`); `Constant::Accept` routes `type=="Z"` there; `visit_constant_string` now ALWAYS escapes/quotes (DAD `string()`). dast (JSONWriter) already discriminated by type (LiteralBool vs LiteralString) — unaffected.
- **`while(true)` spacing.** DAD emits the endless-loop keyword as `while(true)` (no space), unlike pretest `while (cond)`. We emitted `while (true)`. Fixed to match.

tvleanback 500-sample exact-match 96.6%→96.8%, bench 97.2%→97.6%; parity 26/26, sweep 0-crash unchanged.

**Follow-up — posttest do-while latch spacing (2026-06-18):** DAD writer.py:269 emits the posttest latch as `} while(` WITHOUT a space (same as endless `while(true)`; only pretest `while (` keeps the space). We emitted `} while (`. Fixed to `} while(` ([writer.cpp](native/dad_cpp/writer.cpp) `EmitLoop` posttest path). `JsonReader.skipQuotedValue` now byte-identical to DAD. parity 26/26, sweep 0-crash, tvleanback 500-sample 98.0% identical mismatch set (no posttest do-while loops in that sample's diff lines).

### Production fix — readable UTF-8 strings/identifiers, not `\uXXXX` (2026-06-19)

Non-ASCII string literals and obfuscated identifiers were emitted as `\uXXXX` escapes (`"연결…"` instead of `"연결…"`) — valid Java but unreadable, a real problem for a triage tool reading e.g. localized phishing strings. Two stacked escapers caused it: (1) `EscapeJavaString` ([writer.cpp](native/dad_cpp/writer.cpp)) re-emitted every decoded codepoint as `\uXXXX`; (2) `SanitizeUtf8` ([decompiler.cpp](native/dad_cpp/decompiler.cpp)), a whole-output post-pass, re-escaped *everything* non-ASCII to pure ASCII (and so undid any fix to #1). Both were conservative guards against pybind11's strict UTF-8 decode rejecting MUTF-8's 0xED-prefixed surrogate halves. **Fix:** both now emit **per UTF-16 code unit, exactly as ART decodes MUTF-8 into a `mirror::String`** (`ConvertModifiedUtf8ToUtf16`; AOSP wiki `concepts/art-object-model.md` — String is UTF-16/compressed-Latin-1, `concepts/dex-file-format.md` — strings are MUTF-8). A BMP non-surrogate code unit is emitted as readable UTF-8 (`"연결 시간이 초과되었습니다"`, identifiers show CJK/Hangul); a **surrogate** (so a supplementary char stays the `😀`-style surrogate PAIR ART keeps in memory — NOT folded into a 4-byte codepoint) and a decoded **control** char (incl. MUTF-8's `C0 80` → ` `) become `\uXXXX`. The result carries the **same UTF-16 code units ART sees**, is readable for the common BMP case, and is valid UTF-8 for pybind11 (no raw surrogate bytes). DAD itself ASCII-escapes everything (writer.py:757 `unicode-escape`), so this is a beyond-DAD fidelity/usability divergence; it also makes the text path consistent with the AST path (`Mutf8ToUtf8`). Validated: two obfuscated APKs (2033 and 5302 classes) decompiled, **0 pybind11 decode errors**; parity 27/27 (`EscapeJavaString` checks in `writer_parity_test`: BMP UTF-8 passthrough, control/NUL escape, emoji→surrogate-pair, MUTF-8-pair→same-pair), sweep 0-crash/0-timeout/159,305.

**Follow-up — consolidated onto a shared ART-faithful decoder (`mutf8.h`/`mutf8.cpp`, 2026-06-19):** the three hand-rolled MUTF-8 decoders (writer's `EscapeJavaString`, decompiler's `SanitizeUtf8`, dast's `Mutf8ToUtf8`) were drifting copies of the same logic. They now share one decoder ported **1:1 from AOSP ART** ([native/dad_cpp/mutf8.h](native/dad_cpp/include/mutf8.h) / [mutf8.cpp](native/dad_cpp/mutf8.cpp), `// ART :NNNN` anchors against `art/libdexfile/dex/utf-inl.h` `GetUtf16FromUtf8` + `utf.cc` `ConvertModifiedUtf8ToUtf16` — AOSP as spec reference, not a runtime dep, same posture as the DexFileVerifier port). API: `Mutf8ToUtf16` (the ART port → UTF-16 code units), `Utf16ToUtf8` (value path: combines a surrogate pair into one 4-byte code point — for dast), `AppendUtf16Escaped` (text path, per unit: surrogate/control → `\uXXXX`, BMP → readable UTF-8 — for the writer's string escaper) and `AppendUtf16AsIdentifier` (dexllm#28 — the same rules over a whole run, except that a VALID surrogate pair is combined and emitted readably; the decompiler's identifier sanitiser uses this one). `SanitizeUtf8` keeps an ASCII fast-path so structural `\n`/indent pass through verbatim (it only escapes controls that arrived as multibyte sequences). **One deliberate divergence from ART, documented in the header:** ART's `GetUtf16FromUtf8` reads continuation bytes from a NUL-terminated, structurally-valid stream without bounds checks; we are length-delimited and validate defensively (a truncated/malformed sequence yields the lead byte as a lone unit instead of reading past the end). This guard is redundant given `VerifyMutf8` for the current callers but kept as a `SafeWidth`-style leaf self-defense — the keep-vs-remove call (and every other OOB-prevention divergence from AOSP) is catalogued for a later decision in [docs/aosp-oob-divergences.md](docs/aosp-oob-divergences.md). **Verified behavior-preserving:** on 300k well-formed inputs (incl. 207k with lone surrogates + ASCII controls) the new `SanitizeUtf8` is **byte-identical** to the pre-refactor version; divergence appears only on genuinely malformed bytes (verifier-rejected, never in decompiler output) where the new path is ART-faithful and still memory-safe + valid-UTF-8. New 28th parity suite [`mutf8_parity_test.cpp`](tests/parity/mutf8_parity_test.cpp) **differentially compares our port against an inline verbatim copy of ART's `GetUtf16FromUtf8`** over 4000 fixed-seed random streams (0 mismatch) + curated edge cases. parity 28/28, sweep 0-crash/0-timeout/159,305, 25,309-class corpus decompile 0 decode errors.

### Smali rendering decodes MUTF-8 BEFORE escaping (dexllm#22, 2026-08-06)

`EscapeSmaliString` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) escaped raw **BYTES** — only `\ " \n \r \t` and bytes `< 0x20` — so every byte `>= 0x20` of a dex-pool MUTF-8 string survived verbatim into the rendered text. Two consequences: (1) a literal holding a **surrogate pair** (supplementary-plane char) or an **embedded NUL** (`C0 80`) reached pybind's strict-UTF-8 `str` conversion as raw bytes and **RAISED `UnicodeDecodeError`** — **26 of the 188,065 methods / 22 of the 25,309 classes** of the apk-only sweep corpus (29 / 25 counting the bare `.dex` files, 11 files in total; the issue reported only the method half); (2) worse, anything that decoded the ASSEMBLED text afterwards MATERIALISED characters that had never been escaped — a **verifier-ACCEPTED non-NUL OVERLONG** (`VerifyMutf8` checked lead/continuation shape only — believed at the time to match ART; **it does not, see the identifier-pair section below, which ports ART's canonicality check so such a dex no longer loads at all**) decodes `E0 80 A2` → `"` and `E0 80 8A` → newline, **terminating a literal early or forging an entire instruction line**. The listing goes to an analyst / LLM via MCP, so that is a hostile-input write into the analysis view.

**Fix at the origin: decode the pool string, THEN escape the resulting CHARACTERS.** A decoded `"` is escaped like any other, and `C0 80` becomes `\x00` like every other control character instead of a raw NUL in the text. Decode semantics match the binding's `DecodeMutf8ForPy` **for verifier-accepted `string_data`** (surrogate pair → one code point, LONE surrogate → U+FFFD) — the two diverge on malformed bytes (measured: 0 mismatch over 200k verifier-legal streams, 171,646 over arbitrary bytes), which `VerifyMutf8` makes unreachable so a rendered literal equals what `list_method_strings` reports. **A first attempt decoded the assembled text at the pybind boundary and was REJECTED by the review gate as a HACK** — it fixed the raise but *created* the injection (measured: ≥1 unbalanced literal on a crafted dex where HEAD raised instead — the harness stops at the first payload, so 1 is a floor, not a count), because escaping upstream on bytes cannot cover characters produced downstream. Three-way a/b: HEAD `0 injection / 2 raise`, binding patch `1 injection / 0 raise`, escaper fix `0 / 0`.

**Build note:** `mutf8.cpp` became its own dependency-free leaf target **`dexkit_mutf8`** ([CMakeLists.txt](CMakeLists.txt)) so the DAD decompiler, `core_ext`, and now the vendored Core's renderer share ONE implementation — the alternative was a fifth hand-rolled decoder, exactly what the earlier consolidation removed. No vendored build file is edited; the top-level CMake adds the link. **Coupling to note:** the vendored SOURCE now `#include`s a header from `native/dad_cpp/include`, so `dexkit_static` no longer builds standalone — a `DEXKIT_CORE_ROOT` override or a bare vendor build needs that include path.

**Measured:** raise 29+25 → **0**; a/b over **228,017 render records** (all classes + methods, every loadable container) differs in **exactly the 54 previously-raising records, 0 previously-working outputs changed**; oracle (`_smali_strings` ≡ `list_method_strings`) **0 mismatch / 201,079 methods**; crafted overlong `"`/newline → 0 unbalanced literals, 0 raw control chars, dex still `verify valid`. parity 28/28. Guards: `test_smali_literals_cannot_be_broken_by_overlong_mutf8` (crafts the dex in place — 3-byte sequence → same-length overlong, so byte length / `utf16_len` / `string_ids` order are unchanged and it still verifies — **this guard was later INVERTED and renamed `test_overlong_mutf8_is_rejected_at_the_verifier`: its premise "ART accepts overlongs too" was false, and porting ART's check moved the contract from "escaped on render" to "rejected at load"; see the identifier-pair section below**), `test_smali_never_contains_raw_control_chars`, `test_render_smali_decodes_mutf8_literals`; each verified against BOTH rejected implementations, and the claim is per-test, not blanket: the overlong guard fails against both; `test_smali_never_contains_raw_control_chars` fails against both ONLY after being widened to `loadable_apks` (on the `dk` fixture it was VACUOUS — that APK carries zero control-bearing literals, so it passed against every implementation, which is how it slipped through the first review); `test_render_smali_decodes_mutf8_literals` fails against HEAD but PASSES against the escape-before-decode variant, which also decodes.

**The identifier half of dexllm#22, and the `type_ids` verifier gap (dexllm#23), were both closed next — see the section below.** (What this section left open: `list_classes` / `list_class_methods` / match descriptors returned raw MUTF-8, so an astral identifier raised; and a **type descriptor** never reached a validity check, because `VerifyClassDefs` validates a type only where it is a field_id class/type, a method_id class, or a class_def class/super/interface — ART's `CheckInterTypeIdItem`, which validates EVERY type_id, was missing from the port, and `emit_index`'s `kIndexTypeRef` wrote it UNESCAPED. A reviewer forged a `0x0: nop` line that way on a `verify valid` dex.)

### Identifiers cross the Python boundary as a decode/encode PAIR + every `type_id` is verified (dexllm#22 identifier half + dexllm#23, 2026-08-06)

An IDENTIFIER — a class descriptor, a member name, a proto — is dex string-pool MUTF-8 exactly like a literal is, and a supplementary-plane character is stored there as a **surrogate pair**, which is not valid UTF-8. The verifier explicitly permits one in a name (`IsValidPartOfMemberNameUtf8Slow` accepts a leading surrogate followed by a trailing one, mirroring ART), so handing those bytes to pybind11's strict `str` conversion **RAISED `UnicodeDecodeError`** — and `list_classes()` is the entry point for the decompile drivers, the sweep harness and the MCP tools, so the whole analysis of such a sample died on an exception naming an encoding rather than a cause. **Now CONSTRUCTED, not reasoned:** a length-preserving in-place patch (6 ASCII bytes of a simple name → the 6-byte surrogate pair, `utf16_len` −4, patch position past the neighbours' longest common prefix so the ART UTF-16 sort order holds) yields a `verify valid` dex on which HEAD raised for `list_classes` / `list_methods` (then spelled `list_method_descriptors`, renamed in dexllm#37).

**The fix is a PAIR, applied together, because identifiers are also INPUT.** Decoding alone would be strictly worse than the crash: every identity API takes a descriptor back (`decompile_method`, `render_method_smali`, `list_class_methods`, `find_call_sites_to`, …) and the matchers compare against RAW pool bytes, so a decoded descriptor handed back in would silently MISS. Same pairing dexllm#19 established for string content.
- **decode-OUT `ident_out`** ([module.cpp](native/binding/module.cpp)) on every identifier-returning site — the listing APIs, and the `py::class_` attributes, which moved from `def_readonly` to `def_property_readonly` lambdas (a raw `std::string` field raises on ATTRIBUTE ACCESS, which no return-type wrapper can catch). `__repr__` decodes too. `ResolvedArg.string_value` (`ArgOrigin` until dexllm#69) is included and was the one **corpus-reproducible** raise this found beyond the issue's report (a const-string with an embedded NUL, `C0 80`, in `StringTests.dex`).
- **encode-IN `ident_in`** (= `mutf8::Utf8ToMutf8`) on every descriptor/name ARGUMENT — including the L7 **NAME** matchers, which dexllm#19 had deliberately left unconverted because the path was unreachable while enumeration still raised. That closes the residual #19 recorded.
- **the shared decoder.** The binding's private `DecodeMutf8ForPy` body moved into the codec as **`mutf8::Mutf8ToUtf8Lossy`** ([mutf8.h](native/dad_cpp/include/mutf8.h)/[mutf8.cpp](native/dad_cpp/mutf8.cpp)) — lossy exactly where UTF-8 has no form (lone surrogate / malformed → U+FFFD), so the result is ALWAYS valid UTF-8. One implementation now serves the binding and the renderer, so a rendered identifier and `list_classes()` cannot drift. Only addition: an ASCII fast path (it now runs per identifier, not per method).
- **the smali renderer decodes at the EMISSION POINT** (`SmaliIdent`, [dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) — `FormatMethodRef` / `FormatFieldRef` / `emit_index`'s `kIndexTypeRef` / the `.class` / `.super` / `.implements` / `.field` headers. **Not over the assembled text**: that variant is the one the earlier review REJECTED as a hack for the literal half, because decoding after assembly MATERIALISES a structural character that was never escaped. Identifiers are decoded rather than escaped because they are unquoted in smali and a loadable dex cannot carry a structural character in one — see dexllm#23 below, whose check runs on the DECODED code points.
- **`DecompileClass` sanitises the part it assembles itself** ([decompiler.cpp](native/dad_cpp/decompiler.cpp)) — the class header and the field declarations never passed through `RunPipeline`'s `SanitizeUtf8` (only method bodies did), so an astral class name made the whole class decompile raise. Found by the new sweep-shaped test, not by reasoning. At the time, the Java-text path kept its `\uXXXX` code-unit rendering (`class A\ud800\udc00sTest {`, valid Java) as a deliberate difference from the readable-UTF-8 smali listing. **dexllm#28 later OVERTURNED that for identifiers** — see its section below; the code-unit rule now applies to string LITERALS only, so this class renders `class A𐀀sTest {` today.

**dexllm#23 — ART `CheckInterTypeIdItem` ported** ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp) `CheckInterSection`): a per-`type_id` `IsValidDescriptor` loop, no leading-char predicate (ART has none there). Before it, a descriptor was validated only where ANOTHER id table referenced it, so a type used ONLY as a proto return/parameter type or as an instruction operand (`const-class`, `new-instance`, `check-cast`, `new-array`, …) could hold arbitrary bytes and still pass `VerifyDex`. Fixing it at the **verifier** is candidate (1) of the issue and the one that restores the documented invariant ("a load-time structural verifier is the single gate") rather than escaping identifiers in the renderer. It also runs under `lenient=True` (which skips only `VerifyInsns`), so the channel does not reopen for packer dumps.

**Two further fixes the mandatory review gate forced — both CONFIRMED by BOTH reviewers independently, each having constructed and RUN the input:**

- **The overlong round-trip break (the reason ART's canonicality check is now ported).** `VerifyMutf8` checked lead/continuation SHAPE only, documented in three places as "ART does the same". **ART does not**: `CheckIntraStringDataItem` rejects a non-NUL OVERLONG as an "Illegal representation" (dex_file_verifier.cc **:1897** 2-byte `value != 0 && value < 0x80`, **:1922** 3-byte `value < 0x800`) — verified against the AOSP checkout, not inferred. Consequence with the identifier pair in place: a 3-byte in-place patch (`nal` → `E0 83 A9`, the overlong for U+00E9) yields a `verify valid` dex where `list_classes()` returns `LAéysisTest;` and then `locate_class_dex` → **-1**, `list_class_methods` → **[]**, `render_class_smali` → **''**, `get_class_summary().is_internal` → **False** — an app class reported as external, with **no exception anywhere**. HEAD raised loudly on the same input, so decoding alone would have turned a crash into a silent **3-byte class-hiding primitive** — precisely the "strictly worse" outcome the pair exists to prevent. **Both checks are now ported** ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp) `VerifyMutf8`): the pair becomes a genuine bijection over every dex that can LOAD, the "1:1 ART DexFileVerifier port" claim becomes true where it was not, and the smali decode-without-escaping argument becomes **structural** — no multibyte sequence can decode to a structural character any more, so it no longer leans on the member-name validator's `>= 0x00A0` arm. **This inverted an existing guard**: `test_smali_literals_cannot_be_broken_by_overlong_mutf8` asserted "the crafted dex must still verify"; it is now `test_overlong_mutf8_is_rejected_at_the_verifier` and asserts the load-time rejection (plus a canonical-3-byte control so it cannot pass on an unrelated rejection). Corpus overlong incidence: **0 across 316,407 string_data entries / 36 dexes**, so 0 false-reject. **Deciding to break the documented claim was escalated to the user (CLAUDE.md rule 5) with this evidence, and approved.**
- **`PythonUnicodeEscape` did not escape the DOUBLE quote** ([dexitem_code_source.cpp](native/core_ext/dexitem_code_source.cpp)) — it mimics Python's `unicode-escape`, whose repr is SINGLE-quoted, but the caller wraps the result in double quotes to build a **Java** literal. So a `"` in a `static final String` initializer ended the literal early: **9 lines of real corpus output are invalid Java** (`= "<?xml version="1.0" encoding="utf-8"?>";`), and a crafted value appends a fabricated field declaration to the class body `decompile_class` hands an analyst or an LLM. Pre-existing and outside #22/#23; **escalated to the user and approved for this commit** because it is the same family (hostile input writing into the analysis view) and one line. The method-body (`EscapeJavaString`) and smali (`EscapeSmaliString`) emitters already escaped it; this path was the outlier.

**A third pass (delta review of the fixes) then caught a HIGH the refactor itself introduced:** replacing the whole-text `SanitizeUtf8` with per-component sanitising missed the **field INITIALIZER** append. Only the STRING arm (0x17) of `DecodeEncodedValueText` is pre-escaped; its **TYPE (0x18)** and **FIELD/ENUM (0x19/0x1b)** arms emit RAW pool identifiers, so a crafted `static final X F = Astral.class;` still made `decompile_class` raise on a `verify valid`, `list_classes`-clean dex — the exact failure this change claims to eliminate. Invisible to every measurement: the corpus has 0 non-ASCII identifiers AND 0 `0x18/0x19/0x1b` static values, and the astral fixture only renames a CLASS, so it never produces such an initializer. Fixed (`out += SanitizeUtf8(init);` — the seventh append site) and **verified discriminating by toggling that one line**: OFF raises at the reviewer's exact byte position, ON decompiles all 340 classes with the type rendering as `𐀀`. Guard: `test_astral_type_in_a_field_initializer_decompiles` (crafts the 0x17→0x18 retype in place). **Lesson: a whole-text safety net that is removed for a structurally-better per-component discipline must be replaced at EVERY append, and the append that carries "already-escaped" text may not always be escaped.** The same pass also flagged that the 2-byte overlong arm had zero coverage (the 3-byte one had all the payloads) — a `C1 A9` case was added — and that the non-vacuity control lacked the LCP guard its sibling fixtures compute.

Also from the review, without escalation: `Mutf8ToUtf8Lossy` clamps `> U+10FFFF` to U+FFFD (its "always valid UTF-8" contract could be broken by an `F5`–`F7` lead — unreachable from a pool, but it is now a public codec entry) and gains its own coverage in [mutf8_parity_test.cpp](tests/parity/mutf8_parity_test.cpp) §7 (4000 random byte streams: output is always well-formed UTF-8; 2000 verifier-legal streams: agrees with the ART decoder); `DecompileClass` sanitises **per component** at each append site instead of once over the assembled text (the whole-text pass was the very pattern the earlier review rejected for smali — it escapes rather than materialises only because the validators happen to reject decoded values below 0xA0, and relying on that was the incidental-guarantee smell), including the `// METHOD ERROR (` descriptor that is appended after the method loop starts; and the forgery fixture now prefers a type_idx that a method signature actually RENDERS, with the `_guarded_type_idxs` ClassDef offset bug fixed (it read access_flags at +4 where superclass_idx is at +8, which could have made the fixture target a type the OLD verifier already rejected — latent, not manifest).

**Measured (a/b OFF vs ON, SAME scripts, build identity asserted per half):** two axis sets over **31 loadable sources** — verify verdicts, every identifier listing, the whole-corpus smali render, class summaries, the whole-corpus decompile, all L7 matchers, call-site / arg-resolution / field / type xref, class strings, external refs, permission callers, IOC extraction — give **1 raise→value** (`ArgOrigin.string_value`) and **4 decompile changes**, which a LINE-LEVEL diff over **2,313,468 decompile lines** resolves to **exactly 9 lines, all the intended `"` → `\"`**. Verify verdicts are **unchanged on every source** (0 false-reject from either new verifier check). parity 28/28, sweep 25,309 classes / 213,374 methods 0-crash 0-timeout, pytest 245 passed, determinism 3 fresh processes byte-identical, lint trio clean.

**Guards:** [tests/test_mutf8_identifiers.py](tests/test_mutf8_identifiers.py) (astral fixture verifies; enumerate + round-trip through every identity API; findable by an astral NAME query incl. one straddling the character; a driver-shaped sweep that asserts **productivity, not merely that nothing raised** — "no exception" was the reviewer's point, since a broken round trip returns empty everywhere and raises nothing; a corpus-wide `locate_class_dex(c) >= 0` oracle over every enumerated class, which is the round-trip invariant stated as a property rather than a fixture; the overlong-identifier rejection; the `ResolvedArg` const-string case, which now asserts the decoded VALUE round-trips rather than merely not raising) + [tests/test_verifier_type_ids.py](tests/test_verifier_type_ids.py) (forged descriptor rejected with the `type_id` reason, strict AND lenient; 0 false-reject over the corpus). **7 of the 11 verified to FAIL against a pre-fix rebuild** (plus the initializer guard, verified by a one-line toggle since its shape did not exist pre-change); the 3 that pass both are non-discriminating BY DESIGN and say so (the fixture-is-loadable sanity check, the no-false-reject guard, and the corpus round-trip oracle — all properties that must hold on both sides). The forgery targets a type_idx NOT referenced by any field_id / method_id / class_def, i.e. exactly the #23 channel — targeting a referenced one would be caught by the OLD verifier too and the test would be vacuous.

### An IDENTIFIER renders readably in Java text — the code-unit claim is scoped to LITERALS (dexllm#28, 2026-08-10)

The Java text path claims **ART code-unit fidelity**: it emits the exact UTF-16 units `mirror::String` holds, so `AppendUtf16Escaped` turns a surrogate or control unit into `\uXXXX`. Applied to IDENTIFIERS that made one class read **two ways in a single session** — `LA𐀀sTest;` from `list_classes()` and from `render_class_smali`, but `class A\ud800\udc00sTest {` in decompiled Java. For the consumer (an analyst or an LLM reading both panes) that is a correlation failure: naive matching between the two views misses, and a class name copied out of the Java pane is not the symbol. It was also inconsistent rather than principled — a **BMP** identifier (`A한ysisTest`) always rendered readably, surviving by unit count, not by rule.

**User decision (2026-08-10): go readable, and narrow the README claim.** The deciding argument was dynamic-analysis correlation — for symbolic hooking the thing that resolves is neither spelling as text but the **UTF-16 unit sequence** (`Java.use` / `loadClass`) or the **MUTF-8 bytes** (JNI `FindClass`), and the readable form is the one that is safe in more places: in JS the two literals are the SAME string (`"\ud800\udc00" === "𐀀"`), in Python and in dexllm's own APIs only the readable form round-trips, and for JNI both need the same `Utf8ToMutf8`-style conversion. The escape form is only correct where `\uXXXX` is processed as source (JS, Java) — pasted into Python or JSON as data it matches nothing.

**Change:** `mutf8::AppendUtf16AsIdentifier` (new, beside the per-unit escaper) combines a VALID surrogate pair into its code point and emits it readably; a LONE surrogate and a control char still escape. `SanitizeUtf8` ([decompiler.cpp](native/dad_cpp/decompiler.cpp)) — the identifier path — uses it; the Writer's `EscapeJavaString` (string LITERALS) is untouched, so literals keep ART's exact units. Literals are already ASCII `\uXXXX` escapes by the time `SanitizeUtf8` runs, so the change structurally cannot reach them. A lone surrogate in a NAME is impossible (`IsValidPartOfMemberNameUtf8Slow` rejects it), which is why the identifier path needs no lone-surrogate rule beyond the existing escape.

**Measured (a/b OFF vs ON, same script, both `.so` md5-verified):** decompile + smali + `list_classes` over **27,018 classes / 32 sources → identical sha256**. The corpus has 0 non-ASCII identifiers, so the change is crafted/obfuscator-only — which is the point of the a/b: it must be a no-op on real input. parity 28/28, sweep 27,018 0-crash, determinism 3 processes byte-identical, pytest 280, lint clean. Crafted verification: `list_classes` / smali / Java all read `A𐀀sTest`, and the BMP control is unchanged on all three.

**Docs narrowed, not silently:** README's "a supplementary char is kept as a surrogate pair, exactly like ART" now says **in a string literal**, with the identifier rule stated next to it; [docs/api.md](docs/api.md), [docs/dexkit-vs-art-dex-handling.md](docs/dexkit-vs-art-dex-handling.md) follow. This is a CLAUDE.md rule 5 case — a marketed claim was narrowed, so it was escalated and decided by the user before implementing, not folded in as a fix.

Guards: [tests/test_identifier_rendering.py](tests/test_identifier_rendering.py) — 5 tests, **2 discriminating** (verified to FAIL against a pre-fix rebuild: the astral identifier reads the same in all three views, and `decompile_method_ast` no longer disagrees with ITSELF — a review found its `cls_name` was already readable while its own `source` field carried `\uXXXX`, so the inconsistency lived inside a single returned dict and nothing covered it). Plus a C++ vector set in [mutf8_parity_test.cpp](tests/parity/mutf8_parity_test.cpp) §8 pinning the property the corpus a/b cannot reach (the corpus has no non-ASCII identifier at all): over 20,000 random UTF-16 streams the new renderer is BYTE-IDENTICAL to the per-unit escaper on every input containing no valid pair, differs on exactly those that do, and never emits invalid UTF-8. The other 3 must hold on BOTH sides and say so: the BMP control (which is what shows the old rule was arbitrary) and two literal guards pinning the half of the claim that was NOT narrowed. Only ONE of those two can catch a relaxed literal escaper (the one asserting the escape is present); its sibling asserts the call does not raise, which is all it can assert — a raw surrogate would fail at pybind11's strict decode before any assertion ran, so a stronger-looking predicate there would be a tautology, and an earlier draft's was. **One inherited guard was updated**: dexllm#22's `test_astral_type_in_a_field_initializer_decompiles` matched `\ud800\udc00` in the output; a field TYPE is an identifier, so it now matches the readable character. What it guards (that the initializer append site is sanitised at all) is unchanged.

### String CONTENT crosses the boundary as a `surrogatepass` PAIR — a lone surrogate round-trips (dexllm#29, 2026-08-09)

A string LITERAL may legally hold a **LONE SURROGATE**: `VerifyMutf8` checks sequence shape and canonicality, not surrogate PAIRING, which is exactly what ART's `CheckIntraStringDataItem` does. (The asymmetry with identifiers is correct — `IsValidPartOfMemberNameUtf8Slow` accepts a leading surrogate only when a trailing one follows, so a NAME cannot hold one, and every identifier path is unaffected by this change.) Such a literal did not round-trip: `list_value_strings()` returned **U+FFFD** for it and `find_*_using_strings` then MISSED, silently — the forward and reverse string APIs disagreeing with no error, the last case of the dexllm#19 round-trip class.

**The premise the issue and CLAUDE.md both recorded was wrong.** They said a Python `str` cannot carry a lone surrogate, so nothing could be done short of changing a released return type. It can (`"\ud800"` is a legal `str`), and CPython's **`surrogatepass`** error handler encodes/decodes it as the standard 3-byte form `ED A0 80` — **exactly what the dex pool stores**. The loss was pybind11's STRICT UTF-8 codec on both sides of the boundary, so the fix does those two conversions itself and the return type stays `str` (no `.pyi` change, no `bytes`/`*_raw` accessor).

**Applied as a PAIR, to string CONTENT only** ([module.cpp](native/binding/module.cpp)): **OUT** a shared `decode_content` (= `Mutf8ToUtf8`, which already keeps the raw 3-byte form, behind the ASCII fast path `Mutf8ToUtf8Lossy` has and the non-lossy decoder lacks — ~3× a passthrough, and these paths run once per POOL STRING) feeding `content_out` (`ResolvedArg.string_value`, the AST string values) and `decoded_unique` (`list_value_strings` / `list_class_strings` / `list_method_strings`, which needs the decoded text as its dedup key anyway). The fast path has to be in the SHARED helper: the delta review caught the first cut putting it only in `content_out`, whose two callers are not the listing accessors — so the one place that actually lost it, `decoded_unique`, still had, while the docs claimed it fixed (`AstToPy`, whose producer `dast.cpp` already decodes non-lossily); **IN** a `QueryStr` pybind type_caster on the five content matchers, replacing the default `std::string` caster with one that encodes a `str` via `surrogatepass` and takes `bytes` / `bytearray` verbatim (the `bytearray` arm is required — pybind11's own caster accepts one, and dropping it would NARROW the API).

**The rule for what stays lossy is DISPLAY vs QUERY, not identifier vs content.** A surface whose value is fed back as a query is lossless; one that exists to be shown keeps U+FFFD, because printing a lone surrogate raises. That covers the NAME matchers (`ident_out`/`ident_in`, where the case is also unreachable — the verifier rejects a lone surrogate in a name), every `__repr__`, the smali renderer, and **`ClassSummary.source_file`** — which a reviewer showed is NOT verifier-protected the way a name is (`CheckClassDefItem` only range-checks `source_file_idx`, [dex_verifier.cpp](native/core_ext/dex_verifier.cpp)), so a lone surrogate IS reachable there; it takes no query counterpart, so the display rule governs and it deliberately shows U+FFFD. The first cut of this change justified the split as "identifiers only", which was false for exactly that field.

**KNOWN AMBIGUITY, inherent to the storage format (adversarial-review finding, pinned not fixed):** the pool encodes an astral character as a SURROGATE PAIR (CESU-8), so `"\U000dfffd"` and the two-half string `"󟿽"` — different Python strings — have IDENTICAL pool bytes. A byte-comparing matcher cannot separate them: a half-surrogate query matches INSIDE a legitimately-paired literal under `contains` (reproduced on the unmodified bundled `Annotation_classes.dex`: `"\udb3f"` → 2 hits), and `equals` on the split form finds the paired one. The OUT direction always reports the pair as the combined character. Passing the halves as `bytes` always did this — making a `str` query work is what puts it in reach of a `str`, so the change WIDENS the reachability of a pre-existing format property rather than creating one. Pinned by a test so it is an asserted semantic. **Batch KEYS are deliberately NOT converted** (they are caller labels, not pool content, and come back as `str` keys), so `{s: [s] for s in …}` still raises `TypeError` for such a value — loud, and unchanged.

**`decoded_unique`'s dedup key moved with it**, from the lossy text to the lossless one: two distinct pool strings no longer collapse into a single U+FFFD entry. That is the only key for which "deduplicated" and "the result can be fed back to `find_*_using_strings`" are both true.

**Cost, accepted deliberately (the user was asked before implementing):** a `str` carrying a lone surrogate RAISES at any strict-UTF-8 **encode** of it — `str.encode()`, a text-mode file write, `print()` to a UTF-8 stream, `json.dump(fp)`. It is safe through `==` / `in` / `re` and through `json.dumps` at its default `ensure_ascii=True`, which is what [mcp_server.py](src/dexllm/mcp_server.py) and [server.py](src/dexllm/server.py) use. (An earlier draft of this paragraph listed `json.dumps(..., ensure_ascii=False)` as a raising call — it is NOT: `dumps` returns a `str` and the raise comes when that result is encoded. Both reviewers caught it.) That `json.dumps` is load-bearing rather than cosmetic: **the MCP transport's own serializer cannot encode the raw value** (a `TextContent` holding it fails with `PydanticSerializationError`), so pre-serializing to ASCII is what keeps the wire safe — noted at the call site so a later refactor to structured content does not silently turn a miss into a transport crash. The failure this can produce is loud and local; the one it replaces was a silent miss in the reverse lookup of a crafted sample. It also makes `Mutf8ToUtf8Lossy`'s "always valid UTF-8" contract no longer the whole story at the binding — the function keeps its contract, but string CONTENT no longer goes through it.

**Measured (a/b OFF vs ON, SAME script, both halves' `.so` md5-verified):** 45,924 records over 32 dex-bearing sources — every value/class/method string listing, the matcher round trip for each, both batch forms, `bytes`-argument behaviour, 3,998 `ArgOrigin.string_value`, 893 AST hashes — **identical sha256**, as expected since the corpus holds no lone surrogate (the only input on which the two decoders differ). Argument-type acceptance is unchanged (`str`/`bytes`/`bytearray`/str-subclass accepted, `memoryview`/`int`/`None`/`list` still `TypeError` — a reviewer read pybind11 3.0.4's `string_caster` and confirmed the sets match exactly, so nothing widened either). parity 28/28, sweep 27,018-class 0-crash 0-timeout, determinism 3 fresh processes byte-identical, pytest 274, lint trio clean, corpus-less run 66 passed / 212 skipped / 0 failed.

**Two independent reviewers**, both of whom REFUTED the attacks that would have blocked it, with work worth recording: `content_out` cannot raise (exhaustive over all 16.8M byte strings of length ≤ 3 plus 400k random streams against a model of `mutf8.cpp` — 0 failures of `PyUnicode_DecodeUTF8(..., "surrogatepass")`); the AST double-decode is idempotent over the same corpus; `lenient=True` does NOT weaken the precondition (`VerifyMutf8` is in `CheckIntraSection`, not gated on `check_insns_`); the OUT/IN pair is a genuine BIJECTION on loadable pool strings (400k verifier-legal streams incl. lone surrogates, `Utf8ToMutf8(Mutf8ToUtf8(x)) == x`, 0 failures); and the a/b's byte-identity was structural rather than lucky (147,721 differences on streams WITH a lone surrogate, 0 without). Fixed from their findings: the `enc` refcount leak if `assign` throws (now `reinterpret_steal`), the false "identifiers only" justification, the `json.dumps(ensure_ascii=False)` error, the missing guards, the smali-oracle scoping, and the lost ASCII fast path. A THIRD, delta review of those responses then caught two of them being wrong: the fast path went into the function that had not lost it (fixed by the shared `decode_content`), and scoping the smali oracle in its DOCSTRING left its assertion unconditional — it FAILS on a verifier-valid `$DEXLLM_TEST_APK` carrying a lone surrogate, the same "corpus dependency must SKIP, never fail" trap the access-flags guard hit — so both sides now exclude surrogate-bearing strings and the equality is an invariant again. A FOURTH round (two fresh reviewers on the committed change) then found **two more responses wrong**: the dedup "coverage gap" premise above, and a tautology fix that was still a tautology (`listed[listed.index(s)]` is `s` by definition, since `list.index` searches by `==` — the property is now asserted over the LISTING). It also found three guards that FAIL rather than SKIP on legitimate input (a dex with no value strings; an astral literal that is static-init-only, which degenerated the ambiguity pin to `0 == 0`), a `.pyi` still narrower than the runtime signature, a `mutf8.h` lead-in contradicting its own bullets, and the missing null-handle guard pybind's caster opens with. **The pattern is the finding**: five of the defects in this change were in RESPONSES to review, not in the original design — each was a claim about the fix rather than the fix itself.

**Boundary note (delta review, LOW):** the display-vs-query rule holds inside the PYTHON API. It does not extend to the MCP transport: a value comes OUT safely (escaped to `\uXXXX` by `ensure_ascii=True`), but sending it back IN as a tool argument is rejected while PARSING the request — mcp's json parser refuses a lone-surrogate escape where stdlib `json.loads` accepts it. So over MCP such a value is readable but not requeryable. Likewise "the MCP and HTTP servers use `ensure_ascii=True`" is true of the paths that carry dex strings; Starlette's own `JSONResponse` uses `ensure_ascii=False`, but no endpoint using it carries one. Deliberately NOT changed: `PyErr_Clear()` on an encode failure stays a `return false` rather than a rethrow, matching pybind11's own `string_caster` — its dispatcher expects `load()` to report failure, not throw.

Guards: [tests/test_lone_surrogate.py](tests/test_lone_surrogate.py) — 15 tests, **11 verified to FAIL against a pre-fix rebuild**: the value keeps the surrogate, the listed value round-trips, the method- and class-scoped accessors round-trip, the query is accepted, `ResolvedArg.string_value` keeps it, the AST string value keeps it, the smali↔accessor divergence holds, the half-surrogate ambiguity, a surrogate-bearing batch VALUE reaches the matcher while a batch KEY still raises, and the dedup-key pair above. The other 4 are non-discriminating BY DESIGN and say so: the crafted dex is loadable (the premise), the `bytes` and `bytearray` query paths still match, and a clean-corpus value still resolves. **Both reviewers independently found that two of the three OUT sites had NO guard** — `ArgOrigin.string_value` and `AstToPy` were individually revertible with a green suite (the pre-existing dexllm#22 ArgOrigin test filters to NUL/astral literals, the two cases where the lossy and lossless decoders AGREE, so it cannot discriminate this line) — and that the repo's own `test_method_strings_match_smali_ground_truth` oracle had silently degraded from an invariant to a corpus fact, since smali stays lossy; its docstring now scopes the equality and the divergence is pinned in both directions.

The dedup-key change **is** guarded, after a fourth review REFUTED the "accepted coverage gap" this section first recorded. The claim was that two pool strings differing only inside a lone surrogate "cannot be produced from the corpus by length- and sort-order-preserving crafting" — wrong: craft the SAME corpus string twice with DIFFERENT surrogates and CONCATENATE the two dexes into one file, a shape dexllm#25 explicitly supports and exactly what a packer dump looks like. Under the lossy key both collapse to one U+FFFD entry and one silently disappears from the listing. `test_two_lone_surrogates_no_longer_collapse_in_the_listing` builds precisely that and fails pre-fix. (The direction was never in doubt — on verifier-legal input the new key strictly REFINES the old one, since a 4-byte sequence and an overlong are both rejected at load, so two distinct legal byte strings cannot decode alike — but "no guard because it is not craftable" was a false premise, not a risk assessment.) The fixture is crafted in place, length- and sort-order-preserving (3 ASCII bytes → the 3-byte lone surrogate, `utf16_len` −2, patch position past the LCP with both string_ids neighbours), and is asserted loadable before any test uses it. **One pre-existing guard was INVERTED**: `test_lone_surrogate_query_is_rejected_not_silently_wrong` pinned the rejection as a desirable LOUD failure; it is now `test_lone_surrogate_query_is_accepted`, the same treatment dexllm#22's overlong guard got when its premise turned out to be false.

### D-3 — source-line ↔ bytecode-offset map (dexllm#1, 2026-06-25)

For precise smali ↔ Java cursor sync (the only remaining JEB/jadx-parity gap in `dexllm-web`'s xref), the decompiler now exposes which dex byte offset each emitted line/statement came from. **Metadata-only, parity-neutral** (text + AST output byte-identical to before — observed at emit, never mutated). Pipeline:

1. **`IRForm::source_byte_off`** (`uint32_t`, default `UINT32_MAX`) — stamped once at the dispatch funnel ([basic_blocks.cpp](native/dad_cpp/basic_blocks.cpp) `BuildNodeFromBlock`, `ir->source_byte_off = ri.byte_off`), since `DispatchInstruction` returns one IR node per instruction. No per-handler plumbing.
2. **Writer harvests `pc_map_`** ([writer.cpp](native/dad_cpp/writer.cpp)): `Write()` counts `\n` for the current line; `record_line` fires at FOUR sites — `VisitIns` (statements; gated on `buffer grew && !skip_` so an elided implicit `super()` that writes only indent doesn't claim the next statement's line) + `EmitIf` + `EmitLoop` (pretest + posttest) + `EmitSwitch`. The header sites are essential: `if`/`while`/`} while`/`switch` lines are emitted via `visit_cond`/`Accept`, NOT through the statement chokepoint — they're the short-circuit / multiple-anchor cases D-3 exists for. Header offset comes from `CondBlock::repr_ins()` (a virtual shared with the AST path; ShortCircuit/Loop delegate to the compound condition's last ins).
3. **JSONWriter sidechannel** ([dast.cpp](native/dad_cpp/dast.cpp)): same four logical sites; the map is kept OUT of the nested-list AST (so the tree stays byte-identical to androguard) and keyed by **add()-order = post-order DFS statement index** (consumer contract documented on `JSONWriter::pc_map`).
4. **API:** `Decompiler::DecompileMethodWithPcMap` (shares `RunPipeline` with the cached `DecompileMethod`) → binding `decompile_method_with_pc_map`; AST `pc_map` field on `decompile_method_ast`.

**Validated:** parity 28/28, sweep 188,065-method 0-crash, throughput unchanged, `decompile_method` text byte-identical, header coverage (if/while/do-while/switch + short-circuit) gated by `tests/test_pc_line_map_headers.py` (MANDATORY — a statement-only test would pass while broken). Tests: `tests/test_pc_line_map.py` (+ elided-super regression), `test_pc_line_map_headers.py`, `test_pc_map_coverage.py` (every offset lands on a real `RawIns` byte offset). Found via adversarial review + fixed: the elided-super-→-offset-0 mis-map (the `!skip_` gate). **Line-number contract:** `line` is a 1-based index into `source.split("\n")` — the `\n`-only line counter in `Writer::Write`. A string literal may carry a raw U+2028/U+2029/U+0085 (valid Java, emitted as readable UTF-8), which Python's `splitlines()` / a Unicode-line-aware split would treat as a line break but the counter (and a JS `text.split("\n")` consumer) do not. Using `splitlines()` to index the map desyncs by the count of such separators — an earlier review flagged "offsets on `}` lines" that were entirely this measurement artifact (`\n`-split → 0; the tests use `\n`-split). No known product limitations: the do-while-non-`CondBlock`-latch footer-gap a finder raised does not occur in the corpus (0/188,065). **Intended (not a limitation):** the both-branches-identical `if` form (DAD `writer.py:285`) renders its condition only as a `// Both branches…` / `// if (…)` comment — no executable line carries the if-test offset, so the map anchors that offset to the comment line (~0.06%; the comment IS the condition's sole rendering — the most faithful attribution). Both adversarial passes (the `\n`-contract proof over 267k entries and the repr_ins/RunPipeline/`!skip_` equivalence audit) found 0 desync / 0 mislanded offsets.

### Method access flags are the RAW dex bits — upstream's Modifier rewrite removed (2026-08-06)

Upstream DexKit's `InitBaseCache` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) rewrote `ACC_DECLARED_SYNCHRONIZED` (0x20000) → `ACC_SYNCHRONIZED` (0x20) while reading `class_data`, for `java.lang.reflect.Modifier` compatibility (`access_flags ^ kAccDeclaredSynchronized | kAccSynchronized`, duplicated in the direct- and virtual-method loops). **Removed** — `method_access_flags` now stores the dex's own bits verbatim.

**Why.** (1) The rewrite is **lossy**: in dex, 0x20 means JNI `synchronized native`, a *different* property, so the result conflates two facts and drops one if a method carries both bits. (2) It made one method describe itself two ways — `get_class_summary` said `synchronized` while `decompile_class` said `declared_synchronized`. (3) DexKit is a Java library whose users pass `Modifier` constants; this is a dex analyzer whose Python API documents no such normalization (`.pyi` said plain `int`, docs asserted nothing).

**The whole dexllm L8.1 patch was retired with it.** That patch existed only to keep an unrewritten *second copy* of the vector for the DAD decompiler (`method_raw_access_flags` + `GetMethodRawAccessFlags()`); with the rewrite gone the two vectors are element-identical, so [dexitem_code_source.cpp](native/core_ext/dexitem_code_source.cpp) `GetMethodAccessFlags` reads the single remaining one. Net effect on the vendored tree is **fewer** local modifications, and one `vector<uint32_t>` of `MethodIds().size()` per dex is gone (corpus: 226,844 entries ≈ 0.87 MB; largest APK 51,016 ≈ 200 KB).

**Blast radius is one attribute.** The transformed value reached Python through exactly one route — `get_class_summary(...).methods[i].access_flags` on the raw binding. The other two consumers of the vector are dead ends: `MethodBean.access_flags` is dropped by our `ParseMethodMetaArray` (`MethodRef` carries only dex_id/method_idx/descriptor), and `IsAccessFlagsMatched` is unreachable because every L7 wrapper passes 0 for the access-flags matcher (0 `CreateAccessFlagsMatcher` call sites). The **SDK and MCP are untouched** — `ClassInfo`/`FieldInfo` carry class/field flags (never rewritten) and the MCP `get_class_summary` tool returns only the class's, while `MethodAst.access_flags` is modifier *names* off the DAD path (already raw-derived).

**One coupled fix:** the vendored smali formatters `FormatAccessFlags` / `FormatMethodAccessFlags` rendered 0x20 but had no branch for 0x20000, so raw method flags would make a `synchronized` method render with NO modifier. Both gained the branch. Inert today (`FormatMethodAccessFlags` has zero callers; `FormatAccessFlags`'s only live call site passes CLASS flags, where 0x20000 is never set) — verified by an a/b smali snapshot over every class holding a synchronized method: **byte-identical**. Committed anyway because the change is what made them latently wrong (adversarial-review ADV-2).

**Measured (a/b, same script, both halves' `.so` md5-verified and bit-reproducible):** 354,757 summary records → **447 differ, all methods, all exactly `(new ^ 0x20000) | 0x20 == old` with 0x20000 set in new** — 0 class records, 0 field records, 0 unexplained. Decompiler output **byte-identical** (814 classes = every class holding a synchronized-or-declared-synchronized method plus a deterministic control slice; sha256 equal both halves), as expected since DAD already read the raw copy. Smali render **byte-identical** (117 classes). 0 methods in the corpus carry both bits, so the lossiness is structural, not corpus-manifest. parity 28/28, sweep 25,309-class / 188,065-method 0-crash 0-timeout, pytest 233 passed.

**Guard:** [tests/test_access_flags.py](tests/test_access_flags.py) — 4 access-flag tests (the file later gained a 5th, unrelated: the field-xref per-instruction contract, and then 6 more for the SECOND contract it now carries, dexllm#41's UNKNOWN ≠ 0). Two **fail against the pre-removal build** (verified by rebuilding it): the corpus-wide check that a method the DAD path calls `declared_synchronized` reports 0x20000, and a cross-layer oracle decoding the summary bits with the AST's own name table. A third pins the DAD path on its own (`LruCache.size()`) so the oracle can't stay green if BOTH routes regress together; a fourth guards the `| 0x20` half. **Corpus dependency is a SKIP, never a failure** — "this APK has a synchronized method" is a property of the sample, and `$DEXLLM_TEST_APK` (documented in conftest) can narrow the fixtures to one of the 8 bundled APKs that have none; the first cut asserted on it and reported "the rewrite is back" for an environment change (BOTH reviewers confirmed this independently). The discriminator used instead is `decompile_method_ast`, which reported the raw form under both behaviours. The oracle asserts `sync_checked` separately from the aggregate count (the broad slice alone satisfies the aggregate, so it would not prove the sync stratum was reached — ADV-3) and filters `unkn_<flag>` entries, which `GetAccessImpl` emits for the three ACCESS_ORDER bits absent from the name table and which a crafted dex can set on a method (method access flags are not verifier-validated — ADV-4).

**Accepted, not fixed:** this changes the VALUE of a released public attribute with no alias mechanism (unlike the dexllm#21 renames), so an out-of-repo consumer masking `& 0x20` silently stops matching rather than erroring. Both reviewers raised it; it belongs in the release notes and in the still-open deprecation-policy decision (issue #24).

### `access_flags` is `None` when UNKNOWN — 0 is a legal dex value (dexllm#41, 2026-08-14)

`get_class_summary` reported `access_flags == 0` wherever it could not read modifiers. **In dex 0 is a legal, common value** — package-private + non-static + non-final + … (no bit exists for default access, so all-bits-clear IS a declaration): measured **5.14% of methods (9,674/188,065), 8.70% of fields (12,298/141,383), 34.9% of classes (8,835/25,309)** across the corpus. So "unknown" and a real declaration were the same value, every framework class read as package-private, and `[m for m in s.methods if m.access_flags & ACC_NATIVE]` answered `[]` for `android.app.Activity` with confidence. The v0.12.0 `class_methods()` (dexllm#37) exists precisely to test method modifiers, so the API invited the query on a surface that could not answer it.

**Option A of the issue — make the ignorance REPRESENTABLE** (`std::optional<uint32_t>` on `MethodInfo` / `FieldInfo` / `ClassSummary` → Python `None`), the same "this field is only meaningful for some kinds" modelling `ResolvedArg` already uses. The alternatives were rejected with reasons: a sibling `access_flags_known` leaves the DEFAULT read wrong (the consumer who does not know still gets `[]`); dropping the members loses the genuinely observed `method_ids` data (what the app references of `Activity` is real, useful triage input); an injected framework-classpath oracle is the right long-term answer but needs an `android.jar` reader and still needs a way to say "unknown" when absent — after this it becomes a pure improvement (`None` → a value).

**Two sources of unknown, and the second was found by BOTH reviewers, not by the issue:**
1. an **external** class — no `class_data` at all.
2. an **inherited field REFERENCE on an INTERNAL class**. `class_field_ids[field.class_idx]` is built from the WHOLE `field_ids` table ([dex_item.cpp:140](vendor/dexkit_core/Core/dexkit/dex_item.cpp#L140)) — every field reference grouped by the class named in the reference — while `field_access_flags` is written only inside the `class_data` loops ([:200](vendor/dexkit_core/Core/dexkit/dex_item.cpp#L200)/[:205](vendor/dexkit_core/Core/dexkit/dex_item.cpp#L205)). So a subclass's field list holds inherited fields it does not declare, whose slot keeps the default 0. Reproduced: `VectorDrawableCompat$VClipPath` reports `mNodes` as **0** while its declaring superclass `$VPath` reports **4 (protected)** in the SAME session; corpus-wide **2,238 such fields, 1,151 with a NONZERO real declaration**. **Methods are unaffected** — `class_method_ids` is populated only inside the class_data loops. Fixed with a `field_access_flags_declared` bitvector in the vendored core (3 lines inside the existing walk) that `FillInternalClassSummary` gates on; the previous `idx < flags.size()` bounds check could never be false and structurally could not see an in-range-but-never-written slot.

**Measured (a/b OFF vs ON, same script, both `.so` md5-verified and each build reproducing its md5):** 32 loadable sources — internal 380,982 entities with **2,415 changed, all 0→None, 0 unexplained, 0 nonzero flags lost**; external 55,330 entities, **all** 0→None; `format_class` rendering byte-identical; the MCP tool dict differs only in that key. parity 28/28, pytest 415, corpus-less 110 passed / 310 skipped, sweep 27,018-class / 202,519-method 0-crash 0-timeout, determinism 3 processes byte-identical, lint trio clean, doc fences executed.

**Breaking**, deliberately: a released attribute's type changes `int` → `int | None`, and this repo keeps no aliases (#24), so `& FLAG` on an external member now raises `TypeError` instead of answering. That loud failure IS the fix. Release-notes material.

**Guards** (6, in [tests/test_access_flags.py](tests/test_access_flags.py)): external class/method flags, external FIELD flags **on a class that actually has fields** (the first external class with methods has none, so an `all(...)` over its empty field list was vacuous — reverting `FieldInfo` alone passed the whole suite until a reviewer built that mutant), the inherited-field split checked against an **independent `class_data` parser over the raw dex bytes** (not against the value under test — the weaker version skipped, and therefore survived, a mutant that dropped the declared gate), the loud `TypeError`, a declared 0 **corroborated through the DAD path** (`decompile_method_ast(...)["access"]` must decode no modifier for it), and propagation through the SDK models + the MCP JSON. Mutation matrix: `FieldInfo`→`uint32_t`, `MethodInfo`→`uint32_t`, and drop-the-declared-gate each killed by their intended guard. **Corpus dependency is a SKIP, never a failure** — the first cut asserted "this APK has a package-private member" and went RED on 6 of the 25 bundled APKs under `$DEXLLM_TEST_APK`, the exact trap this file's own history already records.

**The LIST itself was fixed next — see the section below (dexllm#45).**

### A class's field list is what it DECLARES (dexllm#45, 2026-08-15)

#41 made the modifiers on a referenced-but-not-declared field honest (`None`); the entry itself still claimed a declaration the class does not have. `DexItem::class_field_ids` is keyed on the whole `field_ids` table grouped by the class named in the REFERENCE ([dex_item.cpp:140](vendor/dexkit_core/Core/dexkit/dex_item.cpp#L140)), so a subclass's list also holds inherited fields it only touches — `VectorDrawableCompat$VClipPath` declares **zero** fields yet listed all three of `$VPath`'s. Corpus: **2,413 such entries over 1,108 of 26,938 internal classes** (1.6% of 151,319 listed fields).

**Why it existed.** The grouping is a BYPRODUCT of an unrelated sweep — the loop exists to identify `@Target` / `@Retention` enum constants and appends `class_field_ids[field.class_idx]` as one extra line, at a point where declaredness (a `class_data` fact, read 60 lines later) is not yet known. The method side avoided it by accident, not by design: `class_method_ids` HAD to come from the `class_data` walk because that is where `code_off` → `method_codes` is read, and methods got a SEPARATE structure (`pending_cross_ref_method_ids`) for the reference view. Upstream DexKit is a runtime SEARCH library with no "list this class's members" API at all, and for `FindField` narrowed by class, matching an inherited reference is arguably the point. dexllm then built two DECLARATION-shaped APIs on that reference-shaped index — `get_class_summary` (L1.5) and `render_class_smali` (L5). **The knowledge already existed in-tree**: [dexitem_code_source.cpp:637](native/core_ext/dexitem_code_source.cpp#L637) re-derives the field order from `ClassData` with a comment saying `class_field_ids` does not preserve it, so `decompile_class` was always correct — the insight just never propagated to the other two consumers.

**Fixed on FOUR surfaces** (the issue named three; `find_fields_by_name` was found during the work): (1) `FillInternalClassSummary` ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)) — and with it everything derived from the summary: `class_fields`, `format_class`, the MCP `field_count`; (2) `RenderClassSmali` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) — a `.field` line only for a `class_data` entry, as baksmali emits, with the trailing blank line now gated on "any line emitted" rather than "the list is non-empty"; (3) `FindFieldsByName` ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)) — **only when a `declaring_class` is given**, so that argument means what it says. All three reuse the `field_access_flags_declared` bitvector #41 added, so no new state. **(3) is filtered dexllm-side on the returned `FieldRef` (which carries `dex_id` + `field_idx`), NOT in the vendored matcher** — `FindField`'s scan list, `IsFieldsMatched`, `GetFieldBean` and `GetClassBean.field_ids` keep upstream semantics (the latter three are dead ends for dexllm: the parser discards the bean's field list and no dexllm query populates a `fields()` sub-matcher).

**An UNSCOPED `find_fields_by_name` deliberately still returns references** — the first cut filtered unconditionally, justified as "the way `find_methods_by_name` already behaved", and a reviewer showed that justification is FALSE: `find_methods_by_name` is declaration-only in its `declaring_class` fast path but a whole-`method_ids` scan without one (constructed: it returns `FastSafeIterableMap;->descendingIterator`, which that class inherits). So filtering unconditionally made the field arm the ASYMMETRIC one while the docs claimed symmetry — and it lost real answers, because an inherited field's declaration is usually in the FRAMEWORK: `find_fields_by_name("rightMargin")` went from 12 hits to **0**, i.e. every site where the app touches it. Listing a class's MEMBERS and SEARCHING the id tables by name are different questions, and only the first is answered with declarations alone. Guarded in both directions (`test_an_unscoped_field_search_still_returns_references` kills the unconditional variant; the scoped test kills its removal).

**Alternative considered and declined:** populate a `class_declared_field_ids` inside the existing `class_data` loops, mirroring `class_method_ids` exactly, so surfaces (1) and (2) walk one shared list instead of repeating the predicate (a reviewer's suggestion; it would also hand `dexitem_code_source.cpp`'s `ParseClassFieldOrder` the static→instance order it currently re-derives). Declined for this change on two grounds: a second `vector<vector<uint32_t>>` per dex is the same kind of duplicate index the L8.1 `method_raw_access_flags` patch was RETIRED for (see the RAW-dex-bits section), where the `vector<bool>` already exists and costs a bit per field; and walking a declaration-ordered list would REORDER the `.field` lines, a behaviour change outside #45 needing its own a/b. The cost is three one-line predicates across two translation units, which `test_smali_field_lines_agree_with_the_summary` exists to catch drifting.

**DROPPED rather than moved to a new accessor** (the issue's open question). The reference view is not lost — it is exactly `list_fields()`, the whole `field_ids` table, filtered by the `Lcls;->` prefix; **verified 0 of the referenced fields lost recoverability**. A `class_referenced_fields` accessor would add a name to four layers and to three naming-audit axes for something already expressible, and an `is_declared` flag would duplicate the signal `access_flags is None` already carries while leaving the default read wrong.

**Measured (a/b OFF vs ON, SAME scripts, both `.so` md5-verified and each build bit-reproducing its md5):** 3.80M records over 33 sources — every summary field row plus **every line of every class's smali render** → **5,173 removed, 0 ADDED, 0 changed**: 2,413 summary rows, 2,413 `.field` lines, and **347 BLANK separator lines**. The smali side is recorded per RENDERED LINE, not per `.field` line, on a reviewer's finding: the blank-line gate is the one edit whose effect is not a `.field` line, so a `.field`-only attribution was blind to precisely it (and no test in the repo looked at smali blank lines either — now `test_a_class_declaring_no_fields_emits_no_field_separator` does). Every removed summary row carried `access_flags is None`, i.e. exactly the set #41 had already marked. `find_fields_by_name` (both match types × scoped/unscoped, queries drawn from the build-independent `list_fields()` so the two halves compare VALUES): **26 removed, 0 added, ALL of them scoped** — 0 unscoped rows move, which is the scoping decision above stated as a measurement. **`list_fields()` and the whole decompile are byte-identical** (the DAD path re-parses `ClassData`, so it never read this index). **Independent oracle:** a raw-bytes `class_data` parser that never goes through DexKit agrees with `get_class_summary` on **26,938 / 26,938 internal classes** (0 mismatch), and **0** referenced fields lost recoverability through `list_fields()`. parity 28/28, sweep 26,938-class / 201,079-method 0-crash 0-timeout, determinism 3 processes byte-identical, pytest, corpus-less, narrowed, lint trio, doc fences.

**Breaking**, deliberately: a class's `fields` list shrinks (up to ~27% of the entries on an affected class), `render_class_smali` loses those `.field` lines, and a `declaring_class`-scoped field search stops answering for an inherited reference. No aliases (#24). Release-notes material.

**Guards:** [tests/test_declared_fields.py](tests/test_declared_fields.py) (9) + the INVERTED `test_an_internal_class_lists_exactly_the_fields_it_declares` in [tests/test_access_flags.py](tests/test_access_flags.py) — #41's inherited-field test asserted the entries EXIST and report UNKNOWN, which #45 would have made vacuously true, so it was inverted into the set EQUALITY against the raw `class_data` oracle rather than deleted (the same treatment #22's overlong and #29's lone-surrogate guards got). **Mutation matrix, each of 5 mutants built and run:** revert the summary filter → 5 fail; the smali filter → 3; the blank-line gate → 1; remove the find-fields filter → 1; make it unconditional → 1. Every edited line has a guard that dies with it, including the two a reviewer had to CONSTRUCT (the blank line and the unconditional filter both survived the first cut's suite). The blank-line mutant is re-checked NARROWED to a2dp.Vol / partialsignature / hello-world, since the delta review showed it surviving those before the floor was fixed; the whole guard file is run narrowed to **each of the 26 bundled samples one at a time** (all green), which is what caught the RED above and which the `tests/data/multidex.apk` CI leg cannot reach (that sample has 0 inherited references, so these tests skip there). `test_smali_field_lines_agree_with_the_summary` is a DRIFT guard — it kills each one-sided mutant but is blind to a symmetric regression, and says so, and it now carries a floor requiring its capped scan to actually REACH an affected class (on 8 of the 26 bundled samples the window held none). `test_an_inherited_field_is_still_reachable_through_list_fields` is non-discriminating BY DESIGN and says so: it pins the recovery expression the docs tell readers to use.

**A DELTA review of the review responses then found three more — two of which RE-INTRODUCED the very defect class the response was fixing,** [[review-responses-are-the-weak-spot]] a third time in this repo: (1) the new "the declaring class still answers" guard re-derived the OWNER from the unscoped search hits minus the candidate class — but those hits are REFERENCES, so it landed on a sibling that also only references the field, whose scoped query correctly answers nothing. It went **RED on `hello-world.apk` and `app-prod-debug.apk`** — a fix FOR the corpus-fact rule that broke the same rule. The fixture now RETURNS the owner (membership, not single-element equality: a class may declare two same-named fields of different types, or be declared in two dexes). (2) The new blank-line guard's `require_corpus_shape` floored on "internal class declaring no fields", which is true of ~700 classes in any APK — the DISCRIMINATING shape is "declares none but DOES carry references", and 0 of a2dp.Vol's 21 fell inside the `[:200]` window, so the mutant **survived a `$DEXLLM_TEST_APK=a2dp.Vol_137.apk` run, green, without even skipping**. Now floored on the right shape (and it splits on `"\n.method"`, so a `.source` value containing the token cannot truncate the head). (3) A sentence the response ADDED was false: "without a `declaring_class` the whole id table is searched". `try_match_field` gates on `type_def_flag[field_def.class_idx]`, so an entry grouped under a class no loaded dex declares is never a hit either way — measured, `->bottomMargin:I` has 11 `field_ids` entries, 8 unscoped hits, and the 3 missing are spelled under framework classes. Corrected in `docs/api.md`, the `.pyi` and the C++ comment, with the framework-spelled residual documented as reachable only through `list_fields()`. Also from the delta pass: "**exactly** `list_fields()` filtered by the prefix" is wrong on multidex — that list is the raw table and repeats a descriptor once per dex (measured 2,273 duplicates on one APK), so the recovery expression is documented as a superset needing `set()` to count.

**Three of the guards were defective in ways only review caught, all the repo's own recorded patterns:** the propagation test's MCP leg was `len(X) == len(X)` (`tools.py` computes `field_count` from the very call it was compared against) and its `format_class` leg asserted the absence of a `name:Type` substring that emitter never produces in any case — **both passed against the entire pre-fix build**, so "it propagates" was unguarded on 2 of its 3 layers; all three legs now compare against the independent `class_data` oracle. And `test_the_declaring_class_still_answers_for_the_same_field` would **FAIL on a corpus fact** — the usual inherited field is declared in the FRAMEWORK, so no loaded dex answers, and 43 of tvleanback's 412 candidates / 59 of app-prod-debug's 237 are that kind; it passed only because the first candidate happened not to be. It now takes an `inherited_ref_declared_internally` fixture that `require_corpus_shape`s (issue #46: an environment fact must SKIP). The candidate finder is also scoped to `list_fields_in_dex(0)` on both sides, since the oracle reads one dex while the summary resolves first-wins across all of them — a dex-1 reference to a dex-0 class would be absent from the summary before AND after, silently turning the guards into tautologies.

**The GIGO this rests on was closed next (dexllm#48, see below):** `field_access_flags_declared[F]` means "some `class_data` declared F", and the filter relies on that being F's OWN class — which the verifier only guaranteed for a class_data's FIRST member. The change was neutral on it either way (the entry was listed under the other class before this too, with fabricated flags), but it was a real divergence from the "1:1 ART `DexFileVerifier` port" claim.

### Every `class_data` member's defining class is verified (dexllm#48, 2026-08-15)

ART's `CheckInterClassDataItem` (`dex_file_verifier.cc:3208`, field loop `:3226`, method loop `:3244`, plus a per-member re-check at `:934`/`:961`) loops all four member lists and rejects any entry whose `field_id.class_idx` / `method_id.class_idx` is not the declaring class. The port called `FindFirstClassDataDefiner` (defined `:2579`, called `:3070`) and compared **one** member — the name was accurate, the coverage was not — so a `class_data` whose first entry was its own could declare another class's members and verify clean. It is replaced by **`CheckClassDataDefiners(off, cls)`** ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp)), which walks every static field / instance field / direct method / virtual method, each list restarting its own delta chain, and compares each resolved id's `class_idx` to `cls`. It stays in the INTER pass because that is where the class is known (`VerifyClassData` in the intra pass has the offset but not the class). It repeats the INDEX checks; it does NOT repeat the offset check, which is a documented precondition (both passes walk the same `class_defs` with the same `!= 0` condition, and `lenient` gates only `VerifyInsns`) — the first cut's comment claimed "self-contained", which was not true of that half.

**Not a memory-safety gap, a wrong-ANSWER one** — every index was already bounded, so nothing read out of range. What it corrupted is what the core builds while walking `class_data` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)), written BY INDEX with no check that the index belongs to the class being walked: `field_access_flags` / `field_access_flags_declared`, and for methods the same **plus `methods.emplace_back(class_method_idx)`**, which injects the foreign method into this class's `class_method_ids` — so `list_class_methods` / `get_class_summary().methods` / `render_class_smali` report a method the class does not declare. The method half is the worse one, and was the half with no guard until review.

**Measured against a pre-fix build** (a SEPARATE reproduction, not the committed fixture — that one walks bare `.dex` only, so it cannot touch an APK): a length-preserving patch to one `hello-world.apk` class_data's SECOND field entry yields a dex that `verify()` calls **valid** and that loads with 2,119 classes, on which `Landroid/support/annotation/Dimension;` silently **loses two fields it declares** (`PX`, `SP`) — the delta chain shifts every entry after the patched one, and since #45 an undeclared entry is dropped rather than listed — with nothing raised anywhere. Post-fix the same dex is rejected, strict and lenient. The committed fixture crafts the equivalent shape from whichever bare `.dex` offers one.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified):** 34 corpus sources × {strict verify, lenient verify, `verify_report`, `dex_count`, per-source class-list hash} → **byte-identical, 0 false-reject**; a reviewer widened it to **641 sources / 664 logical dexes** (incl. a v41 container and AOSP's own `art/test/dexdump/*.dex`) → still **0 invalid**. Expected: ART runs this exact check, so anything Android loads passes it. **The lenient axis carries near-zero information** on a clean corpus — `check_insns_` gates only `VerifyInsns`, so those verdicts are trivially equal to the strict ones; the population it would matter for (a partially-decrypted dump with in-range but wrongly-owned `class_data`) is exactly what this now rejects, and is unmeasured. Cost: bounded STRUCTURALLY rather than by timing — the extra walk is one pass per DISTINCT class_data (a shared one bails at its first member for every class_def but the owner, and the duplicate-class_def check precedes it), strictly dominated by the intra pass which already walks the same bytes plus `VerifyCodeItem`; the wall-clock ≤0.5% best-of-7 agrees but has no resolution to prove it. parity 28/28, sweep 26,938-class 0-crash, determinism 3 processes identical, lint trio clean.

**One observable change beyond the verdict:** the rejection REASON for the first-member case moved from `class_data_item defines members of another class` to ART's own `Mismatched defining class for class_data_item field` / `... method`, which also says WHICH list. Nothing documents the exact wording and no in-repo consumer matches it, but an out-of-tree one would — release-notes material.

**Guards** (8 in [tests/test_verifier_class_data_definer.py](tests/test_verifier_class_data_definer.py)), crafted IN PLACE and length-preserving so every offset — and therefore every other check — is untouched, patching the SECOND entry precisely because the first is what the old code caught. The rejection test is **parametrised over all four lists**, asserting the reason names the right member KIND: the first cut had one fixture, and a reviewer killed it with two surviving mutants (leave `fields(inf)` unchecked, leave both method loops unchecked) because the class it happened to pick had `sf=0`. Per-list mutation matrix, each built and run: dropping the static / instance / direct / virtual check fails 2 / 3 / 2 / 1 tests, all methods 2, all fields 3. Non-discriminating BY DESIGN and saying so: the corpus no-false-reject sweep, the empty-class_data acceptance (ART allows it explicitly, and the new code writes that branch from scratch), and "the first member is still checked", which accepts either reason wording.

**Two fixture defects review caught, both the repo's own recorded shapes:** the first cut decoded static+instance as ONE delta chain — the exact opposite of the per-list restart rule the fix implements — which on `FieldsTest.dex` (sf=1, inf=2; real indices static=[2], instance=[0,1], modelled [2,2,3]) produced a patch leaving the dex VALID, so the test would hard-FAIL rather than skip on a corpus where that file sorts first (issue #46, in the guard file for a change about a delta chain). And it never verified its own premise. `_forge` now re-decodes after patching and requires a genuine owner mismatch AND no out-of-range index — the latter because an out-of-range shift is caught by the INTRA pass with a different reason, which would again fail on an environment fact.

**Deliberately still out of scope, all pre-existing, all wrong-answer rather than crash surface:** member ACCESS FLAG validation (`CheckFieldAccessFlags` / `CheckMethodAccessFlags`); **`CheckStaticFieldTypes` `:1289`** (a static field's declared type vs its `encoded_array` initializer) — which this repo currently *relies on the absence of*, since `tests/test_mutf8_identifiers.py::test_astral_type_in_a_field_initializer_decompiles` retypes a static value `0x17`→`0x18` and expects the dex to load; and the orphan-`class_data` check ART gets by driving from the MAP where this port drives from `class_defs` (inert — the core walks `class_defs` too, so it never parses one).

### An unrenderable static initializer is no longer indistinguishable from none (dexllm#64, 2026-08-22)

`DecodeEncodedValueText` returned an EMPTY string for five `encoded_value`
types, and that empty string is filtered out **twice** — once by the producer
([dexitem_code_source.cpp](native/core_ext/dexitem_code_source.cpp)
`DecodeStaticInitMap`), once by the renderer
([decompiler.cpp](native/dad_cpp/decompiler.cpp)). So a field whose
`static_values` entry existed but could not be spelled and a field with no entry
at all produced **byte-identical** Java. The constant was recoverable from
nowhere else: `decompile_class` is the only surface that reads `static_values`
(`render_class_smali` emits none since dexllm#45; neither the SDK nor MCP has an
initializer accessor). Pre-existing for `0x1a`/`0x1c`/`0x1d`; dexllm#63 widened
the set to five while fixing their payload-consumption bug, and recorded it as an
accepted residual rather than filing it.

**Both reference decompilers do worse here, which is why this follows neither —
and that was measured, not assumed.** Five crafted dexes (one per type, on the
committed fixture) run through **jadx 1.5.0**:

| type | androguard / DAD | jadx 1.5.0 | dexllm before | dexllm now |
|---|---|---|---|---|
| `0x15 METHOD_TYPE` | the raw payload as an int | **whole CLASS fails** (`Can't decode value`) | dropped | `invoke.MethodType.methodType(Double.TYPE, TestInvocationKinds.class)` |
| `0x16 METHOD_HANDLE` | the raw payload as an int | **whole CLASS fails** | dropped | `// = TestBadBootstrapArguments::bsm` |
| `0x1a METHOD` | `['LMain;', '<init>', ['()', 'V']]` (the proto NESTS) | `= ;` (a syntax error) | dropped | `// = Main::new` |
| `0x1c ARRAY` | a **memory address** | `= {7}` | dropped | `= {7}` |
| `0x1d ANNOTATION` | a **memory address** | `= @B` | dropped | `// = @annotations.BootstrapMethod(Hello = 7)` |

androguard's `0x1c`/`0x1d` are non-deterministic across runs (the address of an
`EncodedArray` object with no `__str__`), which this project gates against, so
dropping them was right at the time. jadx crashing the class for two of them is
what settles the direction: this is not "catch up to the oracle", it is a place
both oracles are wrong.

**The androguard column is per-type and NOT uniform, which an earlier draft of
[docs/api.md](docs/api.md) got wrong in a way this table did not.**
`EncodedValue.__init__` opens with `if VALUE_SHORT <= value_type < VALUE_STRING`,
i.e. `0x02 <= vt < 0x17` — which swallows `0x15` **and** `0x16` into
`_getintvalue`, so both come out as a raw integer. Only `0x1a` reaches
`cm.get_method(id)` and renders the Python list. A correctness reviewer RAN
androguard on checksum-corrected crafts of the fixture to establish that, and
found the two mirrors disagreeing.

**TWO shapes, and the flag travels with the VALUE, not the type code.** A
`MethodType` and an array HAVE Java expression forms, so they render after `=`.
A method handle, a method reference and an annotation do NOT — Java cannot
assign any of them to a field — so they ride as a trailing `// = …` comment and
the declaration stays valid. `{Foo::bar}` has no expression form either, so an
array is an expression exactly when every element is: `ClassInfo` grew a
`field_init_comments` vector DISJOINT from `field_init_texts`, and the renderer
picks by which one is non-empty. (The alternative — a marker string the renderer
sniffs — is a protocol; two parallel vectors each mean one thing.)

**The rendering vocabulary was HOISTED, not re-spelled.** dexllm#67 already
taught the IR builder to reconstruct an `invoke-custom` bootstrap chain, which
spells a proto as `MethodType.methodType(…)` and a handle as `Cls::name` /
`Cls::new` / `Cls.name`. Those rules moved to `dad_cpp/util` as
`ClassLiteralText` / `MethodTypeText` / `MethodHandleText` / `MethodRefText` — a
rule read a second time drifts, and its prose drifts with it, which is the whole
content of dexllm#70. **TWO of the four are genuinely shared**:
`instruction_dispatch.cpp` calls `ClassLiteralText` and `MethodHandleText`, and
only the node WRAPPING stayed there, because the AST needs structure a flat
string cannot carry. `MethodTypeText` and `MethodRefText` have a single caller
each and live beside the shared pair rather than beside it — the IR path
assembles `methodType` from IR NODES instead. An earlier draft said the IR
builder calls all four; it does not, and that overstatement is exactly what left
ARGUMENT ORDER unguarded. **Sharing also bought coverage the crafts here cannot reach.** Every
`method_handle` in all three committed fixtures is kind 4 or 5
([[fixture-dead-branches-hide-guards]], the same census dexllm#67 recorded), so
no static-value craft in this change can exercise `MethodHandleText`'s FIELD
(`Cls.name`, kinds 0x00-0x03) or CONSTRUCTOR (`Cls::new`, kind 0x06) branches —
but dexllm#67's `test_a_handle_argument_renders_by_its_KIND` patches
`method_handle_type` IN PLACE for exactly those two, and now drives the shared
helper. A duplicated body would have left both branches guarded on one caller
and dead on the other. That covers the SPELLING and nothing more: a correctness
review pointed out that `ResolveMethodHandle`'s own field-vs-method dispatch
(`method_handle_type >= 4` → `GetMethodRefTriple`, else `GetFieldRefTriple`) is
reached from the IR path only, so this change pins it from the static-value route
with its own in-place kind patch. A guard pins that both layers call the helpers, and a
behavioural one pins that they agree: the proto is
`(ILjava/lang/String;Ljava/lang/Double;)I`, which the fixture's own bootstrap
uses AND whose parameters are not all one type, so `decompile_class` (crafted
static value) and `decompile_method` (untouched IR path) must produce the
identical text through genuinely different code — including the ORDER, which a
homogeneous signature cannot see.

**The standing rule bound this commit for the fifth time**
[[a-rule-you-wrote-binds-your-next-commit]]. `VerifyEncodedValue`'s `0x16` arm
declined to bound the index and justified it as *"for a value nothing
consumes"* — this arm is that consumer. (**dexllm#72 later bounded it at the
gate**, ART :1204/:1212, so the reader bound below is defence in depth on this
route now.) The bound moves to the READER, which is
the tier the safety contract permits for an out-of-scope section, and it is
dexllm#67's existing `ResolveMethodHandle` (the one place that bounds BOTH the
handle index and the handle's own `field_or_method_id`) rather than a second
resolution. The two consumers now behave DIFFERENTLY on a crafted index and the
comment says so: the slicer's annotation path THROWS out of `ArrayView`, while
this one returns false, so an unresolvable handle renders nothing instead of
taking the whole class decompile down.

**An UNRESOLVABLE value still renders nothing, and that is dexllm#67's rule
rather than a relapse.** A crafted `0x16` index the reader cannot resolve
produces no output at all — refusing beats inventing,
the same call dexllm#67 made for an unresolved call site. It is reachable only
from a craft: every value the gate can vouch for resolves, and those are exactly
the ones that now always render.

**A `//` comment, and `/* … */` would have been a hole.** A string element
inside a rendered array is `PythonUnicodeEscape`d, which escapes quotes,
backslashes and every control character — but NOT `*` or `/`, so a literal
containing `*/` closes a block comment early and the rest of the line becomes
code. A line comment has no such terminator. The remaining channel is a
NEWLINE, and it is real rather than theoretical: an annotation element **name**
is bounded by `VerifyEncodedAnnotation` as a string INDEX and never validated as
a member name, so it can point at any pool string — and `invoke-custom.dex`
itself ships two that end in a raw `0x0A`. `SanitizeUtf8` does not help (its
ASCII fast path passes `0x0A` through verbatim, deliberately, so the Writer's
own newlines survive), so **`CommentSafe`** folds it — along with every other C0,
DEL, and the three Unicode separators — at the one append that is
line-terminated. Same family as dexllm#22, and the first cut of that function
folded only `\n` and `\r`, which is the review finding below.

**Measured (a/b OFF=`d581b96` `c723499f…` vs ON, SAME script, both
`.so` md5-verified and the ON build bit-reproducing its md5 after the halves were
swapped back; re-captured on the FINAL build after the review fixes and identical
on every axis, so the record covers the shipped binary and not a predecessor
[[verify-build-identity-before-measuring]]):** 70 sources — the whole bundled corpus, every committed fixture,
every `art/test/dexdump/*.dex`, every `tools/dexter/testdata/*.dex`, and **7
crafted dexes** — × {both verify verdicts, load, class list, a hash over the
static-field declaration lines, the whole decompile} = **259 axis records, 14
changed, and every one of them is a crafted source on one of the two decompile
axes**. The declaration axis is a WEAK one for this change and a correctness
review had to say so: its filter keeps a line that ends in `;`, and a
comment-bearing declaration ends in `// = …`, so those lines DROP OUT of it
rather than differing within it — it registers the change but does not carry it.
The whole-decompile axis is what carries the signal. Verify verdicts and class lists are identical on every source; **0 real
sources changed on any axis**. The corpus carries **0** values of all five types
(the issue's independent raw-dex census: 55 sources / 33,787 class_defs / 6,934
`static_values` arrays / 113,349 top-level values / 0 hits — only 10 of the 18
type codes occur at all), so a corpus-only a/b is byte-identical BY CONSTRUCTION
and proves nothing about the mechanism; the crafted sources are in the same
measurement for exactly that reason [[ab-must-prove-the-mechanism-fires]].

parity **29/29**, pytest **909 passed / 10 skipped**, TRUE corpus-less
(`test_apk` MOVED aside) **501 passed / 418 skipped / 0 failed** — every one of
the 56 new guards runs in the CI leg — narrowed to `tests/data/multidex.apk`
**810 passed**, the guard file green narrowed to each bundled sample, sweep
**25,309-class / 213,374 method-block 0-crash 0-timeout, GATE: PASS**,
determinism 3 processes x 3 `PYTHONHASHSEED`s -> one digest (unchanged from
before the fix), lint trio clean, doc fences 77,
`scripts/check_dad_boundary.sh` clean.

**Stated rather than discovered, from the review:**
* a rendered ARRAY is a new LINEAR output amplifier — pre-change `0x1c`
  accumulated no text, and a 400,000-element array of one 51-byte string turns an
  832 KB dex into a 22 MB `decompile_class` result (0.10 s, 106 MB RSS). Linear,
  not quadratic (the gate caps nesting at 16 — verified, 16 accepted / 17
  rejected), the same order as the pre-existing N-fields-one-big-string route,
  and `0x1c` has 0 incidence in any real dex. No budget added; worth one if a
  budget is ever added elsewhere in this decoder.
* `{7}` on an `int` field is invalid Java, and this change turns a previously
  VALID `static final int X;` into it. That is the un-ported
  `CheckStaticFieldTypes` (ART :1289) gap CLAUDE.md already scopes out and which
  `tests/test_mutf8_identifiers.py` actively relies on; the same mismatch is
  already producible pre-change with a STRING value. Crafted-only.
* an earlier draft justified NOT widening `CommentSafe` by claiming a member
  NAME may already carry U+2028, so the class was pre-existing. **A delta
  reviewer refuted that from the ported predicate**: `case 0x2028: return
  leading == 0x202f;` REJECTS U+2028/U+2029, and `case 0x00: return leading >=
  0x00a0;` rejects NEL and every C1 — and a field TYPE goes through
  `IsValidDescriptor` to the same predicate while a String initializer is
  `PythonUnicodeEscape`d. So EVERY component of a declaration line excluded
  these before dexllm#64, the annotation element name is the only channel, and
  the honest conclusion is the opposite of the draft's: widen. `CommentSafe`
  escapes C0, DEL, the whole C1 range, the three separators and the backslash.
  What genuinely IS pre-existing is the BIDI/invisible class — the same
  predicate ALLOWS U+2066-U+2069 (`0x2066 & 0xfff8` is 0x2060, matching no case,
  so `return true`) and U+FEFF in a member name — so those reach a declaration
  line through `SanitizeUtf8(finfo.name)` today and stay out of scope.
* the two vectors are disjoint only because `GetFieldInfo(...).init_text` is
  hard-coded empty. If that hook is ever populated, `decompiler.cpp`'s fallback
  would emit `Type name = <fallback>;  // = <comment>` — a declaration asserting
  two values. The header comment says "check both"; nothing enforces it.

**Guards** (56 cases in
[tests/test_static_initializer_rendering.py](tests/test_static_initializer_rendering.py),
ALL corpus-independent — every craft re-lays the eight bytes of
`LTestLinkerMethodMinimalArguments`'s `static_values` in the committed
`tests/data/invoke-custom.dex`, so they run in the CI leg and under any
`$DEXLLM_TEST_APK` narrowing). The craft is length-preserving: a payload of N
bytes takes 1 + N, the array's count drops to `1 + (7 - N) // 2`, the surviving
one-byte INTs follow, and the leftover bytes are never read — no offset, no
section size and no neighbouring structure moves. Those survivors double as a
**desync oracle**. Each index is chosen to reach a DIFFERENT branch (`<init>`
vs a plain method name, an empty array vs a populated one, an annotation with
and without elements) and is resolved by an independent walk of the dex, not by
asking the decoder under test.

**Three inherited guards were INVERTED rather than deleted**, on the dexllm#22 /
dexllm#29 / dexllm#45 precedent: dexllm#63's desync tests asserted the
declaration `endswith("RETURNS_NULL;")`, which was the PREMISE of the day and
not the subject — the subject is that the three values AFTER it keep their own
constants, and that is untouched. Two source-level anchors also had to move
(`"std::string DecodeEncodedValueText"` no longer matches a struct return type);
both now anchor on the PARAMETER list and **raise loudly** if the definition ever
disappears — which is how the coupling was found in the first place, since the
dexllm#63 invariant test failed with a `ValueError` instead of silently
auditing an empty string.

## What the reviewers found — 23 findings over two rounds, and the code DID move

**Round 1 found 12 and round 2 found 11 more. Calling them "none in what the
code does" was wrong twice over** — the headline of each round is a defect in
what this change EMITS, and both were introduced BY it. Round 2's is the sharper
one, because it was introduced by round 1's own fix.

**Round 1: a REGRESSION this change introduced, and only an OFF/ON measurement
could have said so.** The first cut folded `\n` and `\r` into
the comment and called that "cannot forge a line of Java". `SanitizeUtf8`'s ASCII
fast path passes EVERY byte below 0x80 through verbatim, so VT, FF, FS, GS, RS,
ESC and DEL reached the output raw, and the multibyte path renders U+0085 /
U+2028 / U+2029 READABLY (dexllm#28, right for an identifier, wrong here).
Python's `str.splitlines()` breaks on eight of them (not ESC or DEL,
which are escaped because they reach a TERMINAL, not because they split a line). An adversarial reviewer re-laid
pool string 3 in place, pointed an annotation element name at it, and got

```java
    static final int FAILURE_TYPE_LINKER_METHOD_RETURNS_NULL;  // = @…BootstrapMethod( C
  static final String PWNED = "owned";  //     = 7)
```

on a dex `verify()` calls **valid** — then ran the same seven crafts against the
PREVIOUS build and got `forged_line=False` on every one, because 0x1d rendered
nothing there so the name never reached the output. It also breaks an invariant
this repo states out loud: `test_smali_never_contains_raw_control_chars` forbids
raw C0 in the smali listing, its docstring enumerates U+2028 / U+2029 / U+0085 /
DEL as the only contract exceptions, and the Java path was C0-clean until this
change. `SingleLine` became **`CommentSafe`**, folding every C0, DEL and the
three Unicode separators; all twelve are pinned, and folding only the two
newlines now fails TEN of them (a delta reviewer built that mutant and counted;
an earlier draft of this line said seven).

**Round 2: the escape alphabet re-forged the line it had just folded.** A Java
compiler translates a `\uXXXX` escape BEFORE it recognises comments (JLS 3.3),
so folding a newline TO `\u000a` hands the next Java-aware consumer the newline
back — and `\` was not escaped either, so the six ASCII bytes could simply be
written. A delta reviewer took this file's OWN `[lf]` guard case, ran the emitted
line through **javac**, and got the fabricated `static final String PWNED` field;
reproduced here, with a positive control (the pre-fix rendering compiles and
yields the field, the fixed one does not). The invariant is now **no backslash
survives in a comment** — escapes are written `<U+XXXX>` — which also defangs the
`\uXXXX` escapes `SanitizeUtf8` ITSELF emits for a decoded control, and is
checkable in one line. The contrast that shows it is specific to this change:
the pre-existing `EscapeJavaString` emits the same escape inside a STRING
literal, where javac fails loudly; a comment is the one place it succeeds
silently, and before dexllm#64 no attacker-controlled text reached one.

**Round 2: `SanitizeUtf8` was droppable with a green suite.**
`CommentSafe(SanitizeUtf8(x))` is a two-part composition and every one of the 46
crafts used a pure-ASCII body, on which the two forms are byte-identical — so
deleting the inner call passed all 899 tests while a lone surrogate in an
annotation element name made `decompile_class` raise `UnicodeDecodeError`, i.e.
the dexllm#22 failure class re-opened. Three non-ASCII name crafts close it.

**`MethodTypeText` has ONE caller, and three places said otherwise.** The IR
builder assembles `methodType` from IR NODES (the AST needs structure a flat
string cannot carry), so it shares only `ClassLiteralText`. That made ARGUMENT
ORDER a property nothing held the two layers to — and both protos pinned here
were blind to it, one having a single parameter and `(II)I` being homogeneous:
**the exact hole dexllm#67 paid for once as its own M9.** A reviewer walked
`ParseParamsType` backwards and passed all 875 tests. The claim is corrected in
`util.h`, the guard docstring and this file; the fixture's mixed
`(ILjava/lang/String;Ljava/lang/Double;)I` is pinned as a literal, and the
cross-layer test moved onto it — the IR path renders that exact string in
`TestDynamicBootstrapArguments.testCallSites()V`, so the comparison is now
order-sensitive on both sides.

**Two more unguarded lines, each demonstrated by a mutant that passed 875:**
the `|| el.text.empty()` half of the array demotion (without it an unresolvable
element yields `= {?};` — uncompilable Java on the right of an `=`, which is
precisely what the two-shape design exists to prevent), and the
`idx > UINT32_MAX` clause (0x16 WAS the one arm the gate let through EIGHT bytes
wide, so `2**32` truncates to 0 and FABRICATES handle 0 for a value naming none;
every other 0x16 craft in the file is one byte). **dexllm#72 closed that width at
the gate**, so on THIS route the clause is now dead and its guard is a source
pin; the same truncation in `ParseCallSiteArg`, which reads a call_site array the
gate does not walk, was never given the clause at all — dexllm#74.

**A guard of mine tested the wrong function.** The new kind-dispatch case
asserted the `.` / `::` separator — which `MethodHandleText` derives from the
KIND alone, so it says nothing about which TABLE `ResolveMethodHandle` consulted.
A mutant that always takes the method table passed all 128 cases. It pins the
resolved NAME now (`field_ids[0]` is `TestDynamicBootstrapArguments.bsmCalls`,
`method_ids[0]` is `Main;-><init>`), which is the half that differs.

**Four factual claims were wrong and each was disproved by RUNNING something.**
androguard swallows `0x15` **and** `0x16` into `_getintvalue` (its
`VALUE_SHORT <= vt < VALUE_STRING` range), so only `0x1a` yields the Python list
— [docs/api.md](docs/api.md) said otherwise while the table here said it right,
i.e. one commit shipping two contradictory mirrors. jadx does NOT lose the class
on a method reference; it emits `= ;`, and the two it loses are `0x15`/`0x16`
(README overstated it). `<clinit>` IS a `method_id` a constant can name — four of
them in this very fixture — so `MethodRefText`'s stated reason for not handling
it was false. And the 0x1c arm called an empty element "unreachable" thirty lines
below the arm that makes it reachable. Plus a comment naming a function that does
not exist (`ResolveHandleText`), a verifier comment scoped to "TWO consumers"
when `ParseCallSiteArg` is a third reader, and — the pattern this file keeps
recording — the dexllm#63 section still describing, in the present tense, the
residual this change removes, while its C++ twin had already been deleted
[[a-rule-you-wrote-binds-your-next-commit]].

**Everything else they attacked, they REFUTED with their own instruments:** the
five new arms' memory safety (**451 crafted inputs judged by SUBPROCESS EXIT
STATUS** — an 8-byte index, handle indices 29 / `0xFFFFFFFF` / `2**64-1`, an OOB
`field_or_method_id`, kind `0xFFFF`, table boundaries — **0 signals, 0 hangs**),
consumption desync (**12,000 fuzzed cases over three seeds, 7,590 gate-accepted,
0 desync** — the trailing sentinel INTs never move), the recursion cap (depth 17
accepted, 18 rejected, inherited from the gate), the choice of `//` over
`/* */`, injection into the EXPRESSION path (structurally impossible — 0x17 and
array-of-string are both escaped), and amplification (0x17 already offers the
same).

**26 mutants, each BUILT and RUN with a distinct `.so` md5, each killed.** Round
two adds five for the lines round two touched: the escape form reverted to
`\uXXXX` (**19 failures** — the shape a delta reviewer took through javac), the
backslash left unescaped, C1 narrowed back to NEL-only, `SanitizeUtf8` dropped
from the composition, and the annotation arm's `?` removed. Round one's fifteen: each
of the five arms dropped alone (6 / 4 / 3 / 5 / 3 failures), a handle rendered as
an EXPRESSION (`= Foo::bar`, uncompilable), the array's composition rule removed
so an array of handles claims to be one, the comment sanitiser removed, the
shared handle bound removed, the IR builder re-spelling the kind rule as a correct DUPLICATE
(killed at SOURCE level only — nothing behavioural can see it), `methodType`'s
return type moved LAST, a primitive rendered `int.class` instead of the boxed
`TYPE`, `<init>` no longer `::new`, and a full pre-fix revert (**20 failures**).

**The pre-fix mutant is the one worth recording, because the harness REFUSED it
and a correctness review caught the gap in the evidence rather than in the
product.** Its anchor, `case 0x15: {  // METHOD_TYPE`, matches TWICE in that file
— `DecodeEncodedValueText` and `ParseCallSiteArg` — so `assert count == 1` fired
and the run reported 13 md5s, not 14. The first hand-written replacement then did
not COMPILE (a fallthrough group duplicates the 0x16/0x1a labels), and a build
failure is not a kill [[mutation-harness-restore-pitfalls]] — the harness's own
`md5 UNCHANGED` branch is what said so. It was rebuilt as five per-arm edits and
run (md5 `84d2d061…`), and the reviewer independently constructed the same revert
and reached the same 20 failures.

**Docs:** [docs/api.md](docs/api.md)'s claim that the header+fields region
matches androguard `DvClass.get_source()` *"byte for byte except that a `"` is
escaped"* was **already false** before this change — CLAUDE.md's own record has
614 `= None` lines on a single APK turning into `null`, plus the IEEE754 and
TYPE/FIELD/ENUM divergences — so it is replaced with the actual divergence table
rather than merely extended.

### Decompiler API surface (pybind11)

Exposed via `dexllm.DexKit(apk_path)`. The constructor identifies the file **by content, not extension** — a `dex\n` magic loads as a bare `.dex` via the core's `AddImage`; otherwise it must prove out as a real zip/apk container (PK signature + parseable central directory via `ZipArchive::Open`) and carry at least one sequential `classes*.dex`. A disguised `.apk` (renamed, wrong, or absent extension) therefore still loads; a non-dex/non-zip file or a zip with no `classes*.dex` now raises a clear `std::runtime_error` (the error reports whether `AndroidManifest.xml` was present) instead of the old silent 0-dex load. Detection lives in `DexKitExt::DexKitExt` ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)). Arg name stays `apk_path` for backward compatibility.

**Multi-source / packer-unpack load.** `DexKit(sources: list[str], lenient=False)` loads several sources (each a `.dex` or zip/apk) **in order** — earlier sources get lower dex_ids, so first-wins prefers them. List a runtime-decrypted/dumped dex BEFORE the original apk to make the unpacked class win a collision (mirrors ART, where the packer orders the decrypted dex first). `lenient=True` runs the verifier in **ART-structural-equivalent** mode (`VerifyDex(..., check_insns=false)` — skips `VerifyInsns`, the one part beyond ART's structural `DexFileVerifier`) so a *partially*-decrypted dump (valid structure, garbage method bodies) still loads, exactly as ART loads it; header/ids/code_item bounds stay verified. A **concatenated** dump (several dexes in one file — what unpackers actually produce) is verified per LOGICAL dex, and the ones that verify still load even when a sibling is rejected (dexllm#25); `lenient` was the mode that walked straight into that hole. **Lenient memory-safety:** skipping `VerifyInsns` lets unvalidated instruction operands reach the core's cross-ref collectors, so those bound each operand index at the source ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp) `InitBaseCache` / `GetUsingStringsFromCode`; a third, `GetInvokeMethodsFromCode`, was bounded by the same pass and turned out to be dead code — deleted in dexllm#61): an out-of-range `const-string` string index, `iget/sget` field index, or `invoke-*` method index is dropped so `method_using_string_ids` / `method_using_field_ids` / `method_invoking_ids` never feed an OOB id into the load-time cross-ref maps (`field_get/put_method_ids`, `method_caller_ids`) or the L7 matchers — without this a crafted dump OOB-read the string pool (SEGV on a 32-bit `const-string/jumbo` index) or OOB-indexed the caller maps at load. The decompile path was already safe (snapshot `ResolveConstRef` + adapter getters bound-check); this extends the guarantee to `list_value_strings` / L7 search / IOC-xref / `dangerous_*`. A second-pass review also bounded `BuildMethodDescriptor` in [dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp) (it OOB-read `MethodIds()` for a `resolve_call_args` `ResolvedArg` whose `method_idx` is a raw `invoke` operand — its sibling `BuildFieldDescriptor` already had the guard). Bounds are no-ops on strict-verified input. (Session adversarial-review finding; regression `test_lenient_oob_operand_does_not_crash` in [tests/test_lenient_verify.py](tests/test_lenient_verify.py) exercises `list_value_strings` / `find_methods_using_strings` / `decompile` / `resolve_call_args` / `extract_iocs` on crafted OOB-operand dumps.) `dexllm.add_dumped_dexes(dk, dumps, prefer=True, lenient=True)` ([packer.py](src/dexllm/packer.py)) is the "re-analyze after dumping" verb — returns a fresh `DexKit` over `dumps + dk.sources()` (clean rebuild → consistent caches). Both constructors share `CollectSource` (per-source probe + VerifyDex + collect). The constructor refactor and these knobs are the packer-analysis scaffold ([[project-packer-analysis-direction]]); `detect_packer` (attachBaseContext + unpacker-API signals) is the next step.

`dexllm.identify(path)` is the load-free probe behind the same logic — returns `{format: "dex"|"zip"|"unknown", is_apk, has_manifest, dex_count, source}` without constructing a `DexKit` (`source` echoes the path, so a probe result can say what it describes — dexllm#26's lesson, and what lets `dk.source_info()` reuse the shape). Use it to pre-filter resources-only containers (0-dex) before loading, e.g. in sweep harnesses (`dexkit_ext.cpp::Identify`, bound in [module.cpp](native/binding/module.cpp)).

| Method | Purpose |
|---|---|
| `decompile_method(method_descriptor)` | Java text decompile. **GIL released** during execution (parallel-safe). |
| `decompile_method_with_pc_map(method_descriptor)` → dict | **D-3 (dexllm#1)** — Java text + a source-line ↔ dex bytecode-offset map for smali sync: `{"source": str, "pc_map": [(line_1based, byte_off), …]}` (one entry per line, first-anchor-wins; lines with no source op — braces, `while(true)` — omitted; condition/loop/switch HEADER lines are mapped via the four emit hooks). **`line` = 1-based index into `source.split("\n")` — only `\n` (0x0A) delimits a line; do NOT use `splitlines()` / a Unicode-line-aware split** (a string literal may carry a raw U+2028/U+2029/U+0085 that those split on but the `\n`-only counter does not — a JS consumer's `text.split("\n")` matches the contract). Uncached (recompute is cheap), GIL released. Parity-neutral: the map is observed during emit, never mutates the text, which stays byte-identical to `decompile_method`. |
| `decompile_class(class_descriptor)` | Full Java class text — `package`, class header (access + extends + implements), static→instance field declarations with compile-time initializers (EncodedValue decoded), then method bodies. The header+fields region follows androguard `DvClass.get_source()`'s structure but deliberately DIVERGES from it wherever androguard emits invalid or non-deterministic Java — see the table in [docs/api.md](docs/api.md). |
| `decompile_method_ast(method_descriptor, include_source=True)` → dict | Signature components + Java `source` + full DAD `dast.py` nested-list `ast` (`{triple, flags, ret, params, comments, body}`) + **D-3 `pc_map`** (a sidechannel `[(statement_seq, byte_off), …]` kept OUT of the `ast` tree so it stays byte-identical to androguard; key = post-order DFS statement index — see `JSONWriter::pc_map`). `include_source=False` skips the separate text-emit pipeline (AST and text emitters each mutate the graph, so they can't share one run) — ~1.7× faster for AST-only consumers. |
| `list_classes()` → list[str] | Every declared class descriptor across all loaded dexes. Replaces androguard's `AnalyzeAPK→get_classes` (100×+ faster). |
| `list_class_methods(class_descriptor)` → list[str] | Every declared method's full Dalvik descriptor. |
| `list_value_strings()` → list[str] | Every distinct string the app loads as a VALUE — `const-string`/`jumbo` (0x1a/0x1b) operands + static-field `VALUE_STRING` (0x17) initializers (MUTF-8→UTF-8, deduplicated). Excludes identifier/metadata pool entries (type/method/field names, shorty, source files). The IOC feed. (`list_strings()` — the whole pool — was **removed**; only IOC used it.) Impl: `DexKitExt::ListValueStrings` (const-string union via `GetUsingStrings` + a bounded static_values 0x17 scan). |
| `list_class_strings(class_descriptor)` / `list_method_strings(method_descriptor)` → list[str] | **FORWARD string accessors (dexllm#17)** — "which strings does THIS code load", the inverse of `find_{classes,methods}_using_strings` and the code-scoped counterpart of `list_value_strings()`. Answers "what literals does this method carry" without rendering smali / decompiling (the old workaround: a `const-string` regex over `render_class_smali`). MUTF-8→UTF-8, deduplicated, first-occurrence order; `[]` (never raises) for an external / abstract / native / unknown target. **Method scope is bytecode-only** (`const-string`/`jumbo` operands — a `static final String` is a class-level EncodedValue, not in any body); **class scope** = the union over DECLARED methods (ascending method_idx — `class_method_ids` is sorted, so the dex's per-class order, NOT source declaration order; no superclass walk) THEN that class's static-field `VALUE_STRING` initializers — the same (a) code / (b) static-init order `ListValueStrings` uses app-wide, so it is always a subset of it. Impl: `DexKitExt::ListMethodStrings` (indexed descriptor→method_idx resolution, same path as `FindCallSitesFromMethod`, then `GetUsingStrings`) / `DexKitExt::ListClassStrings` (`GetClassMethodIds` union + the static_values scan scoped to one class_def). Exposed on all three layers: raw binding + `.pyi`, `sdk.EnumerationPort`, MCP/agent tools. |
| `find_classes_declaring_strings(strings, match_type, ignore_case)` → list[ClassRef] | **DECLARATION-side string search (dexllm#20)** — the counterpart of `find_classes_using_strings`, which searches the `const-string` BYTECODE index ("which code LOADS S") and therefore cannot see a `static final String` the app declares but never loads. That empty result is CORRECT for its question (javac inlines a compile-time constant at each use site, so a constant that IS used also exists as a const-string and is found) — this API answers the other question, and is the only way to locate an indicator kept solely in a constant (1,236 static-init-only of 29,588 value-strings, summed per-APK over the corpus). Searches the class-level EncodedValue `VALUE_STRING` (0x17) initializers via a lazily-built per-dex declaration index (`EnsureDeclaredStringIndex`, the `ApiResolveIndex` one-shot + GIL-precondition pattern), and reuses the core's own `DexItem::IsStringMatched` (hoisted from private) so per-pattern match semantics are the same code as the `using` family. ALL query strings must match. **Edge cases deliberately diverge**: `using` routes an empty-ish matcher through upstream's Aho-Corasick keyword path instead of `IsStringMatched`, so an empty query returns EVERY class there and nothing here, and `""`/`"^"`/`"$"` match 61 vs 403 on tvleanback. **Adversarial-review hardening:** `static_values_off` is NOT required to be unique across class_defs (the structural verifier only requires the array to PARSE), so a valid 5.7 MB dex pointing every class_def at one huge encoded_array made the retained index quadratic — **1,583 MB RSS, reached straight from `extract_iocs`**; fixed by dedup + `shrink_to_fit` (erase after `unique` keeps the 400 KB capacity — that slack WAS the 1.6 GB) plus a `kMaxDeclaredIds` (2^21, ~50× the whole corpus) budget that REFUSES the index and falls back to scanning per query (verified identical results by shrinking the cap to 4). Result **1,583 MB → 4.8 MB**. The build also assembles into a LOCAL and publishes by move: appending into the member left a partial index after a mid-build `bad_alloc` that the next call appended to again, duplicating every indexed class for the instance's lifetime. **No method-level analogue** — a static-field EncodedValue belongs to a class_def, not a method (method annotations carry EncodedValues too; this index does not scan them). An EMPTY query returns nothing, unlike the `using` family where it returns every class. Non-ASCII literals match like any other since the query is MUTF-8-encoded at the binding (dexllm#19). |
| *(dexllm#19 — string QUERIES are MUTF-8-encoded at the binding)* | The matchers compare against the RAW MUTF-8 bytes of the dex string pool, but a query arrives from Python as UTF-8. The two differ for exactly two things — NUL (`C0 80` vs `00`) and a supplementary code point (dex stores a SURROGATE PAIR, UTF-8 uses 4 bytes) — so such a literal could never match, **including one this library had just returned** (`find_methods_using_strings(list_method_strings(m)[0])` → 0 hits). `dexkit::dad::mutf8::Utf8ToMutf8` (the missing inverse, added beside the ART-parity-tested decoder) is applied in [module.cpp](native/binding/module.cpp) via `to_mutf8_query` for every string-CONTENT matcher (`find_{classes,methods}_using_strings`, both `batch_*`, `find_classes_declaring_strings`) — at the binding, so the whole family is fixed once and `dad_cpp` stays DexKit-free. Identifier/NAME matchers are deliberately NOT converted — a dex may legally carry a supplementary-plane identifier (the verifier allows a surrogate pair in a member name), but `list_classes()` on such a class already raises `UnicodeDecodeError`, so that path is broken independently; recorded as a known residual rather than claimed fixed (0 non-ASCII identifiers in the corpus). **Measured:** corpus round-trip failures **1,299 → 1,236** — the 63 MUTF-8 cases go to **0** and the 1,236 static-init-only ones are unchanged (they need `find_classes_declaring_strings`, dexllm#20). Both former crafted-only residuals (0 across the corpus's 292,157 raw string_data entries) are now CLOSED. A non-NUL OVERLONG encoding was one, which `VerifyMutf8` accepted "as ART does" — **wrong on both counts**: ART rejects it and the check is now ported, so such a dex does not load (see the identifier-pair section). The other was a LONE surrogate, recorded here as "a Python `str` cannot hold one" — **also wrong**: `"\ud800"` is a legal `str` and CPython's `surrogatepass` handler encodes it to exactly the 3 bytes the pool stores; the loss was pybind11's strict codec on both sides, and dexllm#29 closed it (see the string-content section). **Adversarial-review hardening:** pybind accepts `bytes` for these arguments, so malformed UTF-8 reaches the encoder; the original 4-byte branch matched leads 0xF8-0xFF (`c & 0x07`) and synthesised bytes on over-long input — `F0 80 80 80` became a RAW NUL (impossible in a pool) and `F0 80 81 9E` became `^`, silently turning a Contains query into StartWith. The branch now requires a well-formed F0-F4 lead decoding to >= 0x10000; anything else passes through untouched. Guard: 4000-stream `pool→UTF-8→pool` round-trip + edge cases in [mutf8_parity_test.cpp](tests/parity/mutf8_parity_test.cpp), and `test_method_strings_round_trips_into_the_reverse_query` dropped its encodability filter. |
| `dexllm.extract_iocs(dk, *, with_xref=True, denoise=True, xref_limit=300)` → dict | **Python** ([ioc.py](src/dexllm/ioc.py)). Static C2/network-IOC over `list_value_strings()` → `{urls, ips, domains, emails, onion}`. Each row is `{value, methods, declared_in}`: `methods` = call sites that LOAD it, `declared_in` = classes that DECLARE it as a constant (dexllm#20 — an indicator kept only as a constant has no call site, so this is its only location; 21 such indicators in the bundled corpus, e.g. `https://wear.googleapis.com/3p_auth/` → `OAuthClient`). **Defang-aware** (`hxxp://`→http, `[.]`→., `[at]`→@ via an in-tree literal refang) and **public-suffix-validated** (tldextract — the one lib dep, `[ioc]` extra; `com.google.util` rejected). Denoise drops residual identifier hosts (dex packages, RDN/platform roots, xmlns URIs, word-gTLD collisions like `os.name`/`Matcher.group`). Each indicator cross-refs to its method via L7. **iocextract was evaluated + dropped — its regexes ReDoS on dex blobs**; all extraction is in-tree hand-bounded (ReDoS-safe). MCP tool `extract_iocs`. See [[project-ioc-redesign-lessons]]. |
| `dexllm.dangerous_permission_apis(dk)` / `dangerous_permission_api_callers(dk)` → dict | **Python** ([dangerous_api.py](src/dexllm/dangerous_api.py)). Joins AOSP's permission→API map ([aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set) — metalava `@RequiresPermission` + the runtime-enforcement bridge for annotation-less runtime-enforced APIs like SMS ICC ops → SEND_SMS; bundled as [data/perm_api.json](src/dexllm/data/perm_api.json) + perm_levels.json, dangerous slice DERIVED) against the APK's external method refs → which **dangerous** permissions are exercised through real API calls. **Signature-precise**: the bundled table comes from AOSP's clean metalava signatures, so overloads are disambiguated (arity-primary + same-arity type match; constructor `<init>` + inner-class `$`↔`.` normalized). `dangerous_permission_api_callers` adds calling methods (default `app_only=True` drops bundled framework/library callers — androidx/kotlin/play-services; `app_only=False` keeps them). `dataset_path=`/`$DEXLLM_AOSP_DATASET` override. MCP tools `dangerous_permission_apis` / `dangerous_permission_api_callers`. |
| `dexllm.add_dumped_dexes(dk, dumps, prefer=True, lenient=True)` → DexKit | **Python** ([packer.py](src/dexllm/packer.py)). Re-analyze with runtime-dumped dex(es): returns a fresh `DexKit` over `dumps + dk.sources()` (prefer → dumps first → unpacked classes win collisions; lenient → ART-structural-equivalent verify for partial-decrypt dumps). `dk.sources()` exposes the construction sources. Packer-unpack workflow. |
| `identify(path)` → dict | Module-level. Content-based probe (no load): `{format, is_apk, has_manifest, dex_count, source}`. Proves a disguised `.apk` and pre-filters 0-dex containers. |
| `source_info()` → list[dict] | **dexllm#42** — what each construction source WAS, probed once at LOAD: one row per `sources()` entry, in the same order, with `identify()`'s keys. A **session fact**, so it survives the file: the MCP `identify` tool re-probed the path per call, and a source deleted after the load — a dump in a temp dir, exactly what `add_dumped_dexes` is for — answered `format: "unknown", dex_count: 0` for a live 286-class session, where 0 is the documented "resources-only container, nothing to analyse" sentinel. `CollectSource` already ran `ProbeContainer` to decide HOW to load, so this keeps a result that was being computed and thrown away; `ContainerInfoFrom` is the single place a probe becomes a `ContainerInfo`, shared by `Identify()` and the loader so they cannot drift. Ask `identify(path)` about a PATH and this about the SESSION. **Breaking:** the SDK `ContainerInfo` gains a required `source` field (last, so the four existing positional arguments keep their meaning) and `identify()`'s dict gains the key — `/upload`'s `identified` carries it too, and now comes from the loader's own record rather than a second read of the disk. |
| `verify_report()` → list[dict] | Per-loaded-dex structural-verification verdict: `{dex_id, name, valid, reason, source}`. The malformed-dex gate (`VerifyDex`) runs at load; this exposes its results (a fully-rejected container raises at construction instead). **One row per LOGICAL dex** (dexllm#25) — a concatenated source contributes several rows sharing a `name` — and an accepted row's `dex_id` is the REAL dex_id, so the accepted rows are exactly `0 … dex_count()-1` (dexllm#27: it used to be `out.size()`, the load-order IMAGE index, which drifted by the split count and made `sdk._dex_name` / `tools._dex_name_map` attribute a dex to another source). A rejected row is still `dex_id == -1`. |
| `set_decompiler_cache_capacity(capacity)` / `decompiler_cache_capacity()` | LRU cache cap (default 4096, 0 = unbounded). |
| `clear_decompiler_cache()` / `decompiler_cache_size()` | Cache lifecycle. |
| L1-L7 search family | Pre-existing find/match APIs (class/method/field by name/strings/annotation/etc). |

The class+method enumeration APIs let drivers (sweep, bench) drop the androguard dependency entirely. Last reference run: **full sweep 60s → 9.7s (6×)**, **DexKit vs androguard end-to-end 60× faster** (per-method decompile 6.3× faster, APK load 142× faster).

### `CapabilityReport.by_caller` maps a caller to the APIs it calls (dexllm#35, 2026-08-15)

`summarize_capabilities` ([capability.py](src/dexllm/capability.py)) built the caller index INSIDE the permission loop — `for perm in perms: … by_caller.setdefault(…).add(perm)` — so an API declaring no `permissions` registered no callers at all. **Every** `REFLECTION` / `PROCESS_EXEC` / `DYNAMIC_LOAD` / `NATIVE_CODE` / `CRYPTO` / `WEBVIEW` / `STORAGE` entry is permission-less (14 of the catalog's 42), and so are **6 domain entries** — `Settings$Secure.getString` (the ANDROID_ID read), `SmsManager.getDefault`, `BluetoothAdapter.getDefaultAdapter`, `LocationManager.getProviders`, `TelephonyManager.getNetworkOperator{,Name}`. So "who calls `Runtime.exec` / `DexClassLoader` / `Class.forName` in this app", the question those entries exist to answer, could not be asked of the index. **Measured: 317 DISTINCT callers corpus-wide, 17 covered — 5.4%.** Pre-existing, not a regression (identical in the pre-0.2-taxonomy tree).

**Option (b) of the issue — the value is now the API SIGNATURES, not the permissions.** The nesting was *consistent* with the declared `caller → {permissions}` type, so this is a deliberate re-definition of what the field is FOR, not a patch: it is the transpose of `ApiUsage.callers`. Rejected: (a) keep it a permission map and just document the exclusion — leaves the caller-indexed question unanswerable; (c) add a second `by_caller_apis` field — two overlapping caller indices, and the released one stays 95% blind.

**The first cut justified (b) as "lossless — the reverse could not be recovered", and a reviewer REFUTED that.** `api_hits` carries `callers` per API and always did, so `{h.api_descriptor for h in api_hits if c in h.callers}` reconstructs the new index from a **pre-fix** report — demonstrated by rebuilding the full 76-entry tvleanback index from a pre-fix run whose own `by_caller` had 4 entries. Both directions were always derivable; the bug lost the INDEX, never the data (the issue said as much and the first draft talked past it). The honest statement, now in all four doc sites: `by_caller` is a CONVENIENCE INDEX, and signatures make it the more primary view — the field-level asymmetry (APIs give back permissions and tags, a permission set cannot give back an API) is real but is a claim about the FIELD, not about the report.

**Measured (a/b, SAME script, the field changes by construction so the gate is "ONLY `by_caller` changes"):** over 31 sources × 4 `only_categories` filters, every other field — `permissions`, `categories`, `flags`, `total_call_sites`, `catalog_*`, `matched_apis`, and every `api_hits` entry INCLUDING its `callers` set — hashes **identical**; the MCP tool dict is **byte-identical** (it omits `by_caller` for context size, asserted rather than assumed). Per-source `by_caller` sizes sum **27 → 691** over those 31 sources (**26 → 634** over the 22 bundled `.apk` alone — the same quantity at two scopes, which the first draft quoted side by side as if they were one). Corpus invariant: `by_caller` equals the transpose of the hits' callers on **31/31 sources, 0 mismatch**. corpus-less 128 passed, lint trio clean, both new doc fences now EXECUTED by the runner (they were free-variable fences the collector silently skipped — 71 → 73 collected, floor ratcheted 67 → 69).

**Breaking**, deliberately: a released field's VALUE changes meaning on the raw `CapabilityReport` and the SDK model (`Mapping[str, tuple[str, ...]]` — the type is unchanged, so a consumer gets wrong data rather than an error, the one case in this series that fails quietly). No aliases (#24). The MCP surface never carried it. A reviewer proposed renaming to `apis_by_caller` so the break raises `AttributeError` instead, citing dexllm#38 (which renamed `dex_count` for exactly this shape) and #41 ("that loud failure IS the fix") — **declined**: `by_caller` names the KEY, which did not change, and the issue that specified option (b) scoped it to the value. Worth revisiting if a consumer appears.

**`content_uris.json` has no unclassified bucket (dexllm#31 Tier B, 2026-08-16).** `provider` was never a family — it meant "unclassified" — and it held **20 of 209 entries**, so a tenth of the dataset grouped under a label that tells a consumer nothing, while `{"uri": …, "family": "provider", …}` reads as though the classification succeeded. The 20 were seven coherent groups with no family assigned; each got a FLAT new family (`voicemail` 2, `blockednumber` 2, `simphonebook` 2, `timezone` 2, `userdictionary` 2, `bluetooth` 1) except HBPCD's 7 numbering tables, which are `telephony`. **The family follows the DATA, not the owning package** — a rule a review had to correct: the first cut classified all three `com.android.bluetooth.*` providers as `bluetooth`, which is a TRANSPORT and breaks the axis the other 13 families use, and it made discoverability WORSE than `provider` for the case that matters — AOSP's `MmsFileProvider` builds its Uri on `Mms.CONTENT_URI`, i.e. it re-exposes Telephony MMS parts over Bluetooth MAP, so an analyst filtering `family == "sms"` on an SMS-abuse sample would MISS it. It is `sms`; `AvrcpCoverArtProvider` (album art) is `media`; only `BluetoothShare` (the OPP transfer log) stays `bluetooth`. The same review found `content://icc/adn` — the legacy SIM phonebook URI — still sitting in `telephony`, missed because the first cut added `simphonebook` without sweeping the 189 rows it did not touch; **adding a family requires re-reading the whole dataset**, which is the lesson. **Measured (dataset a/b vs HEAD):** URI set and every `classes` list IDENTICAL, **21 families changed** (20 out of `provider`, plus `icc/adn`), `provider` now 0, families 9 → 14. The corpus-level a/b is near-vacuous by construction (the bundled APKs match exactly ONE provider URI, not in the moved set) — the change lives in the dataset, so that is where it is measured, and the guards are the only thing standing between a refresh and a silent regression. Guards ([tests/test_content_uris.py](tests/test_content_uris.py)): `provider` LEFT the pinned `FAMILY_VOCABULARY`; `test_no_entry_is_left_unclassified` bans it outright (INVERTED from the Tier A test, which only asked whether a leftover was MISfiled and goes vacuous once the bucket empties); `test_a_contract_is_owned_by_one_family_unless_declared` GENERALISES the ownership property from `provider` entries to all, so a contract cannot end up half-classified — which is how the bucket accumulated. Two review-driven repairs to that guard: (a) it forces siblings only when a root contract appears MORE THAN ONCE, and three entries name a SINGLETON root (`BluetoothShare`, `MmsFileProvider`, `AvrcpCoverArtProvider`) — a reviewer retagged two of them to any family at all with the suite still green — so those are pinned INDIVIDUALLY in `TIER_B_CORRECTIONS`; (b) the exception check was exact-set equality, which also rejected NARROWING a declared exception and reported it as "contracts split across families", i.e. blocked the removal of a split and blamed it for causing one — it is `fams - allowed` now, and a shrunk exception is caught by the staleness assertion with an actionable message instead. 9 mutants, each killed (one entry left `provider`; a half-classified sibling; a whole group reverted; a third family on `Telephony`; a stale exception entry; and the four the review constructed). Breaking: a consumer grouping on `family` sees 21 values move (no alias mechanism for a data value, #24). The "closed set of 14" is scoped to the BUNDLED dataset in all three doc sites — `_validate` deliberately accepts any `str`, because the override channel exists for a consumer's own vocabulary.

**The catalog expresses a FIELD read — and the field lookup can actually see one (dexllm#36, 2026-08-16).** `summarize_capabilities` resolved every key with `find_call_sites_to`, whose `ParseApiDescriptor` requires a `(` after `->`, so a FIELD descriptor matched nothing on every *possible* input and raised nothing; three `CONTENT_URI` entries shipped that way from 2026-05 until `7747246` deleted them as dead weight, taking `CONTACTS` / `CALL_LOG` / `CALENDAR` out of the vocabulary. Reading `ContactsContract…CONTENT_URI` is exactly how an app reaches contacts, and `detect_content_providers` does NOT cover it (it matches value STRINGS; an app reading the framework constant carries no `content://` literal — the two are complements). A key is now a method descriptor OR a field descriptor, **dispatched on SHAPE** (a type descriptor cannot contain `(`), so no schema key says which and a replacement catalog needs no migration.

**The first cut was still inert, and both reviewers proved it.** `find_methods_reading_field` → `LocateField` began with `LocateClassDex`, which resolves only a class DECLARED in a loaded dex — so a FRAMEWORK field returned `[]` on every input, and the change merely swapped one always-empty lookup for another: the same defect one layer down. The strongest evidence is a round-trip failure of the dexllm#19 kind: a2dp.Vol's `La2dp/Vol/service;` contains `sget-object … ContactsContract$PhoneLookup;->CONTENT_FILTER_URI`, that exact descriptor is what `list_fields()` returns, and `find_methods_reading_field` on it answered `[]`. **Fixed in `LocateField`** ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)), which now walks the reader's OWN `field_ids` table across ALL loaded dexes: `class_field_ids[type_idx]` is *emptied* for every type the dex does not declare (the core swaps it into `pending_cross_ref_field_ids`), so the grouped index is empty for exactly the classes that matter, while the raw table always has the entry and `field_get_method_ids` is sized to that same raw table. It also fixes a second, independent miss — the old lookup searched ONE dex, so in a multidex app a read from `classes2.dex` was invisible even for an app class. Measured after: `PhoneLookup;->CONTENT_FILTER_URI` → the exact method the smali shows; `Build$VERSION;->SDK_INT:I` → 272 reads / 187 methods (was 0). **a/b over the field xref itself (22 sources × the first 600 fields each, OFF = HEAD):** fields answering at all **4,011 → 5,073**, **0 sources lost an answer** (the change is monotone — it only adds), 16 of 22 sources moved; **1,011 of the 1,062 gains are fields whose owner is NOT declared in the app**, i.e. impossible for the old lookup by construction, and the remaining 51 are the multidex half. So `find_methods_reading_field` / `find_methods_writing_field` now answer where they used to be silent — a behaviour change for any consumer, in the direction of correctness.

**The counters stay SEPARATE, but not for the reason first written.** `call_site_count` = invoke instructions, new `field_access_count` = read instructions; `total_call_sites` / `total_field_accesses` mirror it. The first cut justified the split with "a call site is an instruction and a field access is a method" — FALSE, and a reviewer's mutant applying `dict.fromkeys` (i.e. making the code match that docstring) survived the entire suite. `find_methods_reading_field` is documented as NOT deduplicated, so both are instruction counts, their sum IS meaningful (the MCP ranking does exactly that), and `field_access_count != len(callers)`. The real and sufficient reason is compatibility: widening `call_site_count` needs no type or name change, so a consumer would read a different number with nothing to warn them — the quiet break dexllm#35 was. Corrected in 8 places. The tag Counters count both kinds, which flips the documented inequality to `sum(categories.values()) >= total_call_sites + total_field_accesses` — corrected in usage.md / api.md / sdk.md **and in capability.py's own module docstring**, which the first cut left asserting the old form 300 lines above a new test proving it false. `CapabilityReport.total_field_accesses` was missing from the SDK model while docs/sdk.md already documented it (`AttributeError`), so the inequality was unexpressible on that layer.

**Reads only, stated as a BOUND rather than a justification:** `resolver.insert(Events.CONTENT_URI, …)` and `.query(…)` emit the SAME `sget-object`, so a field entry cannot tell a provider reader from a writer and a pure writer is reported under `READ_CALENDAR`. The entry says "this app touches the calendar provider"; the permission is the read-side one because that is the common case, not because it was proven.

**8 field entries**, each verified against a local AOSP checkout by brace-matching the nesting — including the four a reviewer identified as the ones that make the feature demonstrable: `PhoneLookup;->CONTENT_FILTER_URI` (READ_CONTACTS), `RawContacts;->CONTENT_URI`, `CallLog$Calls;->CONTENT_URI_WITH_VOICEMAIL`, `Telephony$Sms;->CONTENT_URI` (READ_SMS — the catalog's SMS category had only a send-side entry). Catalog 0.2 → 0.3, 42 → 50 entries. **Measured:** the corpus now genuinely exercises the path — a2dp.Vol and partialsignature match `PhoneLookup;->CONTENT_FILTER_URI` as CONTACTS / READ_CONTACTS, a capability the catalog previously could not express at all. The earlier "byte-identical, the corpus references no CONTENT_URI" a/b was true but MIS-ATTRIBUTED: it would have been byte-identical on an APK that does read one, so it could not distinguish "corpus-silent" from "inert" — which is how the critical finding survived a green measurement. The MCP ranking is now a TOTAL order (touches, then signature): `sorted` is stable, so re-serialising the catalog silently reordered `top_apis` on 16 of 32 sources with no count changing. Guards: 10 mutants, each killed — field key routed to the method lookup; `call_site_count` filled for a field entry; the totals folded; the adapter dropping the counter; the MCP dropping the keys; a typo'd key (AOSP-gated); **the `LocateClassDex` gate restored**; `dict.fromkeys` deduping; the sort key reverted; a malformed key routed to the method lookup. The gap that let the critical finding through was that EVERY field test drove a stub: `test_a_field_entry_matches_on_a_REAL_dex` now asserts the primitive against the real binding.

**The SDK now SORTS both caller tuples** (`by_caller` values and `ApiUsage.callers`). They are built from `set`s, so `tuple(v)` follows per-process string hashing; multi-valued `by_caller` entries were rare when the values were permissions and are the norm now, so a pre-existing corner case became the routine one.

**Guards** (10, in [tests/test_capability_catalog.py](tests/test_capability_catalog.py), all corpus-less on the existing `_StubDk`). **7-mutant matrix, each built and run:** pre-fix module → 9 fail; out of the loop but re-gated on `if perms:` → 8; value kept as `.update(perms)` → 8; nested in the CATEGORY loop → 1; adapter conversion dropped → 2; adapter capping each entry to one API → 2; adapter not sorting → 1 (×2, one per axis). **Three of those mutants survived the first cut and a reviewer had to construct them:** the category-loop nesting (dexllm#35's shape one axis over — invisible because every BUNDLED entry has a category, while an override catalog need not, and `_validate_catalog` does not require one), the `[:1]` cap (natural, since the field just grew ~25× and `tools.py` already omits it for size), and the unsorted conversion. The ordering guards use 10 APIs × 8 callers rather than 2 — at two elements an unsorted `tuple(set)` is in sorted order half the time, so the first version of that guard passed the mutant on the seed it ran under, and with one caller per API the `callers` half was trivially sorted; both are now verified dead on five `PYTHONHASHSEED` values. Also fixed: the mutation-matrix prose claimed "the transpose test is what kills the `if perms:` variant, which the first three would not have" while the measured output in the same paragraph showed four failures including two of those three, and `test_the_permission_view_of_a_caller_is_still_recoverable` hard-coded a catalog VALUE (now derived from `_entries()`, so a catalog edit is not a red join test).

**A bundled library's call sites are not the app's — `app_only=True` is the DEFAULT (dexllm#49, 2026-08-17).** The counters are of CALL SITES in the dex, not executions, and nothing looked at WHO calls — so a class the APK merely bundles contributed exactly like one the app drives. Measured over the corpus that is not a corner case but most of the signal: **90% of the 515 distinct callers are library code**, and per category **REFLECTION 1206→27 (98% library), SCHEDULING 50→3 (94%), PACKAGE_INFO 34→6, STORAGE 55→15**, while **BIOMETRIC (30), SETTINGS (10), NATIVE_CODE, DYNAMIC_LOAD and CLIPBOARD are 100% library** — so `docs/usage.md` advertised, for a Google TV *sample app*, `120 × REFLECTION` (of which **2** are the app's), `3 × SCHEDULE_EXACT_ALARM` (100% `AlarmManagerCompat`) and `3 × USE_FINGERPRINT` (100% `FingerprintManagerCompat`). The values were correct; what they meant was "this APK bundles androidx". Pre-existing — the 0.3 catalog had it for REFLECTION alone — but dexllm#30 widened it to several categories and **documented** it rather than fixing it, because a filter is a behaviour change to a released API with its own a/b. Conversely BLUETOOTH (34), CONTACTS, PROCESS_EXEC and USAGE_STATS are 0% library, so the filter SEPARATES the signal rather than suppressing it.

**Option (a) of the issue — filter, with the sibling's verb and the sibling's default.** `summarize_capabilities` gains `app_only: bool = True` ([capability.py](src/dexllm/capability.py)) and filters per **TOUCH**, BEFORE the emptiness check: an API left with no kept touch drops out of `api_hits` entirely, and every number downstream — the three Counters, `by_caller`, the per-hit counts, `matched_apis`, both totals — derives from that one list, so they cannot disagree. Per touch, not per API, is the load-bearing part: the caller register MIXES both kinds (18 of tvleanback's 20 `Class.forName` sites are androidx), so a variant that keeps an API whole as soon as one app caller exists would still count the 18. Rejected: a second pair of counters (the dexllm#36 precedent) keeps both facts but leaves the DEFAULT read — `top_categories()`, the headline — still measuring the bundle, which is the one thing the issue is about; and `app_only=False` as the default is the shape dexllm#41 explicitly argued against ("the default read is the misleading one"). The library view is not lost: `app_only=False` is the escape hatch, and `by_caller` / `ApiUsage.callers` then name everyone.

**What the default DID need, and only an adversarial reviewer's measurement made visible: a dropped-count signal.** This module RAISES on an unknown `only_categories` tag with the reason that *"silently returning an empty report would be indistinguishable from 'the APK exercises none of this'"* — and the new default ships precisely that shape for **11 of the 17 corpus sources that report anything at all** (`multiple_locale_appname_test.apk` goes 301 touches / 30 APIs / 204 callers → **0 / 0 / 0**), while the MCP payload an LLM is told to *"start with … to orient"* omits the caller sets that would otherwise reveal it. So `CapabilityReport` gains **`dropped_touches` / `dropped_apis`** (appended after the dexllm#36 field, so no positional binding moves; 0 under `app_only=False`, hence invisible to the a/b of every other field), threaded to the SDK model and the MCP payload. `dropped_touches` is in the same unit as `total_call_sites + total_field_accesses`; `dropped_apis` counts entries that left `api_hits` entirely — and only entries that HAD a touch, a bug the new guard caught on its first run (the catalog is walked whole, so most entries arrive already empty and the naive counter reported 262 of 263).

**"A bundled library" is ONE definition, not two that agree today.** The prefix list moved to [_callers.py](src/dexllm/_callers.py) and both APIs import it, so `dangerous_permission_api_callers` and this one cannot drift; `dangerous_api` re-exports it because that is the module that has always spelled it (its test imports the private name). The **blind spots are stated there rather than discovered**, and only one direction is safe: a library the list does not name reads as app code and is KEPT (tvleanback's surviving hits are mostly `com.bumptech.glide`), while code that merely SITS under `com.google.android.*` — what a repackaged sample does — reads as a library and is DROPPED. So a filtered report is a triage aid, never proof of absence. Rejected: an `AndroidManifest` package basis (no manifest in a bare `.dex` or a packer dump, and a multi-module app's own code is not one prefix) and a caller-supplied `library_prefixes=` (a released surface and a dexllm#44 argument-axis entry for a case no consumer has asked for).

**Measured (a/b OFF vs ON, SAME script, HEAD swapped in and md5-verified both ways):** 32 loadable sources × {the full report — every counter, `by_caller`, every `api_hit` with its sorted caller set, both totals, `top_*` — plus the SDK model and the MCP tool dict}. **`app_only=False` is IDENTICAL to HEAD on the report and the SDK on all 32**, and the tool dict gains **exactly** one key (`app_only`) with no other value moving. `app_only=True` is sound on every axis: **0 APIs added, 0 counts grew, 0 dropped API had an app caller, 0 library caller survives in `by_caller`**, and every kept caller set is exactly the non-library subset — touches 1493 → 115, APIs 263 matched-slots → 50 kept / 213 dropped. A second corpus pass pins the new fields as an IDENTITY rather than a number: over all 32 sources `kept + dropped_touches == the unfiltered total` and `dropped_apis == matched_apis(False) - matched_apis(True)`, with `app_only=False` dropping nothing — 1378 touches / 213 APIs dropped corpus-wide, and **11 sources report 0 matched APIs with a nonzero `dropped_touches`**, which is exactly the silent-zero population the fields exist for. pytest 532, corpus-less 203 passed / 335 skipped, narrowed to `tests/data/multidex.apk` 456 passed, lint trio clean, doc fences 76 executed (floor ratcheted 71 → 75).

**Breaking**, deliberately, and QUIETLY — this is the one in the series that fails silently: a released field's VALUE changes with no type or name change to warn a consumer (the shape dexllm#35 was), because `report.categories` / `permissions` / `total_call_sites` / `matched_apis` / `by_caller` / `api_hits` all shrink. No aliases (#24). Release-notes material. The MCP tool ECHOES `app_only` in its output for exactly this reason: it omits the per-caller sets to bound context, so nothing else in that payload reveals which mode produced the counts.

**Guards** (11 functions / 21 cases, in [tests/test_capability_catalog.py](tests/test_capability_catalog.py), ALL corpus-less — `_StubDk` for ten, the committed `tests/data/multidex.apk` plus a recording double for the adapter — so they run in the CI leg with no APKs and under any `$DEXLLM_TEST_APK` narrowing, and 5 of the 11 prefixes have zero corpus weight so no a/b could reach them anyway). **19 mutants, each built and run, each killed** — 10 in the first cut: default flipped to False → 3; the filter deleted → 4; the filter moved AFTER the emptiness check → 1 (**the first cut's stated reason for this was WRONG** — a reviewer built the mutant and showed the leftover has BOTH counters 0, which is NOT the field-entry shape and is distinguishable from one; the real consequence is worse: `tools.py` ranks by `-(call_site_count + field_access_count)`, whose maximum is 0, so every phantom sorts to the TOP of `top_apis` ahead of the real hits); per-API instead of per-touch → 3; the adapter dropping the kwarg → 1 (it type-checks, satisfies the `Protocol` — which carries no runtime signature conformance — and passes the argument-name audits, so it is wrong only in the value it returns); the tool dropping it → 1; the echoed key removed → 1; a DUPLICATED prefix list in `capability.py` → 1 (object identity, not equal behaviour on a sample of descriptors, because a copy passes every other test in the file and drifts on the first edit); the schema property removed → the pre-existing `test_every_mcp_tool_argument_exists_on_another_layer`; the port losing the parameter → the pre-existing `test_raw_and_port_share_one_spelling_per_argument` — but only in that ONE-SIDED form: `summarize_capabilities` is a MODULE function, not a raw `DexKit` method, so that audit's rule 1 (raw ⊇ port) skips it entirely and only rule 2 (adapter == port) applies, and a COHERENT port+adapter rename is caught by nothing but the new adapter test's keyword call. The FIELD-key branch has its own guard: the two key forms take different lookups (dexllm#36) and the field one does not return `CallSite` objects, so it is the easy branch to leave unfiltered.

…and 9 more from the review round: the use-site drift → 9; a prefix DELETED from the tuple → 1 and one ADDED → 1 (**the first fix for that was itself self-referential** — a guard parametrised over `_FRAMEWORK_CALLER_PREFIXES` is blind to an EDIT of the tuple by construction, so the delete-mutant survived it and only a PINNED literal, the `CATEGORY_VOCABULARY` device this file already uses, closes it); the port default inverted → 1; the schema default inverted → 1; the echo un-coerced → 1; `dropped_touches` never counted → 2; the adapter dropping the new fields → 1; and the adapter forwarding correctly but rebuilding `by_caller` from a second UNFILTERED call → 1 (which is why the adapter double SYNTHESISES a mode-dependent report — watching only the forwarded argument would pass it, and `tests/data/multidex.apk` matches no catalog API, so a real report would make both modes identically empty and the value check vacuous).

**Two independent reviewers, and the findings were in the GUARDS and the PROSE, not the filter.** Neither could violate an invariant: 384 report computations (32 sources x 2 modes x 6 `only_categories`, incl. a flag-only filter) gave **0** violations of `sum(categories) >= total_call_sites + total_field_accesses`, `matched_apis == len(api_hits)`, per-hit sums == totals, `by_caller` == the exact transpose of `ApiHit.callers`, no zero-touch hit, no library caller surviving; and `app_only=False` was independently confirmed byte-equivalent to HEAD's module INCLUDING the `only_categories` path, structurally so (`if app_only:` guards the only new statement — disassembled). The `_callers` move is byte-identical to HEAD (extracted and diffed), no cycle, 7 microseconds. What they DID find:

- **HIGH — the "ONE definition" guard tested the SYMBOL, not the USE SITE.** A mutant keeping the shared import (so identity passes and ruff sees it used) and drifting only the METHOD branch to an inline 2-prefix tuple made the feature a **complete no-op** — tvleanback 8 touches → 156, i.e. exactly `app_only=False` — with **202 tests, black, ruff and mypy all green**. Sibling HIGH: the tuple's CONTENT is unpinned (deleting `"Lcom/google/android/"`, 69 corpus touches, passed 126 tests), because the only content assertions live in a corpus-gated test that SKIPS in the CI leg with no APKs and whose integration half computes its expectation with the predicate under test. Root cause of both: the hand-written fixtures exercised **2 of the 11 prefixes**, while `Landroid/support/` alone is **71% of what the corpus drops**, and 5 of the 11 have ZERO corpus weight so no a/b could ever see them move. Closed by PARAMETRISING over `_FRAMEWORK_CALLER_PREFIXES` itself, on BOTH key forms — a new prefix arrives with its own case.
- **MEDIUM — the silent zero** (the `dropped_touches` / `dropped_apis` fields above).
- **MEDIUM — the echo could affirm the wrong belief.** `app_only="false"` (a common JSON-boolean slip) is a truthy STRING: it filtered, and the payload echoed `'false'` beside app-only counts. `tools.execute` is also the in-process dispatcher for the HTTP / agent loop and validates nothing, so the schema does not save it. Now `bool()`-coerced, and it is the COERCED value that is echoed — the sibling `limit` was already `int()`-coerced two lines away.
- **LOW — no test in the repo asserted a parameter DEFAULT on any layer.** The Protocol declaring `app_only: bool = False` passed 111 tests (mypy does not check a Protocol's default VALUES), and an `input_schema` `"default": False` against a `True` impl passed 178 — and the schema default is what an LLM reads to decide whether to pass the argument. dexllm#44 locked the argument NAME axis on four layers; this locks the DEFAULT for this parameter across module / port / adapter / schema.
- **LOW, from the correctness side — the SDK model's own docstring example was left wrong on 5 of 6 values**, with a `by_caller` key (`Landroid/arch/lifecycle/…`) the default provably CANNOT report, since that prefix is in the tuple. The SAME example was updated one file over in `docs/api.md`: the drift was seen in one mirror and missed in the other. Also fixed: the "the join is defined WITHIN one report" caveat named only `only_categories` while the new prose actively suggests reading an `app_only=False` `by_caller` next to a default report (reviewer RAN it: `KeyError`); a fourth bullet on the `data_dir` override contract (a catalog of LIBRARY-facing APIs now reports zero by default); the `.pyi` for `is_framework_descriptor`, which called itself "the `app_only` rule" while being a THIRD, different prefix set for a different question (referenced TYPES, not callers — it has no `Landroidx/`); and the doc-fence ratchet, 71 → 75.

**Left open by the issue and NOT done here:** dexllm#30's ACCESSIBILITY finding — a category dropped because its corpus touches were 100% library. It could come back on its merits now, but its abuse surface is invoked on `this` inside the app's own subclass, so no MEMBER key can name it; the filter does not change that. **Resolved by dexllm#51 below** — the class itself is nameable through its CONSTRUCTOR, so `find_classes_by_super` was not needed after all, and `ACCESSIBILITY` is back.

**A subclassed framework service is reachable through its CONSTRUCTOR (dexllm#51, 2026-08-17).** The item dexllm#49 left open — and it needed neither `find_classes_by_super` nor a new key form. A dex `method_id` records the STATIC RECEIVER type, so a subclass's `this.m()` is spelled under the SUBCLASS and the interesting members are callbacks the SYSTEM invokes. Measured on the corpus's only real case, a2dp.Vol's `NotificationCatcher`: it calls **none** of the suggested members (`getActiveNotifications` has 0 `method_id`s in that APK) and realises the capability by overriding `onNotificationPosted`. **So a member-counting key returns 0 for the very case it exists to detect** — which refutes the issue's framing, where the worry was a 40x inflation from counting `this.m()` calls. A **constructor is never inherited**, so `super()` — emitted by the compiler whether or not the source writes it — IS spelled under the framework class: `NotificationCatcher;-><init>()V` opens with `invoke-direct {v1}, Landroid/service/notification/NotificationListenerService;-><init>()V`. Subclassing is therefore an ordinary call site, and **the issue's open decisions collapse**: the unit stays INSTRUCTIONS (so `sum(categories) >= total_call_sites + total_field_accesses` needs no restatement), `app_only` needs NO new meaning (the caller is the subclass's own `<init>`, so the existing prefix predicate separates an app service from a bundled one — corpus control `Service;-><init>()V`: 35 sites, 25 of them androidx / support plumbing), and no third key FORM is needed (the catalog already curates `<init>` keys — `AudioRecord`, `DexClassLoader`, `ProcessBuilder`, `Socket`). **NOTHING under `src/dexllm/*.py` changed** — the defect was in the curated SELECTION and the fix is there. **Four entries** (catalog 0.4 → 0.5, 263 → 267): `AccessibilityService` (`ACCESSIBILITY`, restored to the vocabulary — the `aa83f42` removal of its 10 MEMBER keys STANDS, those are dead in every possible APK), `InputMethodService` (new `INPUT_CAPTURE`, named on the `SCREEN_CAPTURE` precedent — the risk, not the subsystem), `NotificationListenerService` (`NOTIFICATIONS`, which already carried `isNotificationListenerAccessGranted` — a question that presupposes the subclass) and `DeviceAdminReceiver` (`DEVICE_ADMIN`, complementing the `DevicePolicyManager` calls that are what an admin app DOES). **`TileService` was deliberately EXCLUDED** — a quick-settings tile is a UI convenience every music player / VPN client / flashlight has, so it is oversight surface with near-zero signal (the `aa83f42` "the catalog's selection is curated" posture). Permissions stay EMPTY and that is correct: the real gate is a manifest `BIND_*` the service requires OF the system, not a permission the app holds. **Measured (a/b OFF 0.4 vs ON 0.5, SAME script, both halves in ONE process via the `data_dir` override so no build moves and the build-identity hazard does not arise):** 248 report pairs over 34 sources × {app_only True/False} × 4 `only_categories` filters — **0 reports differ outside the 4 new entries**, 0 invariant violations; the entries add exactly 2 touches (the one `NotificationCatcher`, in two APKs), and `only_categories={"NOTIFICATIONS"}` goes 0 → 1 matched on a2dp.Vol. No C++ moved, so parity is untouched; pytest 543, corpus-less 213 passed / 336 skipped, narrowed to `tests/data/multidex.apk` 466, the guard file green narrowed to **each of the 26 bundled samples one at a time**, lint trio clean, doc fences 76 executed (floor ratcheted 75 → 76). **KNOWN BLIND SPOT, stated rather than discovered:** a subclass declaring NO constructor emits no `super()` and is invisible to a ctor key — real, not hypothetical (17 of the corpus's 7,539 non-`Object` subclasses are in that shape, 12 of them CONCRETE, all R8-minified Play-services internals), so the set equality `find_classes_by_super(S)` ≡ "classes calling `S`'s ctor" holds for the 6 superclasses measured (221 classes / 0 disagreement / 227 sites), NOT universally. It is structurally out of reach of these four: the framework instantiates a service reflectively through its no-arg constructor, so one that lost it would not start — corroborated, of 178 corpus `Service` / `BroadcastReceiver` / `Activity` / `Application` / `ContentProvider` subclasses, **0** lack one. Two further limits are documented: a hit is a **dex fact only** (the manifest is unread, so it is triage signal, not runtime reachability) and the form does not extend to **interfaces** (no constructor) — which is not a gap but a different mechanism, closed by the paragraph below. Guards: 10 in [tests/test_capability_catalog.py](tests/test_capability_catalog.py) plus a new reverse-direction invariant `test_every_declared_tag_is_carried_by_at_least_one_entry` — a declared tag with NO entry makes `only_categories` return a SILENTLY EMPTY report, the exact outcome the module raises `ValueError` to prevent, reached by the other route; newly consequential because the two new tags are each carried by a SINGLE entry. **Three of the four entries have ZERO corpus matches**, so every guard for them is a PINNED literal or a stub — a corpus measurement is blind to them by construction — and the end-to-end guard rides the one real `NotificationCatcher` and SKIPS under a narrowing (issue #46). **6-mutant matrix, each built and run, each killed by its intended guard:** drop each of the four entries from `CURATED`, regenerate with `--allow-drop` AND update the pinned digest + count (the realistic regression, since that disarms the blanket digest guard — **the first harness pass MISSED the flag, so the generator refused to write and every "kill" was a false positive**), revert the two new tags in the pinned vocabulary, and route an `<init>` key to the FIELD lookup. **Two independent reviewers, and every finding was in the GUARDS or the PROSE, not in the selection — 2 MEDIUM+HIGH each, all fixed and each re-verified by reproducing it first:** (1) **the change WEAKENED an existing guard.** Before it, the barrier against re-adding the dead MEMBER keys `aa83f42` removed was that `ACCESSIBILITY` had left the closed vocabulary, so restoring them meant editing the pinned vocabulary too; declaring the tag again dropped that barrier, and a mutant re-adding `getRootInActiveWindow` / `performGlobalAction` / `dispatchGesture` / `getActiveNotifications` (**0 call sites corpus-wide**, dead by construction) passed the WHOLE suite on a regenerate-and-re-pin — reproduced independently, 68 passed. Fixed by asserting the `<init>` key is the class's ONLY key, which states the curation decision directly instead of letting a tag's absence imply it. (2) **the new doc fence verified NOTHING.** It was written as a list COMPREHENSION, and the runner's `_loop_body_lines` walks only `For`/`AsyncFor`/`While` — so it required no line, ran against the first APK (`Invalid.apk`, 0 `api_hits`), and never evaluated the body: **all four attribute names renamed to nonsense still passed**, and the fence floor had been ratcheted 75 → 76 for it. That is the exact vacuity `test_doc_examples.py` exists to prevent, reproduced through a comprehension. Rewritten as a real `for` whose body line touches all three attributes; each of the three now FAILS when mutated. (3) **"no member key can name them" was FALSE**, with the counterexample in the very APK the docs cite: an overridden callback that calls `super.onX()` emits `invoke-super` UNDER the framework class (`NotificationCatcher;->onCreate()V` carries `invoke-super {v3}, …NotificationListenerService;->onCreate()V`, so a curated `onCreate` WOULD match 1 site). The design is unaffected and the argument is strictly stronger — `super.onX()` is OPTIONAL, a `super()` in a constructor is UNCONDITIONAL — but the absolute phrasing was in three mirrors plus the new guard's failure message, all narrowed. (4) **"a hit means the APK declares such a service, not that it constructs one" over-generalised from 2 of the 4**: `AccessibilityService` / `NotificationListenerService` are `abstract` in AOSP so naming their ctor is PROVABLY a subclass, but `InputMethodService` / `DeviceAdminReceiver` are CONCRETE and `new X()` emits the identical descriptor — demonstrated on the corpus, where 49 non-subclass constructor callers exist. The split is now pinned as data and the docs read "declares OR constructs" for the concrete two. (5) **a fourth non-universality cause was missing** — a class with SEVERAL constructors needs each overload curated (`Thread` has 4; of 30 corpus subclasses only 27 chain `()V`), and the fact that makes ONE key complete here (each of the four declares exactly one, no-arg) was nowhere stated. (6) two stale mirrors: `docs/api.md` still said "the two limits" after the third was added elsewhere, and `sdk/model.py`'s `CapabilityReport` example still read `catalog_version='0.4', catalog_size=263` — the "one mirror updated, the other missed" pattern this file already records. **The first mutation harness was itself wrong** and would have reported false kills: it omitted `--allow-drop`, so the generator REFUSED to write and the catalog never changed.

**An INTERFACE needs no key form — its REGISTRATION call is one (dexllm#51 interface half, 2026-08-17).** The half the constructor work left open. **An EMPIRICAL finding about the capability surface, not the structural universal the first cut claimed** — that cut argued the handover is ALWAYS an ordinary call on a framework receiver (an implementation is inert until the app hands it over; only classes are declarable manifest components), and an adversarial review REFUTED it from the corpus with three handovers that are not calls: an AIDL `Stub` returns its binder as the RETURN VALUE of the system-invoked `onBind`; `Parcelable$Creator` is a static FIELD the framework reads reflectively; `ServiceLoader` registers through a `META-INF/services` RESOURCE (`multiple_locale_appname_test.apk` ships two, for kotlinx.coroutines). **What survives is narrower and is what the decision rests on: for the interfaces that are CAPABILITIES the handover IS a call, and where it is not, the class is reachable another way or is not a capability** — an AIDL `Stub` is an abstract CLASS so the ctor form above covers it, `Creator` is serialization boilerplate, the corpus's `ServiceLoader` entries are coroutine internals. Residual risk stated rather than denied: a capability-shaped interface whose handover is NOT a call would be invisible, and none is known. The subclass case needed a new key for the OPPOSITE reason — the system instantiates a manifest-declared service ITSELF, so no app-side call exists at all. **Measured over the same 32 loadable sources as the a/b:** of the framework interfaces app (non-library) classes implement, exactly TWO are capability-shaped rather than UI / lifecycle / serialization boilerplate — **`android.location.LocationListener`, implemented by an app class in TWO REAL APKs** (a2dp.Vol, partialsignature; `StoreLoc$2`), whose registration `requestLocationUpdates` is already curated and FIRES (3 sites, `LOCATION` 5) = the decision working end-to-end on real input, and `javax.net.ssl.X509TrustManager`, only in a bare test dex. **Raw per-interface counts are deliberately NOT quoted:** the first cut published 2,565 app classes / 79 interfaces / 620 edges / `Runnable` 66 from a hand-rolled prefix list without de-duplicating `list_classes()` (which repeats a descriptor per dex, dexllm#45), and BOTH reviewers independently failed to re-derive them under any definition — they move with how app-vs-library and "framework interface" are defined, and they were corroboration, not evidence [[ab-harness-must-itself-be-deterministic]]. Near-miss: a2dp.Vol's `IBluetooth` / `IBluetoothA2dp` AIDL copies (two classes each, `$Stub` and `$Stub$Proxy`) are not evidence themselves — the hidden service is reached REFLECTIVELY (7 `Class#forName` + 24 `Method#invoke` there), which `REFLECTION` already reports. **The answer carries a PROOF OBLIGATION — "the registration call is already curated" has to be TRUE — and that is where the work was.** Audited: present for `requestLocationUpdates` and `addPrimaryClipChangedListener`, ABSENT for one family, TLS trust. **Three entries** (catalog 0.5 → 0.6, 267 → 270, `NETWORK_IO` at the time and `CUSTOM_TLS_TRUST` since dexllm#52; **NOTHING under `src/dexllm/*.py` changed**, the dexllm#51 shape): the per-connection `HttpsURLConnection#setHostnameVerifier` — the ASYMMETRIC sibling of an already-curated pair, since the instance `setSSLSocketFactory` WAS curated and its verifier twin was not; `SSLContext#init`, which an OkHttp client consumes indirectly (its builder is not a framework class, so this is the only framework spelling left in the dex); and `SSLCertificateSocketFactory#setTrustManagers`, **added because an adversarial reviewer CONSTRUCTED a fully undetected path** (`new SSLCertificateSocketFactory(0)` + `setTrustManagers` + `createSocket`, all public API, none spelled under a curated class) — i.e. the proof obligation was still unpaid after the first cut, which had called `SSLContext#init` "the single choke point". `SSLContext#setDefault` is deliberately NOT curated (redundant — a context carrying app trust went through `init` first). **Two TLS surfaces stay uncurated because they register no interface**, so they belong to a separate curation task rather than to this decision: `SSLCertificateSocketFactory#getInsecure` (AOSP's own doc says all checks are disabled) and `SslErrorHandler#proceed` (the `onReceivedSslError` WebView bypass, an overridden callback). A third gap has no framework spelling at all — an OkHttp `HostnameVerifier` goes through `OkHttpClient$Builder#hostnameVerifier` with no `SSLContext`-shaped choke point behind it. **Measured (a/b OFF 0.5 vs ON, SAME script, both halves in ONE process via the `data_dir` override so no build moves):** 320 report pairs over 32 sources × {app_only True/False} × 5 `only_categories` filters — **4 pairs differ, ALL on `app-prod-debug.apk`, and the ONLY key that moves is `setHostnameVerifier`** (matched 9→10 / 31→32; `NETWORK_IO`-filtered 3→4 / 4→5); every other source identical on every counter, `by_caller`, per-hit caller set and both totals, vocabularies unchanged. `SSLContext#init` and `setTrustManagers` fire **0** times corpus-wide, which is why their guards are stubs and pinned literals rather than measurements [[ab-must-prove-the-mechanism-fires]]. No C++ moved, so parity is untouched. pytest 563, corpus-less 229 passed / 340 skipped / 0 failed, narrowed to `tests/data/multidex.apk` 483, the guard file green narrowed to **each of the 34 bundled samples one at a time** (25 APK + 9 bare dex) plus the committed one, determinism 3 processes under 3 `PYTHONHASHSEED`s identical, lint trio clean, doc fences 76 executed (floor unchanged — this change adds prose, not fences). **Guards** (6 new functions / 17 collected cases, 70 → 87, in [tests/test_capability_catalog.py](tests/test_capability_catalog.py)): the six TLS registration keys as PINNED literals with their tag; the instance/`setDefault*` PAIR property; a `_StubDk` end-to-end for `SSLContext#init`; the real-APK `setHostnameVerifier` hit; the real-APK **`LocationListener`** hit, which is the strongest evidence and had NO guard until a reviewer pointed out the change was asserting it did not exist; and the proof obligation AS DATA — a pinned interface → registration-call map whose value is EVERY door, not one (the first cut mapped `X509TrustManager` to `SSLContext#init` alone, which is exactly how the `setTrustManagers` path stayed unreported), so a dropped registration fails as "nothing registers `LocationListener`" rather than as an anonymous digest mismatch. **10 mutants, each built and run, each killed:** drop `setHostnameVerifier` (4 fail), `SSLContext#init` (3), `setTrustManagers` (2), retag `init` as `CRYPTO` (2), drop `requestLocationUpdates` (2), `addPrimaryClipChangedListener` (1), `setDefaultHostnameVerifier` (3), and — the reviewer's shape, which is the realistic one — the same three TLS entries deleted TOGETHER WITH their pinned literals (3 / 2 / 1, caught by the pair property and the interface map, the layers that survive a re-pin). Every drop mutant regenerates with `--allow-drop` AND re-pins count + digest, which disarms the blanket digest guard and is the trap the dexllm#51 harness fell into. **Two independent reviewers, and every finding was in the ARGUMENT or the PROSE, not in the curation** — the guards survived 10 mutants, the descriptors and tag are right, the a/b reproduced exactly, and `require_corpus_shape` behaved on all 34 narrowings. What they found: the refuted universal above, the unpaid TLS obligation (both fixed here), the un-re-derivable census, the `LocationListener` self-contradiction (the change's own `_INTERFACE_REGISTRATION` classified it capability-shaped while three mirrors said no such APK existed), `TelephonyManager#listen` cited as an INTERFACE registration when `PhoneStateListener` is a CLASS — inside an argument whose whole subject is that distinction — a miscounted guard total, and a stale CLAUDE.md mirror still calling the interface decision open two lines above the paragraph closing it. **The issue's MANIFEST half stays OPEN and is deliberately not attempted:** it needs a binary-AXML parser, a subsystem of its own, and it would change every a/b axis rather than adding to this one.

**The app's own TLS trust decision is its own tag — `CUSTOM_TLS_TRUST` (dexllm#52, 2026-08-17).** The follow-up dexllm#51's interface half named and deferred: two framework APIs disable TLS validation while registering NO interface, so they fell outside that decision. `SSLCertificateSocketFactory#getInsecure` implements nothing at all — AOSP's javadoc, verified verbatim against the local checkout, reads *"a socket factory with all SSL security checks disabled … **Warning:** … vulnerable to person-in-the-middle attacks!"* — and `SslErrorHandler#proceed` is the `onReceivedSslError` bypass. **The CALLBACK cannot be curated and `proceed` can**, the dexllm#51 static-receiver lesson a third time: the system invokes `onReceivedSslError` on the app's own `WebViewClient` subclass so it is spelled THERE, while `proceed()` is called BY the app ON a framework object. `cancel()` is the CORRECT behaviour and is deliberately NOT curated — curating both detects that a WebView exists, the `AccessibilityNodeInfo` mistake `aa83f42` removed. **The category was the real decision and it is BREAKING** (user's call): 6 trust-weakening entries were `NETWORK_IO`, where "the app supplies its own trust decision" was counted exactly like "the app uses the network", which every app does. **`javax.net.ssl.SSLSocketFactory#createSocket` deliberately STAYS `NETWORK_IO`** — but NOT for the first cut's reason ("creating a socket decides no certificate"), which a reviewer refuted from AOSP by pointing at its `android.net` namesake, whose hostname-less overloads skip verification and which IS curated now; the real reason is that a `javax` factory's trust comes from the `SSLContext` that built it, and every way of customising that context is a key. Catalog 0.6 → 0.8, 270 → 281 entries, 32 → 33 categories; **NOTHING under `src/dexllm/*.py` changed** (the dexllm#51 shape). **THREE things the review changed, none of them in the curation itself.** **(1) The name.** `TLS_VALIDATION` (the first cut) was REPLACED: *every* app validates TLS, so it did not discriminate — an MCP payload `('TLS_VALIDATION', 2)` reads to an LLM as "validated TLS twice" — the docs had to spend a paragraph saying the tag is not what it sounds like, and the `INPUT_CAPTURE` comment 20 lines up in the SAME list says "name the RISK, not the subsystem", so two contradictory naming rules sat adjacent. `CUSTOM_TLS_TRUST` states the definition; `TLS_BYPASS` stays rejected for the reason that survived review (the same APIs implement PINNING, and what a `TrustManager` decides is in its BODY, not at the registration). **(2) The EXCLUSIVITY premise was FALSE** — three prose sites and a guard's failure message said "`categories` is a single EXCLUSIVE axis so an entry cannot carry both", which the catalog refutes with **6 dual-tagged entries** (`WebView#loadUrl` = `[WEBVIEW, NETWORK_IO]`, `WifiManager#getScanResults` = `[WIFI, LOCATION]`, …) and which **`docs/usage.md` contradicts 120 lines above the new section** ("A second tag is only correct when the API genuinely spans two domains … does count once in each"). The real rule is *no tag IMPLIED by another*, which justifies the split just as well. The false premise had a cost: `SslErrorHandler#proceed` was the ONLY one of the ten `android/webkit` keys without `WEBVIEW`, so a consumer sweeping `only_categories={"WEBVIEW"}` MISSED the bypass — it is `[WEBVIEW, CUSTOM_TLS_TRUST]` now. **(3) Three fully UNDETECTED paths, each CONSTRUCTED by the reviewer, each resolvable by the generator** — so the completeness claim was unpaid again, exactly as in dexllm#51: `org.apache.http.conn.ssl.SSLSocketFactory#setHostnameVerifier` + the `ALLOW_ALL_HOSTNAME_VERIFIER` FIELD (the legacy Apache stack shipped through API 28 — the exact twin of the curated `HttpsURLConnection` setter, the most-cited Android bypass, and it never touches `SSLContext` so no choke point catches it); `SSLCertificateSocketFactory#createSocket` (AOSP: *"Hostname verification is not performed with this method"* — the SAME evidence standard as `getInsecure`, on a class this change had already touched); and `SSLContext#setDefault`, whose "redundant, it must have gone through `init`" justification is refuted by AOSP's own *"The default context must be immediately usable and NOT require initialization"*. All curated. `createSocket` is curated by member NAME so all 6 overloads are emitted, and they split **3/3** — the three taking a hostname DO verify, the three that do not carry the warning — so the curation is deliberately over-inclusive; reaching for that deprecated raw-TLS factory is itself the signal, and AOSP says the verifying three stop verifying on a `getInsecure` instance anyway. (The first cut said "the 2 that DO verify", a number nobody had re-derived — [[published-counts-need-the-repos-own-predicate]] in its smallest form.) **Measured (a/b OFF 0.6 vs ON, SAME script, both halves in ONE process via the `data_dir` override):** 320 report pairs over 32 sources × {app_only True/False} × 5 `only_categories` filters, **0 violations** of a FILTER-AWARE gate — `NETWORK_IO` loses exactly the retagged touches, the new tag gains exactly those plus new-key touches, everything else identical. Only `app-prod-debug.apk` moves (`NETWORK_IO` 4→2 at `app_only=True`, 5→3 at `app_only=False`; `CUSTOM_TLS_TRUST` 2). **The first gate was WRONG and the measurement was right:** it flagged `only_categories={"NETWORK_IO"}` as a violation, where a retagged entry now drops out ENTIRELY — the point of the split and the breaking half, not a defect. **15 of the 17 emitted keys fire 0 times corpus-wide** (only `setHostnameVerifier` and `setSSLSocketFactory` fire, 1 site each, same caller, same APK — the first cut's comment said only the former, contradicting its own a/b), so guards are pinned members and `_StubDk` e2e rather than measurements [[ab-must-prove-the-mechanism-fires]]. pytest 582, corpus-less 248 passed / 340 skipped / 0 failed, narrowed to `tests/data/multidex.apk` 502, the guard file green narrowed to each of the 34 bundled samples one at a time, determinism 3 `PYTHONHASHSEED`s identical, lint trio clean (CI scope; two PRE-EXISTING unformatted files under `scripts/` untouched), doc fences 76, generator reproduces the committed JSON byte-identical. No C++ moved, so parity is untouched. **Guards** (8 new functions / 19 collected cases, 87 → 106, in [tests/test_capability_catalog.py](tests/test_capability_catalog.py)): the 12 curated MEMBERS pinned (by `Lclass;->member`, not descriptor — the generator emits every overload, so pinning descriptors would list six mechanical `createSocket` rows and re-fail on an AOSP refresh); **COMPLETENESS in the other direction** — the tagged set must equal the pinned set, the hole a reviewer had to CONSTRUCT (retagging ten unrelated `java.net.Socket;-><init>` overloads INTO the tag, with count and digest re-pinned, passed the whole file); the implication rule (no member also `NETWORK_IO`) plus an anti-vacuity assertion that dual-tagged entries still EXIST, so the refuted exclusivity cannot creep back as an accident; every `android/webkit` key reachable from a `WEBVIEW` sweep; `javax` `createSocket` still `NETWORK_IO`; `_StubDk` e2e for the no-interface pair and for the Apache field (which exercises the dexllm#36 FIELD key form); and `cancel` asserted NOT curated. dexllm#51's own TLS test dropped its tag assertion — the dexllm#52 block asserts it over a superset, so it was 6 duplicate cases. **11 mutants, each built and run, each killed by its intended guard:** drop `getInsecure` (2 fail), `proceed` (2), the Apache field (2), `createSocket` (1), `SSLContext#setDefault` (1); strip `WEBVIEW` off `proceed` (2, the C5 regression); **retag ten unrelated `java.net.Socket;-><init>` overloads INTO the tag (1 — the constructed hole, which SURVIVED the first cut)**; swallow the `javax` `createSocket` (2); curate `cancel` (2); re-add `NETWORK_IO` to `SSLContext#init` (1); and drop `getInsecure` TOGETHER WITH its pinned member (1). Every drop mutant regenerates with `--allow-drop` AND re-pins count + digest, which disarms the blanket digest guard. **Mutant counts are measured WITHOUT the AOSP dataset** (the CI shape) — with it present `test_the_committed_catalog_is_what_the_generator_produces` adds one failure to most of them, and it is the ONLY killer of a whole-taxonomy revert, which CI SKIPS. **BREAKING, in the quiet way dexllm#35 and dexllm#49 were:** `report.categories['NETWORK_IO']` shrinks and `only_categories={'NETWORK_IO'}` stops returning the family, with no type or name change to warn a consumer — [docs/usage.md](docs/usage.md) now says so in a callout, since dexllm#49 added `dropped_touches` precisely because a silent zero is indistinguishable from a real one. No aliases (#24). Release-notes material. **Still uncurated, deliberately:** an OkHttp `HostnameVerifier` goes through `OkHttpClient$Builder#hostnameVerifier` with NO `SSLContext`-shaped choke point behind it, so that path has no framework spelling in the dex at all — recorded so it is not rediscovered as a bug.

### Typed API — `dexllm.sdk` (ports & adapters over the raw binding)

For embedding, `dexllm.sdk` wraps this whole raw surface in a typed ports-and-adapters layer ([src/dexllm/sdk/](src/dexllm/sdk/) — `model.py` frozen dataclasses / `ports.py` `@runtime_checkable` Protocols / `adapter.py` `DexKitAdapter`; component reference in [docs/sdk.md](docs/sdk.md)). `open_apk(sources) → DexKitAdapter` satisfies the composite `DexAnalysisUseCase`, which composes **eleven session-bound ports** — `Decompilation` (incl. `render_*_smali`), `Enumeration` (classes/methods/fields/value-strings/external-{method,field,type}-refs, per-dex + all-dex), `DexExtraction` (`extract_dex` → `ExtractedDex`), `ClassInspection` (`class_info`/`class_fields`/`class_methods`/`locate_class_dex` — the god-object `get_class_summary` decomposed by ISP), `CrossReference` (call-sites/args/field-read-write/type-refs), `Search` (the L1–L7 family, `match_type: Literal`), `PermissionAnalysis`, `IndicatorExtraction`, `Capability`, `ContentProvider`, and `CacheControl` (the operational cache/lifecycle knobs) — plus the load-free `ContainerProbePort` (`identify`). `.raw` is the escape hatch to the underlying `DexKit`. This is the boundary a consumer programs against instead of the dict/struct raw returns; the audit invariant is **every session-bound port fully implemented, isinstance-conformant, and 0 adapter-method-without-a-port drift apart from an explicit allow-list** — the documented `.raw` escape hatch plus the enumerated dexllm#21 back-compat aliases (now none — stage 4 removed them, and the allow-list is an empty declaration) (locked by `tests/test_sdk.py::test_adapter_public_surface_has_no_undeclared_drift`, which asserts the set equality; before 2026-08-05 the "locked by tests" half was overstated — the isinstance test only checked ports ⊆ adapter, never the reverse). **The raw ↔ port axis is locked too** (`test_raw_and_port_share_one_spelling_per_operation`): a raw `DexKit` method and its port method must share a NAME — the dexllm#21 series existed because `find_call_sites_to_api` (raw) and `find_call_sites` (port) were one operation under two names for three releases and nothing noticed. Set EQUALITY both ways against three declared exception kinds: `_RAW_DEPRECATED_ALIASES` (alias→canonical, and the canonical must itself be unified, so a new raw method cannot be hidden by listing it), `_RAW_DECOMPOSED` (`get_class_summary` → `class_info` + `class_fields` + `class_methods`, an ISP split = a genuinely different operation), and `_PORT_FROM_MODULE_FUNCTION` (`identify`/`verify`/`extract_iocs`/… are module-level `dexllm` functions, a location difference not a naming drift). Verified to catch a port-side rename, a stale exception entry, an alias claiming a non-unified canonical, and a bogus module-function claim. **Adding a raw binding now requires either the matching port name or a conscious edit to one of those three lists.** **The TYPE axis is locked too since dexllm#37** (`test_raw_and_sdk_share_one_spelling_per_record_type`): a record type present on both layers uses ONE name — `ClassMemberField` (raw) and `FieldInfo` (SDK) were one field-for-field identical record under two names, the exact defect #21 removed, on an axis nothing checked (reverting a type rename in `model.py` passed every existing assertion). Set equality both ways against `_SDK_ONLY_MODELS` (a composite, or a raw dict/tuple return given a type) and `_RAW_ONLY_MODELS` (`ClassSummary`, the god object the SDK decomposes). An exception must be JUSTIFIED, not merely listed: a raw-only type field-identical to an SDK-only model is rejected, because otherwise the cheapest way past a failure is to add BOTH names to the two lists — which absorbs the very defect (constructed: renaming SDK `MethodRef` to `MethodHit` goes green that way). **The MCP tool-NAME axis is locked too** (`test_every_mcp_tool_name_exists_on_another_layer`): every advertised tool must carry the name THAT operation already has on the raw `DexKit`, on a port, or as a module-level `dexllm` function. Two assertions, because name-existence alone is the weaker claim "the name SOME operation has" — under which renaming the `get_class_summary` tool to `class_info` passes silently, the mirror defect (one name, two operations); the second ties each tool to `_t_<name>` and requires that impl to CALL an identically-named operation (`safe_`-wrapped counts, for the two decompile tools). **The ARGUMENT axis is locked too since dexllm#44** (its own paragraph below). It was the last unlocked NAME axis and it had drifted — `capability_report` was `summarize_capabilities` under a second name; renamed outright (the MCP surface has no consumers yet, so it takes no alias), and the exception list is an empty declaration. **A shared NAME can still carry a shared KEY with two meanings**, which assertion (2) cannot see (the impl does call the same-named operation). The one such case — MCP `identify` overwriting `dex_count` with the count of all LOADED dexes while `dexllm.identify(path)` reports one container's own — was fixed in dexllm#38 by making every shared key mean the same thing, moving that total to `loaded_dex_count` and adding `source` (WHICH source the shared keys describe: `add_dumped_dexes` puts the dump first, so a packer session probes a bare dex — dexllm#26's lesson for `extract_dex`). Rename to `session_info` was the alternative and was REJECTED for a stated reason: no such name exists on raw/port/module, so it would have taken the first entry in `_MCP_ONLY_TOOLS` and weakened the audit being locked in the same change. Guard `test_identify_means_the_same_thing_on_every_layer` is driven by a CRAFTED concatenated dex — a packer dump is ONE source that splits, so the earlier belief that only a multi-source session diverges was false, and the crafted fixture also removes the skip and the second-source-fails-to-load hazard. Two legs, because on a single source `identify(apk_path())` and `identify(sources()[-1])` are the same call: 5 of 6 mutants die (the survivor swaps `dex_count()` for `len(verify_report())`, which coincide unless a dex is rejected). Distinct from the *internal* `IDexCodeSource` hexagonal boundary above (that isolates `dad_cpp` from DexKit; this one is the outward Python API).

**Call-site xref naming — one spelling in all four layers (dexllm#21, 2026-08-05).** The reverse/forward call-site pair is `find_call_sites_to(api)` / `find_call_sites_from(method)` on the raw `DexKit`, the `CrossReferencePort`/adapter, AND the MCP tool catalog. Previously the SDK said `find_call_sites` while raw + MCP said `find_call_sites_to_api` / `find_call_sites_from_method`, so a name learned in one layer raised `AttributeError` in another. `_to`/`_from` was chosen over `find_callers`/`find_callees` because the return is one entry per invoke INSTRUCTION (a caller invoking twice yields two entries) — "call sites" is the accurate noun, "callers" reads as a deduped set. Every pre-rename name still worked as a **deprecated alias** (all REMOVED in stage 4 below): extra `.def`s in [module.cpp](native/binding/module.cpp) (pybind registers the same C++ member twice — verified to produce two independent methods, not an overload chain), **delegating** methods on `DexKitAdapter` (deliberately NOT on the Protocol — a port-annotated call to an alias is a mypy error (which names the replacement when the spelling is close enough for its did-you-mean)), and — at the time — a `TOOL_ALIASES` map resolved in `tools.execute` (**since REMOVED in stage 3, see below**: the MCP catalog now carries no aliases at all). **The adapter aliases MUST delegate, not rebind** (`find_call_sites = find_call_sites_to` binds the base function object, so a subclass overriding the canonical name is silently bypassed when a caller uses the old spelling — `DexKitAdapter` is the documented embedding surface, so subclassing is supported; guarded, until the aliases were removed in stage 4, by `test_deprecated_adapter_aliases_delegate_not_rebind`). **Accepted MCP caveat:** an alias is not advertised in the catalog, and mcp validates arguments only for advertised names, so an alias call skips JSON-Schema validation — a malformed argument becomes an in-band `{"error": …}` instead of a protocol-level error (error SHAPE only; no crash, no OOB — probed with non-string / list / dict descriptors, negative offset, `limit=10**12`). The same change documents what the issue's second half asked for — which half of a `CallSite` is FIXED depends on the producing direction, `bytecode_offset` is always inside the CALLER, and `caller_method_idx` is a **dex-local** `method_ids` index (not a stable global id) — in `sdk/model.py`, `_dexkit_core.pyi`, docs/api.md §13 and docs/sdk.md. Guards: `test_call_site_names_are_unified_across_layers` (tests/test_sdk.py) + `test_no_adapter_alias_survives` (tests/test_sdk.py).

**Decompile naming — the `_java` suffix dropped (dexllm#21 stage 2, 2026-08-05).** raw was the only layer spelling it `decompile_method_java` / `decompile_class_java` / `decompile_method_java_with_pc`; the SDK already said `decompile_method` / `decompile_class` / `decompile_method_with_pc_map` and the MCP catalog said `decompile_method` / `decompile_class` (it exposes no pc-map tool), so **raw moved to them and the SDK/MCP did not change** (the SDK has consumers — align the cheap layer, not the expensive one). The suffix was not merely redundant, it was **misleading**: it advertised a parallelism with `decompile_method_ast` that does not exist — the AST call returns the SAME Java text in its `source` (verified byte-identical, at the default `include_source=True`; the documented opt-out returns an empty `source`), so the family is base-vs-**enriched** (`_with_pc_map` adds an offset map, `_ast` adds the structured tree), not two output formats. A genuinely different output form already uses a different VERB (`render_*_smali`), so a format suffix inside `decompile_*` is redundant by construction. The module-level hang-safe wrappers moved with them (`dexllm.safe_decompile_method` / `safe_decompile_class`) — leaving those as `*_java` would have re-created the very mismatch this removes. Every pre-rename name still worked as a **deprecated alias** (all REMOVED in stage 4 below): extra `.def`s in [module.cpp](native/binding/module.cpp), and plain module-level assignments in [safe.py](src/dexllm/safe.py) (safe there, unlike the adapter's method case — these are functions, so there is no subclass-override dispatch to bypass); both old and new wrapper names stayed in `__all__` + `__init__.pyi` (the old ones REMOVED in stage 4 below). Guard: `test_deprecated_aliases_are_removed` (tests/test_dexkit.py), which also pins the `_ast`-carries-the-same-`source` claim the rename rests on.

**Field-xref + cache naming, and NO MCP aliases (dexllm#21 stage 3, 2026-08-05).** Two last groups, decided by the SDK's OWN house style rather than by majority. (1) **Field xref** — in 17 of the 19 `find_*` methods on the adapter surface the noun right after `find_` is what the call RETURNS (the ratio holds on every layer — ports 14/16, raw 14/16 excluding aliases) (`find_classes_by_name`, `find_methods_using_strings`, `find_call_sites_to`, `find_type_references`); `find_field_readers` / `find_field_writers` (SDK) and `find_field_read_methods` / `find_field_write_methods` (raw + MCP) BOTH inverted that — they return METHOD descriptors while naming the queried FIELD. All three layers moved to **`find_methods_reading_field` / `find_methods_writing_field`**, which follows the family rule; the two old spellings stayed as deprecated aliases on raw (`.def`) and on the adapter (delegating) — REMOVED in stage 4 below. (2) **Cache control** — the SDK's scheme is coherent (**action = verb-first, read-only accessor = noun**: `clear_decompiler_cache` / `set_decompiler_cache_capacity` / `warm_analysis_caches` vs `decompiler_cache_capacity` / `decompiler_cache_size`), while raw was internally inconsistent — it already had verb-first `warm_analysis_caches` next to `decompiler_clear_cache`. **raw moved to the SDK spelling; the SDK did not change**, old raw names kept as aliases — REMOVED in stage 4 below. (3) **`TOOL_ALIASES` was REMOVED** (with it the stage-1 `find_call_sites_to_api` / `find_call_sites_from_method` MCP entries — those spellings now return `unknown tool` from `tools.execute`, while remaining valid on raw + adapter) — the MCP catalog now carries no deprecated names at all. An MCP alias is not a transparent one: mcp validates arguments against the inputSchema of the tool it ADVERTISES, so a call under an unadvertised spelling skips schema validation entirely and a malformed argument degrades from a protocol-level error to an in-band `{"error": …}`. Renaming a tool outright keeps `TOOL_DEFINITIONS` ≡ `TOOL_IMPLS` an exact set equality and every advertised name validated; deprecated spellings live on the Python API, which is where released names actually need protecting. Guards: `test_canonical_field_xref_and_cache_actions_work` (tests/test_dexkit.py) + `test_tool_catalog_carries_no_aliases` (tests/test_tools.py); the stage-1 drift audit caught the two new adapter aliases automatically and its allow-list was extended.

**Stage 4 — the aliases are GONE, and the ARGUMENT names are unified too (2026-08-06).** Stages 1-3 unified the METHOD names and kept every pre-rename spelling as a back-compat alias; issue #24 tracked the unresolved question of what to do with 16 aliases that shipped SILENT (no `DeprecationWarning`). **Resolved by deletion** (user decision): all 16 removed — 9 raw `.def`s (`decompile_method_java` / `decompile_class_java` / `decompile_method_java_with_pc` / `find_call_sites_to_api` / `find_call_sites_from_method` / `find_field_read_methods` / `find_field_write_methods` / `decompiler_clear_cache` / `decompiler_set_cache_capacity`), 5 delegating adapter methods (incl. the SDK's own former `find_call_sites`), and 2 `safe.py` module aliases. `safe.py`'s `_bound_decompile` legacy-spelling FALLBACK went with them — it existed only to keep a duck-typed stand-in on the old name working, so keeping it while deleting the aliases would have been the same compatibility promise by another route.

The same pass unified the ARGUMENT names, which stages 1-3 left alone. An audit of all four layers found four genuine inconsistencies (the first cut claimed three — the correctness reviewer found the fourth): (1) **`api_descriptor` → `method_descriptor`** on `find_call_sites_to` + `resolve_call_args`, against `find_call_sites_from`'s `method_descriptor` — the value is a method descriptor in both directions, `api_descriptor` said "framework API", which is only the common case; the METHOD name already carries the role, so the parameter should name what the value IS. (2) **`get_class_summary(descriptor)` → `class_descriptor`** — every sibling and even the MCP schema already said `class_descriptor`; raw + `.pyi` were the sole outlier. (3) **`set_decompiler_cache_capacity(cap)` → `capacity`** — the only abbreviation in the API, and the one place raw disagreed with the SDK port. (4) **`format_class(dk, descriptor)` → `class_descriptor`** — a module-level helper that forwards the value STRAIGHT into `get_class_summary`, so #2 left it as a second outlier; every sibling module function (`safe_decompile_class`, `descriptors.signature`, `filters.filter_*_refs`, `tools._t_get_class_summary`) already said `class_descriptor`. Deliberately NOT changed: `super_class` / `interface_class` / `annotation_class` / `declaring_class` go through `NormaliseClassNamePattern` and are **patterns**, not descriptors, so `_descriptor` would be wrong; `filters.py`'s keyword args mirror the MODEL field names, a different and self-consistent axis.

Both are breaking for anyone on the released spellings — deliberately, and there is no alias mechanism left to soften it. Guards: `test_deprecated_aliases_are_removed` (hard-coded names, asserted absent AND canonical-still-produces, so a wholesale break cannot pass) + `test_no_adapter_alias_survives` + the drift audit's now-empty `_RAW_DEPRECATED_ALIASES` / `_DEPRECATED_ALIASES` (kept as empty declarations so re-introducing one is a conscious edit) + `test_call_site_names_are_unified_across_layers`, extended to assert the ARGUMENT name **by `inspect.signature`** on the port, the adapter and the MCP impl (plus the MCP schema and a raw keyword call). The port needs its own check because a Protocol carries NO runtime conformance for parameter names — reverting only `ports.py` passes mypy and every other assertion, which the reviewer demonstrated; `__code__.co_varnames` was also replaced because it matches locals, not just parameters. `test_unified_argument_names_are_callable_as_keywords` covers the renames that no test called by KEYWORD (`get_class_summary`, `resolve_call_args`) — a rename every call site passes positionally is unguarded by construction. Both guards were verified to FAIL against a one-line revert.

**The ARGUMENT axis — a ratchet, not a repair (dexllm#44, 2026-08-15).** v0.12.0 finished locking the METHOD (#21), TYPE (#37) and MCP tool-NAME (`22a020f`) axes; parameter names were pinned for exactly THREE operations by `test_call_site_names_are_unified_across_layers` and were otherwise unified only because #21 stage 4 did it by hand. A full audit of all four layers measures **0 mismatches today** — so nothing was repaired here, and that is the point: the whole #21 series exists because exactly this kind of unification decayed unnoticed over three releases. Two tests, one per layer pair, each with a non-vacuity floor. **`test_raw_and_port_share_one_spelling_per_argument`** ([tests/test_sdk.py](tests/test_sdk.py)): (1) **raw ⊇ port, in order** — a port parameter must carry the name the raw operation gives it, and the shared names must keep their relative ORDER so a positional call means the same thing on both layers; only CONTAINMENT, because the SDK deliberately omits knobs (`dataset_path`, `only_categories`) and an absence is not drift; (2) **adapter == port, exactly** — the adapter IS the port's implementation, and it needs its own check because a `Protocol` carries NO runtime conformance for parameter names: **mypy is blind to a COHERENT rename on either side**, verified by renaming a port parameter alone and by renaming the adapter's parameter together with its body — the CI trio accepts both, this test rejects both (mypy catches the adapter case only when the body is left referring to the old name, i.e. incidentally). **`test_every_mcp_tool_argument_exists_on_another_layer`** ([tests/test_tools.py](tests/test_tools.py)): (3) **schema properties == impl parameters** — the transport has TWO name lists, and the advertised `input_schema` is the one an LLM reads and the only one mcp validates against, yet nothing compared them; a property the impl does not accept is a `TypeError` the moment a model uses it, and a parameter the schema omits is unreachable over the wire (SETS: key order in a JSON object carries no meaning); (4) **every impl parameter is a parameter of the SAME-named operation** on raw / a port / a `dk`-first module function, or one of the declared `_MCP_TRANSPORT_ARGS` (`limit`, `offset`, `max_chars`, `pattern` — pagination and truncation exist only where the answer crosses the wire). Set EQUALITY against that list so a stale entry fails too, and the list is **JUSTIFIED, not merely listed** (the sibling audits' defence): a transport name that ANY referenced operation also uses would be a real domain parameter, and listing it there would let a rename hide behind it — a live hole, since a param renamed to a spelling another operation uses passes the equality. Raw names come from pybind's generated signature line (`conftest.raw_param_names`), i.e. **what a keyword call actually resolves against**, not the `.pyi` shadow; an unreadable one FAILS rather than shrinking the audit to nothing. **Mutation matrix, 8 mutants each built and run, each killed by its intended assertion:** a port+adapter rename → (1); a port+adapter REORDER → the order half of (1); an adapter-only rename → (2); a schema-property rename → (3); an impl+schema rename together → (4); a stale `_MCP_TRANSPORT_ARGS` entry → the set equality; a real parameter (`class_descriptor`) listed as transport → the justification assertion, proving it is not dead code; and the parser blinded to `None` → both non-vacuity floors. **Deliberately NOT done:** the KEY-name axis the issue raises alongside — `loaded_dex_count` (#38) is a third spelling for what raw and the port both call `dex_count()`, and a nested `{session: {dex_count, source_count}}` would express the scope structurally instead of by prefix. That is a breaking change to a released MCP output shape and a decision of its own, not part of an argument-name ratchet.

**`extract_dex_bytes` → `extract_dex`, returning provenance with the bytes (dexllm#26, 2026-08-06).** The bytes alone could not say WHICH file they came from, and nothing else could supply it: `verify_report()`'s `name` is the file PATH for a bare `.dex` but only the ENTRY NAME for a zip member, so a multi-source session reports `classes.dex` twice with nothing to separate them — and a CONCATENATED / packer-dump source, which the core splits into several logical dexes over one image (`AddImage` → `ParseLogicalDexOffsets`), has **no `verify_report` row at all** for its second dex (measured: `dex_count()==2`, one row, and the SDK's `_dex_name(1)` returns `""`). That measurement is SINGLE-SOURCE only, and a reviewer showed the multi-source case is worse: `verify_report`'s `dex_id` is the load-order IMAGE INDEX (`out.size()`), so once one source splits, every later row's id is off by the split count and `_dex_name` returns **another source's name** — mis-attribution, not absence. `_dex_name` / `tools._dex_name_map` still read that field and are NOT fixed here (issue #27). Since the return type had to change anyway, the name changed with it — `extract_dex_bytes` no longer described what came back. Returns `{bytes, dex_id, source, entry, offset, size}`; the SDK gets an `ExtractedDex` model, and `verify_report()` / `verify()` rows gain the same `source` field. `extract_dexes()` is the whole-container form (every dex in dex_id order) — a separate PLURAL name rather than an optional `dex_id`, because a signature whose RETURN TYPE depends on its argument forces every caller to branch, and this is the all-vs-one axis `list_classes()` / `list_classes_in_dex(dex_id)` already draws. Being the first API that walks EVERY dex_id unprompted, it surfaced a shape the singular form never reached: a logical dex whose `DexItem` failed to construct (a packer dump whose second dex has an intact header but an undecrypted body — `ParseLogicalDexOffsets` splits on the size field with no magic check) left a null item, and `GetDexOrigin`'s null-item bail returned the DEFAULT `DexOrigin`, i.e. `dex_id == -1` — the OUT-OF-RANGE sentinel, in the MIDDLE of the list, so `dex_ids` came back `[0, -1, 2]` and a dumping loop wrote a 0-byte `dex-1.dex`. Fixed by stamping `dex_id` as soon as the id is in range, BEFORE the null-item bail: `-1` now means out-of-range and nothing else, and an unreadable dex reports its real id with empty bytes (`size == 0`). The null item itself is a PRE-EXISTING SEGV in the search family on the same input — escalated on issue #25, not fixed here. **(Both closed by the dexllm#25 per-logical-dex gate, 2026-08-08 — see the Malformed-dex safety section: the undecrypted second dex is now REJECTED at load rather than parsed into a null item, `AssertLoadedDexesWereVerified` refuses a load that produced one anyway, and `verify_report`'s `dex_id` is a real dex_id with a row for every logical dex, so `_dex_name` / `tools._dex_name_map` no longer mis-attribute. The `-1`-in-the-middle stamping fix stays as the defensive net it was.)**

Provenance is resolved through the **IMAGE**, not by load-order index: `DexKitExt::CollectSource` records `MemMap* → (source, entry)` BEFORE moving the image into the core, and `GetDexOrigin(dex_id)` matches `DexItem::GetImage()` against that map — because one source can back several dex_ids, the load-order index is not the dex_id. `offset` is the logical dex's start within its image (nonzero only for the concatenated case), computed from the same reader-header base `GetDexBytes` slices with.

Beware the coupled contract: `verify()` (load-free) is documented as **byte-identical** to `DexKit(path).verify_report()`, so the static path had to grow `source` on all five of its row-emitting sites too — adding it to only the load path broke that equality, and `test_verify_matches_verify_report` caught it. That test compares the two IMPLEMENTATIONS to each other, so it catches an ASYMMETRIC omission only; a review showed a symmetric one passes, so it now also PINS the value (`r["source"] == apk`). Guards: `test_extract_dex_provenance_disambiguates_sources` (two sources sharing an entry name; asserts the ambiguity EXISTS in the fixtures, else it proves nothing) + the provenance half of `test_extract_dex_slices_concatenated_container` (asserts `offset` separates the two logical dexes AND that `verify_report` has only one row, pinning the assumption that does not hold). a/b: whole-corpus decompile text byte-identical, parity 28/28, sweep 25,309/0-crash, pytest 246.

### One Dalvik descriptor, one word for it (dexllm#68, 2026-08-24)

v0.12.0 finished locking the NAME axes — but only three of four: raw <-> port
METHOD names (dexllm#21), raw <-> SDK TYPE names (dexllm#37) and the four-layer
ARGUMENT names (dexllm#44). Record **ATTRIBUTE** names were the axis nothing
audited, and unlike #44 this was not a ratchet over a clean state: it had drifted
into the defect #37 removed one axis over — one concept, two names.

Five public attributes held a Dalvik descriptor and spelled it `signature` —
`ExternalMethodRef.signature`, `ExternalFieldRef.signature`,
`ArgOrigin.field_signature` / `.method_signature`, `CapabilityHit.api_signature`
— while every `find_*` PARAMETER, `is_member_descriptor`, every MCP schema and
every other record (`MethodMatch.descriptor`, `CallSite.caller_descriptor`, …)
say `descriptor`. And one side's OUTPUT is the other side's INPUT:
`dk.find_call_sites_to(ref.signature)` resolves, at a parameter named
`method_descriptor`. **Worse than the `AttributeError` dexllm#21 removed**,
because both names resolve — so a consumer that guessed wrong got a wrong
ATTRIBUTE rather than an error.

`signature` is RESERVED now for the dotted Java rendering
(`android.util.Log.d(java.lang.String) -> int`), which is a genuinely different
artifact that the `java_` prefix already marks.

## The issue's own "why nothing caught it" was FALSE, and measuring it shaped the guard

It claimed renaming `signature` in `model.py` *"to anything at all passes the
whole suite"*. Each was applied to the PRE-change tree (all three are
python-only, so no rebuild is involved) and the WHOLE suite run:

| mutant | fails | what caught it |
|---|---:|---|
| ONE layer (`model.py` alone) | **2** | dexllm#37's own audit compares the two layers' attribute SETS; the adapter's keyword call raises |
| COHERENT `ExternalFieldRef.signature` (`_enrich` + `model` + `adapter` + `.pyi`) | **1** | a value-composition assertion that happens to SPELL the name |
| COHERENT `CapabilityHit.api_signature` (its 4 python layers) | **13** | tests and doc fences that happen to spell it |

So the axis was not unguarded — it was guarded **incidentally and unevenly**, and
whether a rename was noticed depended on how often the name appeared in an
assertion. **Nothing audited the WORD**, which is what the new guard does.

## What changed, and the two decisions the user made

The direction and both open sub-decisions were escalated (CLAUDE.md rule 5 — this
BREAKS released public attributes and this repo keeps no aliases, dexllm#24), and
the user chose: rename everything; `CapabilityHit.api_descriptor` with the MCP key
`"descriptor"`; and `dexllm.signature()` renamed NOW rather than deferred to
dexllm#69.

| layer | before | after |
|---|---|---|
| raw pybind | `ExternalMethodRef.signature` | `.descriptor` |
| py `_enrich` | `ExternalFieldRef.signature` | `.descriptor` |
| raw + SDK | `ArgOrigin.field_signature` / `.method_signature` | `.field_descriptor` / `.method_descriptor` |
| `capability.ApiHit` + SDK `CapabilityHit` | `api_signature` | `api_descriptor` |
| module | `dexllm.signature(cls, name, proto)` | `dexllm.method_descriptor(...)` |
| MCP `summarize_capabilities` | per-hit key `"api"` | `"descriptor"` |
| C++ | `ArgOrigin::field_signature` / `method_signature`, `BuildMethodSignature` / `BuildFieldSignature`, the `caller_sig` locals | `*_descriptor` / `Build*Descriptor` / `caller_desc` |

The C++ struct fields are renamed because the pybind property reads them TWO
LINES away, and the builders because they are assigned to a `*_descriptor` field
ONE line away — the "a builder and its validator disagree" shape the issue names,
on the internal side. `dexllm.method_descriptor()` is the same shape one layer up:
it BUILDS the string `require_member_descriptor` validates in the same module.

**`api_descriptor` keeps the `api_` prefix that dexllm#21 stage 4 REMOVED from a
PARAMETER, and the reason is the opposite one**: `find_call_sites_to`'s argument
was renamed because `api_descriptor` asserted "framework API" of an arbitrary
callee, whereas `ApiUsage` (`CapabilityHit` until dexllm#69) IS one catalog-API hit, so the prefix names the
catalog entry rather than assuming anything. Stated in `sdk/model.py` and
`docs/api.md` so it is not read as a relapse.

## The MCP `"api"` key meant two things, and that is the collision this closes

`summarize_capabilities` abbreviated `api_signature` to `"api"`, landing on a key
`dangerous_permission_api_callers` already used for the AOSP DATASET form — and
that sibling spells the Dalvik form `"descriptors"` in the SAME dict. So
`payload["api"]` meant `Landroid/…;->m()V` in one tool and
`android.location.LocationManager#getLastKnownLocation(String)` in the other: the
dexllm#38 shape, on the surface an LLM reads, reached through the `signature`
spelling rather than independently. The capability key is `"descriptor"` now; the
dangerous-API one is UNTOUCHED, because there `api` genuinely names a different
artifact — and the a/b proves it did not move.

## `_ARG_VALUE_FIELD` was two copies; it is one object now

`tools.py` and `sdk/adapter.py` each held a private map from `ResolvedArg.kind` to
the attribute it fills, and this change renames two of the VALUES — so "must
change in lockstep" stopped being theoretical. They share
[src/dexllm/_argkinds.py](src/dexllm/_argkinds.py) (a `MappingProxyType`, so
neither layer can mutate what both read), the `_callers.py` precedent from
dexllm#49. The guard asserts object **IDENTITY**, not equal contents: a correct
COPY passes every behavioural test and drifts on the first edit, which is the
shape #49's own review had to construct. The map now carries `Parameter` too; the
MCP view renders that kind as `pN`, so it consults the map only after its own
branch.

## Measured

a/b OFF=`9f1baa1247b5b2796d7458f615c00033` vs ON=`30f53ca61e161e7d39714de1798247b9`,
SAME script, both `.so` md5-verified before AND after each capture — and the OFF
build **BIT-REPRODUCES the recorded HEAD md5**, which is the diff's functional
content stated as a measurement. 43 sources — the whole bundled corpus plus every
committed fixture — x 29 axes = **1107 axis records present, 14 changed**, on
exactly TWO axes (`mcp_cap`, `mcp_cap_keys`) and exactly SEVEN sources, and those
7 are **precisely the sources carrying at least one capability hit** (re-derived
programmatically, not asserted). The 1107 is re-derivable rather than a harness
number: 38 sources load and carry all 29 axes, 5 are not containers at all and
carry only `load` — 29x38 + 1x5
[[published-counts-need-the-repos-own-predicate]]. Every VALUE is captured under a
NEUTRAL key, so the two halves compare VALUES rather than names: external method
refs, external field refs, every `resolve_call_args` argument, every capability
hit, `by_caller`, `dangerous_permission_api_callers` and its MCP payload, all four
SDK-layer axes, the decompiled Java, the smali and the class lists are
**identical on every source**.

A separate probe pins that the rename is a **RENAME**: on ON the OLD spelling is
ABSENT from every record and from `dexllm.__all__`, and on OFF the new one is.

**The a/b harness lied TWICE, and both halves were re-measured from scratch each
time.** (1) `mcp_cap` reported all 38 loadable sources as changed — the harness
called `tools.execute(dk, name, args)` with the arguments in the wrong order, so
that axis captured an error string containing the DexKit object's `repr`, i.e.
**a memory address**, and the 38 "changes" were pure ASLR
[[ab-harness-must-itself-be-deterministic]]. The tell was its SIBLING axis
`mcp_cap_keys` reporting ZERO: two axes that must move together did not. (2) The
four SDK-layer axes were **never captured at all** — the block did
`with open_apk(...) as sdk:` and `open_apk` returns the adapter, not a context
manager, so it raised on EVERY source and stored the exception under a single
`sdk` key. That string is IDENTICAL on both halves, so it compared EQUAL and read
as coverage; the claim "the SDK models are identical on every source" was
unsupported until this was found and fixed. **An axis that silently degrades to a
constant is worse than a missing axis, because it looks verified.** The harness
now exits non-zero on any erroring axis — scoped to exclude `load`, where an
error IS the measurement for the five bundled sources that are certificates or
resources-only containers.

## Guards

Four in [tests/test_sdk.py](tests/test_sdk.py), beside their three siblings, and
two in [tests/test_tools.py](tests/test_tools.py). All six are corpus-INDEPENDENT
— those that need live values run on the committed `tests/data/multidex.apk`
(which yields both an external method ref and an external field ref) or drive the
real pass over a STUB `dk` — so they hold in the corpus-less CI leg and under any
`$DEXLLM_TEST_APK` narrowing. **That sentence was FALSE when first written**: the
MCP-key guard took `test_tools.py`'s module-local `dk` fixture, which globs the
corpus and SKIPS without it; an adversarial reviewer measured the skip and showed
the guard's unique half had no CI coverage at all. The corpus-driven version is
KEPT — it is real evidence on a real APK — and a stub-driven twin covers the CI
leg.

`test_signature_is_reserved_for_the_dotted_java_rendering` collects every public
attribute of every record on BOTH layers (43 records / 232 attributes today) plus
every name in `dexllm.__all__`, and requires the ones containing `signature` to
EQUAL a PINNED exception list — set equality both ways, so a new offender AND a
stale exception both fail. The list is a LITERAL rather than a `java_`-prefix
scan, because a guard parametrised over the thing it guards cannot catch an EDIT
of it. The module half is not decoration: a record-only audit would not have seen
`dexllm.signature()`.

`test_the_java_rendering_exception_is_earned` is the JUSTIFICATION half, without
which the cheapest way past the audit is to ADD the offender to the list — which
absorbs the very defect, the same defence dexllm#37 applies to its own two lists.
Each exempted attribute's live value must NOT be a Dalvik descriptor, AND the
`descriptor` sibling on the same record must BE one (so the audit cannot be
satisfied by DELETING the attribute instead of renaming it), and the loop must be
shown to have RUN.

`test_the_arg_kind_attribute_map_has_one_definition` pins object identity and that
every mapped attribute EXISTS on the raw record — so a rename that misses the map
fails structurally and corpus-free, rather than as an `AttributeError` inside a
corpus-dependent xref call.

`test_the_capability_tool_no_longer_shares_the_api_key_with_a_second_grammar`
(corpus) and `..._corpus_free` (stub) each assert BOTH halves: the capability
payload no longer carries `api` and its `descriptor` is a member descriptor, AND
the sibling tool still says `api` with the DOTTED form. Checking only the renamed
key would pass a build that renamed both and re-created the collision one word
over — measured: that mutant survives the corpus-less run byte-identically
without the stub twin.

`test_a_descriptor_valued_attribute_is_spelled_descriptor` is the POSITIVE half —
by VALUE, because a ban on one word cannot enforce a rule about all of them. Its
two exception lists are different in kind and are checked as such: a ROLE name
must be used by BOTH layers (that is what separates it from a cross-layer rename,
so a `sdk.` entry whose `raw.` twin is unlisted FAILS), while DRIFT is the three
pre-existing dexllm#69 cases named above. SUBSET, not equality, because which
records a sample reaches is an environment fact — a class with no interfaces never
produces `ClassInfo.interfaces` — while a NEW offender is a product fact.

`test_a_parameter_arg_renders_as_pN_not_as_a_bare_index` pins the one rendering
the shared map does NOT supply, which nothing asserted and which this change made
newly dangerous to lose.

The record scan WALKS the package rather than naming two modules, and that is not
tidiness: a hand list had `_dexkit_core` + `sdk.model` and therefore left
**`dexllm.capability.ApiHit`** (now `ApiUsage`, dexllm#69) — the raw counterpart of the SDK's `CapabilityHit`,
returned by `summarize_capabilities` — outside an audit that looked complete.
Walking finds 43 records / 232 attributes. Stated honestly, this closes a SCOPE
gap and not a silent hole: the adapter reads that record, so a one-module rename
breaks loudly elsewhere (measured: 18 failures in `test_capability_catalog.py`
alone). What the widening buys is that the audit
NAMES the cause, and that a record added to some future module is covered without
anyone remembering to extend a list. A module that fails to IMPORT is recorded and
must be a declared optional-extra one, so a missing dependency cannot shrink the
scan into vacuity.

## What the two reviewers found — 3 CONFIRMED, and one of them the change itself CAUSED

Both worked in FULLY ISOLATED copies (own venv, own `.so`), and both built their
own OFF half rather than trusting mine — one of them reproduced `ab_old.json`
BYTE-FOR-BYTE, and the other caught its own first OFF build being a **no-op**
because `cp -a` preserved mtimes and ninja said "no work to do" while the `.so`
still carried the change [[mutation-harness-restore-pitfalls]].

**CONFIRMED — the audit banned ONE WORD while the docs claimed the POSITIVE
rule.** `found = {... if "signature" in attr}` enforces *"no descriptor is spelled
`signature`"*; CLAUDE.md, `docs/api.md` and the docstrings all stated *"every name
holding a Dalvik descriptor is `descriptor`"*. A THIRD word sails through, so a
correctness reviewer renamed `api_descriptor` -> `api_sig` coherently across four
layers, the tests and the docs, and **the whole suite stayed green** — the exact
one-concept-two-names defect this issue exists to ratchet, re-created past its own
guard. Closed by `test_a_descriptor_valued_attribute_is_spelled_descriptor`, which
checks the positive half BY VALUE: it instantiates every reachable record and
requires any attribute whose LIVE value is a Dalvik descriptor to be spelled
`descriptor`. A capability HIT is not reachable from the committed fixture, and
that is one of the renamed records, so it is driven through the real pass over a
STUB `dk` rather than left corpus-gated.

**CONFIRMED — the `Parameter` -> `pN` rendering had no guard, and this change made
losing it WORSE.** An adversarial reviewer deleted `_arg_to_compact`'s `Parameter`
branch: the whole suite AND the lint trio stayed green. Attribution is exact and
belongs to this change — HEAD's private map had NO `Parameter` key, so the same
deletion yielded `None`, while the SHARED map has one, so it now yields a bare
INT under the same `value` key that carries a `ConstInt` literal. **One key, two
grammars, on the LLM-facing surface** — the dexllm#38 shape, re-created by the
refactor that was closing another instance of it. The sibling drift test compares
KEY SETS only and cannot see it; `test_a_parameter_arg_renders_as_pN_not_as_a_bare_index`
pins the value.

**CONFIRMED — the MCP-key guard was corpus-DEPENDENT, and the record said the
opposite.** `tests/test_tools.py` carries its own module-local `dk` fixture that
globs `test_apk/APK/*.apk` and SKIPS without it, ignoring `$DEXLLM_TEST_APK`
entirely — so the claim "all four guards are corpus-INDEPENDENT" was false, both
`require_corpus_shape` calls inside it were unreachable, and its UNIQUE half (that
the SIBLING tool still spells `api` for the AOSP DOTTED form) had no CI coverage:
making that sibling's `api` carry the Dalvik form survived the corpus-less run
BYTE-IDENTICALLY. `test_the_capability_tool_shares_no_key_with_a_second_grammar_corpus_free`
drives BOTH tools through a stub `dk`, so both halves hold with no corpus.

**Three more holes they constructed, each of which passed the suite as it then
stood**, all closed: the identity guard on the shared map checked the module
SYMBOL and not the USE SITE (keep the import, read a correct private copy — the
hole dexllm#49's own review had to construct, one axis over); `dexllm.signature()`
re-added OUTSIDE `__all__` was invisible, because the module half scanned `__all__`
rather than the namespace; and a record declared as a **NamedTuple** rather than a
dataclass was not enumerated at all. The optional-module exception list gained an
EARNED half too (a listed module must genuinely declare no record, or listing it
hides one in any environment without the extra), and the "earned" predicate now
refuses any Dalvik form the two validators happen not to cover — a proto, a
shorty, a bare internal name — since each was launderable into the exception list.

**Two pre-existing counterexamples to the positive rule, which no audit could
see** (a value-driven sweep found 32 descriptor-holding attributes, 6 not spelled
`descriptor`; 4 are ROLE names both layers agree on): `ClassSummary.superclass_descriptor`
-> `ClassInfo.superclass` and `interface_descriptors` -> `interfaces`, plus
`MethodAst.class_name`. `ClassSummary` is in `_RAW_DECOMPOSED`, so dexllm#37's
field-set equality never runs for it, and neither name contains `signature`. They
are dexllm#69 §4 and §6, not this issue, and are PINNED as declared DRIFT so the
audit tolerates exactly these three and no new one.

**Everything else they attacked, they REFUTED with their own instruments:**
`_arg_to_compact`'s restructure is behaviour-preserving over **20,601 real
arguments across all 11 kinds, 0 differences**, plus 48 synthetic cases covering
the `UnicodeDecodeError` containment and an unknown future kind; the a/b
re-derives on independently built halves; the blast radius is clean (no consumer
left reading an old name, `mcp_server.py` / `server.py` never touch the capability
keys); `filters.find_call_sites_to_ref`'s `hasattr` discriminator is unchanged in
strength; a broken subpackage fails the audit LOUDLY rather than shrinking it; and
all four guards pass narrowed to six different bundled samples.

## Mutation matrix

20 mutants, four of them constructed by the REVIEWERS. The harness restores from a
pristine SNAPSHOT (not `git checkout`,
which would delete the untracked `_argkinds.py`), `touch`es every restored file
(`copy2` preserves mtime, so ninja would SKIP), REBUILDS to the control before
every mutant and ASSERTS `md5() == CONTROL` at that point, and asserts the control
again when it ends. It runs the two GUARD files — `tests/test_sdk.py` +
`tests/test_tools.py` — so a kill count says how many of THOSE die, which isolates
the new guards instead of counting the incidental spellings elsewhere in the suite
(the "13" above was the WHOLE suite against the PRE-change code; the two are not
the same measurement and are not comparable).

| mutant | md5 | killed |
|---|---|---|
| M0  CONTROL: all 25 files at HEAD | `9f1baa12` — **HEAD's exactly** | 0, by design: the guards go with them, so nothing CAN fail. The md5 identity is the diff's functional content stated as a measurement. |
| M0b PRE-FIX: production at HEAD, the guards KEPT | `9f1baa12` | **9** |
| M1  sdk model alone | control | 5 |
| M2  COHERENT `ExternalFieldRef` (4 py layers) | control | 4 |
| M3  COHERENT `CapabilityHit` (4 py layers) | control | 2 |
| M4  `dexllm.method_descriptor` -> `signature` | control | **1** — the MODULE half of the name audit, which a record-only scan misses |
| M5  the shared map DUPLICATED as a CORRECT copy | control | **1** — object identity, invisible to every behavioural test |
| M6  a rename that MISSED the shared map | control | 8 |
| M7  the MCP collision back (capability key -> `api`) | control | 2 — the corpus guard AND its stub twin |
| M8  the collision one word over (dangerous row -> `descriptor`) | control | 2 |
| M9  a `signature` descriptor ADDED and ABSORBED into the exception list | control | 3 — incl. the justification half |
| M10 the audit satisfied WITHOUT the rename (`descriptor` -> `ident`) | control | 3 |
| M14 `capability.ApiHit` ALONE | control | 4 |
| **M15 REVIEW: a THIRD word — `api_descriptor` -> `api_sig`, coherently** | control | **1** — `test_a_descriptor_valued_attribute_is_spelled_descriptor`, and nothing else. This is the mutant that passed the WHOLE suite before that guard existed. |
| **M16 REVIEW: `_arg_to_compact`'s `Parameter` -> `pN` branch DELETED** | control | **1** — `test_a_parameter_arg_renders_as_pN_not_as_a_bare_index`; it passed the suite AND the lint trio before |
| **M17 REVIEW: the sibling tool's `api` made DALVIK** | control | 2 — and the STUB twin is the one that catches it corpus-less |
| **M18 REVIEW: use-site drift — shared import kept, a correct private copy read** | control | **1** — the use-site half of the identity guard |
| M11 raw only: the pybind property | `f37319e2` | 5 |
| M12 COHERENT across C++ AND python | `f37319e2` — the SAME C++ edit as M11, so an identical `.so` is a FACT, not a harness failure; the python halves differ and the kill sets show it | 4 |
| M13 `ArgOrigin` pybind property | `99d73046` | 9 |

**M4, M5, M15, M16 and M18 each die to exactly ONE guard and to nothing else**, so
none of the six is redundant — and four of those five are the guards a REVIEWER
forced into existence. M9, M10 and M14 are caught by the JUSTIFICATION half rather
than by either audit.

## The MUTATION harness lied three times too, and one round was discarded whole

(The a/b harness's own two failures are recorded above; these are separate.)

1. **The restore set was the CHANGED files**, so M8's edit to `dangerous_api.py`
   — a file the change does not touch — SURVIVED the restore and sat in the tree
   while the post-run `.so` md5 reported the control as OK. **A `.so` md5 cannot
   see a python mutant** [[mutation-harness-restore-pitfalls]].
2. **Restoring the SOURCE without REBUILDING** let every python-only mutant
   measure the previous C++ mutant's binary: after M0b reverted the C++ to HEAD,
   M1..M10 all reported HEAD's md5 rather than the control's. That whole round was
   discarded and re-run; the harness now rebuilds to the control before every
   mutant and ASSERTS it there.
3. **M0 reverted the GUARDS too**, so nothing could fail and it reported 0 kills
   while looking like a pre-fix mutant. It is a CONTROL now (its value is the md5
   identity with HEAD), and M0b is the real pre-fix half.

Two `pkill -f` invocations also killed their own shells, because the wrapper's
command line contains the pattern — the self-matching-pgrep shape the same memory
records — and two anchors went stale under `black`, which is why an anchor that
does not match exactly once is reported as **not a mutant** rather than skipped.

### The record vocabulary is ONE vocabulary (dexllm#69, 2026-08-24)

dexllm#68 found one WORD used two ways. This is the rest: record type names spanned
**nine suffixes on five different axes**, an ordinal was spelled **four** ways, and
the same value changed name at the layer boundary. dexllm#37 locks *"a record type
on both layers uses ONE name"* and every record passed it, because each had one name
per layer — **coherence WITHIN the vocabulary is a different axis and nothing checked
it**, the same gap #68 reported for attributes.

**Every claim re-measured on the current tree first, and two were stale.** #69 was
filed before #68 landed: its §8 lists `field_signature` / `method_signature` beside
`class_descriptor` inside `ArgOrigin`, which #68 already fixed, and its §3 cites
`descriptors.signature()`, renamed to `method_descriptor()` there. Everything else
reproduces, and §5's identity claim is now PROVEN rather than asserted
(`MethodMatch.method_id == 402 == CallSite.caller_method_idx` for the same method).
The suffix census is also **under-counted by the issue**: 30 record types in 19
buckets, not the 9 it tables — `Location`, `Group`, `Use`, `References` and
`Indicator` are not in it.

**The direction and all six decisions were escalated to the user (CLAUDE.md rule 5),
who chose the maximal scope**: unify the suffixes onto one axis, give `*Info` both
`class_descriptor` and a derived `descriptor`, and close the ordinal at three tiers.

## The rule, and the four families it actually touches

**A record's suffix names WHAT THE RECORD IS, never how it was obtained.**
`Site` / `Ast` / `Status` / `Report` / `Location` / `Dex` / `Info` / `Summary` all
pass it unchanged. Four did not:

| from | to | why |
|---|---|---|
| `ClassMatch` / `MethodMatch` / `FieldMatch` | `ClassRef` / `MethodRef` / `FieldRef` | `Match` is PROVENANCE — "a `find_*` produced it". What the record IS is a located reference |
| `ApiHit` (raw) **and** `CapabilityHit` (sdk) | `ApiUsage` | `Hit` is provenance's second word — **and the two were ONE record under two names** |
| `ArgOrigin` | `ResolvedArg` | provenance's third word; `ResolvedCallSite.args: tuple[ResolvedArg, ...]` now reads as one thing |
| `PermissionCallerRow` / `PermissionCallerGroup` | `ApiCallers` / `PermissionCallers` | `Row` is a presentation SHAPE |

`External*Ref` keeps `Ref`, and that is the rule rather than an exception: there the
STATUS is carried by the `External` PREFIX, which is where a status belongs, so `Ref`
is free to mean what the record is. **`Info` vs `Summary` is deliberately NOT
collapsed** — both name what the record is, and merging them would make
`ClassSummary` (header + member lists) and `ClassInfo` (header only) **one name for
two shapes**, which dexllm#37 ranks as worse than two names for one shape.

## An unreported dexllm#37 violation, and the guard it had been switching off

`dexllm.capability.ApiHit` and `sdk.CapabilityHit` had **identical field sets** (7,
order aside) and two names for as long as both existed. #37's audit could not see it:
its "raw" side is `_dexkit_core` — the pybind module — alone, so a plain python
dataclass carrying a second name was outside its reach entirely.

It was not merely invisible, it was **suppressing a live assertion**. #68's
`_DESCRIPTOR_ROLE_ATTRS` twin rule skips an `sdk.` entry when `record not in
raw_records`, and `CapabilityHit` was never in `raw_records` because the raw record
was spelled `ApiHit`. Unifying the name turned the rule ON and it immediately
demanded the missing `raw.ApiUsage.callers` pin. **A one-record-two-names defect was
disarming the guard that would have caught the next one.**

## The other five sections

| § | change |
|---|---|
| 1 | `ExternalTypeRef.java_name` -> **`java_type`**. All three `java_*` properties are the same `descriptor_to_java()` body, and this one's input IS a type descriptor (55 of a2dp.Vol's 576 external type refs are ARRAYS, so `Type` is right and only the `_name` was drift) |
| 3 | `MethodInfo` / `FieldInfo` gain **`class_descriptor` + a derived `descriptor`**, APPENDED so the three positional arguments keep their meaning. `MethodRef`, `ExternalMethodRef` and `ClassSummary` all carry an identity string; `*Info` was the only member record without one. The joined form is NOT stored — the binding computes it, so the struct pays one string per member rather than two, and `GetClassSummary` stamps the class in ONE place rather than at each of the four construction sites |
| 4 | the raw AST dict renames 4 keys — `cls_name` -> **`class_descriptor`** (its VALUE is a descriptor, so it was a THIRD spelling), `ret_type` / `params_type` / `access` -> `return_type` / `param_types` / `access_flags` |
| 5 | three tiers, and `_num` disappears: **`_idx`** = a position in a dex `*_ids` table (the spec's own word), **`_id`** = a handle dexllm assigns by load order (`dex_id` is not a dex structure), **`_index`** = any other ordinal. So `class_id`/`method_id`/`field_id` -> `_idx`, `reg_num` -> `register_index`, `dex_id` / `parameter_index` / `statement_index` unchanged |
| 6 | `ClassInfo.superclass` / `.interfaces` -> **`superclass_descriptor` / `interface_descriptors`**, i.e. back to what the raw layer says. With §4 that empties #68's `_DESCRIPTOR_NAME_DRIFT` list entirely |

**§7 is deliberately only half-done.** `java_name` was its one item with a decision
attached; `ExternalMethodRef.name` (a member SimpleName) and `DexVerifyStatus.name`
(a zip entry, or the path for a bare `.dex`) are both genuinely "the name of the
thing" and are left.

## Scoped OUT, each for a stated reason rather than by omission

* **`InvokeArg::reg_num`** — an internal simulation struct explicitly documented as
  "Not surfaced to Python". The rule is about the public vocabulary; the boundary
  line `o.register_index = src.reg_num` is an ordinary mapping.
* **the `dad_cpp` AST fields** (`cls_name`, `ret_type`, `params_type`, `access`) —
  unlike #68's `ArgOrigin` fields, which were dexllm-invented, these MIRROR
  androguard's own `DvMethod` and are part of the `// DAD:` 1:1 traceability this
  project keeps on purpose. The public KEY is the API; the field is the port.
* **`PermCallerRow` / `PermCallerGroup`** — internal C++ structs the binding turns
  into a dict, and `PermissionCallers` is already the name of the FUNCTION that
  produces them. Only the public KEY moved.
* **`perm` / `protectionLevel`** — the raw permission dict renames two of its three
  keys at the SDK boundary and `protectionLevel` is the only camelCase key in the
  API. Same defect class as §4, **found by this work and not enumerated by the
  issue**, so it is recorded rather than folded in. `rows` -> `apis` DID move on both
  producers, because it is in the approved table and leaving the raw half would have
  created a NEW drift rather than left an old one.

## Two producers, one shape — and it broke exactly as predicted

`dk.permission_callers()` is built in C++ and
`dangerous_api.permission_api_callers()` in Python; both are documented as the same
dict and the SDK adapter reads whichever it is handed. Renaming the key in the python
one alone produced a `KeyError` on exactly the C++ path, mid-implementation. Both
moved, and a SOURCE-level guard now pins that they emit the same literal key set —
source-level because `tests/data/multidex.apk` has two external method refs and
matches no permission-gated API, so a behavioural guard would SKIP in the
corpus-less CI leg forever [[a-guard-can-pass-having-exercised-nothing]]. A source
pin is WEAKER (it cannot see a key that is present and wrong) and the test says so;
the behavioural twin is corpus-gated beside it.

## Measured

**a/b OFF=`30f53ca61e161e7d39714de1798247b9` (HEAD, and the OFF build BIT-REPRODUCED
it) vs ON=`c6b8bdaee5cb7060c3ddfe1d123fe209`, SAME script, both `.so` md5-verified
before AND after each capture:** 43 sources — the whole bundled corpus plus every
committed fixture — x 30 axes (verify verdicts, class list, all three external-ref
families, all three `find_*` families, class summaries, call sites, resolved args,
every method's AST, the whole decompiled Java, the whole smali, the capability
report, IOCs, content providers, permission callers, four SDK-layer axes, the MCP
tool dicts) = **1145 axis records present, 74 changed — and BOTH changed axes are
the mechanism, not a value.**

Every attribute this change renames is read through a `g(obj, old, new)` accessor, so
the two halves compare **VALUES and not names**. **28 value axes are byte-identical
on every source.** The two that move:

* **`newapi` (36)** — the §3 mechanism proof: `<absent>` on ALL 43 sources of OFF,
  present on ON (`MethodInfo.descriptor` on 35 sources, `FieldInfo.descriptor` on 16
  — the other 27 sources' probed class declares no field).
* **`mcp` (38)** — name-sensitive BY CONSTRUCTION: it hashes the tool dicts, whose
  keys are part of what this renames. A VERBATIM structural diff resolves it exactly:
  **8 key paths renamed (`api_hits*` -> `api_usages*`), 0 shared key paths with a
  different value.** `summarize_capabilities` is the only tool whose payload moves.

parity **29/29**, pytest **1124 passed / 24 skipped**, TRUE corpus-less (`test_apk`
MOVED aside) **720 passed / 428 skipped / 0 failed**, narrowed to
`tests/data/multidex.apk` **1024 passed / 124 skipped**, the guard files green
narrowed to **each of the 38 bundled samples one at a time** plus the committed one,
sweep **25,309-class / 213,374 method-block 0-crash 0-timeout, GATE: PASS**,
determinism 3 processes x 3 `PYTHONHASHSEED`s -> one digest, lint trio clean (black
26.5.1), doc fences 78, `scripts/check_dad_boundary.sh` clean.

**And the same two legs under the CI SHAPE**, which is what the blocker below made
non-optional: with the two optional extras BLOCKED, corpus-less is **710 passed / 435
skipped / 0 failed** and narrowed is **1009 passed / 136 skipped**. **14 of the 15
vocabulary cases run there** — the 14th is the corpus-gated permission twin, whose
source-level sibling runs everywhere. Suffix buckets **19 -> 17**, ordinal spellings
**4 -> 3**, `_DESCRIPTOR_NAME_DRIFT` **3 -> 0**.

## Guards

15 cases in [tests/test_record_vocabulary.py](tests/test_record_vocabulary.py), all
corpus-INDEPENDENT except one corpus-gated twin — every live probe runs on the
committed `tests/data/multidex.apk`, so they hold in the CI leg and under any
`$DEXLLM_TEST_APK` narrowing. Each pins a **LITERAL**, because a guard parametrised
over the production source cannot catch an EDIT of it: a suffix -> RECORD-SET table
(set equality both ways, so a new suffix, a stale pin AND a record added under an
existing suffix all fail), the ordinal attribute -> tier map, the `java_*` set, the
permission dict's raw keys and its SDK model's fields. The record walker enumerates
the WHOLE package rather than two modules — that scope is the entire content of the
`ApiHit` finding — and FAILS if any module does not import, so a missing dependency
cannot shrink the audit into vacuity.

`test_no_two_record_names_describe_the_same_shape` is the one that generalises: no
two DISTINCT record names may have identical field sets, on any layer. It is what
would have caught `ApiHit` / `CapabilityHit`, and it needs no exception list today.

One more lives with its fixture rather than here:
`test_astral_member_identity_is_decoded_exactly_once` in
[tests/test_mutf8_identifiers.py](tests/test_mutf8_identifiers.py). The computed
`*Info.descriptor` is a JOIN of raw pool bytes passed through `ident_out` ONCE, and
an ASCII identifier cannot tell a correct decode from a missing one — every member in
the corpus is ASCII, so the astral craft is the only input that separates them.

## Mutation matrix — 23 mutants, 22 killed, 1 PROVEN equivalent

Each C++ mutant BUILT and RUN with a distinct `.so` md5; the harness restores from a
pristine snapshot, `touch`es it (`cp -a` preserves mtimes and ninja then says "no
work to do" — [[mutation-harness-restore-pitfalls]], hit twice during this change),
rebuilds to the control before every mutant and ASSERTS the control md5 there and
again when it ends. An anchor that does not match exactly once is reported as **NOT
A MUTANT**, which caught two of my own anchors matching twice.

**Every mutant runs in BOTH shapes** — the developer environment and a simulated
CI (`ModuleNotFoundError` for the two optional extras) — because the blocker below
was invisible in the first. That is not decoration: **R1 fails 6 guards in the dev
shape and 12 in the CI shape**, so the second leg catches twice what the first
does, which is the two-shape matrix earning its place as a measurement.

**All six mutants the REVIEWERS constructed are killed**, each having passed the
file as it then stood: the walk hard-failing on an absent optional extra (R1), a
`FieldInfo.descriptor` that drops the declaring class (R2), a COHERENT four-layer
deletion of the `FieldInfo` identity (R3), an SDK `class_fields` that emits an
empty one (R4), BOTH new `ident_out` wrappers removed (R5), and the AST docstring
keeping the four old key names (R6).

**M5 SURVIVED the first pass**: renaming the SDK `PermissionCallers.apis` field back
to `rows` passed all 219 guard cases. The source pin reads the two RAW producers and
the runtime twin compares them to EACH OTHER, so the SDK model's own field name was
covered by nothing. `test_the_permission_models_name_the_entities_not_the_table_shape`
closes it, and it is the matrix earning its place rather than review finding it.

The other sixteen: `java_type` reverted (§1), sdk `*Info` losing its identity, the
`ClassInfo` suffix dropped again (§6), `MethodAst.class_name` back (§4 sdk half), the
python producer emitting `rows`, `capability.ApiUsage` renamed back to `ApiHit`,
`PermissionCallers` -> `PermissionCallerGroup`, and on the C++ side `class_idx` ->
`class_id`, `register_index` -> `reg_num`, the raw AST key back to `cls_name`,
`gd["apis"]` back to `gd["rows"]`, the computed `MethodInfo.descriptor` deleted, the
`GetClassSummary` class-stamp deleted, `ClassRef` renamed back to `ClassMatch`, and
the identity joined WITHOUT `ident_out` — which raises `UnicodeDecodeError` at the
pybind boundary on an astral identifier, the dexllm#22 failure class, and is caught
by `test_astral_member_identity_is_decoded_exactly_once`.

**M17 is a genuine EQUIVALENT mutant and was decided by MEASUREMENT, not argument.**
Joining the three ALREADY-DECODED pieces instead of decoding the joined string
survives the suite — so it was built and compared: **351,897 member identities across
39 sources, including the crafted astral dex, 0 differences.** MUTF-8 decoding is a
per-sequence transform and every join lands on an ASCII boundary between
independently well-formed pool strings (`->` and `:` are explicit separators, and the
one adjacency with none — `name + proto` — is safe because a proto always begins with
`(`). Recorded rather than papered over.

## What the two reviewers found — 1 BLOCKER, 2 unguarded halves of the change's own feature, and 7 stale mirrors

Both ran in isolated private COPIES with their own venv and build, both asserted the
`.so` md5 before and after every measurement, and both re-derived the a/b
independently. **Neither could move a value**: the adversarial reviewer built its own
OFF half (all 41 files reverted via `git show`, distinct md5, control bit-reproduced
afterwards) and reports **595 axis records + 410 MCP records → 0 value changes**, with
**the same 8 renamed MCP key paths**; the correctness reviewer independently verified
**188,213 methods / 139,162 fields over 24 sources, 0 mismatches**. Every finding is in
the guards, the CI reach, or a mirror.

**BOTH independently CONFIRMED the BLOCKER: this change turned CI RED.** `_walk_records`
ended in `assert not skipped`, and CI installs `pip install -e ".[ioc]"` — no `[mcp]`,
no `[server]` — so `dexllm.mcp_server` and `dexllm.server` do not import and **five of
the eleven guards failed**, on both the corpus-less and the narrowed leg. The code
contradicted its own comment (`except ImportError:  # an optional extra is the only
allowed reason`) and then rejected exactly that reason, and the published *"corpus-less
715 passed / 0 failed"* had been measured in an environment with every extra installed.
It is the `conftest` rule this repo states out loud — **an environment fact must produce
a skip, never a failure** (dexllm#46) — and it was a regression of a pattern solved ONE
COMMIT EARLIER: dexllm#68's walker already had `_OPTIONAL_MODULES` and already EARNED
the exception (a listed module must declare no record when the extra IS present).

**The fix is the one this change itself argues for elsewhere: ONE definition.** The two
walkers became [tests/_records.py](tests/_records.py), imported by both audits — the
`_callers.py` / `_argkinds.py` precedent. That closed a second finding for free: the copy
was **blind to `NamedTuple` records**, which is the exact hole a dexllm#68 reviewer had
already had to construct against the original, so a `class LeakedMatch(NamedTuple)` was
invisible to all five audits. The CI shape is now REPRODUCED in the gates (a
`sitecustomize` that raises `ModuleNotFoundError` for the two extras) rather than
assumed, and the mutation matrix runs every mutant in BOTH shapes.

**BOTH also CONFIRMED, each with a BUILT mutant, that half of §3 — the change's own
headline feature — was guarded by nothing.** `tests/data/multidex.apk`'s two classes
declare **zero fields**, so `for f in fields:` executed zero times in every environment.
A `FieldInfo.descriptor` that drops the class (`this$0:LFoo;`, not a member descriptor
at all) passed the entire suite, and so did a COHERENT four-layer deletion of both new
`FieldInfo` attributes. The method half had a floor; the field half had none
[[a-guard-can-pass-having-exercised-nothing]]. The guard is parametrised over
`tests/data/invoke-custom.dex` (committed, 17 fields across 14 classes) as well, with an
`assert fields` floor so it cannot go vacuous again.

**The adversarial reviewer found a third: the two NEW `ident_out` sites were
unguarded — dexllm#22 re-opened.** Removing both wrappers left the suite identical while
an astral identifier RAISED `UnicodeDecodeError` at the pybind boundary, which is the
failure class this project closed and pins on every other identifier-returning surface.
The method half was covered by `test_astral_member_identity_is_decoded_exactly_once`,
added after their copy was taken (it kills that mutant); the FIELD half was not, because
the class-name craft yields astral METHOD identities and **no field one**. The guard is
parametrised over both crafts now — the field-NAME craft is the reverse — so neither
decode site can be deleted quietly.

**Seven stale mirrors, four of them CONFIRMED by both:**

| where | said | reality |
|---|---|---|
| `module.cpp:1224` — the RUNTIME docstring, i.e. `help(dk.decompile_method_ast)` | `{cls_name, ret_type, params_type, access, …}` | four `KeyError`s; it is the only description of the shape at a REPL |
| `CLAUDE.md:35` (the dast port-status row) | *"now returns `{cls_name, …}`"* | same, in the file that adds the §69 section |
| `docs/api.md:1048`, `docs/usage.md:905` | the permission dict returns `"rows"` | `apis`, on both producers |
| `docs/usage.md:1034` | `for row in g.rows` | `AttributeError` — the diff edited the trailing COMMENT on that very line and left the accessor |
| `docs/usage.md:1026-1028` | `ClassInfo(superclass, interfaces …)`, `FieldInfo(name, type, access_flags)` | the §6 spellings, and the two fields §3 adds |
| `tests/test_access_flags.py:180/218` | `ast['access']` inside assertion-failure f-strings | a `KeyError` instead of the diagnostic, on a genuine regression — and `:218` is the SAME statement whose assertion at `:214` WAS updated |

`docs/usage.md:1034` is the sharpest: the fence runner structurally cannot see it (the
block contains a `"..."` literal, which is on its drop list, so everything after it is
truncated), and `docs/sdk.md` was updated correctly on the same day — one mirror updated,
the other missed, inside one line. **Nothing pinned the docstring either**, so
`test_the_ast_docstring_advertises_the_keys_the_call_returns` now compares the advertised
key set against a real call.

**Smaller, all fixed:** `black --check` failed under black 26.5.1 on the new guard file
(mine had reported clean on an earlier revision of it); `an ResolvedArg`; a continuation
line left unaligned by the rename in `ConvertArg`; and `tools.py`'s `_match_to_desc`
`class_name` fallback, which named nothing on any layer after §4 and was dead anyway
(the search family returns records that all carry `descriptor`) — deleted with the
reason recorded at the site.

**Declined once, then REVERSED by measurement — the PARAMETER axis.**
`descriptors.java_to_descriptor(java_name=…)` was flagged by an adversarial reviewer
as "the exact word §1 removes" and first kept, on the argument that the attribute is
the dotted OUTPUT while the parameter is the dotted INPUT. Asked directly whether the
two issues had considered parameter names, the axis was AUDITED instead of asserted:
across every public module function, every port and adapter method, every MCP impl
and schema, and the raw pybind signatures, **exactly one parameter carried a retired
spelling — that one.** And the family's own convention refutes the decline: its
inverse is `descriptor_to_java(descriptor)`, i.e. the parameter is named after WHAT
THE VALUE IS, not the role it plays, and this value is a TYPE (it accepts a class, a
primitive, or an array). Renamed to `java_type`.

**dexllm#44 could not have caught it, and that is the ratchet.** #44 locks a
parameter name raw<->port and MCP-schema<->impl; a module helper has neither twin, so
this word survived BOTH issues on a public keyword-callable surface.
`test_no_public_parameter_carries_a_retired_spelling` scans the same four layers one
axis over, against a pinned literal of the eleven retired spellings, with a `>= 300`
floor so the walk cannot go vacuous. Verified discriminating: reverting the one-word
rename fails it and nothing else.

**A published count is a PREDICATE, not a number.** "8 renamed MCP key paths" is the
count under the a/b harness's own enumeration — leaf paths, so a renamed LIST is counted
where its elements are, not additionally as itself. The adversarial reviewer re-derived
exactly 8 with the same convention; the correctness reviewer counted **9** under a
convention that also counts the list node. Both are right about their own predicate, and
the number now travels with it [[published-counts-need-the-repos-own-predicate]].

**Two measurement artefacts that were NOT the change**, both correctly disclosed by the
reviewer who hit them: three `test_doc_examples` failures caused by `_PLACEHOLDER_FILE`'s
`/tmp/` alternative matching a worktree that lives under `/tmp` (a latent fragility in
that runner, pre-existing, out of scope here), and an MCP axis that captured a `repr()`
memory address from `tools.execute(dk, name, args)` in the wrong argument order — the
same harness trap this file already records, caught by its sibling axis reporting zero.

## One defect NEITHER reviewer could have found, caught by reading the diff

A global `sed` over `tests/` renamed the ordinal — and **`field_id` / `method_id` are
also the DEX FORMAT's own names for its id tables**, which this change does not touch.
Nine prose sites went with it, turning true statements into false ones: ART's
`CheckClassDataItem` rejecting an entry *"whose `field_id.class_idx` is not the
declaring class"*, the type-id verifier's *"referenced from `field_id` (class/type),
`method_id` (class)"*, *"a `<clinit>`, which HAS a `method_id`"*. `docs/` was excluded
from that sed by hand; `tests/` was not.

All nine are reverted, and what remains on that axis is exactly the five legitimate
renames — three record attributes and three `docs/api.md` table rows. Neither reviewer
saw it: both worked from copies taken before the rename reached those files, which is
the cost of parallel review and the reason reading your own diff is not optional.

## A process lesson, and it is a NEW variant of one this file already records

The two reviewers ran concurrently in isolated private COPIES of the tree — the
[[reviewer-agents-swap-the-worktree]] discipline — and that held. What did not is
the **scratchpad**: the a/b harness and both captured halves lived at a shared path,
and a reviewer building its own a/b OVERWROTE `capture.py`, `on.json` and `off.json`
there. The earlier diff was computed before that and its result stands, but it was no
longer RE-DERIVABLE, which for a headline measurement is the same as not having it.
The harness was reconstructed in a private directory and **both halves re-measured
from scratch on the SHIPPED tree** — 1145 records, 74 changed, the same per-axis
breakdown — with the tree diffed against a snapshot afterwards to prove the restore
was exact. **Isolating the worktree is not enough; the MEASUREMENT ARTEFACTS need a
private path too.**

Two smaller ones, both already in the record and both hit again here:
`cp -a` preserves mtimes so ninja skipped a restore and the md5 assertion is what
caught it, and an early `git checkout -- docs` reverted doc edits that a patch made
BEFORE them could not restore.

**Breaking**, deliberately and on several surfaces at once: eight record TYPE names,
eleven attribute names, four raw-dict keys and one MCP payload key. This repo keeps
no aliases (#24), so a consumer on the old spellings gets `AttributeError` /
`KeyError` — loud, which is the point. Release-notes material.

### The docs' PROSE is audited, not just their fences (2026-08-25)

A post-release verification of the two rename issues asked a narrower question
than "did the renames land": **is every comment and every `.md` file actually
current?** The renames themselves were clean — **0 retired spellings reachable at
runtime** across 43 records / 240 attributes / 39 module exports / 47 SDK exports
/ 54 `DexKit` methods / 36 MCP tools / 39 payload keys / both raw dict producers,
**0 cross-layer defects**, and all 31 source-comment mentions legitimate (the
deliberate field-vs-key split, the dex FORMAT's own `field_id` / `method_id`,
`InvokeArg::reg_num` which is documented "Not surfaced to Python", the `dad_cpp`
DAD-traceability fields, and the §1 note itself).

**The docs were not.** Absence of an old name is not the same as an accurate
description of the new state, and a prose field list does not RUN, so nothing
caught four claims — **all PRE-EXISTING, none caused by the renames**:

| where | said | reality |
|---|---|---|
| `docs/api.md` `ResolvedArg.kind` | `'StringConst'` \| `'IntConst'` \| `'Field'` | the binding emits `ConstString` / `ConstInt` / `FieldRead` and **has never emitted those three** — a consumer branching on the documented spelling matches nothing, silently |
| `docs/api.md` `ResolvedArg` table | 8 of 9 fields | `crossed_branch` missing (dexllm#16) |
| `docs/api.md` + `docs/sdk.md` `CapabilityReport` | 10 of 12 fields | `dropped_touches` / `dropped_apis` missing (dexllm#49) |

The `kind` one is the worst and the field-NAME audit cannot see it: `kind` is
present and correctly named; it is its documented VALUE SET that is fiction.

**Guards** (3 new in [tests/test_doc_examples.py](tests/test_doc_examples.py) —
the file that already owns "the docs must be true", and all corpus-free).
`test_the_docs_enumerate_the_fields_a_record_actually_has` audits both notations
against the LIVE attribute set: `sdk.md`'s ``- **`Name`** `(a, b, c)` `` and
`api.md`'s ``### `Name` `` + `| field |` table, falling back to the first-paragraph
PROSE form (`` `name: type` ``) — which is what `CapabilityReport` uses and what a
table-only parser skipped entirely. **A table is checked BOTH ways and prose only
for MISSING**, because a sentence may legitimately name the record itself or
cross-reference another API while a table row is a field claim; the two abridged
one-line summaries are pinned and their exception EARNED (they must have no
table). `test_the_documented_arg_kinds_are_the_ones_the_binding_emits` reads
`ArgKindName`'s switch from the C++ source — corpus-free, and the authority
rather than a second list. `test_no_in_page_doc_link_is_dangling` checks every
`](#…)` in all 27 md files against the headings AND the explicit `<a name>`
anchors.

**Each of the four reverts is KILLED**, verified by applying them one at a time.
Two of them survived the guard's first cut and are why it has two more notations
than it started with. The anchor guard was written after **I invented a dangling
`#which-unknown` while fixing the others** — the exact defect the audit was
looking for, committed by the audit itself. Its slug rule had to be measured too:
GitHub keeps `[A-Za-z0-9_]`, spaces and hyphens, and maps EACH space to a hyphen
**without collapsing runs**, so a heading with an em dash slugs with a `--` in it
— a collapsing slugifier reported three false danglings before that was fixed.

### Type stubs (PEP 561) — `py.typed` + `.pyi` typed shadow (2026-07)

The pybind extension carries no static types, so consumers / type-checkers would see `Any` for `DexKit`, `CallSite`, `identify()` dict keys, etc. The wheel ships a typed shadow: `src/dexllm/py.typed` (PEP 561 marker) + [`_dexkit_core.pyi`](src/dexllm/_dexkit_core.pyi) (the `DexKit` ctor overload, every `.def` method, each `py::class_` return object + its readonly attrs, the `_enrich.py` Python-side properties, and `TypedDict`s for the dict returns — `identify` / `verify_report` / `decompile_method_ast` / `_with_pc` / `permission_callers`; `match_type` is `str` — the raw binding accepts any string (`ParseStringMatchType` maps an unknown value to `Contains`), so the honest raw contract is `str`; the opinionated `Literal` narrowing lives one layer up in the `dexllm.sdk` `MatchType`) + [`__init__.pyi`](src/dexllm/__init__.pyi) (mirrors `__init__.py`'s re-exports + `__all__`; native names resolve via `_dexkit_core.pyi`, pure-Python helpers via their submodule inline annotations). **Runtime is the source of truth** — the stubs were built by introspecting the LIVE module, so they advertise no name the runtime lacks (e.g. `ExternalTypeRef` exposes `java_type` — `java_name` until dexllm#69 — NOT the `java_class` an early draft assumed), `ResolvedArg` fields are plain (the raw pybind object populates all of them; the Optional-narrowed view is the derived `dexllm.sdk.ResolvedArg`), and `Any` appears only for the genuinely-open DAD AST (`decompile_method_ast` → `ast: dict[str, Any] | None`). **Maintenance (mirror the rebuild loop):** change a binding in `module.cpp` → reflect the added/removed/renamed `.def` / `py::class_` attribute in `_dexkit_core.pyi`; change `__init__.py`'s `__all__` → update `__init__.pyi`. Locked by [`tests/test_stubs.py`](tests/test_stubs.py) (**bidirectional** runtime↔stub coverage — DexKit methods, native module classes, and each return-class's attribute set; a new unstubbed `.def` / `def_readonly` / `_enrich` property fails the test) plus a mypy check (a consumer script type-checks clean; wrong usage — bad return type, unknown method, unexported name, wrong `TypedDict` key — is caught). scikit-build-core's `wheel.packages` includes the `.pyi` + `py.typed` automatically (verified in the built wheel).

### Caller-lookup path — reverse index + O(1) target resolution (2026-07-06)

`FindCallSitesToApi` / `ResolveCallArgs` (and their consumers `permission_callers` / `summarize_capabilities`) find every caller of a target API. The original impl scanned **all methods of all dexes** (O(all-methods)) per call. Redesigned to use the data DexKit already builds: the core's `method_caller_ids` **callee→callers reverse index** ([dex_item.h](vendor/dexkit_core/Core/dexkit/include/dex_item.h) `GetMethodCallerIds`, warmed by `InitFullCache`), plus a lazily-built per-dex **`ApiResolveIndex`** (`type_name→type_idx` + `class_idx→ascending method_idxs` hash maps, [dexkit_ext.h](native/core_ext/include/dexkit_ext.h)) that turns the O(num_types)+O(num_methods) linear target resolution (`FindTypeIdx`/`FindMethodIdx`) into O(1). `CollectApiCallers` ([dexkit_ext.cpp](native/core_ext/dexkit_ext.cpp)) walks the reverse index honouring DexKit's **cross-dex aggregation** (`BuildCrossRefAggregates` MOVES an app-declared method's callers into its DECLARING dex tagged with their SOURCE dex_id and clears the source; each caller entry is re-resolved to the target's method_idx in its ORIGIN dex — mirroring `GetCallMethods`'s `ori_dex_id` branch), then sorts the result by `(caller living-dex, caller_idx)` so list order equals the old scan in ALL cases (incl. a class declared with a body in 2+ dexes — multi-source/packer). `PermissionCallers`' external-ref index is `std::unordered_map` (probed by key only). **Measured:** single framework FCS **600µs → 0.6µs (~1000×)**, `permission_callers` **19.7ms → 7.0ms (~2.8×)**. **Byte-identical** to the pre-redesign scan — a 1,009,984-record FCS+RCA capture across all test APKs (incl. multidex cross-dex) has the same sha256 OFF vs ON. `ApiResolveIndex` build is a lazy one-shot guarded by a plain bool; safe because every caller-analysis binding holds the GIL (documented precondition in `EnsureApiResolveIndex` — must gain a `std::once_flag` if any is ever GIL-released). Reviewers: adversarial 0 confirmed (all attacks REFUTED — cross-dex aggregation, resolution equivalence, lifetime, bounds), correctness 1 MEDIUM (duplicate-class ordering → the final sort) + 1 LOW (GIL doc). Order contract locked by `tests/test_dexkit.py::test_call_sites_cross_dex_multidex`.

### L4 arg resolution is JOIN-AWARE — path-insensitive values no longer reported as unconditional (dexllm#16, 2026-08-05)

`AnalyzeMethodInvokes` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) was a single linear pass that **wiped the whole register file at every branch instruction**, so (1) every argument defined before a branch came back `Unknown`, and (2) worse — since state was cleared where a branch is EMITTED and never where control MERGES — a block falling through into a join leaked its state, and a value valid on only ONE path was reported as unconditional. A rule requiring `setComponentEnabledSetting(c, 2, 1)` therefore missed every real call site (flags defined pre-branch → `Unknown`) yet matched androidx.work's own toggling (the `2` was one path's value).

**Now:** one pre-pass collects branch targets (if / goto / packed+sparse-switch payload tables) and catch handlers; the scan **MEETS** the register file at every target (intersect fall-through with each recorded predecessor; disagreement → a tombstone `Unknown` carrying the new **`crossed_branch`** flag). Branches no longer clear (a dominating definition survives); `return`/`throw`/`goto` clear because nothing falls through. A target with a BACKWARD edge is resolved by a **second pass** (pass 1 records what the back edge carries, pass 2 meets it in) — this recovers compiler-emitted shared tails, which are backward `goto`s that are not loops and were the dominant conservatism. **Sound by monotonicity:** pass-1 states are ⊑ the true fixed point, and meeting with a ⊑ state only removes entries, never invents a value. NOT a fixed point: a value defined only before a genuine loop does not survive its header; a catch handler always clears. `crossed_branch` is plumbed core_ext `ResolvedArg` → pybind → `.pyi` → `sdk` model/adapter → MCP tool (`varies_by_path`).

**Measured (a/b vs HEAD, 26,267 sites / 52,578 args):** `Unknown`→value **+3,545**, value→`Unknown` **275** (the unsound positives), value→*different* value **0**. **Independent oracle** (a separate CFG + reaching-definitions fixed point built from the *smali text*, `/tmp/l4_oracle.py`): **0 unsound / 31,305 args**; residual 436 conservative cases are 435 loop + 1 other. parity 28/28, sweep 25,309/0-crash, determinism (3 processes byte-identical), pytest 207+.

**Cost:** the pass runs twice and copies the register file per forward branch — **2.6–3.3×** the previous scan (2,407 sites 2.1→6.3 ms; 3,534 sites 3.1→10.2 ms). Footnoted in [docs/usage.md](docs/usage.md)'s perf table.

**Two independent reviewers — 6 CONFIRMED findings, all fixed here (the algorithm itself survived: 715k-arg differential + 9,000 random CFGs found 0 unsound):**
- **`*-int/lit8` / `*-int/lit16` destinations were SWAPPED** (pre-existing): slicer's table says 0xD0-0xD7 are `k22s` (dest = 4-bit `A`) and 0xD8-0xE2 are `k22b` (dest = 8-bit `AA`); the code had them reversed, so the arithmetic write erased an unrelated register and the clobbered one kept a stale origin. Harmless-ish before (branch clearing hid it), but the join merge PROMOTED it to a wrong definite value (`StandardGifDecoder.read` reported `ConstInt 16384` for a value that is `v9 + 4096` on the fall-through). Guard: `test_lit8_lit16_kill_their_real_destination`.
- **The pending-target cap was FAIL-OPEN.** `pending` entries are erased as the scan consumes them, so the table drains and a later edge to the same target re-inserted it with only that later predecessor — the meet then ran with an INCOMPLETE predecessor set. Reproducible at exactly 4096 live targets with a 25 KB verifier-passing dex, and *less* sound than pre-change code on that input. Now a `poisoned` set makes the cap **fail CLOSED** (tombstone everything at that target). Verified by shrinking the cap to 2 and re-capturing: 962 args became `Unknown`, **0 new concrete values**.
- **Unbounded memory** — the cap bounded the map COUNT, not the entries; each entry is a full register-file copy and `registers_size` reaches 65535, so a 142 KB crafted dex allocated **5.7 GB / 2.95 s** (vs 31 MB / 0.004 s pre-change). Added `kMaxStateEntries` (2^16) alongside; verified **output-identical to unbounded** on the corpus, so it bites only on crafted input (same posture as `gt_budget`).
- **Wide (64-bit) destinations left a stale origin on the high half** — `vN+1` is part of the value but kept an unrelated tracked origin, and `invoke-*` lists one arg entry per register, so it WAS surfaced (`PagingIndicator.createDotAlphaAnimator` reported the high half of a `const-wide` as `NewArray [F`). Fixed table-driven off slicer's own `GetVerifyFlagsFromOpcode() & kVerifyRegAWide` rather than a hand-kept opcode list. Guard: `test_wide_value_high_half_has_no_stale_origin`.
- **`const-method-handle`/`const-method-type` (0xFE/0xFF)** write `vAA` but fell to `default:`, contradicting the contract's "anything else clears the affected register" — added to the erase group. **`goto/32`** computed `2 * (int32)` in `int` (UB on a crafted >2^30 offset) — now widened first, mirroring the switch path.
- **The first cut of the tests did not test the change**: two passed against the pre-fix binary, and one compared an invoke's offset with a `move-exception`'s own offset — structurally impossible, so its assertion ran **0 times**. Replaced with fixtures pinned to hand-verified bytecode (`ActivityCompat.setEnterSharedElementCallback` — `v3` dominates the site, `v0` is genuinely `null`-or-`new`), **verified to FAIL against the pre-fix build** (4/6; the lit8/lit16 one fails against the C1-reverted build, which is what it guards). Plus assertions that the flag actually reaches the SDK model and the tool dict (the invariant-only versions passed with the flag always False).

Contract wording was corrected in both directions: the loop claim UNDERSTATED the pass (the second pass does carry a loop-re-established value through a header), and `crossed_branch=True` OVERSTATED it (a loop/catch barrier tombstones registers that happen to agree, so it means "a definition was discarded", not "two values provably reach"). `MethodReturn`/`FieldRead`/`NewInstance` identity is an ORIGIN identity, not a value identity — documented.

### L4 arg resolution walks a BASIC-BLOCK WINDOW whose radius is a caller-chosen `depth` (dexllm#32 pre-work, 2026-08-17)

The whole-method two-pass simulation is REPLACED. `AnalyzeMethodInvokes` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp)) now builds the code item's real basic-block CFG once (`BuildCfg` — leaders, predecessor lists, catch-handler marks, has-invoke marks; it replaces `CollectJoinPoints`'s forward/backward/barrier CLASSIFICATION OF OFFSETS) and, for each block holding an invoke, resolves the arguments from a WINDOW: that block plus the blocks within `depth` predecessor edges of it. Nothing outside the window is looked at, so `depth` IS the analysis budget and the caller chooses it — `resolve_call_args(method_descriptor, depth=2)` on the raw binding, the port, the adapter and the MCP schema (the dexllm#44 argument axis, default 2 on all four). `depth` counts predecessor LEVELS: 0 is the invoke's own block alone. **Deleted with the old pass:** `back_in`/`back_out`, the two-pass loop, `pending`, the `poisoned` fail-closed set, `kMaxPending`, `record_branch`, `fall_through_live`.

**The window is a block SET, not a per-path budget — this is the design decision.** A first formulation spent the budget along each path independently; on the canonical dexllm#16 fixture (`ActivityCompat.setEnterSharedElementCallback`, site `0x1c`) the two predecessors `0xe` and `0x12` then get resolved to different radii, so the receiver `v3` — which both paths agree on — is TOMBSTONED. That is an artefact of the accounting, not a fact about the code. Resolving the window first and analysing every block in it under the SAME boundary condition (an edge from outside carries nothing) makes the two paths comparable, and the dexllm#16 guarantees hold inside it unchanged: `v3=Parameter`, `v0=Unknown+crossed_branch`. A cycle inside the window is resolved farthest-first with a not-yet-resolved edge contributing nothing (information is only removed).

**`crossed_branch` is NOT the "raise `depth`" signal, and the first cut of the docs said it was** (correctness review, F2/F3). A boundary edge tombstones a register some OTHER in-window edge defines; a register NO in-window edge defines is simply ABSENT — `Unknown` with `crossed_branch=false`. So `false`, not `true`, is the flavour a deeper window most often resolves, and neither is a promise. A **catch handler** is the sharpest case: it is entered with an EMPTY register file, so nothing is carried in and **nothing is tombstoned there either** — the whole-method pass reported `true` there (it had a live register file to tombstone), this reports `false`, and no `depth` will ever change it. `docs/usage.md` had claimed the opposite and contradicted itself inside one paragraph; corrected in the header, the `.pyi`, `sdk/model.py`, api.md, sdk.md and usage.md, and pinned by `test_a_catch_handler_is_entered_with_an_empty_state`.

**A soundness bug the a/b caught and prose would not have: the METHOD ENTRY is an edge.** The first cut seeded the parameter registers only when the entry block had NO predecessors. An entry block that is ALSO a loop header therefore took only the back edge, and `VersionedParcel.getRootCause` (`p0.getCause()` at `0x0`, `goto` back to `0x0` after reassigning the register) reported the receiver as `MethodReturn getCause()` — asserting the loop-carried value as if it also held on the first iteration. The whole-method pass got this right BY ACCIDENT (it tombstoned every loop header). Now the entry contributes `param_state()` as one more edge into the meet, so the header yields `Unknown+crossed_branch`. Guard: `test_the_method_entry_is_an_edge_of_the_entry_block`.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified and each build reproducing its md5):** 31 sources × every external method ref + a 2,000-method internal slice = **386,630 call sites / 681,401 arguments**. **Site identity byte-identical — 0 mismatches** (caller / dex_id / offset / opcode / arity), which is what lets `find_call_sites_from` ask for `depth=0`; that API is separately **sha256-identical on all 31 sources / 37,311 rows**. Argument transitions: **35,253 value→`Unknown`** (the bounded window's cost), **10 `Unknown`→`Parameter`**, and **0 concrete→a DIFFERENT concrete** — the one shape that would mean an answer was wrong at one of the depths. `crossed_branch` flips are **only True→False** (31,031), so nothing is asserted more strongly than before. The 10 gains are PROVEN correct rather than assumed: in each case the register is never written anywhere in the method (`writes-to-v14: []`), so the parameter reaches the call on every path — the old pass lost them to a pass-1 loop-header tombstone. Corpus-wide resolution 85.9% → 80.8% at the default; `ConstString`, the kind the use case is actually about, loses **224 of 52,422 (0.43%)**.

**Cost is now a curve, not a constant** (best-of-9, 400 APIs / 1,153 sites, tvleanback, vs the join-aware whole-method pass): depth 0 **1.04×**, 1 1.25×, **2 (default) 1.50×**, 3 1.79×, 4 2.10×, with resolution 69.9 / 82.4 / 86.3 / 88.1 / 88.6 % — the fixed part is building the CFG, and the rate saturates around 3–4 (a2dp at depth 8 reaches 92.7%, i.e. ABOVE what the whole-method pass resolved, since the window recovers loop-carried agreement the two-pass scheme tombstoned). Table in [docs/usage.md](docs/usage.md)'s perf footnote.

**Budgets:** one `kMaxWork` (2^22 simulated instructions, whole method) bounds time and one `kMaxWindowEntries` (2^16 stored register entries, per window) bounds the transient memory a window holds; on exhaustion the window is abandoned and the block is emitted from an empty state — the same fail-closed direction a boundary edge already takes. This is two constants where the old pass had two plus the `poisoned` set, so #32's "the caps exist because of the design" is REDUCED, not eliminated: a bounded window still needs a memory bound because a block with a pathological predecessor count makes every window large.

**Guards:** [tests/test_arg_depth.py](tests/test_arg_depth.py) (13 cases). **13 mutants, each built and run**; 10 killed, 3 proven EQUIVALENT rather than escaped. Killed: the entry-as-an-edge revert; the binding ignoring `depth` (4 fail); the adapter accepting it and not forwarding; the MCP impl dropping it; the port default; the schema default; an unclamped negative depth (-1 → 4294967295); the meet skipped in favour of the first predecessor (4 fail, incl. the pre-existing dexllm#16 pair); a window one level too WIDE and one too NARROW; and **both handler guards removed together**. The whole pre-existing L4 guard set — dominating definition, conditional argument, switch-case joins, lit8/lit16, wide high half, catch handler — passes UNCHANGED at the default depth, which is the strongest single statement about the rewrite.

**Two guard holes the review found, both now closed — and the second only because a mutant was tried rather than reasoned about.** (1) Nothing pinned what `depth=0` MEANS: `d < depth` → `d <= depth` widens every window by a level, makes the documented `depth=0` semantics wrong on all five layers, and left the **whole suite green** — because the first cut asserted only the endpoints (`kinds[1]` was computed and never used) and compared `kind` strings, while the off-by-one at depth 0 moves only `crossed_branch`. The guards now compare `(kind, crossed_branch)` TUPLES and assert three DISTINCT answers at depths 0/1/2. (2) The two handler guards — the BFS stopping at a handler, and `is_handler[w]` forcing an empty IN — **MASK EACH OTHER**: removing either alone is byte-identical over the whole corpus (measured, so they are equivalent mutants, not escapes), and only removing BOTH lets a value leak into a handler (5 arguments change, `Unknown` → a concrete origin). Nothing caught that. The fixture is now `SearchView$AutoCompleteTextViewReflector.<init>()V`, whose three `setAccessible` calls sit one per try/catch: the first block is NOT a handler and resolves `v1` to `ConstInt 1`, the second and third ARE and cannot resolve it at ANY depth. Asserting BOTH is what keeps it from degenerating into "everything is Unknown", and its premise is the method's smali TEXT (a byte-exact line), which is independent of the analysis under test — several corpus APKs ship a build with different offsets and simply skip. Two intermediate probes were tried and DISCARDED for being non-discriminating, each verified by measurement rather than argument: "an invoke shortly after a `move-exception`" (these handlers carry no `move-exception` at all) and "a register written exactly once by a `const` must resolve at depth 40" (write-once is not the same as DOMINATING — 94/552/5616 counts were byte-identical under the mutant).

**Reviewers (2 independent, both run on the committed shape):** adversarial — **0 CONFIRMED, every attack REFUTED**, with its own evidence rather than agreement: the dexllm#16 reaching-definitions oracle rebuilt from the smali text over **368,402 args at depth 2 AND depth 100 → 0 unsound** (false-Unknowns fall 20,321→13,057 as depth rises, so the window is the only limiter and it fails toward Unknown); **8,000+ crafted lenient dexes** (random branch/switch/goto operands, fuzzed `registers_size`) at depths {0,2,5,40} → no crash; DoS worst case 12 ms; site identity across depths {0,1,2,3,7,50,5000} → 0 mismatch / 297,118 sites; **0 concrete→different-concrete over 508,653 args**. Worth recording: its first oracle reported 2,411 "unsound", which it traced BY HAND to its own per-caller cache colliding across two APK builds of one descriptor — the pass was right and the oracle was wrong. Correctness — **3 findings, all real, all fixed here** (the two guard holes above and the `crossed_branch` doc), plus a 192-case-label diff proving the opcode switch is byte-faithful, an independent `EnumerateInvokeSites` cross-check (276,425 sites, 0 mismatch), and a hand-traced 10-block derivation of the canonical fixture at depths 0–3.

**Breaking**, deliberately: `resolve_call_args` resolves fewer arguments by default, with no type or name change to warn a consumer (the quiet shape dexllm#35 and dexllm#49 were). No aliases (#24). Release-notes material.

### `resolve_call_args` stays a bounded window, and moves out of the vendored core (dexllm#32, 2026-08-18)

dexllm#32 asked where this primitive should live, offering **(a) keep and harden**, **(b) rebuild on the `dad_cpp` IR**, **(c) narrow the contract** — and noted that whichever wins, moving it out of `vendor/dexkit_core/Core/dexkit/dex_item.cpp` should be part of it. **Decided (a) + the move, on measurement.**

- **(c) is refuted by the consumers.** `tools.py` `_ARG_VALUE_FIELD` and `sdk/adapter.py` both map EVERY kind generically and the MCP schema documents all of them, so nothing is "actually consumed" in the narrow sense the issue hoped for; the issue's own census (6 APKs, every declared method as a target) puts `Parameter` + `FieldRead` alone at **69%** of resolved arguments — a figure that is population-dependent (a review re-measured 50% over EXTERNAL targets, 65.5% over internal ones), so the durable form is the one it re-derived independently: the `Const*` kinds are only **15%** of resolved arguments, i.e. **85% of what this API produces is exactly what (c) would delete**. `ioc.py` / `dangerous_api.py` do not call it at all. Narrowing to the `Const*` kinds would delete the majority of what it produces for no measured reduction in demand.
- **(b) costs 4–7× wall-clock, measured, and the issue asked for exactly that measurement.** The L4 path is a reverse-xref loop: one target API → N caller methods, each analysed. Per *caller method* the `dad_cpp` pipeline is **8–14× heavier** (257 µs vs 18–33 µs on 3 APKs), and the natural amortisation is small — a caller calls only **1.8–2.1** of the queried targets AT THE 400-TARGET SAMPLING the a/b used (it rises to ~2.5 over the full external-ref set) — so even assuming perfect per-method caching the wall clock is **4.1–6.7×**, or ~3–6× at full scope. A review's independent per-method measurement put the ratio at 11–19× rather than 8–14×, i.e. these numbers UNDERSTATE the cost of the alternative being rejected. The proxy used (`decompile_method_ast(include_source=False)`) is an UPPER bound on the snapshot+Graph+BuildDefUse prefix (b) would actually need, and no binding stops there, so the honest statement is *heavier, direction certain, magnitude uncertain*. Against that, v0.17.0's window rewrite had already retired most of what the issue objected to: `CollectJoinPoints`, `back_in`/`back_out`, the two-pass loop, `pending`, the fail-open-then-fail-closed `poisoned` set and `kMaxPending` are gone, and `BuildCfg` builds a real CFG.
- **(a) needed one thing it did not have: the completeness invariant** — see the section below, which found and closed seven holes and a wide-pair aliasing bug that a green suite had been hiding.

**The move.** `DexItem::AnalyzeMethodInvokes` + its private helpers (`Cfg`, `BuildCfg`, `SameOrigin`, the bounded LEB readers) are now `dexkit::ext::AnalyzeInvokes` in [native/core_ext/invoke_args.cpp](native/core_ext/invoke_args.cpp) / [invoke_args.h](native/core_ext/include/invoke_args.h), and `ArgKind` / `InvokeArg` / `InvokeSiteWithArgs` / `kDefaultArgDepth` moved with them. It was never a member in any meaningful sense: the whole input is one `dex::Code*` plus the end of the image it lives in, both already public (`GetMethodCode()` / `GetImage()`), so the free function takes those two and `dexkit_ext.cpp` reads them through a one-screen `AnalyzeInvokesOf` helper. **A pure LIFT, not a rewrite** — in particular it keeps DexKit's own `GetBytecodeWidth` and `ReadInt`/`ReadLong` (via `utils/opcode_util.h` / `utils/byte_code_util.h`, for which `${DEXKIT_CORE_ROOT}/Core/dexkit` joins `dexkit_ext`'s include path) rather than swapping in slicer's equivalent, because changing the width function is a separate decision with its own blast radius. `core_ext` including DexKit headers is not a boundary violation: only `dad_cpp` is required to stay DexKit-free. The include directory is **PRIVATE**, and that word is load-bearing — a first cut made it PUBLIC, which propagated `${DEXKIT_CORE_ROOT}/Core/dexkit` through `dexkit_dad` to every domain TU, where a DexKit header would then COMPILE. Both reviewers caught it independently and one constructed the proof: with PUBLIC, a `dad_cpp` file including `utils/opcode_util.h` builds AND `scripts/check_dad_boundary.sh` still answers `clean`, because its FORBIDDEN pattern does not match `utils/`. So the change had briefly removed the compiler as the enforcer of a boundary half the script never covered. PRIVATE restores it at zero cost — the `.so` is byte-identical either way, and no public header of `dexkit_ext` needs the directory. **Net: the vendored tree carries 858 fewer dexllm lines** (`dex_item.cpp` −772, `dex_item.h` −91/+5; 863 is the GROSS deletion count, which an earlier draft published as the net). `EnumerateInvokeSites` — a separate, self-contained ~25-line L2.5 extension the issue does not name — deliberately STAYS; moving it is not part of this decision.

**Contract fix, the issue's last item.** The MCP output key `varies_by_path` claimed "two values provably reach"; the flag it mirrors means "a definition was DISCARDED here", which is weaker (a merged edge may simply have carried nothing because it came from outside the window). Renamed to **`crossed_branch`**, the spelling every other layer already uses. (An earlier draft justified it as "the one output key that spelled a raw attribute differently"; that is FALSE — the same dict abbreviates `caller_descriptor` to `caller`, and `tools.py` does the same in at least nine places. The compact dicts abbreviate deliberately; what was wrong here was the MEANING, not the abbreviation.) The docstring plus the tool description now say *unproven*, not *more than one possible value*. The MCP surface has no consumers, so it takes no alias [[mcp-surface-has-no-consumers-yet]]. Two reviewers then found the retired reading still alive in three places the first sweep missed — the raw `ResolvedArg.__repr__` (`"(varies per path)"`, on the very layer everything was aligned TO), the `docs/api.md` fence comment `# ≥2 possible values` four lines under a table saying the opposite, and `sdk/model.py`'s comment on the FIELD ITSELF, which said "the site has more than one possible value" and escaped grep by hyphenating `varies-by-path`. All three are fixed here; a doc gate that greps for the old key cannot see a paraphrase.

**Measured (a/b, SAME script, every half `.so` md5-verified — 2a72b7… before the move, 5d3bac… after):** 34 bundled samples, 31 of which load × `resolve_call_args` at depths {0,2,4} over 400 external targets each + the `find_call_sites_from` sibling = **131,807 records / 54,771 sites / 99,657 arguments → identical sha256**, which for a pure lift is the whole point. parity 28/28, pytest 619, corpus-less 260 passed / 365 skipped, narrowed to `tests/data/multidex.apk` 522, guard files green narrowed to each of the 34 bundled samples, sweep 25,309-class / 213,374-method 0-crash 0-timeout, determinism 3 processes × 3 `PYTHONHASHSEED`s identical, lint trio clean. An adversarial reviewer additionally rebuilt the commit-1 binary and ran its OWN a/b (31 sources × depths {default,0,1,2,3,7}, 109,542 sites / 199,314 args, plus multi-source cross-dex sessions and 600 crafted lenient dexes) — sha256 identical on every axis, and a from-scratch configure reproduced the `.so` byte-for-byte. The 6-mutant matrix was **re-run against the moved file** (the guards' source locator now points at `invoke_args.cpp`) and all six still die — the path change itself was caught by the suite going red, which is the locator working.

**What #32 leaves open, deliberately:** the enumeration is still hand-maintained (checked by a test, not derived at runtime), and the primitive is still a bounded heuristic rather than a fixed point. Both are the accepted cost of (a); the issue's own framing is that deleting it is not on the table and that (b)'s tension is cost, which is now measured rather than assumed.

### A write the analyzer does not model must not leave a value behind (dexllm#32, 2026-08-18)

`AnalyzeInvokes`' `default:` branch **clears no register**, so the analysis's soundness rests on the switch above it enumerating EVERY register-writing opcode. That obligation was hand-maintained, undocumented AS an obligation, and had already been wrong twice (the `*-int/lit8`/`lit16` destination swap and the wide high half, both dexllm#16 review findings). A miss is the worst failure this API has: a stale origin survives its own overwrite and is reported with `crossed_branch` **False**, i.e. as an UNCONDITIONAL value — and the API exists to answer "which string was passed to `Cipher.getInstance`", so a hole makes it answer *confidently and wrongly*.

**Audited mechanically against slicer's own instruction table** (`dex_instruction_list.h` — a source independent of the switch): of 256 opcodes, **167 write a register, 160 were handled, 7 fell to `default:`** — ART's runtime-only **`iget-*-quick`** family (`0xE3`/`0xE4`/`0xE5`/`0xEF`/`0xF0`/`0xF1`/`0xF2`), which write vA but carry a vtable/field OFFSET rather than a field_idx, so there is nothing to track and the fix is to CLEAR. (A naive "operand A is a register" rule flags an eighth, **`check-cast` 0x1F**, as a writer; it is not — a cast leaves the value unchanged, so preserving the origin across `(String) x` is correct and wanted. Both counts appear in review notes; **167/7 is the one the shipped predicate reproduces**.) `check-cast` has **31** companions that legitimately land in `default:` carrying a register in operand A (`monitor-enter/exit` 2, `fill-array-data` 1, `aput*` 7, `iput*` 7, `sput*` 7, `iput-*-quick` 7) — all of which only READ it. That is why a blanket "fail closed, clear vA whenever slicer says A is a register" rewrite was **REJECTED**: it would clear v0 across every ordinary `iput v0, …` / `(String) v0` before a call, and a reviewer measured the cost by building it — 6 arguments lost on a 6-APK / 1,053-site sample, invisible to every source-level assertion. The fail-closed direction is obtained at the TEST layer instead, where a NEW opcode is a failure by default.

**Reachable on a STRICT-verified dex, not merely under `lenient`:** `VerifyInsns` bounds registers and indices and has **no opcode-legality gate** (there is none in ART's structural verifier either — legality lives in the runtime method_verifier we refuse to vendor), so a dex carrying one of these returns `valid: True` in BOTH modes, confirmed by measurement. An **odex-derived packer dump** is the realistic source, and `add_dumped_dexes` / `lenient=True` exist for exactly those. Worth recording: today's AOSP marks `0xE3-0xF2` as `unused-e3…` (quickening was removed from ART), so the **vendored slicer table is the only in-tree source that still knows these forms** — and it is the table our decoder actually consults. `native/dad_cpp/opcode_ins.cpp` leaves `0xE3-0xFF` `Unused`, so the two in-tree tables do not corroborate each other here.

**CONSTRUCTED, not reasoned** — a one-byte, format-preserving patch (`iget-object` 0x54 → `iget-object-quick` 0xE5; both k22c, both 2 code units, so every offset and section size is intact) on a corpus method whose `const-string v4` is overwritten by an `iget-object v4` before `PrintWriter.print(v4)`: pre-fix the argument came back **`ConstString "mName="`** (the overwritten literal, `crossed_branch` False) where the correct answer is `FieldRead BackStackRecord.mName`; post-fix it is `Unknown`. The dex verifies strict-valid on both sides.

**A SECOND hole, found by the adversarial reviewer and fixed here — wide-pair ALIASING.** dexllm#16 closed the forward direction (a wide write clears its high half); the reverse was open, so a **narrow** write to vN+1 did not invalidate the 64-bit origin parked at vN. `const-wide v0` + `const/16 v1` + `invoke {v0,v1}` reported the whole original constant for v0 with `crossed_branch` **False** — the same confidently-wrong-value class, on a strict-valid dex. Fixed with a `wide` bit on `InvokeArg` (set from the DEFINING opcode, so `move-wide` / `move-result-wide` carry it without a second opcode list) plus a `kill_wide_alias` in both `set_reg_op` and `erase_reg_op`. Not surfaced to Python. Also from that pass: `BuildCfg`'s non-falling group gained **`0x73 return-void-no-barrier`** (ART's odex return), which was getting a spurious fall-through edge — not unsound (an extra predecessor only tombstones more) but the same runtime-only-opcode family, one line away.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — f16475…/60282c… for the enumeration half, 2a72b7… for the aliasing half — and the ON build bit-reproducing its md5 after restore):** 34 sources × `resolve_call_args` at depths {0,2,4} over 400 external targets each + the `find_call_sites_from` sibling = **131,807 records / 54,771 sites / 99,657 arguments → identical sha256** across all three builds, `Unknown` 16,682 and `crossed_branch` 1,853 flat. Expected and REQUIRED to be identical: an independent scan found **0 quick opcodes across 25 APKs / 174,358 methods / 2,356,738 instructions**, and the aliasing shape is likewise corpus-absent (two heuristic "hits" were traced to the detector not modelling intervening kills). So **this a/b proves 0 regression and CANNOT prove either fix fires** ([[ab-must-prove-the-mechanism-fires]]) — the crafted guards are what prove the mechanism. parity 28/28, sweep 25,309-class / 213,374-method 0-crash 0-timeout, determinism 3 processes × 3 `PYTHONHASHSEED`s identical.

**Guards, in TWO layers because neither alone is sufficient** — and the FIRST cut of them was broken in ways only review found. [tests/test_arg_opcode_coverage.py](tests/test_arg_opcode_coverage.py) parses slicer's table and the switch and requires every writer to be handled, which makes a FUTURE opcode a failure by default (no runtime test can do that); [tests/test_arg_quick_opcodes.py](tests/test_arg_quick_opcodes.py) drives the built extension on crafted dexes. **Mutation matrix, 8 mutants, each rebuilt and run, each KILLED:** pre-fix (case removed) → both layers; **labels kept with the body emptied** → source layer PASSES, runtime layer kills, so the two are complementary rather than redundant; **six of the seven labels moved into a `//` comment** → was the reviewer's green-suite revert, now killed by a comment-stripping scan; the quick group losing its wideness; `kill_wide_alias` removed; `check-cast` added to the erase group; a writer excused by widening the predicate; and a writer dropped with no predicate edit.

**What review had to break to make those guards real:**
- the runtime layer exercised **exactly one** opcode (0xE5), so six of the seven were revertible with a green suite. Now parametrised over all seven, plus a **`test_no_two_unit_writer_leaves_the_previous_origin`** that swaps ~30 two-unit 4-bit-A writers into the same byte (a craft whose second unit lands in the wrong table simply fails to verify and is skipped, hence a floor of 8 actually exercised).
- the source layer matched `case 0xNN:` **inside comments**. `_strip_comments` is a left-to-right scanner, NOT two regex passes: this very file contains `// ---- const-wide/* ----`, and a `/* … */` regex applied first swallows ~290 lines to the next `*/` — which SHRINKS the audit silently instead of failing it. That trap was hit while writing the fix and is pinned by the stripper's own self-check.
- `test_a_read_only_operand_a_keeps_its_origin` asserted only a property of the TEST's own predicate; the analyzer was never consulted, so adding `check-cast` to the erase group passed. Replaced by `test_check_cast_preserves_the_origin`, which runs on unmodified corpus code.
- `_READS_A_ONLY` is an EXCUSE list living beside the assertion it feeds, so widening it excuses an arbitrary writer (demonstrated: delete `case 0x0D:` and add `"move-exception"`, suite green). Now pinned as a literal, which does not make it impossible but makes it a deliberate two-place edit.
- the shape finders took the FIRST smali match and hard-failed if the analyzer disagreed, and read `extract_dex(0)` while `list_classes()` spans every dex — a multi-dex sample whose shape lives elsewhere ERRORED instead of skipping (issue #46, reproduced by a reviewer from two bundled dexes). Finders now yield candidates, the caller filters by running the unpatched dex, and the dex is located with `locate_class_dex`.

**Still hand-maintained, now merely checked:** the enumeration is not derived at runtime from slicer's tables, so the invariant lives in a test rather than in the type system. That is the accepted residue of choosing option (a) — see the decision record above.

### A cache-init failure REPORTS — it no longer blocks every waiter forever (dexllm#55, 2026-08-18)

`DexKit::InitDexCache` published a dex's "cache ready" flag ONLY on the success
path. `DexItem::BeginInitCache` CLAIMS the flags it is about to build
(`init_cache_inflight_flags`), `FinishInitCache` is the only publisher and is the
task's LAST statement, and `DexItem::WaitInitCache` is a `cv.wait` with no
timeout and no failure state. So a task that did not reach its last statement —
for any reason — left the claim outstanding and every waiter blocked **forever**,
silently: `ThreadPool::enqueue` wraps the task in a `std::packaged_task`, so a
throw is captured into a future, and `InitDexCache` **discards the future**.
Nothing observed it, the worker survived, and the process did not abort.

**Reachable from a `verify()`-valid dex, and reproduced deterministically.**
Repointing one class_def's `annotations_off` at the map_list — a well-formed
offset holding the wrong structure — yields a dex the structural verifier calls
valid in BOTH strict and lenient mode (annotations are documented out of its
scope), on which `warm_analysis_caches` / `find_call_sites_to` /
`resolve_call_args` / `summarize_capabilities` never return, while
`list_classes` / `render_class_smali` / `decompile_class` / `list_value_strings`
answer normally — the split the issue measured, and itself evidence that the task
aborts inside a specific `InitCache` branch rather than being skipped wholesale.

**Fix — publish the OUTCOME, not only success.** Each of the three
claim/publish state machines gains a failure half:
`DexItem::AbortInitCache` / `AbortPutCrossRef` / `DexKit::AbortBuildCrossRefAggregates`
retire the claim and record `*_failed_flags` + the reason; the matching `Wait*`
waits on `(ready | failed)` and THROWS `std::runtime_error` naming the cause
(pybind → `RuntimeError`); `Begin*` excludes an already-failed flag, so the
failure is sticky and a retry reports instead of re-running work known to throw.
Two things make the publish unconditional rather than best-effort: the task body
runs under a `try`/`catch(...)` that aborts the claim, and the enqueuing thread
retires every claim again once the pool is JOINED — a no-op for flags the task
already published, and the net for a task that never ran at all. **A review
found the second one was not actually unconditional**: it sat after the pool's
scope, so a throw from `pool.enqueue` itself (it allocates twice) skipped it
entirely and stranded the claims of every job not yet submitted — the same
permanent block, reached through the code that installs the cure. The retire is
now in a `catch (...)` + rethrow on both job loops.
`WaitInitCache` keys the throw on the **FLAG, never on the message** — the flag
is the state that means "failed", and `Abort*` never stores an empty reason, so
a caller can never proceed on a cache that was not built.

**The fix had to close a hang it would otherwise have CREATED.**
`EnterQueryExecution` sets `warmup_inflight = true`, unlocks, calls
`InitDexCache`, and clears the flag after it returns. Making `InitDexCache` throw
would leave that flag set forever, so every later query would block in
`EnterQueryExecution`'s own wait — the same hang moved one frame up. It is now
retired on both paths.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `feda34d3…`
OFF, `5d0f0942…` ON, and the ON build bit-reproduced its md5 after the swap):**
34 bundled sources (31 loadable) × 13 axes — verify_report, class list, value
strings, `warm_analysis_caches`, external refs, call sites, resolved call args,
field xref, capabilities, IOCs, permission callers, decompile, smali = **406
records, identical sha256, 0 diff**. Required to be identical: the failure is
crafted-input-only, so this proves 0 regression and **nothing** about the
mechanism — the crafted guard does. parity 29/29, pytest 631 passed.

**The first a/b was WRONG and its own axis proved it**: `json.dumps(…,
default=str)` renders a `set` through `str()`, whose order follows per-process
string hashing, so the capability axis reported 4 spurious differences that
reproduced across three `PYTHONHASHSEED` values on ONE build. Canonicalised
(sets sorted) before re-measuring both sides.

**Guards** ([tests/test_cache_init_failure.py](tests/test_cache_init_failure.py)).
**The crafted-dex half was RETIRED by dexllm#72** — see that section; the record
below is what those 10 cases were and why they are gone, because the file has now
been re-based twice and cannot be a third time. Every call that could hang ran in
a **SUBPROCESS with a deadline**, so a regression FAILED the suite instead of
hanging it — an in-process assertion cannot do that. The fixture crafted the dex
IN PLACE and length-preserving, tried each bare `.dex` in turn, and required the
craft to ACTUALLY break cache init before using it (otherwise the guards would
pass vacuously); 3 of the corpus's 9 bare dexes carried the shape. It separated
THREE outcomes, which the first cut conflated into one and a review took apart:
no bare `.dex` at all (the corpus-less CI leg) SKIPS — an environment fact; bare
dexes that exist but are not craftable go through `require_corpus_shape`; and a
craftable dex whose probe HANGS FAILS unconditionally, narrowing or not, because
that is a fact about the product. The first cut instead `continue`d past a hang,
so a real #55 regression was reported as "no shape in the bundled corpus" — and
SKIPPED outright under a narrowing (reproduced: pre-fix + `$DEXLLM_TEST_APK` gave
10 green tests). It also globbed a RELATIVE path, so the corpus-less leg hit
`pytest.fail` rather than a skip — the issue #46 trap, in a file written after
reading the rule. What replaced them is SOURCE-level pins on the publish/retire/
throw state machine plus the one behavioural guard that survives (`RLIMIT_NPROC`,
which reaches the pool CONSTRUCTOR rather than a task). **The first cut of those
pins had a hole a correctness reviewer found by building it:** `WaitInitCache`'s
BODY was pinned and its CALL SITE was not, so deleting
`dex_item->WaitInitCache(init_flags);` — which makes a published failure go
unread and the caller proceed on caches that were never built — passed the whole
suite at the published 1040. The retired behavioural guards killed it loudly (9
errors, all "warm_analysis_caches never returned"); nothing else did.

**Mutation matrix — and the three survivors are the interesting part.** Killed:
the pre-fix module (9 errors — the fixture itself can no longer be built, which
is the hang), the `EnterQueryExecution` try/catch (2 failures), and the task's
own try/catch (M7). **Survivors, each investigated rather than waved away:**

- **the in-flight retire and the sticky exclusion MASK EACH OTHER.** Removing
  either alone changes nothing observable — stickiness makes `BeginInitCache`
  return before it ever consults the leaked claim, and retiring the claim makes
  stickiness unnecessary for liveness. Verified they are not merely
  hard-to-reach: no single-threaded ordering hangs (4 API orderings tried), and
  neither does an 8-thread concurrent warm (`EnterQueryExecution` serialises the
  warmup, so the second claimant never races the first). Only the COMBINED
  mutant hangs, and the second-call guard kills it. Same shape as the
  ThreadPool handler pair already recorded in this file.
- **the flag-keyed throw was UNGUARDED**, because no crafted input produces an
  empty reason. Rather than leave an untested branch, `Abort*` now never stores
  an empty reason (`"unknown error"` if one arrives), which makes the
  message-keyed variant a provably EQUIVALENT mutant instead of an escape, and
  deletes the dead `error.empty()` fallback at both throw sites. The flag is
  still what the throw reads: it is the state that means "failed", and a
  message-keyed test would silently stop raising if that ever changed.

**Known costs and gaps, stated rather than discovered — several of them by the
review, not by the design:**

- **the sticky failure is COARSE.** `InitCache` builds a whole claimed SET and
  publishes it in ONE `Finish`, so a throw anywhere fails the set, including
  parts already built. Measured: on a crafted dex `find_methods_using_strings`
  returns 683 hits in a fresh process, and 0 (raises) if a failing
  `warm_analysis_caches` ran first — one broken annotation table retires string
  search for the process lifetime. Deliberately conservative (a half-built cache
  must never look ready) and no worse than the pre-fix hang, but it is a real
  loss of function, not merely a diagnostic. Flags a PREVIOUS round published
  stay usable — `Abort*` never marks a ready flag, verified.
- **a `Begin*` return of 0 no longer means "ready"** — it means ready OR
  permanently failed, so a caller MUST pair it with the matching `Wait*`. All
  three call sites do; the contract is now on the declarations.
- **partially-built caches became OBSERVABLE** where they used to be unreachable
  behind the hang: `InitCache` resizes `method_caller_ids` / `method_invoking_ids`
  long before the throw point, and `GetCallMethods` / `GetInvokeMethods` guard on
  `!empty()` rather than on `dex_flag`. Every Python path reaches them through a
  warmup that raises first, so it is not reachable today; it is recorded because
  the guard is not the flag.
- **one error slot per DexItem** — the FIRST reason wins, which is what keeps the
  task's own diagnosis from being overwritten by the generic post-join retire,
  at the cost of a later unrelated failure being reported with the earlier
  message.
- **`PutCrossRef` and `BuildCrossRefAggregates` have no test of their own.** They
  are changed for CONSISTENCY; no crafted input is known that reaches them (they
  run off maps `InitCache` already built, so a corruption fails earlier).
- **the post-join retire is a NET with no test either.** On this input the
  in-task `catch` always publishes first. Its real reason is the enqueue-throws
  path above — NOT, as the first cut's code comment claimed, `ThreadPool::enqueue`
  dropping a task: `enqueue` drops nothing, the skip is evaluated in the task
  body, and these pools pass no skip function at all, so that branch is dead.

**What a second, adversarial review found — three of them defects the fix
itself introduced or depended on, all fixed here:**

- **`ThreadPool`'s CONSTRUCTOR was not exception-safe, which silently voided the
  recovery above.** `std::thread`'s ctor throws when the process is out of
  threads (RLIMIT_NPROC, a container pids limit); unwinding out of a partially
  built pool destroys a still-JOINABLE `std::thread`, which is
  `std::terminate()` — the process dies before ANY caller's catch runs.
  Reproduced with a real `RLIMIT_NPROC`: failing the FIRST pool thread was
  already survivable, failing the SECOND aborted, and 2+ threads is the normal
  configuration for a multi-dex source. The spawn loop now stops, notifies and
  joins what it built before rethrowing.
- **a TRANSIENT failure was latched permanently.** The sticky exclusion is
  justified by "work known to throw on this dex", which is false for "out of
  threads" — and the new catch was exactly what converted a one-instant blip
  into a dead `DexKit` for its lifetime, told to the caller as the generic
  "cache init task did not run". The exception path now RELEASES the claim
  without latching a verdict (it rethrows, so nobody waits for one), while the
  post-join path still latches (the `Wait*` after it needs a verdict).
  Verified: the blip reports `Resource temporarily unavailable`, and the retry
  after it succeeds.
- **`extract_iocs` SWALLOWED the new exception**, turning a loud hang into a
  silently wrong triage report: its per-query `except Exception` ("one bad query
  must not abort the report") caught a systematic cache-init failure too, so
  every indicator came back with `methods: []` and no error — which reads as
  "this indicator appears in no code", the exact ambiguity `declared_in` was
  added to remove. Both it and `detect_content_providers` now re-raise when NO
  query has ever succeeded, which is the difference between one bad query and
  the whole cross-reference layer being unavailable.

Also from that pass: the `AbortInitCache` contract comment overstated safety
(it is safe only for flags THIS caller claimed — the retire clears them from a
shared mask), and the section's pytest count was stale.

**Not the whole story — a SEGV on the same crafted family is filed separately.**
Two other `annotations_off` corruptions SIGSEGV instead of throwing, on a
`verify()`-valid dex, and reproduce identically on the pre-fix build: a signal
never unwinds, so no exception path can contain it. ART's own `DexFileVerifier`
DOES check annotations (`CheckIntraAnnotationsDirectoryItem`, and
`dex_file_verifier.cc:2969`'s `CheckOffsetToTypeMap(annotations_off,
kDexTypeAnnotationsDirectoryItem)`), which is precisely what this port lists as
out of scope alongside the offset→map-type cross-check.

### A pool destroyed on its own worker DETACHES instead of joining itself (dexllm#50, 2026-08-18)

`ThreadPool::~ThreadPool` joined every worker unconditionally. A pool task can
hold the last reference to its own pool — `QueryScheduler::EnqueueDispatchTasks`
captures a `shared_ptr` to the scheduler into a lambda that runs ON the pool, and
the scheduler owns the pool — so when `DexKit` drops its references while a
dispatched lambda is still alive, the last scheduler reference is the one inside
that lambda. Destroying it on the worker destroys the pool THERE, and the
destructor then joined the thread it was executing on: `std::system_error`
"Resource deadlock avoided", uncaught in a thread, `std::terminate`.

**Reproduced deterministically — the issue's own precondition for a fix.** #50
was filed on the code path, observed once and never reproduced ("without that, a
fix cannot be shown to work"). A 30-line standalone program that lets a task own
its pool aborts **10/10** with the exact reported message, and the
scheduler-shaped variant (task → intermediate owner → pool) does too.

**Fix — the shared state OUTLIVES the object.** Everything a worker touches
(queue, mutex, condition, `stop`, `should_skip_task`, `thread_ids`) moved into a
`State` held by `shared_ptr`; the worker lambda captures `state` and NOT `this`,
and so does the packaged task (a queued task can outlive the object, so reading
`should_skip_task` through `this` was a latent use-after-free of its own). The
destructor then detaches the ONE worker it is running on and joins the rest: that
worker's loop reads only `State`, which its own reference keeps alive, and `stop`
is already set, so it exits as soon as the queue drains. Destruction from a
non-worker is **unchanged** — it still joins every worker, which is the contract
the rest of the core relies on.

**Accepted costs, two of them found by review rather than stated up front:**
(1) the self-destruct path leaves one DETACHED thread where before there were
none, so if the process calls `exit()` in that window a detached thread can run
during static destruction. (2) On that path the destructor no longer implies
"every queued task has finished" — the detached worker keeps draining the queue
AFTER the destructor returns and the owner is gone (measured: with a
single-worker pool, 0 tasks done at return and the rest run afterwards). Only a
single-worker pool can reach it (any other worker drains before its join
returns), and DexKit cannot, because a queued dispatch lambda holds a reference
that would have kept the pool alive. Destruction from a NON-worker is unchanged
and still joins. The queue is deliberately not cleared instead: dropping a
queued task leaves its `std::future` unsatisfied forever, which is the failure
mode dexllm#55 exists to remove.

**Why not the other two directions the issue listed:** a `weak_ptr` capture at
the dispatch is not sufficient — `TaskCompletionGuard` must hold a STRONG
reference while it reports completion, and any strong reference on a worker can
become the last one. Keeping the pool alive past the scheduler does not help
either, because the scheduler holds a reference to the pool, so a scheduler
destroyed on a worker takes the pool with it wherever the owner's own references
went. Fixing it inside `ThreadPool` covers every present and future ownership
mistake instead of one call site.

**Measured:** the same 406-record a/b as dexllm#55 above (both fixes were built
and measured together) — **identical sha256, 0 diff**. ASan and TSan on the
reproducer: **clean, 5 runs each**. parity 29/29 (the suite gains
`thread_pool_selfdestruct_test`; `ctest` now reports 29), pytest 619 passed.

**A second UAF the detach opened, found by review and fixed here.**
`ReleaseMatcherThreadLocalCaches(_thread_ids)` used to run after EVERY worker was
joined, i.e. once they were all dead. With one worker detached, the same call
deleted the matcher cache of a thread that is still RUNNING — and
`dex_item_matcher.cpp` holds it in a `thread_local` RAW pointer that no other
thread can reset, so the detached worker would dereference freed memory on its
next task (reviewer's ASan repro: `heap-use-after-free ... thread T1`).
Now only the ids of threads that were actually JOINED are released; the detached
worker keeps its cache — one leaked cache on a teardown-only path instead of a
use-after-free. Verified with an instrumented registry: the live worker's id is
released 0 times with the fix and 1 time without it. `thread_ids` left `State`
entirely with that change — the destructor reads the ids off the `std::thread`
objects, which is race-free and, unlike a slot each worker fills in itself,
already correct before a worker has started.

**Guards**
([tests/parity/thread_pool_selfdestruct_test.cpp](tests/parity/thread_pool_selfdestruct_test.cpp),
7 cases, registered explicitly rather than through the `*_parity_test.cpp` glob —
it includes a DexKit third_party header, which `dexkit_dad` must not carry, and
it STUBS the matcher-cache registry instead of linking `dexkit_static` so a case
can assert WHICH thread ids the destructor released; without that the live-thread
fix above survived a reviewer's mutant 15/15). Every self-destruct case now
PARKS its task until the enqueuing thread has released and then ASSERTS which
thread ran the destructor — without the barrier the last reference can land on
the MAIN thread and the case passes having exercised nothing (it did: the
released-ids case failed the moment it started checking). A seventh case
calibrates `RLIMIT_NPROC` in-process (a `ps`-based estimate misses the one-value
window — measured: it passed against the defect) and pins that the constructor
REPORTS being out of threads rather than terminating.
Cases 1 and 2 (the direct and scheduler-shaped ownership edges) **abort 5/5
against the pre-fix header and pass 5/5 after**, verified per case. **Case 3
exists because a reviewer showed the first four guarded only HALF the fix**:
reverting the worker's capture from `state` to `this` passed the whole file 5/5
in a normal build and was caught only under ASan, because cases 1 and 2 destroy
the pool with an EMPTY queue so the detached worker exits immediately. Case 3
destroys a single-worker pool with 16 tasks still queued, so the detached worker
keeps running them against an object that no longer exists — it kills that
mutant **5/5 with a SIGSEGV in a plain build**. Cases 4 and 5 are
non-discriminating BY DESIGN and say so: they pin the contract the fix must not
break — destruction from a non-worker still joins every task, and a task
enqueued from inside a task still runs.

**The first cut of the guard observed the wrong moment**, and only a per-case
matrix showed it: a flag set by the task (or by the intermediate owner's
destructor) fires BEFORE the pool is destroyed, so the test could reach its end
and exit while the dangerous destruction had not happened yet — case 2 then
passed against the pre-fix header. Every case now signals from a `shared_ptr`
DELETER, which runs strictly AFTER `~ThreadPool` returns. **The matrix itself was
wrong first**: the generated per-case file sat in the same directory as the
saved pre-fix `ThreadPool.h`, and a quoted `#include` searches the including
file's own directory first — so BOTH halves compiled against the pre-fix header
and the "post-fix" column was a copy of the "pre-fix" one.

### The annotations subtree is verified — "the core lazy-parses it" was the wrong test (dexllm#56, 2026-08-18)

`class_def.annotations_off` reached the decode path having been checked for
NOTHING — not that it is in range, and not that it points at an
annotations_directory rather than at some other section. It was excused as
"annotations are lazy-parsed by the core", which is TRUE and IRRELEVANT: the core
parses them (`Reader::ExtractAnnotations`, straight off the class_def, during
`InitCache`), so "lazy" meant "later", not "never".

**The result was a SIGSEGV on a dex `verify()` calls valid in BOTH modes** — the
one failure this project's docs promise cannot happen ("0-crash on malformed
dex", `VerifyDex` as "the single gate"). Reproduced exactly as filed: of 9 crafts
(3 annotated corpus dexes x 3 target offsets, each a 4-byte offset-preserving
repoint) **all 9 verified valid, 7 threw and 2 died**, the split decided by
whichever `SLICER_CHECK` fired first rather than by any gate. Pre-existing — it
reproduces on a rebuilt `7d5b34b`.

**The channel needed TWO documented omissions at once**, either of which alone
would have blocked every input: annotations, and ART's offset->map-type
cross-check (`CheckOffsetToTypeMap` :2564). That second one is NOT ported and
deliberately stays that way, but the reason had to be stated honestly:
`docs/dexkit-vs-art-dex-handling.md` justified it as "contents are validated
directly ... so it stays crash-safe", and that sentence was simply FALSE for
annotations. Without a type map, "the contents are validated directly" has to
hold for EVERY referenced structure; one exception is a crash.

**Fix — walk the subtree, in the shape this port already uses.** ART is
MAP-driven (iterate each section item by item, record `offset -> type`, then
check every reference against it); this port is REFERENCE-driven (walk from the
header's tables and validate what each offset points AT), which is why
`VerifyClassData` / `VerifyEncodedArrayAt` / `VerifyTypeList` exist for the other
four `class_def` offsets. `VerifyAnnotationsDirectory` ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp))
is the fifth: ART's `CheckIntraAnnotationsDirectoryItem` :2111 +
`CheckIntraAnnotationItem` :2056 fused with the offset-following of
`CheckInterAnnotationsDirectoryItem` :3276, because a reference-driven port has
nowhere else to put the second half. Porting `offset_to_type_map_` instead was
rejected: it would mean restructuring the whole verifier to be map-driven for one
section. The walk covers **exactly** what `reader.cc` dereferences, verified line
by line against it — directory header, `class_annotations_off`, the three
per-member lists (bounded, index-checked, order-checked), each `annotations_off`
-> set -> item -> visibility byte -> `encoded_annotation` through the existing
depth-capped `VerifyEncodedValue`, and the parameter `set_ref_list` -> its sets.
The bare `encoded_annotation` was factored out of the `0x1d` value case, since
`annotation_item` stores that form raw exactly as `encoded_array_item` does.

**Non-zero on the three per-member offsets is load-bearing, not ART parity.**
ART checks them unconditionally and the slicer agrees by throwing
(`SLICER_CHECK_NE(annotations, nullptr)`) — except for the parameter one, where
`ExtractAnnotationSetRefList` has **no zero guard at all**, so offset 0 reads the
dex HEADER as a set_ref_list and takes its element count from the magic bytes.
Only `class_annotations_off` may legally be 0, and only a `set_ref_list` ENTRY
may (it means "this parameter carries no annotations").

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `a2fab8b8...`
OFF matching the md5 in the issue, `69aa8ffc...` ON, and the ON build
bit-reproducing its md5 after the swap):** 34 sources x {strict verify, lenient
verify, `verify_report`, `dex_count`, class list, whole-corpus smali render,
whole-corpus decompile, class summaries} -> **0 differing records, 0
false-reject** (the 9 invalid rows are the 3 resources-only containers, on both
sides). Verify cost 157.0 -> 161.8 ms best-of-7 over the whole APK corpus (+3%).
parity 29/29.

**The 0-diff is required, so it proves nothing on its own** ([[ab-must-prove-the-mechanism-fires]]).
What separates "the corpus is well formed and the walk accepts it" from "the walk
is dead" is the count: across 23 sources it walks **23,411 directories / 43,575
sets / 38,140 items / 10,325 parameter ref-lists**, every one accepted.

**Fuzzed, because the claim is memory safety and 9 crafts are not a proof:** 1,500
random multi-byte mutations confined to the annotation sections -> 123 still
verify valid -> **0 killed by a signal**, 122 clean, 1 throw.

**That 1 throw is a separate, pre-existing finding the fuzz surfaced.** The
vendored slicer's `Reader::ParseEncodedValue` implements 16 of the 18
`encoded_value` types: `0x15 METHOD_TYPE` and `0x16 METHOD_HANDLE` fall through
to its `SLICER_CHECK(!"unexpected value type")`. Both are legal per the dex spec
(invoke-dynamic constants, API 26+), so the verifier accepting them is CORRECT —
rejecting them would false-reject real apps, which is strictly worse than a
throw. 0 incidence across the bundled corpus, so it is latent. The gap is in the
slicer, not the gate, and fixing it was out of #56's scope — **filed and then
fixed as dexllm#57, see its section below**, which also re-based #55's fixture a
second time (the craft is unchanged; only the layer that throws moved).

**It also cost dexllm#55 its fixture, and that re-base is part of this change.**
#55's guards crafted the SAME `annotations_off` repoint to make cache init throw;
closing the channel made the fixture unbuildable and turned 9 tests into hard
errors, correctly naming the reason. `tests/test_cache_init_failure.py` then
retyped ONE annotation element to `0x16` — a **one-byte** craft, and (this said)
"a channel no future verifier improvement can take away, because closing it at
the gate would be a false-reject". **That claim was FALSE**: ART's
`NumMethodHandles()` is 0 for a section-less dex, so ART rejects exactly this
craft — dexllm#59 measured it and dexllm#72 acted on it, retiring the vehicle for
good. Kept here because the sentence is the mistake, not a typo: a channel was
called permanent without checking what ART does with the same bytes.

**Guards** (33 in [tests/test_verifier_annotations.py](tests/test_verifier_annotations.py)),
crafted IN PLACE and length-preserving (a `u4` for a `u4`, a byte for a byte), each
verifying its own premise (the UNMODIFIED source must verify valid, or the
rejection is not attributable) and SKIPPING rather than failing when the sample
lacks the shape (issue #46 — only 3 of the bundled bare dexes carry any
annotation, and only 1 carries a parameter annotation). The crash guards run in a
SUBPROCESS with a deadline and assert on the SIGNAL: an in-process assertion
cannot survive the thing it asserts about.

**23-mutant matrix, each BUILT and RUN — and the value was entirely in the
survivors.** The first pass killed 9 and left 2 alive, both real holes the guards
had missed: deleting the `VerifyAnnotationSetRefList` call outright (the
parameter offset is the only path to a `set_ref_list`, so nothing else reaches
it), and deleting the `CheckListSize` on `set->entries` — which is not merely a
missed rejection but the VERIFIER ITSELF reading past the image while deciding
whether the image is well formed, breaking the contract's first guarantee in the
one function that exists to uphold it. A second pass then found `VerifyAnnotationItem`
revertible to a visibility-byte check with the whole suite green — i.e. the
CONTENT of the annotation was unguarded, while `dex::Reader::ParseAnnotation` is
the exact frame the SIGSEGV backtrace bottoms out in. **Structure without content
is not a bound.** All three are now pinned (a repointed parameter offset, four
oversized-count cases, a bad `encoded_value` type code, an out-of-range element
index).

**One mutant is EQUIVALENT on output and was decided by measurement instead** —
the per-kind memo, which no output test can catch. It is not decoration: on a
craft the corpus itself yields (5,665 class_defs pointed at one 1,279-node
subtree, length-preserving and still verify-valid) removing it costs **17.4 ms ->
279.4 ms, 16x**, growing quadratically in both factors, while costing 3% on clean
input — the `gt_budget` / `kMaxDeclaredIds` shape. Pinned by a RATIO guard (both
verifies back to back in one process, so machine speed cancels; ~2.8x with the
memo, ~45x without, threshold 15x) that skips unless the corpus can produce a
genuinely amplifying craft. Finding that craft needed dexes from INSIDE the APKs
— the first cut searched bare `.dex` only and silently skipped.

**Two independent reviewers, and BOTH findings were in the GUARDS, not in the
verifier** — the adversarial pass ran its attacks on reader-coverage, verifier
totality, memo safety, recursion bounds and 0-false-reject and REFUTED all of
them; the correctness pass independently rebuilt both sides, re-derived the
0x1d refactor's depth arithmetic (identical cutoffs through the array path and
the new annotation-item path), reproduced the pre-fix SIGSEGV, and re-ran the
zero-offset asymmetry, the ordering predicate and a 128-case type-confusion
sweep clean. What they found:

- **CONFIRMED, and it is the shape this file keeps recording** — the three
  `CheckIndex` calls on the directory MEMBER indices (`field_idx` / `method_idx`)
  had **no guard at all**. The reviewer neutered all three to `if (false)`,
  rebuilt, and every one of the 27 guards still passed; a `classes.dex` whose
  LAST method-annotation entry carries `method_idx = 0xFFFFFF00` then verified
  valid and **SIGSEGV'd** (`ExtractAnnotations` -> `ParseMethodAnnotation` ->
  `GetMethodDecl` -> `MethodIds()[idx]`, unbounded in `reader.cc`). The
  production code was correct throughout — the gap was that a change whose whole
  discipline is "no load-bearing line without a mutant that kills it" had three
  such lines. The ordering checks were in the same state (a mutant survives, but
  ordering never reaches memory, so it is ART-parity rather than crash surface).
  Both are pinned now, parametrised over field/method/parameter; the index guard
  targets the **LAST** entry precisely because `i != 0 && last >= idx` cannot
  fire there, so nothing but `CheckIndex` can be claiming the rejection.
- **MEDIUM — the memo's ratio guard was a COIN FLIP, and the cause was a number
  in this file's own first draft.** It claimed "~2.8x with the memo, ~45x
  without"; the 45 was arithmetic across two DIFFERENT dexes (the big shared
  craft's memo-off time over a small dex's baseline). Measured with both sides
  being the same file it is ~0.9x vs ~15x — so the 15x threshold sat exactly on
  the mutant, and the reviewer built it and ran the guard ten times: **5 failed,
  5 passed**. Threshold is 5x now. The lesson is narrow and repeatable: a ratio
  guard's margin has to be measured with the ratio the guard actually computes,
  not assembled from two separate measurements.

**Still out of scope, deliberately:** `CheckOffsetToTypeMap` (above), the
annotation definer-match (`CheckInterAnnotationsDirectoryItem`'s "does this field
annotation belong to the annotated class" — a wrong-answer gap, not crash
surface), and `hiddenapi_class_data` (not parsed by the core).

### `invoke-polymorphic` is not false-rejected — `arg[]` is a per-FORMAT layout (dexllm#58, 2026-08-18)

`VerifyInsns`' vararg-register loop bounded `d.arg[0..vA-1]` for **every** opcode
carrying `kVerifyVarArg`. Its comment ("args in d.arg[0..vA-1]") is true for `35c`
and **false for `45cc`** — `invoke-polymorphic` (0xFA), the only other varargs
form, which carries a SECOND index. The slicer decodes it
([dex_bytecode.cc:280](vendor/dexkit_core/Core/third_party/slicer/dex_bytecode.cc#L280))
as `vC` = the first argument register, `arg[0..3]` = vD..vG, and
**`arg[4]` = proto@HHHH**. So the window was **shifted by one at every arity**:

1. **`vC` was bounded by NOTHING**, at every `A`. 0xFA's flags are
   `kVerifyRegBMethod | kVerifyVarArgNonZero | kVerifyRegHPrototype` — no
   `kVerifyRegC` — so the one loop that was supposed to cover the argument list
   skipped the register at the front and read one slot too many at the end.
2. **At `A == 5` that extra slot IS the proto index, and the shift became a FALSE
   REJECT.** Reproduced on an **unmodified AOSP file** —
   `tools/dexter/testdata/method_handles.dex` — whose 16 `invoke-polymorphic`
   sites include exactly two with `A == 5`; replaying the verifier's own predicate
   (widths from the vendored `dex_instruction_list.h`, decode mirrored from
   `dex_bytecode.cc`) isolates them: `verifier_checks=[2,3,1,4,82]` and
   `[2,3,1,4,91]` against `registers_size=5`, where 82 and 91 are prototype
   indices. `DexKit(path)` raised, `verify()` said `code: vararg register out of
   range`, and nothing in that APK could be analysed. Below `A == 5` the extra
   slot is an unused nibble, which a compiler zeroes — which is why only `A == 5`
   ever showed up on real output, and why the other 14 sites,
   `art/test/dexdump/invoke-custom.dex` and `const-method-handle.dex` (all
   `A <= 4`) load fine and the defect went unseen for as long as it did.

**A false reject is the one failure direction an ADDED check has that ART's own
verifier cannot** (`VerifyInsns` is this port's single deliberate non-port), and
this repo already ranks it: dexllm#57 declines to reject spec-legal `0x15`/`0x16`
encoded values precisely because "rejecting them would false-reject real apps,
which is strictly worse than a throw". Here it was not hypothetical — and an
affected APK does not degrade, it is refused. `lenient=True` was the only way in,
and it disables *every* instruction-operand check rather than this one.

**Fix** ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp)): branch the loop on
the instruction FORMAT — for `k45cc` the argument sequence is
`{vC, arg[0], arg[1], arg[2], arg[3]}` truncated to `vA`, and `arg[4]` is not a
register. `fmt` was already computed a few lines below for the index-operand check
and only needed hoisting. The branch is **complete, not a heuristic**:
`kVerifyVarArg[NonZero]` appears on exactly two formats in the slicer's own table
— `k35c` (8 opcodes) and `k45cc` (0xFA alone) — which a guard re-derives from
`dex_instruction_list.h` so a third would fail rather than fall through.
`invoke-polymorphic/range` (0xFB, `k4rcc`) is untouched: it carries
`kVerifyVarArgRangeNonZero`, and the range branch reads `vC`/`vA`, never `arg[]`.

The sequence is **ART's own**, not a re-derivation: an adversarial reviewer used
`Instruction::GetVarArgs` (`dex_instruction-inl.h:563`) as the oracle — ART uses
the SAME function for 35c and 45cc, filling `arg[0..4]` with C,D,E,F,G, and
`CheckVarArgRegs` bounds `idx < vA` — so `{d.vC, d.arg[0..3]}` is exactly the set
ART checks.

**Corollary, stated because something got LESS checked:** the proto index used to
be bounded against `registers_size` **by accident**, and now is bounded by
nothing. That matches the documented index-operand scope (`kIndexMethodAndProtoRef`
and `kIndexCallSiteRef` both fall to the `default:` arm), and nothing dereferences
either — `ResolveConstRef` returns `monostate` and the invoke collectors gate on
the 0x6E-0x72 / 0x74-0x78 opcodes. The comment above that switch used to claim the
bound outright ("so the core never asks the slicer for a nonexistent id"); it now
says which kinds it covers and that a consumer which starts reading the others
must add the bound in the same change.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `69aa8ffc…` OFF
and `4e4a8d35…` ON, and the ON build bit-reproducing its md5 after the swap):**
49 sources — the whole bundled corpus, the committed `tests/data/multidex.apk`,
every `art/test/dexdump/*.dex`, and the dexter testdata dex — × {strict verify,
lenient verify, load, `dex_count`, `verify_report`, class list, and a smali +
decompile digest over the first 40 classes} = **319 axis records, 6 changed, ALL
of them on `method_handles.dex`** and all in the direction rejected → loads (24
classes). **0 other source moved on any axis**, and `lenient` verdicts are
unchanged everywhere (lenient already accepted it, which is the asymmetry that
made the defect survivable rather than invisible). parity 29/29, pytest 677
passed / 6 skipped, corpus-less 274 passed / 409 skipped / 0 failed, narrowed to
`tests/data/multidex.apk` 580 passed, the guard file green narrowed to **each of
the 34 bundled samples one at a time** (25 APK + 9 bare dex) plus the committed
one, sweep 27,018-class / 229,537 method-block
0-crash 0-timeout, determinism 3 processes × 3 `PYTHONHASHSEED`s identical, lint
trio clean.

Unlike most changes in this file the a/b is **not** required to be byte-identical:
the corpus carries no `invoke-polymorphic` at all — 0 occurrences of 0xFA / 0xFB /
0xFC / 0xFD across all 33 dex-bearing sources (the 32 bundled ones plus the
committed `tests/data/multidex.apk`), counted with the PRODUCT's
own decoder (a `render_class_smali` sweep) rather than a hand-rolled instruction
walk, which is not pedantry: a hand-rolled width walk written for this section
desynchronised on payload-bearing methods and reported a confident 88 before the
cross-check killed it. So a 0-diff would have proved only that the corpus is
quiet. The 6 changed records ARE the mechanism firing. A reviewer also ran a
**13,216-case differential fuzz** (all 256 opcodes × 6 A|G patterns × 6 operand
patterns, plus 4,000 random) in place on `tests/data/multidex.apk` against both
builds: **7 verdicts differ, all on 0xFA**, 6 of them accept→REJECT (the new `vC`
bound) and the single relaxation is `A=1` with a nonzero *unused* vD nibble —
i.e. the old code over-rejecting, which ART also accepts.

**Guards** (9 functions / 13 collected cases, in
[tests/test_verifier_invoke_polymorphic.py](tests/test_verifier_invoke_polymorphic.py)),
crafted from `tests/data/multidex.apk` — the one container this repo commits — so
they hold in the corpus-less CI leg and under any `$DEXLLM_TEST_APK` narrowing,
and the AOSP dex is evidence rather than a dependency (the sole exception is the
no-false-reject floor, which walks the loaded corpus and SKIPS where there is
none). The craft is length-preserving to the code unit: an instruction prefix
measuring exactly 4 code units (`invoke-direct` + `return-void`, in a method with
no try/catch) is overwritten by one 4-unit instruction, so `insns_size`, every
later instruction boundary and every section offset are untouched (verified: 688 →
688 bytes, all 5 differing bytes inside the window), and the fixture asserts the
prefix's SHAPE before patching so a substituted container fails loudly instead of
being patched at a wrong offset. **The proto index is the fixture's load-bearing
knob**: the acceptance guard needs it ABOVE `registers_size` (or the pre-fix build
accepts too and the guard proves nothing), and the register guards need it BELOW
(or the pre-fix build rejects on `arg[4]` and they pass against the very defect
they exist to catch).

**6 mutants, each BUILT and RUN, each killed by its intended guard.** Four were
enumerated from the diff; **the two that mattered most were CONSTRUCTED BY THE
REVIEW**, and both passed the entire suite (672 passed at the time) plus
`ctest 29/29` before the guards were extended:

| mutant | guard that kills it |
|---|---|
| pre-fix build | 6 fail — the false reject AND the unchecked `vC` |
| branch present, `regs45` filled from `arg[0..4]` (a cosmetic-looking refactor) | 6 fail |
| `45cc` stops at `arg[3]`, still ignores `vC` — the plausible half-fix | 5 fail — only the parametrised `vC` guard |
| the `45cc` sequence applied to EVERY format (35c then checks `arg[0]` twice and never reaches the fifth register) | `test_the_fifth_register_of_a_35c_invoke_is_still_checked` |
| **`45cc` drops the fifth argument register `vG`** (the obvious way to kill the false reject alone) | `test_the_last_argument_register_of_a_polymorphic_is_checked` |
| **`vC` appended at the END of the sequence** — restores the unchecked-`vC` half for `A ∈ 1..4` while still passing at `A == 5` | the `vC` guard at arities 1-4 (arity 5 passes, exactly as predicted) |

The last two are the finding both reviewers reached independently: the original
guards pinned **2 of the 5 slots at 1 of the 5 arities**, so they proved `vC` was
*in* the sequence and never that it was *first*. `test_the_first_argument_register_of_a_polymorphic_is_checked`
is now parametrised over `A ∈ 1..5` (`vC` is an argument whenever `A >= 1`) and a
`vG` fixture covers the far end.

**Reviewers: 2 independent, 0 findings in the code.** Both re-derived the format
enumeration from the vendored table, both reproduced the AOSP evidence to the
digit (16 sites, `A` distribution `{2:1, 3:12, 4:1, 5:2}`), both rebuilt the a/b,
and both confirmed no new dereference (a crafted `A=5` polymorphic with
`meth@0xFFFF, proto@0xFFFF` — rejected pre-fix, accepted now — through load /
warm / smali / decompile / AST / xref / `resolve_call_args` / capabilities / IOC:
no crash, no hang). Every finding was in the guards or the prose: the two mutants
above, three published counts each exactly one too low (a test had been added
after the numbers were measured), the `A == 5` framing that understated the defect
to a one-arity problem, the index-comment overstatement, and a claim that the
adjacent findings below had been "filed" when they had not.

**Adjacent, found on the same walk — filed as dexllm#60 (rendering) and dexllm#61
(cross-reference)** after the first two `gh issue create` attempts were refused;
this paragraph said "recorded here" until they existed. Same "the vendored
toolchain predates invoke-dynamic" family as dexllm#57, where the slicer's
`encoded_value` parser stopped at 16 of 18 types (now fixed). All are wrong-ANSWER
or missing-output gaps — no crash, no load refusal — and all are **0-incidence
across the bundled corpus** (see above), so no corpus a/b can see them; measured on
the file this fix un-blocks (24 classes / 142 methods):
* `render_*_smali` prints **16** lines of `invoke-polymorphic <unhandled-fmt-29>`
  — the smali emitter has no `k45cc`/`k4rcc` case.
* **6 of 142 methods** emit `// DECOMPILE ERROR: malformed bytecode: null operand
  to MoveExpression` — the IR builder does not model 0xFA, so the following
  `move-result-object` finds no invoke and hits the documented null-guard at
  [instruction.cpp:274](native/dad_cpp/instruction.cpp#L274). Contained and
  reported, but the method is lost.
* the invoke cross-reference misses `invoke-polymorphic` entirely:
  `MethodHandle;->invoke` / `invokeExact` are both in `list_external_method_refs()`
  and 16 methods carry the opcode, yet `find_call_sites_to` answers **0** for each
  — so the caller xref, and every consumer built on it, is silently blind to those
  sites. **This paragraph originally blamed `DexItem::GetInvokeMethodsFromCode`,
  which selects by FORMAT (`k35c || k3rc`), and claimed `invoke-custom`'s
  `call_site` index therefore entered `method_invoking_ids`. Both halves were wrong
  and dexllm#61 proved it**: that function has no caller (and had none in the fork
  snapshot either), so it produced no edge at all, and `method_invoking_ids` is
  built by an OPCODE-keyed collector that never admitted `invoke-custom`. The real
  defect was in four other, live gates. Fixed in dexllm#61 — see its section below.
  The format proxy's own over-admission is real but was worse than recorded: it
  also takes `filled-new-array` (a TYPE index, 624 live corpus sites) and
  `invoke-virtual-quick` (a vtable offset).

**Two notes so they are not rediscovered as regressions of this change:**
`art/test/dexdump/all.dex` is refused on BOTH builds (`code: vC wide register out
of range` — a wide pair whose high half is outside a 3-register frame, genuinely
spec-invalid, and it loads under `lenient=True`, which is exactly the split that
mode exists for). And a reviewer saw the full suite die non-deterministically
(`Segmentation fault` / `Bus error` in `safe.py:_worker`) on BOTH this build and
HEAD while two agents were building concurrently; three full runs here with
nothing else building were clean (677 passed twice, the third cut by a harness
timeout). The likely cause is the shared worktree — `pip install -e .` REPLACES
the mmap'd `.so` under a running interpreter, which is a textbook `SIGBUS` — but
that is a hypothesis, not a measurement.

### The parser implements every `encoded_value` the gate accepts (dexllm#57, 2026-08-19)

`Reader::ParseEncodedValue` implemented **16 of the dex spec's 18** `encoded_value`
type codes. `0x15 METHOD_TYPE` and `0x16 METHOD_HANDLE` — legal since API 26
(`const-method-handle` / `invoke-custom` constants) — fell to its
`SLICER_CHECK(!"unexpected value type")`, and the vendored `dex_format.h` has no
constant for either: the header predates invoke-dynamic. **Upstream AOSP's slicer
has the SAME gap** (verified against the local checkout —
`tools/dexter/slicer/reader.cc` ends in the same `default:`, and its
`dex_format.h` stops at `kEncodedBoolean`), so this is an original fix, not a
port. Found by the dexllm#56 annotation fuzz: of 1,500 mutations, 123 still
verified and exactly 1 threw — this.

**The verifier accepting both is CORRECT, and that is the whole shape of the
issue.** Rejecting a spec-legal value at the gate would false-reject real apps,
which this repo ranks as strictly worse than a throw — and dexllm#58, one section
up, is what happens when an added check gets that wrong. So the fix had to be in
the parser. A dex carrying one **in an annotation** verified clean in both modes,
loaded, and then threw the moment anything walked its annotations:
`warm_analysis_caches`, the caller/cross-ref family, `summarize_capabilities`,
`find_*_by_annotation`. `list_classes` / `decompile_class` / `render_class_smali`
answered normally, which is the split that made it survivable rather than
obvious. `static_values` is NOT affected: the slicer would parse it in
`ParseClass`, which DexKit never calls, and dexllm decodes static values with its
own `DecodeEncodedValueText`.

**Fix:** two constants in
[dex_format.h](vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_format.h),
two slots in the `ir::EncodedValue` union, and two cases in
[reader.cc](vendor/dexkit_core/Core/third_party/slicer/reader.cc) — both plain
`(arg+1)`-byte indices, resolved through `GetProto` / `GetMethodHandle`.

## The review CRITICAL: the index was bounded against ATTACKER data

The first cut rested on a safety claim that was **FALSE**, and an adversarial
reviewer CONSTRUCTED and RAN the counter-example: a **SIGSEGV on a `verify()`-valid
dex** — the exact defect class dexllm#56 closed, reintroduced.

The claim was "what stops a crafted `METHOD_HANDLE` index is `ArrayView`'s own
`SLICER_CHECK_LT` inside `MethodHandles()[]`, which throws rather than reading out
of range". But `MethodHandles()` is
`section<dex::MethodHandle>(mi->offset, mi->size)` — **the count comes straight
from the map**, and nothing validated it: `CheckMap` checked
`item->offset >= size_` and never the EXTENT, `CheckIntraSection` never touches
the method_handle section (out of documented scope), and the slicer's own
`Reader::ptr<T>` guard is inert (see below). So `ArrayView` bounded the index
against attacker-controlled data.

Reproduced (from AOSP `art/test/dexdump/const-method-handle.dex`): map count
`1 → 0x2000000`, one annotation element retyped to `0x16` with `arg=2` and index
`0xFFFFFF` → a read ~134 MB past a 2,524-byte file. `verify()` **valid**, 2
classes load, then `warm_analysis_caches` / `summarize_capabilities` /
`find_call_sites_to` all die with **exit 139**. I re-ran it before fixing
anything: same result.

**Attribution was proven by MUTANT, not by argument** — the reviewer disabled the
`METHOD_HANDLE` reader case (= pre-#57) and the same input merely THREW. So the
hole was dormant for as long as nothing called `GetMethodHandle`, and the parser
fix woke it.

**Fixed at the gate, which is where the contract lives** ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp)
`CheckMap`): bound the **EXTENT** of the two fixed-size sections the HEADER does
not describe — `method_handle` (8 bytes/entry) and `call_site_id` (4). Every other
fixed-size table has its span bounded by `CheckHeader`'s `CheckListSize` off the
header's own size/off pair; these two exist ONLY in the map, so `item->size` is
the sole statement of how long they are.

**This is ART PARITY, not an addition — and the first TWO attempts to say why were
both wrong.** The delta correctness review caught the second one, which claimed
*"neither is a DATA-section type, so ART's own `CheckMap` does not bound them
either"*. That is **backwards**: ART's `IsDataSectionType` (`:82`) returns TRUE for
`kDexTypeCallSiteIdItem` (`:92`), `kDexTypeMethodHandleItem` (`:93`) and
`kDexTypeMapList` (`:94`) — only the header and the six `*_id` tables are false.

So **ART bounds these in TWO places, and this port reached NEITHER**:
* ART's own `CheckMap`, through that `IsDataSectionType`: the `data_items_left`
  budget (`:777`) and the 4-byte alignment check (`:798`). **This port's
  `IsDataSectionType` excludes all three**, so neither applies — and there is no
  `data_items_left` equivalent anywhere in the port.
* ART's map-driven intra pass, `CheckIntraSectionIterate` (`:2199`, entered for
  both at `:2529-2530`), which does
  `CheckListSize(ptr_, 1, sizeof(dex::CallSiteIdItem), …)` at `:2265` and opens
  `CheckIntraMethodHandleItem` with the same call at `:1493`. This port is
  reference-driven and never walks those sections.

The bound added here is the stronger of ART's two — a per-section byte span rather
than a running item budget — and putting it in `CheckMap`, where the map item is
already in hand, is the same intra/inter fusion the dexllm#56 annotation walk used.
Entry sizes confirmed against AOSP `dex_file_structs.h`: `MethodHandleItem` is
4 × uint16_t = 8 B, `CallSiteIdItem` is one uint32_t = 4 B.

**The ALIGNMENT half stays diverged, now deliberately.** Because this port's
`IsDataSectionType` excludes the three, `CheckMap`'s alignment branch never runs
for them, so a misaligned `call_site_id` / `method_handle` section offset is
ACCEPTED where ART rejects it (measured by the reviewer: `off+1`, `+2`, `+3` all
verify `True` and warm cleanly; `map_list` is covered anyway by `CheckHeader`'s
4-aligned `map_off` check). It is **not** memory safety — the new extent bound
spans those sections regardless of alignment, and an unaligned u2/u4 load is
harmless on every supported target. Pre-existing (the exclusion predates this
change), catalogued as divergence B2 in
[docs/aosp-oob-divergences.md](docs/aosp-oob-divergences.md) and filed as
**dexllm#62**, and the function's own comment used to justify itself by misstating
ART the same way — that is fixed too. Variable-length sections cannot be
bounded this way (their `size` counts items of differing length) and are validated
where they are parsed. **Contents stay out of scope** — this bounds only where the
section ends, which is the minimum that makes `ArrayView`'s check mean something.
Post-fix all four of the reviewer's crafts are refused at load (`List too large:
map section span`, or the pre-existing `Map item past end of file` / `encoded
method_type idx`).

**Why the first validation missed it, which is the durable lesson:** the a/b
wrapped every axis in a `try/except`, and **an `except` cannot observe a SIGSEGV**
— the process dies. Its 4 crafted inputs only ever retyped elements on bundled
dexes with NO method_handle section, so `[index]` bounded against size 0 and
always threw. The a/b proved "the corpus is quiet" and "these two crafts throw";
the memory-safety property of the NEW dereference was never exercised. A crafted
input set must include the shape that attacks the new dereference, not only the
shape that exercises the new code path.

## The two halves resolve differently, and the asymmetry IS the design

* `METHOD_TYPE`'s index is bounded by `VerifyDex` (`case 0x15: return
  idx(header_->proto_ids_size, …)`), so `GetProto` runs on verified input — the
  same call every `ParseMethodDecl` already makes, over a table `CheckHeader`
  spans.
* `METHOD_HANDLE`'s index was not bounded against its table at the time (**dexllm#72
  ports ART :1212 and it is now**), so what stopped a crafted one was a leaf
  check — and **which** one depends on the width: `arg > 3`
  throws first in `ParseIntValue`'s `SLICER_CHECK_LE(size, sizeof(u4))` (the
  verifier's `0x16` arm uses `skip()`, not the `arg<=3` `idx()` the other index
  types use), and `arg <= 3` reaches `ArrayView`. The first cut attributed the
  throw solely to `ArrayView`; the correctness review corrected that.

**Consequence, deliberate AT THE TIME:** on a dex with NO method_handle section
every `0x16` index was out of range, so such a value still threw — from the index
bound instead of the missing case. That was the channel
`tests/test_cache_init_failure.py` drove, so **the issue's "this fix needs a third
vehicle for those nine guards" worry did not materialise here** — it materialised
at **dexllm#72**, which bounded that index at the gate and left no vehicle at all.
Both reviewers noted the vehicle rested on a CORPUS property, so that file's
`_craft` **refused a source that has a method_handle section**; the mechanism was
structural, and what took it away was not a corpus dex but ART parity.

**What this change left NOT ported, and the scope line it forced — CLOSED by
dexllm#59:** ART's `CheckIntraMethodHandleItem` also rejects a
`method_handle_type > kLast` (`:1501`) and bounds `field_or_method_idx` against
`field_ids`/`method_ids` (`:1512`/`:1521`). Both are ported now; the paragraph is
kept because `dex_verifier.h`'s out-of-scope list said *"call_site/method_handle
— not dereferenced by the core"*, and THIS change is what made that false for
method_handle, so the line was rewritten here to name exactly what is and is not
bounded (and rewritten again by dexllm#59, which moved method_handle out of that
list entirely). **Two claims in this paragraph did not survive the port** and are
corrected rather than deleted: the residual was called a **"THROW, not an OOB"**
— never an OOB is right, a throw is only the SLICER reader's half, and
dexllm#59's own subprocess measurement found 0 signals and 0 exceptions, with a
garbage TYPE decompiling byte-identically to a legal handle; and the a/b was
sized at *"the three files that have a method_handle section"*, where a raw
census over 8,360 AOSP files finds **9** carriers. A corpus-only a/b is blind
either way: 0 of the 36 gitignored dexes has one.

**Delta self-verification, because both delta reviewers died on API 529s:** eight
crafted shapes aimed at the NEW dereference rather than the new code path, each run
in a subprocess judged by EXIT STATUS (a `try/except` cannot see a SIGSEGV — the
lesson above): extent exactly == EOF (accepted, as it should be — the handle's
garbage contents then throw `[8302 < 243]`), extent one entry past EOF
(**rejected**, so the boundary is exact), the section moved to overlap the header
area (rejected by the pre-existing map-order check), count 0 with a large index
(throws), a garbage `method_handle_type` + index (throws — this is what measures
the un-ported contents check), an inflated `call_site_id` count (**rejected**, so
that arm of the new check is live and not decoration), a `METHOD_TYPE` index one
past `proto_ids_size` (rejected by the pre-existing bound), and the unmodified
fixture (loads and warms). **0 signals.**

**Read-only, and stated rather than discovered:** `WriteEncodedValue` has no case
for either code, so such a value can now be PARSED but not re-emitted. That
asymmetry is new; it is also strictly better than before (neither was possible),
and the slicer's Writer is unreachable from dexllm. Noted in `dex_ir.h` beside the
two union members.

**One coupled fix, and the first comment for it was wrong:**
`GetAnnotationEncodeValueBean` ([dex_item.cpp](vendor/dexkit_core/Core/dexkit/dex_item.cpp))
ends both switches in `default: break` while `AnnotationEncodeValueBean::type` is
an uninitialised member, so a newly-parseable type would be read INDETERMINATE.
The arm now assigns `NullValue` + value 0 (the schema's own "no value"; it is
generated and has no enumerator for either type, and adding one is a Java-API
contract change). The first comment claimed the arm "is reachable where it never
was before" — **the correctness review refuted that**: neither switch has a case
for `0x19 VALUE_FIELD` either, which the reader has ALWAYS parsed, so the arm was
already reachable and `bean.type` could already be read indeterminate. `0x19`'s
own missing mapping is left alone (a separate, pre-existing wrong-ANSWER gap).
Unreachable from dexllm either way — 0 call sites, that surface is DexKit's
Java-facing annotation API — so this is defined-behaviour hygiene, not an output
change, which is exactly why it needs a SOURCE-level guard (below).

## Measured

a/b OFF vs ON, SAME script, both `.so` md5-verified — `4e4a8d35…` OFF (=
dexllm#58's build, i.e. HEAD) and `37667548…` ON, and the ON build bit-reproducing
its md5 after the swap. **54 sources** — the whole bundled corpus, both committed
fixtures, **every `art/test/dexdump/*.dex`** and the dexter testdata dex (the
population the new extent bound could false-reject, including files with 2 and 29
method_handle entries), and **4 crafted dexes** — × {both verify modes, load,
class list, `warm_analysis_caches`, `find_classes_by_annotation`,
`summarize_capabilities`, `find_call_sites_to`, and a smali + decompile digest
over the first 40 classes} = **450 axis records**.

* **39 corpus sources: 0 changed. 11 AOSP sources: 0 changed.** No false reject
  from the new gate check, on real dexes that actually have the section.
* **4 crafted sources: 16 records changed**, all 4 annotation axes on each.
  `METHOD_TYPE` (index zeroed, i.e. a LEGAL value) `RAISED unexpected value type`
  → **OK**; `METHOD_HANDLE` → `RAISED SLICER_CHECK_LT`, i.e. the value now parses
  and the throw has moved to the index bound.

The crafted sources are IN the a/b on purpose: a corpus-only run would have been
byte-identical and would have proved only that the corpus is quiet
([[ab-must-prove-the-mechanism-fires]]).

parity 29/29, pytest 686 passed / 6 skipped, corpus-less 280 passed / 412 skipped,
narrowed to `tests/data/multidex.apk` 589 passed, both touched guard files green
narrowed to each of the 34 bundled samples one at a time, sweep 27,018-class /
229,537 method-block 0-crash 0-timeout, determinism 3 `PYTHONHASHSEED`s
byte-identical (same digest as before the change), lint trio clean.

## Guards

9 in [tests/test_encoded_value_method_types.py](tests/test_encoded_value_method_types.py),
crafted in place and length-preserving — only the TYPE bits of one class-annotation
element change; the `METHOD_TYPE` fixture additionally zeroes the payload, which is
what turns it into a *legal* value rather than merely a parseable one.

**A second committed fixture was needed**: `tests/data/invoke-custom.dex` (31,732 B,
byte-identical to AOSP `art/test/dexdump/invoke-custom.dex`, Apache-2.0,
provenance in [tests/data/README.md](tests/data/README.md)). **0 of the corpus's
36 dexes has a method_handle section**, and two properties can only be tested with
one: the SUCCESS path — a `0x16` whose index actually RESOLVES, which is what makes
a real API-26+ dex load rather than throw, and which the correctness review found
untested — and the CRITICAL above, whose craft needs a section to inflate.

**The source-level trio is the durable part.**
`test_the_slicer_parser_implements_every_value_the_verifier_accepts` (renamed to
`test_every_decoder_implements_every_value_the_verifier_accepts` and
parametrised over both decoders by dexllm#63) states the invariant this issue was
a violation of rather than the two codes: it derives the
verifier's accepted set from `VerifyEncodedValue`'s cases and the reader's from
`ParseEncodedValue`'s, resolving `kEncoded*` through `dex_format.h`, and requires
`verifier ⊆ reader` with a non-vacuity floor on each side. Two corrections from the
delta review: it now **strips comments** before parsing (a mutant that COMMENTED
OUT the METHOD_HANDLE case passed both source guards — the trap dexllm#32's opcode
guard already recorded, recurring with the correct scanner sitting in the same
file), and its name SAID SLICER, because this repo has **two** encoded_value
decoders and the other was out of its reach at the time — dexllm#63 fixed that
decoder and widened this guard to cover both. `VerifyDex` is
the documented single gate, so a code it lets through and the parser does not
implement IS a dex that verifies, loads and throws later. The other two pin the
two constants, and pin that the bean `default:` arm ASSIGNS — the last one exists
because that path is unreachable from dexllm, so **reverting it passed the entire
suite** until the source was pinned.

**7 mutants, each BUILT and RUN, each killed:** pre-fix (6 fail); each reader case
removed on its own (3 / 4); **the `CheckMap` extent bound removed — the CRITICAL —
and the crafted dex goes back to `valid: True`** (1, the inflated-count guard);
the bound kept for `call_site_id` but not `method_handle` (1, so the guard covers
the section that matters and not merely the code shape); the bean arm reverted to
`default: break` (1, source-level only); plus an unmutated control.

**A SECOND decoder has the same gap, and it is out of that guard's reach** (delta
adversarial review): `core_ext/dexitem_code_source.cpp`'s `DecodeEncodedValueText`
reads static-field initializers for `decompile_class` and has no case for
0x15/0x16 either. Its `default:` returns having advanced only past the header
byte, so the payload is not skipped and the following values in that
`encoded_array` desync. Pre-existing, reachable only from a
`MethodHandle`/`MethodType` STATIC INITIALIZER (which javac does not produce),
filed as **dexllm#63** — and **CLOSED there**, along with the guard's scoping: the
invariant is now stated once for both decoders. See its section below.

**This paragraph called that desync "wrong-answer only" and was WRONG**, in the
two sentences dexllm#71 deleted from it: *"the caller is a count-bounded `for`
loop with `value_count` clamped … and `ReadIntLE` is `end`-bounded, so it cannot
read out of range."* Both halves are true and NEITHER covers the four arms that
INDEX a table with the value they just read — a desynced walk hands those an
index the gate validated nothing about. A reviewer rebuilt a pre-#63-shaped
decoder and it SIGSEGVs on 16 of 23 `verify()`-VALID crafted dexes. See the
dexllm#71 section.

**Recorded, not fixed:** the slicer's own pointer guards are inert —
`Reader::ptr<T>` is `SLICER_CHECK_GE(offset, 0 && offset + sizeof(T) <= size_)`,
whose second argument is `0 && …` = `0`, so it reduces to `offset >= 0`
(`dataPtr` has the same shape). That is a pre-existing upstream typo in a SAFETY
guard, and it is why the section start was only ever bounded by `CheckMap`'s
`offset < size_`. Fixing it belongs in its own change with its own a/b — the risk
is a false throw on some legitimate access, which is exactly the direction this
section is about.

### A data section's offset is aligned the way ART aligns it (dexllm#62, 2026-08-19)

`IsDataSectionType` is a port of ART's `dex_file_verifier.cc:82`, whose false arm
is the header item and the six `*_id` tables and nothing else. This port had
**three more** in that arm — `kCallSiteIdItem` (ART :92), `kMethodHandleItem`
(:93) and `kMapList` (:94) — and the predicate's single consumer is `CheckMap`'s
alignment branch, so the branch never ran for them and a **MISALIGNED**
`call_site_id` / `method_handle` section offset was ACCEPTED where ART rejects
it. Pre-existing (introduced with the verifier in `0b75133`); what dexllm#57
changed is that the function became load-bearing enough for the gap to matter.
The comment above it justified the divergence by **misstating ART** in exactly
the way the dexllm#57 delta review caught one file over, and that false claim is
how it stayed unexamined.

**Not memory safety, and the direction matters.** dexllm#57's EXTENT bound spans
both fixed-size sections whatever their alignment, and an unaligned `u2`/`u4`
load is harmless on every supported target — so this is a false-ACCEPT, not a
crash. What it needed was the measurement, because **an added check can only fail
in the direction ART's own verifier cannot: by REJECTING something ART accepts**
(dexllm#58's whole lesson).

**Fix:** drop the three `case` labels so they fall through to `default: return
true`; the existing branch then applies ART's own rule (1 byte for the five
variable-length types it names at :798, 4 for everything else).

**ART calls the predicate in TWO more places and NEITHER is ported** — the first
draft said "ART's OTHER use", singular, which a reviewer refuted from the
checkout. (1) `:775`, the same `CheckMap` block, where it also gates the
`data_items_left` budget (`:777`) — the SUM of every data section's item COUNT
bounded by the data segment's byte size. It guards nothing here: this port is
REFERENCE-driven and reads `item->size` for exactly the two fixed-size sections
the header does not describe, where `CheckMap`'s per-section byte-span bound is
strictly TIGHTER than a running item budget; for every variable-length section
the count is never consumed at all, so porting it would be a pure new rejection
direction with no reachable defect behind it. Catalogued as the new **B2b** in
[docs/aosp-oob-divergences.md](docs/aosp-oob-divergences.md), where B2 is now
closed. (2) `:2354`, inside `CheckIntraSectionIterate`, which rejects a
data-section item at offset 0 (`:2356`) and populates `offset_to_type_map_` —
both belong to ART's MAP-driven intra pass, which this port does not have at all,
so widening the predicate does NOT bring them along; it only means ART applies
them to three more types than we do. Added to `dex_verifier.h`'s out-of-scope
list, where it was missing.

**One claim the CONTROLS corrected, before review saw it.** The first cut wrote
that `kMapList` is "a no-op in practice", because `CheckHeader`'s
`CheckValidOffsetAndSize(map_off, …, 4, "map")` runs first — which the issue said
too. It covers the HEADER field ONLY: the map_list item's own
**self-referential** offset is a separate `u4` nothing compares against it, so
misaligning THAT one was accepted before and is rejected now (27 crafted
sources). Rejecting it is right — it is what ART does, and a map whose
self-reference disagrees with the header is malformed — but the rationale was
wrong, and a control craft is what said so.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `37667548…`
OFF, `920fe5b2…` ON, and the ON build bit-reproducing its md5 after the swap):**
58 real sources — the whole bundled corpus, both committed fixtures, every
`art/test/dexdump/*.dex` and every `tools/dexter/testdata/*.dex` — × {strict
verify, lenient verify, `verify_report`, `dex_count`, class list,
`warm_analysis_caches`, and a smali + decompile digest over the first 40 classes}
= **439 axis records, 0 changed, 0 false-reject**, including the **4** carriers
inside that population (`tests/data/invoke-custom.dex`, AOSP
`const-method-handle.dex` / `invoke-custom.dex`, dexter `method_handles.dex`).
**0 of the 36 gitignored corpus dexes carries either section**, which is why a
corpus-only a/b is blind to this by construction and the AOSP files are evidence
rather than decoration. The a/b globs `*.dex`, so it misses the 6 further carriers
the wider census below finds inside `.jar`s and the fuzz corpora — that population
is covered by the oracle instead, which is the stronger instrument here anyway
since the delta is a pure format property.

**Independent oracle, and it is what actually bounds the risk** (a map-list
parser that never goes through the binary under test — the change's COMPLETE
observable delta is "a map item whose type ART aligns to 4 sits at an offset that
is not"). Over **1,413 logical dexes in 1,256 containers** — the whole local AOSP
tree plus the corpus and both fixtures — there is exactly **1** such item, and it
is an ART **dex-verifier FUZZ CORPUS** input (`art/tools/fuzzer/dex-verifier-corpus/b391842969.dex`,
`call_site_id` at 6998), i.e. a file whose purpose is to be rejected and which ART
rejects at the identical check. **That file is the best evidence the change has**,
because it is unmodified and real where everything else is crafted: OFF it
verifies valid in both modes, ON it is `Misaligned map item`. The map_list item's
self-referential offset equals the header's `map_off` on **1,413/1,413**. So
0-false-reject is a property of the format, not a lucky sample. (A reviewer
independently swept 5,567 files / 1,089 logical dexes and reached the same single
hit.)

**84 CRAFTED sources / 686 axis records → 41 changed**, and the split is the
point ([[ab-must-prove-the-mechanism-fires]] — a flat a/b here would prove only
that the corpus is quiet):

| craft | OFF → ON | n |
|---|---|---|
| `call_site_id` / `method_handle` offset `+1/+2/+3` | valid → `Misaligned map item` | **12** |
| `map_list` item's own offset `+1` | → `Misaligned map item` | **29** |
| same section shifted `+4` (still 4-aligned) | valid → valid | 4 |
| a byte-aligned section (`class_data` / `string_data` / …) `+1` | unchanged | 39 |

12 + 29 + 4 + 39 = 84, changed = 12 + 29 = 41. (An earlier draft wrote 27 for the
map_list row, which did not sum — an adversarial reviewer caught it. 27 of the 29
were valid before; the other 2 were ALREADY rejected for an unrelated pre-existing
reason and now report the alignment one first, so they are a reason change, not an
accept → reject.) The last two rows are the isolation: a check that rejected any
MOVED section, or that aligned every data type to 4, satisfies the first two rows
and fails these.

**Guards** (37 collected cases, 33 run / 4 skipped, in
[tests/test_verifier_section_alignment.py](tests/test_verifier_section_alignment.py)),
crafted from `tests/data/invoke-custom.dex` — the committed fixture, which is the
ONLY source carrying BOTH sections — so they hold in the corpus-less CI leg and
under any `$DEXLLM_TEST_APK` narrowing. The craft rewrites **one `u4`**, the
section's offset field inside its map item, and leaves the COUNT alone: the
extent still fits, so dexllm#57's span bound cannot be what rejects, and
alignment is isolated as the only thing that moved. `_shift` asserts its own
premises (the section exists, starts out 4-aligned, still ends inside the file,
does not collide with the next section), so a fixture that ever stops offering
the shape fails loudly instead of turning a guard vacuous. The 4 skips are
byte-aligned section types the fixture happens not to carry 4-aligned — which one
a dex carries is a property of the sample.

`test_the_uncrafted_fixture_verifies` is non-discriminating BY DESIGN and says so,
but it is not idle: the fixture's `string_data`, `annotation`, `class_data` and
`encoded_array` sections are **genuinely unaligned**, so ART's 1-byte list is
exercised by the pristine file rather than only by a craft.

**The guard an adversarial reviewer had to CONSTRUCT, and the one that matters
most.** The tests above pin the three cases dexllm#62 REMOVED. Nothing pinned the
arm as a PARTITION — so the SYMMETRIC edit, removing a FOURTH case on the same
lines, was invisible: deleting `case kStringIdItem:` makes the verifier reject a
misaligned `string_id` map offset that ART accepts (the exact false-reject
direction this change is about) and passed **the entire 688-test suite**. No
corpus guard can ever reach it either, because a real dex's `string_id` map offset
duplicates a header field `CheckHeader` already forces 4-aligned. Closed by
`test_every_section_type_is_classified_the_way_ART_classifies_it`: **one craft per
map type in the fixture**, judged against `_ART_ALIGNMENT` — ART's WHOLE
classification (:82 plus the :791-798 switch) pinned as a LITERAL, because a guard
parametrised over the production predicate cannot catch an edit OF it. A sibling
reads the `MapType` enum out of the C++ and requires the table to cover it, so a
new map type cannot be added on one side only.

**9 mutants, each BUILT and RUN, each killed by its intended guard:** the pre-fix
predicate (14 fail), each of the three cases restored ALONE (call_site 6,
method_handle 6, **map_list 2** — which is why the map-self guard exists),
alignment forced to 4 for every data type (13, including the pristine premise),
forced to 1 (18), and the reviewer's three — **`string_id` dropped from the false
arm (1, the partition guard and nothing else)**, `code_item` ADDED to the 1-byte
list (1) and `debug_info` REMOVED from it (3). Plus an unmutated control. The last
two are the 1-byte list pinned in BOTH directions; before the partition guard the
add-direction was unguarded, which the change is responsible for because it is
what routes three more types through that branch.

**One observable change beyond the verdict (dexllm#48's precedent that a moved
rejection reason is release-notes material):** the alignment check runs BEFORE
`MapTypeToBitMask`, the duplicate check and dexllm#57's extent bound, so a dex
that is misaligned AND otherwise malformed now reports `Misaligned map item`
where it used to report the other reason. Measured: 2 of the 84 crafted sources,
and a hand-built `method_handle` that is misaligned AND carries an inflated count
moves from `List too large: map section span` to `Misaligned map item`. Nothing
in the repo asserts those strings (`tests/test_encoded_value_method_types.py`'s
span guard touches the COUNT, not the offset, so it is unaffected — verified by
construction and by the suite), but an out-of-tree consumer matching on them
would see it.

parity 29/29, pytest **719 passed / 10 skipped**, corpus-less **313 passed / 416
skipped**, narrowed to `tests/data/multidex.apk` 622 passed, the guard file green
narrowed to **each of the 38 bundled samples one at a time**, determinism (3
processes x 3 `PYTHONHASHSEED`s -> one digest), sweep 25,309-class /
213,374-method 0-crash 0-timeout, lint trio clean, doc fences 78. **The only real
input that moves in the whole 1,413-dex census is ART's own fuzz-corpus seed** —
an earlier draft claimed "no behaviour change on any real input", which a
reviewer showed is literally false for exactly that file. The accurate claim is
the weaker one: everything that moves is malformed, and ART already refuses it.

### A method handle's TYPE and INDEX are checked at the gate (dexllm#59, 2026-08-23)

The third and last piece of the method_handle boundary dexllm#57 opened. ART's
`CheckIntraMethodHandleItem` (`dex_file_verifier.cc:1492`) does three things;
dexllm#57 ported the first as the section's EXTENT bound and dexllm#62 added
ART's ALIGNMENT rule, leaving **`method_handle_type > kLast` (:1501) and
`field_or_method_idx` against field_ids / method_ids (:1512/:1521)** unported.
`VerifyMethodHandleSection` ([dex_verifier.cpp](native/core_ext/dex_verifier.cpp))
ports them, fused into `CheckMap` — ART reaches the check by ITERATING the map's
sections and this port is REFERENCE-driven with no such pass, so the walk goes
where the map item is already in hand, the same intra/inter fusion the dexllm#56
annotation walk used. The call sits immediately after the extent bound and
**depends on that order**: the span it dereferences is bounded by nothing else.

**The issue's own premise was half wrong, and the measurement is what says so.**
dexllm#59 was filed stating the residual is "a THROW at
`GetFieldDecl`/`GetMethodDecl`, not an OOB". Never an OOB is right. A throw is
not: across 11 crafted entries of `tests/data/invoke-custom.dex`, each run in a
SUBPROCESS judged by EXIT STATUS, the pre-fix build gave **0 signals and 0
exceptions**. What it actually did splits by which half is wrong and which
reader runs:

| craft | pre-fix behaviour |
|---|---|
| type `0x09` / `0xFFFF`, index in range | **decompiles BYTE-IDENTICALLY to the control** |
| index past its table | **2 bootstrap lines silently vanish** |

The first is the half the issue never named and the worse one. `IsField()`
(dex_ir.cc :110) is four equality tests against 0x00-0x03 and nothing else — a
type outside that set falls through to the method table rather than being
questioned — and dexllm#67's Writer renders by the same partition, so a handle asserting an **undefined kind** was rendered as
an ordinary `invoke-static` bootstrap with nothing anywhere to mark it — a
fabricated fact, not a lost one. The second is dexllm#67's
`ResolveMethodHandle`, written AFTER this issue was filed: it bounds the index
itself and returns false, so the site renders nothing ("refusing beats
inventing" — but only at the gate is the refusal visible). The throw the issue
measured is real and belongs to the OTHER reader, the slicer's annotation walk,
where `ArrayView`'s `SLICER_CHECK_LT` still fires. Both the source comment and
`docs/dexkit-vs-art-dex-handling.md` say this now; the first draft of this
change repeated the issue's wording before the probe was run.

**Deliberately NOT done, and it is a scope decision rather than an oversight.**
Auditing ART turned up **two more** unported checks in the same family — the
`0x16 METHOD_HANDLE` encoded_value's own index INTO the section, whose width ART
caps at :1204 and whose value ART bounds against `NumMethodHandles()` at :1212.
They matter here because `VerifyEncodedValue`'s `case 0x16` justified its silence
with *"bounding it here would mean bringing method_handle into scope: a new
section to validate"* — which is exactly what this change does, so the standing
rule bound the commit for the sixth time
[[a-rule-you-wrote-binds-your-next-commit]]. The arm's comment is rewritten to
state the REAL remaining reason (blast radius, not scope), the deferral is
catalogued as **B2c** in
[docs/aosp-oob-divergences.md](docs/aosp-oob-divergences.md), filed as
**dexllm#72**, and the scope call was escalated to the user, who chose the issue
as filed. Porting :1212 would
**retire a test vehicle**: `tests/test_cache_init_failure.py` crafts that value
on a section-less dex, where the index is out of range by construction — and
that file and CLAUDE.md both call the channel one "no future verifier
improvement can take away, because closing it at the gate would be a
false-reject", which ART :1212 **refutes** (`NumMethodHandles()` is 0 there, so
ART rejects it). Both mirrors now say so. #59 alone left the vehicle intact,
verified: those 12 guards still passed. **dexllm#72 then took it, and B2c is
CLOSED** — see its section below for what the retirement cost.

**Measured (a/b OFF=`6af3fc5723471894966917c63df5ec87` vs
ON=`256a70cb01465af7156dc4346f3f1099`, SAME script, both `.so` md5-verified, and
re-captured on the FINAL build after every review fix so the record covers the
shipped binary and not a predecessor — the OFF build BIT-REPRODUCES the recorded
HEAD md5, which is the diff's functional content stated as a measurement):** 105
unique sources — the whole bundled corpus (37), every committed fixture (6),
every `art/test/dexdump/*.dex` plus `all-dex-files.jar` and
`multidex-container.dex` (11), every `tools/dexter/testdata/*.dex` (11), **every
ART fuzzer corpus dex (28)** and 12 crafted — x {strict verify, lenient verify,
`identify`, load + dex_count + class hash + `verify_report`,
`warm_analysis_caches`} = **525 axis records, 0 REAL sources changed on any
axis**. Exactly 6 crafts move, on 4 axes each, with the reason naming the member
kind. The v41 amplifier does **not** move — which is the memo's whole property
stated as a measurement: it changes no verdict and no reason, only how long the
walk takes. The 5 ACCEPTANCE controls and the unmodified fixture are unchanged on
both halves, which is the half that says the rule does not over-reject. AOSP's
own **`multidex-container.dex` — the one real v41 container — verifies both
slices on both halves**, and so does a crafted version of it carrying a SHARED
method_handle section of up to 4,000 entries. 19 real sources are rejected on
BOTH halves for pre-existing reasons (`b391842969.dex` — a method_handle carrier
— is dexllm#62's `Misaligned map item`, unmoved by this change).

**The 0-false-reject population is 9 files, and they were found rather than
assumed:** a raw map-list census over the whole AOSP tree — every
`.dex` / `.apk` / `.jar` / `.zip` / `.oat` / `.odex` under it, **8,360 files**,
each split into its logical dexes and its map walked for a type-0x0008 item — finds exactly 9 logical dexes carrying a `method_handle` section — the
three committed fixtures' originals, two copies inside `all-dex-files.jar`, and
**four ART fuzzer-corpus inputs**. All 9 are in the a/b. The gitignored corpus
carries **0**, so a corpus-only a/b is byte-identical by construction and proves
nothing about the mechanism [[ab-must-prove-the-mechanism-fires]] — the crafts
are what prove it.

**All 32 handles in all three COMMITTED fixtures are kind 4 or 5** (the same
census dexllm#67 recorded, [[fixture-dead-branches-hide-guards]]), so the FIELD
branch — 0x00-0x03, bounded against `field_ids` — cannot be REJECTED by anything
in the repo without a craft. An earlier draft generalised that from the three
fixtures to the tree and said the branch was "unreachable from any real dex",
which **this change's own 9-carrier census disproves**: three of the nine carry a
kind `0x03` handle and two of those verify VALID on both builds, so the branch's
ACCEPT path is exercised by real input already inside the a/b. Better coverage
than claimed, and a published claim the data refutes — an adversarial reviewer
found it. `invoke-custom.dex` is also the only carrier
whose `field_ids_size` (21) sits far below its `method_ids_size` (243), and that
GAP is what makes the table bound testable in BOTH directions: one index inside
it must be REJECTED for a field kind and ACCEPTED for an invoke kind, which no
single-sided assertion can say.

parity **29/29**, pytest **1031 passed / 24 skipped**, TRUE corpus-less
(`test_apk` MOVED aside) **622 passed / 433 skipped / 0 failed** — 54 of the 55
new cases run in the CI leg — narrowed to `tests/data/multidex.apk` **932
passed**, and green narrowed to a crafted PACKER-DUMP source (a good dex plus a
dexllm#62-rejected sibling), which is the shape a delta reviewer used to show an
earlier cut of the corpus sweep going RED on an environment fact, the touched guard files green narrowed to **each of the 38 bundled
samples one at a time** (25 `.apk` + 9 bare `.dex`; the other four entries are a
`.apksig`, a `.jar` and two certificates), sweep **25,309-class / 213,374 method-block 0-crash
0-timeout 0-error, GATE: PASS**, determinism 3 processes x 3 `PYTHONHASHSEED`s
-> one digest (unchanged from before the change), lint trio clean, doc fences 78,
`scripts/check_dad_boundary.sh` clean.

**Guards** (55 cases in
[tests/test_verifier_method_handle_contents.py](tests/test_verifier_method_handle_contents.py),
54 of them corpus-independent — every craft rewrites TWO u2 fields of ONE entry
of the committed `invoke-custom.dex`, length-preserving to the byte, so no
offset or section size moves and nothing but the intended operand can be what
changed). The fixture asserts its own premises (a section, >= 2 entries for the
last-entry walk, and a nonempty gap between the two id tables) so a substituted
fixture fails loudly instead of turning a guard vacuous. Both boundaries are
pinned EXACTLY — `0x08` is `kLast` and must be ACCEPTED, `0x09` rejected;
`limit - 1` accepted, `limit` rejected — because every rejection craft targets
the limit itself and would pass an off-by-one that accepts it.

**One inherited guard was NARROWED rather than deleted** — dexllm#62's
`test_a_still_aligned_shift_is_accepted[method_handle]`, which moves the section
by +4 to prove the alignment check rejects MISALIGNMENT rather than movement.
That craft rested on an ABSENCE [[a-guard-can-rest-on-an-absence]]: at the
shifted offset the bytes are not method handles, so this change rejects it for
its CONTENTS and the acceptance control asserted the opposite of what it means.
`_shift` now zeroes the section's count for that one type, which makes the
contents vacuous while leaving alignment the only variable (`CheckMap` checks
`item->offset` before reading an entry). Verified NOT to weaken it: the dexllm#62
mutant that restores `kMethodHandleItem` to `IsDataSectionType`'s false arm still
fails 6 cases.

**22 mutants, each BUILT and RUN with a distinct `.so` md5, each killed by its
intended guard:** the type check dropped (8 fail), the index check dropped (15),
the table forced to method_ids (9) and to field_ids (32), `>=` for `>` on kLast
(3), the field/invoke partition off by one so `0x03` reads the method table (2),
the walk moved ABOVE the extent bound (2), `count` clamped to the first entry
(1), the index limit `+ 1` (11), a half stride (25), the two u2 fields swapped
(37), `check_insns_` gating (3), the `entry`-ternary drop (1), and six on the
per-image state — the memo not consulted (2), never recorded (2), its maxima
never tracked (1), its per-slice re-check skipped (1), the budget check removed
(1), the budget never spent (1), the budget reseeded per slice (1), the caller
not threading the state (2, and that run takes **31 s** where every other mutant
takes 0.4 s — the amplification showing up in the matrix itself), and the REFUTED
`file_size / 8` bound restored (5). One mutant is the whole call site removed —
**its `.so` md5 is `6af3fc57`, the OFF build's exactly**, so it doubles as the
full pre-fix control and says the diff's entire functional content is that one
call. **Five of the twenty-two were CONSTRUCTED BY REVIEWERS** and each passed
the file as it then stood: the `check_insns_` gating, the `entry`-ternary drop,
the v41 amplifier, and the two memo mutants that survived because the first
SHARE fixture patched only one slice's map and therefore did not share
anything.

**One observable change beyond the verdict**, the shape dexllm#48 and dexllm#62
each recorded: the walk lives in `CheckMap`, which runs BEFORE `CheckIntraSection`
— so a dex carrying BOTH a bad handle and an intra defect now reports the handle
reason where it used to report the other one. Crafted-only in reach (all 19
real sources rejected on both halves keep their exact reason, measured), nothing
in the repo matches on those strings, but an out-of-tree consumer would see it.

## What the two reviewers found — 1 HIGH the change itself created, and it was in the one line I wrote to say the cost was free

**The adversarial reviewer CONFIRMED a HIGH, and it is a DoS this change
introduced.** The comment above `VerifyMethodHandleSection` said *"the
CheckListSize above makes `count * 8 <= file size`, so no work budget is needed
(contrast the dexllm#56 annotation memo, where one subtree is reachable from
every class_def)"*. For a **v41 CONTAINER** that contrast is an IDENTITY, not a
contrast: `ComputeDataRange` sets `size_` to `ContainerSize()` for every slice
while `LogicalDexSlices` strides by `file_size`, so one section is reachable from
every sibling and `count` is bounded by the container. Built and run on identical
files across both halves: **2/4/8/16 MB → 0.34 / 1.29 / 5.19 / 20.59 s against
HEAD's 0.00 / 0.01 / 0.02 / 0.04 s**, quadrupling per doubling, extrapolating to
~1.5 h at 256 MB. Attribution is airtight because every slice is rejected on BOTH
halves for the SAME reason — the delta is nothing but the walk — and the work is
paid BEFORE the rejection, on the load-free public `dexllm.verify(path)` that
dexllm#47 reaches from an upload. **The first fix for it was WRONG and a DELTA review refuted it by
construction** — bounding `count` by the slice's own `file_size / 8`. Starting
from AOSP's own `multidex-container.dex`, appending a shared section and nothing
else, the crossover is exactly that bound: **70 entries accepted, 71 rejected**,
and the v41 sibling rule then takes the whole container down. Its justification
("N distinct handles imply id tables of at least 8N bytes inside `file_size`")
assumed handles are DISTINCT, which nothing enforces, and assumed the tables sit
INSIDE `file_size` — which is exactly what a container does not guarantee: that
same slice 0 has `file_size` 564 and `string_ids_off` 684. Sharing is the point
of the format, and the 137x "measured headroom" I published for it came entirely
from three NON-v41 fixtures, where the bound is a theorem and cannot fire.

**What shipped instead rejects (almost) nothing:** a per-image memo plus an entry
budget (`VerifyImageState`, threaded by `ClassifyImageSlices`). The memo is keyed
on a section's BYTES — `(offset, count)` — and stores the two MAXIMA the walk
found, so a later sibling re-checks its OWN tables in O(1), exactly equivalent to
re-walking since "every index < limit" is "max index < limit". Keying it on the
bytes rather than on bytes-plus-this-dex's-table-sizes had to be MEASURED: the
first cut carried the sizes, siblings have their own tables, so the memo missed
on precisely the case it exists for and a legitimate 400-handle shared section
was rejected by the budget. Only the budget can reject, and a legitimate image
cannot reach it — real sections occupy DISJOINT bytes, so their entries sum to at
most `image / 8`, and a shared one is counted once; what exhausts it is
overlapping sections at distinct offsets, i.e. the same bytes charged many times.
Post-fix the amplifier crafts measure HEAD's numbers exactly and the refuted
false-reject is gone (n = 71 and n = 4000 both verify). Catalogued as **B2d**.
Scope is precise: plain concatenation is self-limiting (`stride == file_size ==
size_`), measured at 0.001 s for a 16 MB craft with every count maxed.

**Both reviewers independently CONFIRMED the same two guard holes, each by
building a mutant that passed the whole file.** (1) **No `lenient` axis at all** —
one conjunct, `check_insns_ && item->type == kMethodHandleItem`, left all 39 cases
AND 169 tests across nine verifier guard files green while `lenient=True` accepted
`method_handle_type = 0xFFFF`. Lenient is the packer-dump mode, i.e. the population
most likely to CARRY a malformed section, and three sibling files already pin
strict-AND-lenient — one of them for the SAME map section. (2) **The only
no-false-reject guard SKIPPED in the corpus-less CI leg**, because it took
`loadable_apks` for a contribution of exactly zero (`_candidate_apks` globs
`*.apk`, and the loop filters on a `dex\n` magic, so 0 of 25 survived) while that
fixture's absence skipped the whole test — and its floor was VACUOUS, since the
committed fixture is always a carrier. The direction an added check can fail was
the one direction not covered in CI. Both fixed; the carrier guard now pins the
three fixtures by name and handle count and asserts it walked 32 handles.

**And my own census refuted a claim in my own prose.** I wrote that the FIELD
branch (0x00-0x03) "is unreachable from any real dex in the tree", generalising
from the three committed fixtures — while the same paragraph's 9-carrier census
shows **three carriers declare a kind `0x03` handle and two of them verify
VALID**, so the branch's accept path was already exercised inside the a/b.
Harmless in direction, wrong as published — and the correction needed its own
correction, because all three of those carriers are **ART fuzzer seed-corpus
entries named after bug IDs**, i.e. crafted artefacts. The honest statement is
narrower and stronger as a scope note: the field branch has **no real-world
exemplar anywhere in reach**, and what exercises its accept path is two fuzzer
seeds. Also corrected: a stale dexllm#57
paragraph still saying *"Neither is ported"* and *"the residual is a THROW, not an
OOB"* in the present tense — two claims this change's own measurement refutes, in
the same file, [[a-rule-you-wrote-binds-your-next-commit]]; the sibling module
docstring in `test_verifier_section_alignment.py` still saying the craft leaves
the count alone; a census count published without naming its predicate; a
decorative pinned literal; and a duplicated horizontal rule.

**What they could NOT break, with their own instruments.** Memory safety: **251
crafts plus 15 container/concatenated crafts**, each in a subprocess judged by
EXIT STATUS through verify(strict+lenient) → load → warm → decompile+smali — **0
signals, 0 timeouts**; the extent bound is structural rather than adjacent (the
same `item->type == kMethodHandleItem` drives `entry != 0`, so `CheckListSize`
cannot be skipped while the walk runs). No false reject: OFF-vs-ON over **75
sources** including every `all-dex-files.jar` member and `multidex-container.dex`
→ identical. ART fidelity: every anchor re-derived, and `is_field` proven
EXACTLY equivalent to the slicer's `IsField()` given `type <= 8`. The pre-fix
behaviour table above reproduced to the digit. The `_shift` narrowing proven
necessary AND costless — without it the `+4` control fails on the unmutated
build, with it the dexllm#62 revert still fails 6 cases, and no #62-era
regression could be constructed that the narrowed craft can no longer see. The
census re-derived independently: same 9 carriers, same composition. **Both
reviewers reproduced the OFF md5 by deleting the call alone.**

**HONEST LIMIT, stated in the test rather than discovered later:** the
walk-before-the-bound mutant is killed by a SOURCE-level guard, not a
behavioural one. Such a walk stops at the first byte pair decoding to a type
> 0x08, which arbitrary trailing data usually supplies within a few entries, so
whether it faults depends on the file's tail rather than on the defect. The
crafted inflated-count case pins the half that IS deterministic (rejected by the
span bound, no signal, in a subprocess).

### The OTHER encoded_value decoder consumes what it does not render (dexllm#63, 2026-08-19)

dexllm#57 fixed the SLICER's `Reader::ParseEncodedValue`. This repo has **two**
`encoded_value` decoders, and only one of them was fixed — the delta review of
that change said so, and this closes the other half.
`core_ext/dexitem_code_source.cpp`'s **`DecodeEncodedValueText`** reads
static-field initializers for `decompile_class` (the `= …` on a field
declaration) and is a wholly separate implementation. It had no case for
`0x15 METHOD_TYPE` or `0x16 METHOD_HANDLE`, both legal since API 26 and both
ACCEPTED by `VerifyEncodedValue`. They fell to `default: return {};`, which had
already consumed the header byte (`U1 header = *p++;`) and left the
`(arg+1)`-byte payload unread.

**The failure is not garbling — the values SHIFT.** The next value's decode
starts inside the previous payload, so the first following field loses its
initializer outright and the ones after it are rendered with a constant that
belongs to a predecessor. Measured on the crafted fixture:
`FAILURE_TYPE_LINKER_METHOD_THROWS` loses its initializer,
`FAILURE_TYPE_NONE` reads **`= 2`** where it is 0, and
`FAILURE_TYPE_TARGET_METHOD_THROWS` reads **`= 0`** where it is 3. That is a
confident WRONG FACT handed to an analyst or an LLM with no error anywhere —
strictly worse than the "garbled initializer" the issue predicted. (An earlier
draft of this paragraph said "EVERY following field took its predecessor's
constant", which the adversarial reviewer corrected from the measurement: the
first one takes nothing at all.)

**Bounded, and verified rather than assumed** (this is why it is a wrong-ANSWER
finding and not a crash one): the caller is a count-bounded `for` whose
`value_count` is clamped to `static_field_idxs.size()`, so it terminates, and
`ReadIntLE` is `end`-bounded with `sv_end` clamped to the real mmap end, so it
cannot read out of range. Field ASSOCIATION is by loop POSITION, not by
accumulation, so an empty render is correctly "this field has no initializer" and
does not itself mis-associate anything.

**Fix:** merge both into the existing `0x1a METHOD` case. All three are
`(arg+1)`-byte indices with **no Java literal form** — a `MethodType`,
`MethodHandle` or method reference cannot be written as an initializer
expression, so rendering one would put invalid Java into a field declaration.
`{}` means "no initializer" to the caller, which is exactly right; what was
missing is that the payload must be consumed anyway. The shared case's advance
also moved from an unbounded `p += nbytes` (0x1a's own) to the file's
`end`-bounded `ReadIntLE(p, end, nbytes)` — forced by the merge rather than
chosen, and an EQUIVALENT mutant on reachable input (a reviewer built it: on a
verified dex `p + nbytes` cannot pass `end`), so the comment's "strictly safer"
is a defence, not a fix. The width the merged body must survive is **not
uniform**: 0x15/0x1a go through the gate's `idx` lambda (arg <= 3) and 0x16 used
`skip(arg+1)` with no cap, so an EIGHT-byte "index" was gate-legal until
dexllm#72 joined that arm to the same lambda — `ReadIntLE` reads `arg+1` into a
`uint64` in every case, so consumption matches the gate for all three either
way.

**And the bug CLASS was closed, not just this instance.** `default:` now advances
by `nbytes` too — the same structural defence the THIRD encoded_value decoder in
this repo (`ScanEncodedValueStrings`, `dexkit_ext.cpp`, behind
`list_class_strings` / `find_classes_declaring_strings`) already had, which is
exactly why that one never carried this bug while this one did. Unreachable
today (the gate rejects every code outside the 18, verified by a reviewer's
crafted retypes to 0x01/0x05/0x12/0x14, refused strict AND lenient), so it is
defence for the NEXT code rather than a live fix.

**KNOWN COST at the time, and CLOSED by dexllm#64 — this paragraph is kept for
the record, not as current behaviour.** Rendering nothing meant the caller could
not tell "this field has no initializer" from "this field's initializer is
unrenderable", and `decompile_class` is the ONLY surface that reads static values
at all (`render_class_smali` emits none), so the dropped constant was not
recoverable through another API. Both reviewers raised it; it sat against this
repo's own make-ignorance-representable precedent (dexllm#41's `access_flags →
None`, dexllm#49's `dropped_touches`), and the asymmetry was real — a `MethodType`
COULD render as valid Java through `proto_ids`, a `MethodHandle` could not.
dexllm#63 scoped rendering out in its own words ("whether to RENDER anything is a
separate question") and recorded the residual rather than widening silently;
dexllm#64 is the change that took it up, and the asymmetry above is exactly the
expression/comment split it settled on.

**Reachability:** a static initializer whose constant is a `MethodType` or a
`MethodHandle`, which javac does not produce (a compile-time constant field is a
primitive or a `String`). **0 incidence across the corpus and every AOSP sample**,
so it is latent — reachable by construction and by any non-javac producer.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `920fe5b2…`
OFF, `6141dc8e…` ON, and the ON build bit-reproducing its md5 after the swap):**
58 real sources × {verify, class count, and a hash over **every static-field
declaration line of every class**} = **222 axis records / 123,555 initializer
lines → 0 changed**. 2 crafted sources → **both changed**, and the change is the
shift above being repaired. A 0-diff on the real half is required (0 incidence);
the crafted half is what proves the mechanism fires
[[ab-must-prove-the-mechanism-fires]].

**Guards** (13 cases in
[tests/test_encoded_value_method_types.py](tests/test_encoded_value_method_types.py),
which already owned this subject). Two layers, and the matrix proves they are
complementary rather than redundant:

- **behavioural** — a length-preserving retype of ONE byte (5 bits: the first
  static value's type code) in the committed `tests/data/invoke-custom.dex`,
  parametrised over 0x15 and 0x16. `_first_static_value` LOCATES the byte by
  walking `class_defs` instead of hard-coding it, and asserts the shape the craft
  needs — at least TWO values, since the desync is only observable through the
  value that FOLLOWS the crafted one, and a first value that is an INT so the
  retype keeps the payload width. A fixture that ever stops offering that fails
  loudly instead of being patched at a wrong offset.
- **source-level** — `test_the_slicer_parser_implements_every_value_the_verifier_accepts`
  became **`test_every_decoder_implements_every_value_the_verifier_accepts`**,
  parametrised over BOTH decoders, which is what the issue asked for: the
  invariant "whatever the gate accepts, every decoder behind it handles" stated
  once. Its docstring used to DOCUMENT this gap as out of reach. The
  parametrisation is also what keeps a THIRD decoder from being added silently —
  it would have to be listed there.

**Two more guards, and BOTH reviewers had to construct the holes.** The first cut
had 5 mutants and 13 cases; both reviewers independently built a SIXTH that
survived the entire suite, and the adversarial one a SEVENTH:

- **the payload WIDTH was unguarded.** `_retype_first_static_value` preserves
  `arg` by design, and the fixture's first value has `arg == 0`, so the craft can
  only ever produce a ONE-byte payload — a decoder hard-coding
  `ReadIntLE(p, end, 1)` passed everything. Not academic: a proto index >= 256 is
  ordinary, and the gate does not require a minimal encoding, so `arg >= 1` is
  legal for all three codes. Closed by a SECOND craft that replaces the whole
  8-byte array with `35 01 00 | 17 02 | 04 03 | 1e` — same length, still four
  values, and the second value is a STRING whose position depends on the first
  value's width. So the assertion names the string and states the RIGHT ANSWER
  rather than a difference from some mutant. A sibling guard adjudicates it
  against `list_class_strings`, which reads the same array through the THIRD
  decoder — an implementation that is not the one under test.
- **`0x1a` — the case this change actually MODIFIED — was exercised by nothing.**
  Its advance moved from an unbounded `p += nbytes` to `ReadIntLE`, and a mutant
  dropping only its consume passed the whole suite AND ART's own fuzz corpus (the
  one real `0x1a` static value in AOSP is the LAST value of its array, so nothing
  follows it to shift). Fixed by one entry in the parametrisation.

**8 mutants, each BUILT and RUN with a DISTINCT `.so` md5, each killed:** pre-fix
(5 fail), 0x15 dropped (1), 0x16 dropped (1), the cases present but the payload
not consumed (4), **the width hard-coded to 1 (1)**, **0x1a's consume dropped
(1)**, **the `default:` arm reverted to a bare return (1)**, plus a control.

Two things that matrix says. The single-case drops fail only ONE test each —
because the hardened `default:` now consumes, so dropping a case is behaviourally
correct and only the source invariant catches it, which is the hardening working
rather than a guard weakening. And the `default:` mutant is killed only at the
SOURCE level, necessarily: that arm is unreachable on any loadable dex, so an
unreachable defence has nowhere else to be pinned.

parity 29/29, pytest **728 passed / 10 skipped**, corpus-less **322 / 416**,
narrowed to `tests/data/multidex.apk` 631, the guard file green narrowed to each
bundled sample one at a time, determinism (3 processes x 3 `PYTHONHASHSEED`s ->
one digest, unchanged from before the fix), sweep 25,309-class 0-crash 0-timeout,
lint trio clean. No API, `.pyi`, SDK or MCP surface moves — the change is two
switch arms in a decoder behind `decompile_class`, and a reviewer traced the
blast radius closed: `DecodeEncodedValueText` is file-local with exactly one
caller, which itself has exactly one.

### A gate promise that holds only in LOCKSTEP is bounded at the reader (dexllm#71, 2026-08-22)

`DecodeEncodedValueText`'s `0x17 STRING` / `0x18 TYPE` / `0x19 FIELD` /
`0x1b ENUM` arms indexed `strings[idx]` / `type_names[idx]` / `field_ids[idx]`
with an UNBOUNDED subscript, justified in the source by one line — *"idx
validated in-range by VerifyEncodedValue (static_values gate)"*.

That promise is real, and it is about the value at a given OFFSET. It holds only
while the decoder walks the `encoded_array` in **lockstep** with the gate — same
element boundaries, same consumed widths. A decoder that consumes the wrong
number of bytes for any element reads DIFFERENT bytes for every element after
it, and the index it then extracts was validated by nothing.

**Not reachable on the shipped code**, and that is the whole shape of the issue:
what was filed is that the property had no defence in depth, that it was
maintained by two `switch` statements agreeing BY HAND in two files, that the one
test looking at them pinned the wrong axis — and that a conclusion this file
already recorded about the same function was WRONG.

**Measured with the issue's own named vehicle, because no crafted dex can reach
these bails.** The gate bounds every index it accepts, so a firing case needs a
DESYNC, which needs a bug — the a/b alone cannot separate "the corpus is in
lockstep" from "the bound is dead". dexllm#70's over-consume mutant is what
separates them: built on HEAD it **SIGSEGVs** (signal 11) in `decompile_class` on
**3 of 31 loadable corpus sources** — `com.android.example.text.styling.apk`,
`multiple_locale_appname_test.apk`, `Annotation_classes.dex` — and the SAME
mutant with these four bounds gives **0 signals**, judged by SUBPROCESS EXIT
STATUS (a `try/except` cannot see a signal). So a desync here is a CRASH surface,
not a wrong answer, and the bound is what closes it.

**Two independent pieces, and the second is the durable one.** A third — the
0x1c/0x1d recursion depth, which leaned on the identical conditional promise —
was added after review; see below.

**(1) The bound.** `if (idx >= table.size()) return {};` on the four arms (three
source lines: 0x19 and 0x1b share an arm) — the API-boundary shape the safety
contract already permits, the tier dexllm#66 and dexllm#67 chose for their own
readers, and the TIER the 0x15 / 0x16 / 0x1a / 0x1d arms of this same function
ALREADY used, so it is a consistency fix as much as an addition (the exact SHAPE
is 0x15's and 0x1a's; 0x16 bounds through `ResolveMethodHandle`'s `false` and
0x1d as an inline `?`). `{}` is "could not render" — at TOP level that is
indistinguishable from "this field has no initializer", since the caller drops an
empty text, which is acceptable only because the path is unreachable; nested in a
0x1c/0x1d it renders `?`. Bounding the OUTER index is
what covers the 0x19/0x1b arm's inner two: `f` is then a real field_id, whose
`class_idx`/`name_idx` the verifier's intra pass bounded against
type_ids/string_ids — a per-structure check that does not depend on this walk
being in lockstep with anything.

**(2) The WIDTH, not only the CASE SET.**
`test_every_decoder_implements_every_value_the_verifier_accepts` (dexllm#57,
widened by dexllm#63) asserts that every type the gate ACCEPTS is HANDLED. It
says nothing about how many bytes each arm consumes, so a future type code added
to `VerifyEncodedValue` and to a decoder with a MISMATCHED width satisfies it
while re-opening exactly this.
`test_every_decoder_consumes_exactly_what_the_gate_consumes` derives, from
SOURCE, each arm's consumed width as a function of `value_arg` and each gate
arm's accepted `value_arg` set, and compares them **per type code and per
accepted arg** — 64 numeric comparisons per decoder, over all three decoders that
walk an `encoded_array` the gate walks (`DecodeEncodedValueText`,
`ScanEncodedValueStrings`, the slicer's `ParseEncodedValue`). Both sides fail
CLOSED: an idiom the classifier does not recognise reports width 0 and mismatches
loudly rather than being skipped. `ParseCallSiteArg` — the fourth decoder — is
deliberately absent and says why: it walks a call_site array `VerifyEncodedValue`
never walks, so there is no gate for it to be in lockstep WITH.

**The source model is adjudicated by the shipped verifier, which is what makes it
trustworthy** — it is read out of the same file it audits, so on its own it could
degrade to "everything is accepted" and pass. `test_the_gate_model_matches_the_
real_gate_on_every_type_and_arg` builds **32 type codes x `value_arg` 0..4 = 160
crafted dexes** and requires `dexllm.verify()` to agree with the model on every
one. It checks the WIDTH half too, not only the accepted-arg half: each craft is
LAID OUT using the model's width, so a model that got a width wrong produces a
malformed array the real gate rejects. Exactly **18** type codes are accepted at
some arg, which is the floor that keeps the parametrised guard from passing by
skipping everything.

**And a wrong width MOVES a value the assertion names.** For every (type, arg)
the SHIPPED gate accepts, the 8-byte value region of the committed fixture's
`LTestLinkerMethodMinimalArguments` is re-laid as `[crafted value][INT
sentinels]` — 42 / 51 / 17, none of them a value the fixture has — and the
sentinels must come back on the fields FOLLOWING the crafted one. Not a
hand-listed set: the accepted combinations come from `dexllm.verify()` on the
crafts themselves, so a type code that becomes acceptable in future is exercised
the day it does. Length-preserving to the byte: the count uleb stays one byte,
the region stays 8, and a leftover byte is never read.

**That in-place craft stops at `value_arg == 4`** — the region is 8 bytes, so a
6-byte payload plus its header leaves no room for a sentinel. The first draft of
this section called args 5..7 "unreachable behaviourally" and said the symbolic
width invariant covered them; BOTH halves were refuted in review, and the
append-and-repoint craft that closes it is described there.

**Two independent reviewers, and every CONFIRMED finding was in the GUARDS or the
PROSE — none in the bound.** Both re-derived every headline number from their own
builds; the adversarial one additionally instrumented the four bails and found
**0 firings** across the 60-source a/b, 34-source marker probes, **834 crafted
gate-valid dexes** and 46 targeted probes (arg 4..7, maximal in-range indices,
5-byte NON-MINIMAL ulebs for array count / annotation size / name / type_idx,
nesting 14/15/16), with a **positive control** proving the instrumentation live
(the same build + dexllm#70's over-consume mutant → 8 sources / 16 bails). So
"the bound cannot fire on a gate-accepted dex" survived a serious attempt to
break it, and the table-size equality it rests on (`GetStrings().size() ==
header_->string_ids_size`, via `Reader::section`'s unclamped count) was traced
rather than assumed. Ten attempts to weaken or evade the guards were all killed.

**What they DID find, and all of it is fixed here:**

* **Both, independently: the width invariant was blind to the one line the
  argument rests on.** All three classifiers read ARM TEXT, and `nbytes` is
  computed ONCE at the top of each decoder, outside every arm — the model merely
  ASSUMED it in a docstring, while the new C++ comment names exactly that line as
  the reason lockstep holds. `size_t nbytes = std::min<size_t>(value_arg + 1, 5);`
  left **the whole guard file green AND the TRUE corpus-less run green**, while
  ordinary corpus `long` initializers (`value_arg == 7`, what d8 emits for any
  long ≥ 2^56 — six of them in `app-prod-debug.apk`) rendered wrong values and
  desynced the rest of their array. Fixed by pinning the derivation as a
  LITERAL, for the gate and all FOUR decoders (`ParseCallSiteArg` has its own
  copy of the same line — the blind spot is a property of the LINE, not of which
  gate a decoder answers to).
* **"args 5..7 are unreachable behaviourally" was an artefact of the CRAFT, not a
  fact — and the adversarial reviewer built the counter-example.** APPEND a fresh
  `encoded_array` at EOF (4-aligned), repoint the class's `static_values_off` at
  it, grow `file_size`/`data_size`: the dex verifies, loads and decompiles, so
  every width 1..8 is reachable on the same committed fixture. That craft is now
  a guard — LONG / DOUBLE / METHOD_HANDLE (**three** uncapped types at the time,
  not the two the first draft claimed; `case 0x16: return skip(arg + 1);` had no
  cap either, until dexllm#72 gave it ART :1204's and moved it to the capped
  side of that parametrisation) x arg 0..7, plus INT as the negative control that
  must be REJECTED at arg >= 4.
  It doubles as the model cross-check past arg 4. The in-place craft is KEPT
  rather than replaced: it is length-preserving, so nothing but the intended
  bytes can be what changed.
* **The 0x1c/0x1d recursion was leaning on the SAME conditional promise, in the
  same function, and was the one left undone** (correctness, PLAUSIBLE). It
  recursed with no depth parameter under a comment reading *"capped at 16 by the
  gate … which bounds this walk too"* — true in lockstep; on a desync the nesting
  is bounded only by `end - p`, one stack frame per 0x1c byte, an uncatchable
  SIGSEGV of the emit-walk family. Both `DecodeEncodedValueText` and
  `ScanEncodedValueStrings` now carry their own cap at the gate's own cutoff
  (verified EXACT: 16 nested arrays verify and render, 17 are refused by the
  gate).
* **`DecodeStaticInitMap`'s `value_count` clamp — named by this change as one of
  the four reasons the bounds cannot fire — had NO guard**, and deleting it left
  the entire 935-test suite green (adversarial, CONFIRMED). Now pinned. **The
  behavioural half is honest about what it cannot do**: removing the clamp is
  UNDEFINED BEHAVIOUR, not a guaranteed fault — `static_field_idxs[i]` at
  i ~ 100,000 reads ~400 KB past a four-element vector, which lands in mapped
  heap as often as not, and the rebuilt mutant PASSES that case. The killing
  guard is the source pin; the crafted one pins the observable half (the walk
  stops at the field list, the process survives) in a subprocess judged by exit
  status.
* **The production comment named the WRONG test file** (both reviewers) —
  `test_encoded_value_method_types.py`, which this change does not touch and
  which pins the CASE SET, the axis this change's own prose calls insufficient.
  `docs/aosp-oob-divergences.md` had it right: one mirror updated, the other
  missed [[a-rule-you-wrote-binds-your-next-commit]].
* Prose: *"`{}` … is a distinguishable outcome"* is FALSE at top level (the
  caller drops an empty text, so it reads as "no initializer" — the very shape
  dexllm#64 removed for values it could not SPELL); *"the shape the 0x15 / 0x16 /
  0x1a / 0x1d arms already use"* is the TIER for all four but the exact SHAPE for
  only two; "four lines" is three (0x19 and 0x1b share an arm); the a/b lists six
  axes where 450 = 55x8 + 5x2; and the declaration-line count is static-CONTEXT
  lines (field declarations plus static method signatures), not field
  declarations alone.
* **Measurement hygiene, and it is the durable lesson:** neither crash-probe
  script asserted the `.so` md5, so when a concurrent process restored the
  worktree mid-run the probe **silently reported the fixed build's 0 for the
  pre-fix build's question** — the reviewer saw 1/0/0/0 before catching it. Both
  scripts now assert the binary before AND after
  [[verify-build-identity-before-measuring]].

**Measured (a/b OFF=`54f5b54` `a5faf1ca…` vs ON `6af3fc57…`, SAME script, both
`.so` md5-verified, and the ON capture re-taken on the FINAL build after every
review fix and byte-identical to the one taken before them):** 60 sources — the
whole bundled corpus (34), every committed fixture (5), every
`art/test/dexdump/*.dex` (10) and every `tools/dexter/testdata/*.dex` (11); 55
load — x {strict verify verdicts + reasons, load, class count, class list, the
whole decompiled Java, its line count, a hash over every static-context
declaration line, their count} = **450 axis records (55x8 + 5x2), 0 changed**,
over **33,732 classes / 3,019,567 decompiled lines**. A 0-diff is REQUIRED rather
than reassuring — the bound is a no-op while lockstep holds, and the depth cap
sits at exactly the gate's cutoff — which is why the over-consume demonstration
is the half that proves the mechanism [[ab-must-prove-the-mechanism-fires]].
**The strongest single statement of what the diff contains is that M0, the full
pre-fix build of both files, bit-reproduces the OFF md5** `a5faf1ca…`.

parity **29/29**, pytest **976 passed / 24 skipped**, TRUE corpus-less (`test_apk`
MOVED aside) **568 passed / 432 skipped / 0 failed** — all 81 collected cases of
the new file run in the CI leg, since every craft is on a committed fixture —
narrowed to `tests/data/multidex.apk` **877 passed**, both guard files green
narrowed to **each of the 34 bundled samples one at a time**, sweep
**25,309-class / 213,374 method-block 0-crash 0-timeout 0-error, GATE: PASS**,
determinism 3 processes x 3 `PYTHONHASHSEED`s -> one digest **unchanged from
before the fix**, lint trio clean (CI scope; the two pre-existing unformatted
`scripts/` files untouched), doc fences 78,
`scripts/check_dad_boundary.sh` clean.

**Guards** (81 cases in
[tests/test_encoded_value_lockstep.py](tests/test_encoded_value_lockstep.py), 67
run / 14 skipped — a skip is a type code the gate rejects at every arg, i.e.
32 - 18). Four things are pinned at SOURCE level, because that is the only level
left for each: the four bounds, the two depth caps, the `value_count` clamp, and
the shared `nbytes` derivation. On a loadable dex the first three are dead code —
exactly the position this decoder's `default:` arm is in, and the reason
dexllm#63 pinned that one the same way — and the fourth is a line no arm-text
audit can see. Each pin is derived on one axis and literal on the other: the SET
of arms that must carry a bound is every arm that forms a subscript from a value
it read with `ReadIntLE` (the VARIABLE NAME is derived too, so a rename cannot
empty the set silently), while the TABLE each bound names is a literal, so a
bound cannot be quietly retargeted at a table that is always big enough; the
depth caps' VALUE is pinned against the gate's own `kMaxDepth`, so the two cannot
drift. A bound must also be its OWN STATEMENT and PRECEDE its subscript. The
comment scanner has a self-check, since every derivation rests on it —
`dexitem_code_source.cpp` contains `// ---- const-wide/* ----`, and a `/* */`
regex pass applied first swallows ~290 lines silently instead of failing, the
trap dexllm#32 and dexllm#57 each paid for.

**19 mutants plus M0, each BUILT and RUN with a distinct `.so` md5, each killed
by its intended guard**, with a control md5 asserted before the matrix starts and
after it ends: **M0** the full pre-fix build of both files (2 fail, and it
reproduces the OFF md5); the four bounds removed together and each of the three
sites alone (1 each); a bound retargeted at a bigger table (1); a bound moved
AFTER its subscript (1); the 0x17 width hard-coded to one byte (2 — the source
invariant AND the crafted guard); the 0x11 DOUBLE width fixed at four (9); 0x1f
BOOLEAN consuming a payload it does not have (2);
`ScanEncodedValueStrings`' advancing `default:` stopped (2); the GATE narrowed
from `arg <= 3` to `arg <= 1` for INT/FLOAT (42 + 2 errors); the slicer's 0x17
width hard-coded (5); **`nbytes` clamped to 5** (10); the `value_count` clamp
removed (1); each depth cap removed (1 each); a depth cap lowered to 8 (2); and
each decoder's recursion no longer deepening (1 each). **The width mutants dying
in BOTH layers is the complementarity claim stated as a measurement** — neither
layer alone kills them, while the bound-removal, clamp and cap shapes die only at
source, where nothing behavioural can see them. Two mutants had to be rewritten
rather than counted: a first "retarget" edit named a table not in scope in that
arm and did not COMPILE — a build failure is not a kill
[[mutation-harness-restore-pitfalls]] — and two anchors were not UNIQUE
(`case 0x17: {  // STRING` matches in both `DecodeEncodedValueText` and
`ParseCallSiteArg`; `depth + 1)` matches at both recursion sites).

**Three stale claims corrected in the same commit**
[[a-rule-you-wrote-binds-your-next-commit]]: the four `// idx validated in-range
by VerifyEncodedValue` comments, whose promise this change qualifies; the 0x1c
arm's *"which bounds this walk too"*, whose promise this change now enforces
locally; and the dexllm#57 section's *"Wrong-answer only — verified rather than
assumed"*, whose two supporting sentences are both TRUE and neither of which
covers an index arm.

**Deliberately NOT done:** the gate is unchanged, so no new rejection direction
and no false-reject risk; and the SIBLING decoders keep their own arrangements —
`ScanEncodedValueStrings` and `ParseCallSiteArg` already bound their indices at
the reader, and the slicer resolves through `ArrayView`, which throws rather than
reading out of range.


### "Is this an invoke" is spelled four times, and all four missed `invoke-polymorphic` (dexllm#61, 2026-08-20)

`find_call_sites_to("Ljava/lang/invoke/MethodHandle;->invoke(...)")` answered **0**
on a dex that plainly calls it — the target sits in `list_external_method_refs()`,
16 methods carry the opcode, and the xref was silent. Every consumer built on the
caller index (`resolve_call_args`, `permission_callers`,
`summarize_capabilities`, the IOC cross-reference) inherited the blind spot.

**The issue's own diagnosis was half wrong, and the correction is the useful part.**
dexllm#61 named `DexItem::GetInvokeMethodsFromCode`, which selects by instruction
FORMAT (`k35c`/`k3rc`) and claimed that made `invoke-custom`'s `call_site` index a
wrong edge in the cross-reference maps. **That function is DEAD** — 2 mentions
repo-wide (one definition, one declaration), 0 callers, 0 undefined-symbol
references in the built `.so`, and **0 callers in the fork snapshot at `a6f8c3c`
either**, so it never produced an edge at all. `method_invoking_ids` is built at
`dex_item.cpp:479` by an OPCODE-range gate, which is why no phantom exists.

The format proxy was also wrong in a way the issue missed, and wrong from before
invoke-dynamic existed. Derived from slicer's own table rather than by hand, the
format predicate admits **six** opcodes it should not — and one of them is
ordinary:

| opcode | fmt | what BBBB really is | corpus |
|---|---|---|---:|
| `0x24/0x25 filled-new-array` | 35c/3rc | **type** index | **624 sites / 4 sources** |
| `0xE9/0xEA invoke-virtual-quick` | 35c/3rc | **vtable offset** | 0 |
| `0xFC/0xFD invoke-custom` | 35c/3rc | **call_site** index | 46 (committed fixture) |

`filled-new-array` was `k35c` + `kIndexTypeRef` in the very table the function
consults, on the day it was vendored. Had it ever been called, one real corpus
site (`filled-new-array {v1, v4}, [Ljava/lang/String;` → type_idx 6870 →
`method_ids[6870]`) would have asserted that a method "calls
`MenuBuilder.add`". The correct key was one field over in the same row the code
was already reading.

**The real defect is in FOUR live gates**, none of them the named function — the
hand-maintained-enumeration shape dexllm#32 already records:

| site | role |
|---|---|
| `dex_item.cpp:479` | builds `method_invoking_ids` → `method_caller_ids` |
| `dex_item.cpp:1910` `EnumerateInvokeSites` | turns a claimed caller into per-site rows |
| `invoke_args.cpp:116` `BuildCfg` | marks a block as needing the extractor |
| `invoke_args.cpp:591/625` | extracts the arguments |

`find_call_sites_to` needs the first two; `resolve_call_args` needs 1, 3 and 4.

**Fix.** All four now admit `invoke-polymorphic` (0xFA `k45cc`, 0xFB `k4rcc`) and
still exclude `invoke-custom`. The extractor needed no new arm: `k45cc` is
`AG op | BBBB | FEDC | HHHH` and `k4rcc` is `AA op | BBBB | CCCC | HHHH` —
**byte-identical to `k35c`/`k3rc` on code units 0..2**, with a proto unit at index
3 that no gate reads and that `GetOpcodeLen` already accounts for (it returns 4),
so 0xFA joins the 35c arm and 0xFB the 3rc arm. Verified against the slicer's own
`DecodeInstruction`, not assumed.

**One bound the change was OBLIGED to add.** `VerifyInsns` left
`kIndexMethodAndProtoRef` unbounded and said why, with the condition attached:
*"that is safe only because nothing dereferences them ... so a consumer that starts
reading them must add the bound in the same change."* dexllm#61 is that consumer.
Both reviewers found it independently and both CONSTRUCTED it: a 2-byte
length-preserving patch of one 0xFA's BBBB to 0xFFFF in `method_handles.dex`
verifies **valid in STRICT mode** and then yields a `find_call_sites_from` row whose
`callee_descriptor` is **empty** — a shape previously reachable only under
`lenient=True`, since every opcode that reached the site enumerators had a
VerifyInsns-bounded index. Not a crash (`BuildMethodDescriptor` is bounded and
returns `{}`) but a wrong answer on strict-verified input, and the safety contract's
own justification had silently become false. `kIndexMethodAndProtoRef` now shares
the `kIndexMethodRef` bound; the PROTO half (`arg[4]`, not `ridx`) stays unbounded
because nothing reads it, and `kIndexCallSiteRef` stays in the default arm on the
original terms — restated in the comment rather than left stale. **0 false-reject**
over the corpus plus every AOSP dexdump / dexter dex.

**The dead function is DELETED, with a tombstone.** It is a strictly-worse third
implementation of a question two live functions already answer
(`EnumerateInvokeSites`, `GetInvokeMethods`), it is the only format-keyed one, and
it cannot be guarded because no test can call it. Deleting upstream code from the
vendored fork has precedent (the access-flags `Modifier` rewrite), and the
tombstone convention is the one `dex_item.h:169` already uses for the dexllm#32
move. **dexllm#65 was filed off this**: the fork records no upstream baseline, so
its 54 divergences cannot be catalogued, rebased, or upstreamed — a removal is the
least visible kind, and the convention that records it is not itself checked.

**Guard: the invariant, not the instance** ([tests/test_invoke_opcode_gates.py](tests/test_invoke_opcode_gates.py),
16 cases). The truth set is DERIVED from slicer's table — the opcodes whose index
kind is `kIndexMethodRef` or `kIndexMethodAndProtoRef` — which is a source
independent of the gates under audit, since they read a different field of the
same rows; and it is PINNED as a literal beside it, so widening the derivation
rule is a two-place edit and a future Dalvik invoke form fails CLOSED. Each gate's
selected set is extracted from the source (comments stripped with
`test_arg_opcode_coverage`'s scanner — the trap dexllm#32 already paid for) and
asserted EQUAL. A separate test bans the format-keyed shape by name so the failure
says the cause, not an opcode diff.

**Measured (a/b OFF=`a922a4dde248` vs ON, SAME script, both md5-verified, the ON
build bit-reproducing its md5 after the halves were swapped back):** 59 entries —
the whole bundled corpus, the committed fixtures, every `art/test/dexdump/*.dex`
and every `tools/dexter/testdata/*.dex` — x 10 axes (load, class count, every
`find_call_sites_to` row with its caller/offset/opcode over external AND declared
targets, the opcode histogram, `resolve_call_args` rows, `permission_callers`,
`summarize_capabilities`) = **590 records, 4 sources changed**:

| source | call sites | arg rows | opcodes gained |
|---|---|---|---|
| `method_handles.dex` | 237 -> **253** | 195 -> **211** | `0xFA` x16 |
| `invoke-custom.dex` | 493 -> **495** | 441 -> **443** | `0xFA` x2 |
| `const-method-handle.dex` | 22 -> **24** | 18 -> **20** | `0xFA` x2 |
| `invoke-polymorphic.dex` | 1 -> **4** | 1 -> **4** | `0xFA` x2, **`0xFB` x1** |

**0 rows removed and no pre-existing opcode count moves**; `permission_callers` and
`summarize_capabilities` are unchanged on every source; the entire bundled corpus is
byte-identical — required, since it carries **0** invoke-polymorphic sites. That is
why the fixtures are IN the a/b: without them a flat result would prove only that
the corpus is quiet [[ab-must-prove-the-mechanism-fires]].

**It is NOT purely additive, and the first draft of this paragraph said it was.** An
adversarial reviewer decomposed `const-method-handle.dex` past the row count and
found an ORDINARY `invoke-virtual` whose second argument moves `Unknown` ->
`MethodReturn`: 0xFA now joins the arm that sets `has_last_invoke` /
`last_invoke_callee`, so a `move-result-object` following a polymorphic call finally
resolves. That is an improvement, and it is `Unknown` -> concrete rather than
concrete -> a DIFFERENT concrete (the shape dexllm#16's gate exists for) — but it is
a value change on a site the change does not otherwise touch, and it belonged in the
record.

**The first diff of this a/b reported 3 sources, not 4** — the capture was right and
the DIFF HARNESS lied. It keyed each row on the file's BASENAME, and two different
files are named `invoke-polymorphic.dex` (AOSP's, which loads, and dexter's, which
this repo's verifier rejects for an unrelated `outs_size > registers_size`); the
collision let the second overwrite the first, and the surviving row was identical in
both halves. The one source that exercises **0xFB at all** was therefore reported as
unchanged, and the summary claim "only 0xFA rows appear" followed from it.
[[ab-harness-must-itself-be-deterministic]] — the collision shape, not the ordering
one.

**Two more committed fixtures were needed, and neither is optional.**

`tests/data/method_handles.dex` (28,228 B, AOSP `tools/dexter/testdata/`,
Apache-2.0). The already-committed `invoke-custom.dex` does carry two polymorphic
sites — but in blocks that also hold an ordinary invoke, so reverting the CFG mark
is **MASKED** there (`resolve_call_args` stays at 2). On this file the same revert
takes it 10 -> 0, the only behavioural evidence that gate is load-bearing. Its 16
sites are all in ONE of its 24 classes and all arity 3, which is why it is not
sufficient on its own.

`tests/data/invoke-polymorphic.dex` (1,160 B, AOSP `art/test/dexdump/`,
Apache-2.0). Both reviewers found, independently, that **0xFB
(`invoke-polymorphic/range`) had ZERO behavioural coverage anywhere in the repo** —
not in the other fixtures, not in the corpus, not in dexllm#58's verifier guard,
which is 0xFA-only. Two mutants survived the whole suite on that alone: moving
`case 0xFB` into the 45cc arm (the source guard sees the arms' UNION, so it passes)
and excluding 0xFB with `&& op != 0xfb` while leaving its literal in place. This
file kills both — its one range site has a **7-register window** the arm swap
collapses to empty — and it is the only fixture with a 45cc at **A=5**, where the G
nibble is a real argument rather than padding. Note that dexter ships a file of the
same name that is NOT usable: this repo's verifier rejects it (`outs_size >
registers_size`).

**16 mutants, each BUILT and RUN with a distinct `.so` md5, each killed by its
intended guard.** Eight from the diff — the four gate reverts, the dead function
restored, the derivation rule widened to admit a `call_site` operand, and
`invoke-custom` added to one gate and then to two. **Eight more that both reviewers
CONSTRUCTED, every one of which passed the first cut of the guards in full:**

| escape | why it was invisible | now killed by |
|---|---|---|
| an emit arm opening `if (!emit) break;` (39 fabricated rows on the committed fixture) | the locator stopped at the first `break;` | brace-matched arm bodies |
| a SECOND collector after the first write in the same block | the locator sliced up to that write | the whole `if` block |
| a second `in.invoke` statement | the locator read one assignment | every `in.invoke` statement, unioned |
| `&& op != 0xfb` with the `op == 0xfb` literal left in place | a negated clause makes the extracted set LARGER | `_opcodes_in_condition` REFUSES unmodelled `op` comparisons |
| `case 0xFB` moved into the 45cc arm | the source guard sees the arms' UNION | the 7-register range assertion |
| the 45cc count read from `AA` instead of the B nibble | both behavioural tests asserted only `all(r.args)` | per-row register lists |
| the verifier bound reverted | nothing tested it | the crafted OOB-BBBB rejection |
| a format-keyed gate spelled `ins_formats[op] ==` | the shape test matched only the `op_format` local | both spellings |

**Three defects were in the HARNESS or the GUARDS, found only by RUNNING mutants:**
a `needs_rebuild=no` mutant ran against the PREVIOUS mutant's `.so` (always
rebuild); the "restore the dead function" mutant did not COMPILE, so it was never a
mutant (a build failure is not a kill); and the phantom-edge guard swept only
EXTERNAL refs and was empty — a `call_site` index is small, so it lands on a low
`method_ids` entry, i.e. an app method, and the 40 fabricated rows were all
invisible to it.

**Both reviewers, and every CONFIRMED finding was in the guards, the measurement or
the prose — none in the opcode set or the decode.** They independently re-derived
the 12-opcode truth set from the table, verified the 45cc/4rcc layout against an
oracle built from ART's own `GetVarArgs` (21/21 sites over three files, including
arity 4, arity 5 and the 7-register range form), fuzzed 500 crafted retypings with
subprocess exit-status judging (0 nonzero exits), and refuted the deletion's
behaviour-neutrality attack. What they found: the missing verifier bound (both,
CONFIRMED, fixed above), the eight guard escapes in the table, the a/b's
basename collision, the "all additive" overstatement, a `__repr__`-slicing target
list, a test docstring that contradicted `tests/data/README.md`, a README claim that
the 16 sites are "across 24 classes" when they are all in ONE, and two prose lists
that omitted `invoke-virtual-quick`. All fixed here.

parity **29/29**, pytest **744 passed / 10 skipped**, corpus-less **338 passed /
416 skipped** (+16, the guard file runs there because it uses committed fixtures
only), narrowed to `tests/data/multidex.apk` **647**, the guard file green narrowed
to **each of the 38 bundled samples one at a time**, sweep **25,309-class /
213,374-method 0-crash 0-timeout**, determinism 3 `PYTHONHASHSEED`s -> one digest,
lint trio clean. The a/b was re-captured on the FINAL build (with the verifier
bound) and is **identical on all 59 entries** to the capture taken before it — the
bound is a no-op on every real input, which is the 0-false-reject claim restated as
a measurement.

**Observable change, deliberately:** `CallSite.invoke_opcode` can now be `0xFA`
(250) or `0xFB`, values a consumer switching on the opcode has never seen —
documented in [docs/api.md](docs/api.md), which previously described the field as
"e.g. 110 = invoke-virtual" and said nothing about the admissible set. And
`find_call_sites_to` / `resolve_call_args` now ANSWER where they used to be
silent, for any dex using `MethodHandle`/`VarHandle` (API 26+). Release-notes
material.

**dexllm#60 stays open** — the smali emitter still prints `invoke-polymorphic
<unhandled-fmt-29>` and the IR builder still fails to decompile the six methods
whose `move-result` follows one. Same family, different layers.

### `invoke-polymorphic` renders its operands (dexllm#60, smali half, 2026-08-20)

`render_*_smali` printed **`invoke-polymorphic <unhandled-fmt-29>`** — the mnemonic
with no operands at all, 16 times on `method_handles.dex`. The listing is what an
analyst or an LLM reads, so a call whose whole point is the method handle it invokes
rendered as a bare word. `FormatOperands`' format switch had no case for
`k45cc` / `k4rcc`; before dexllm#58 no dex carrying one could load, so it had never
been observed on a real file.

**The register set differs from `k35c` even though the raw bytes do not.** slicer's
`DecodeInstruction` puts C in `vC` and D..G in `arg[0..3]` for `k45cc`, where `k35c`
puts C..G in `arg[0..4]` — so an arm that reuses the k35c walk prints the **proto
index as a register**. `k4rcc` is `{vC .. vC+vA-1}` with the proto likewise in
`arg[4]`.

**Both operands are emitted, because one cannot be derived from the other.** A
signature-polymorphic method's `method_ids` entry is the DECLARATION
(`invoke([Ljava/lang/Object;)Ljava/lang/Object;`) while the actual call signature is
the separate `proto_ids` operand. `FormatProto` was factored out of
`FormatMethodRef` (which already rendered a proto) so both share one implementation,
and `emit_index` gained `kIndexMethodAndProtoRef` for the BBBB half. Output is
baksmali-shaped: `invoke-polymorphic {v0, v2, v3, v4}, Lcls;->m(...)R, (DI)I`.

**Measured (a/b OFF=HEAD `d1b3ff357f02` vs ON `4d280b8fd662`, SAME script, both
md5-verified):** 63 entries x {class count, whole-source smali sha256,
`<unhandled-fmt-` count} — **7 changed, all of them carriers** (4 distinct files;
three appear at two paths each). Every change is `unhandled N -> 0`. **The whole
bundled corpus's smali is byte-identical**, so the `FormatMethodRef` refactor is
neutral, and **0 `<unhandled-fmt-` remain across all 63 entries**.

**Guard: the invariant, not the two formats**
([tests/test_smali_instruction_formats.py](tests/test_smali_instruction_formats.py),
16 cases). Derived from slicer's own table: **every format a named (non-`unused`)
opcode uses must appear in the switch** — 26/26 today, and a future Dalvik format is
a FAILURE rather than a silent degradation. The behavioural half runs on the three
committed fixtures (corpus-less, narrowing-proof) and pins the three rendered lines
as LITERALS. A proto-derived oracle checks the register COUNT against the call-site
signature (receiver + parameters, `J`/`D` counted twice) — worth having, but its
limit is stated in the test rather than discovered later: it CANNOT catch a
re-indexing that preserves the count, which is exactly the k35c-layout mutant, and
that one dies only on the pinned literals.

**Both reviewers independently CONFIRMED the same HIGH, and this change introduced
it: the `k45cc` arm did not clamp the argument count.** `insn.arg` is `u4 arg[5]`
and `vA` is a 4-bit NIBBLE, so `vA >= 6` walks past the array — into the struct's
own `opcode` field and then off the end of a STACK object. Nothing upstream stops
it, and the neighbouring `k35c` arm is safe for a reason rather than by luck:
slicer's decoder ends its 35c count switch in `SLICER_CHECK(!"Invalid arg count")`,
so a >5 count throws before the renderer runs, while **k45cc has no such check** and
`VerifyInsns`' own vararg loop CLAMPS (`k < d.vA && k < 5`) instead of failing. A
one-nibble length-preserving patch therefore yields a dex that `verify()` calls
**valid** and whose listing prints `v250` (the `opcode` field) and then process
addresses that CHANGE BETWEEN RUNS — an OOB read, an address leak into a primary
output, and a determinism break at once, with an ASan `stack-buffer-overflow` at
the exact line. Fixed with `&& i < 5`, the same bound `VerifyInsns` already applies
to the same operand. Negative controls, both RUN: the OFF build renders
`<unhandled-fmt-29>` (its `default:` arm read no array at all, so the defect is
this change's), and the identical patch on a `k35c` invoke is refused at LOAD by
slicer's check.

**A second CONFIRMED (MEDIUM): the `<bad-proto-idx>` bound had no guard.** dexllm#61
deliberately left the PROTO half of a polymorphic operand unbounded in the verifier
— the method half is bounded there because an out-of-range one produced an EMPTY
`callee_descriptor`, indistinguishable from a real value, whereas this one has a
visible sentinel. That makes the sentinel load-bearing, and deleting its one line
left the whole suite green (347 passed) while a crafted `proto@0xFFFF` on a
`verify()`-valid dex threw `SLICER_CHECK_LT` out of `ArrayView` and killed the
entire class listing. The verifier comment claiming that operand is "dereferenced
by nothing" was made FALSE by this change and is corrected rather than left stale;
the asymmetry between the two halves is now stated as a decision.

**Also fixed from review, none of it in the layout:** a `vA == 0` range invoke
printed `{v0 .. v4294967295}` (`kVerifyVarArgRangeNonZero` is NOT enforced —
`VerifyInsns` guards on `d.vA > 0`), which the pre-existing `k3rc` arm does too and
which is corrected in both rather than left as the thing the new one was copied
from; `_proto_register_width` counted `[J` as two registers, a false positive
against CORRECT output waiting for a `long[]` parameter; the doc comment
`// Format a method's full smali ref` stayed behind with `FormatProto` when the
body moved; and the prose named a function (`RenderInstructionOperands`) that does
not exist.

**What the reviewers could NOT break** — built, not argued: the register layout (an
independent spec decoder over 44 sites in 7 files, 0 mismatch, plus agreement with
AOSP dexdump's own committed expected output), the refactor's byte-identity, every
index bound inside `FormatProto`, the reachability of `kIndexMethodAndProtoRef`
from any other format, and the a/b, which one of them reproduced from its own two
builds.

**10 mutants, each BUILT and RUN with a distinct `.so` md5, each killed by its
intended guard:** the first six (each arm removed, the k35c register layout, the
`emit_index` case, the proto operand, a `FormatProto` regression) plus the four the
review forced — the clamp removed (4 arity cases fail), the `<bad-proto-idx>` line
deleted, the range-underflow guard removed, and an arm wrong ONLY at arity 1.

**The crafted guards cover the arities the fixtures cannot.** The three committed
files carry A in {1, 3, 4, 5} and one 7-register range; **A > 5 appears nowhere**,
which is exactly why the HIGH passed 9/9. The new cases patch a single nibble or
`u2` IN PLACE — section sizes and offsets untouched, so nothing but the intended
operand can be what changed — and they assert on the RESULT (at most five
registers, no register number outside a Dalvik frame, and the same bytes rendering
identically in a FRESH PROCESS) rather than on "it did not crash", which is the
property no crash-check would give.

parity **29/29**, pytest **760 passed / 10 skipped**, corpus-less **354 / 416**,
narrowed to `tests/data/multidex.apk` **663**, the guard file green narrowed to
each of the 38 bundled samples, sweep **25,309-class 0-crash 0-timeout**,
determinism 3 `PYTHONHASHSEED`s -> one digest, lint trio clean. The a/b was
re-captured after the review fixes and is **identical to the pre-fix capture on all
63 entries** — the clamp and the range guard are no-ops on every real input, which
is the 0-regression claim restated as a measurement.

**`invoke-custom`'s operand is not RESOLVED here** — its BBBB is a `call_site_ids`
index, and rendering the call site's contents needs a reader this port did not have
at the time. Honest and out of scope; the issue does not ask for it. (dexllm#67 later
built that reader for the IR, in `core_ext` rather than in the slicer, and
deliberately left THIS listing alone: the smali view stays baksmali-shaped.)
(dexllm#66 later replaced the bare `@N` with the LABEL `call_site@N`, which is a
different claim — the second clause above survives, the "renders as `@N`" headline
this paragraph used to carry does not. Found by a correctness review as a stale
mirror, the pattern this file records elsewhere.)

**The IR half followed in the same series — see the section below.**

### The IR models `invoke-polymorphic`, so a `move-result` after one resolves (dexllm#60, IR half, 2026-08-20)

Six of `method_handles.dex`'s 142 methods emitted `// DECOMPILE ERROR: malformed
bytecode: null operand to MoveExpression` — the builder had no handler for 0xFA/0xFB,
so the following `move-result-object` found no invoke and hit the documented
null-guard at [instruction.cpp:274](native/dad_cpp/instruction.cpp#L274). The guard
was doing its job; the method was still lost, and these are exactly the methods a
`MethodHandle` sample is interesting for. Both reviewers measured a second, QUIETER loss and gave different counts, so it was
re-derived here rather than either published: across the three committed fixtures
**18 methods carry a polymorphic call, and before this change all 18 were broken** —
7 loudly (`DECOMPILE ERROR`) and **11 silently**, the call simply ABSENT from the
emitted body with no error at all (a `NopExpression`). After: **0 and 0**. The error
count alone therefore understates the change by more than half — `Jazzer.exploreState`
gains its whole `invokeExact(...)`, `TestUninitializedCallSite` gains
`.getTarget().invoke()`, and `displayMethodHandle` rendered
`append(Float.valueOf(12300f))` where the truth is `append(p3.invoke(...))`.

**The signature comes from the CALL SITE, and that is the whole design.** Every
`MethodHandle.invoke` shares one declaration,
`([Ljava/lang/Object;)Ljava/lang/Object;`, so taking the signature from the method
would group N arguments as ONE and type every result `Object`. `invoke-polymorphic`
carries a second operand — a `proto_ids` index — that says how many registers each
argument occupies (a `J`/`D` takes two) and what the result really is. Measured on
the fixture: `{v0 .. v6}` (SEVEN registers) + `(Ljava/lang/String;DILjava/lang/Object;I)Ljava/lang/String;`
renders exactly **five** arguments with the `double` consuming two of them.

| layer | change |
|---|---|
| snapshot ABI | `MethodConst::call_site_proto` — a VIEW into the adapter's existing pointer-stable proto cache, so no owned copy and the same lifetime `triple[2]` already has |
| the port | `IDexCodeSource::GetProto` with a **DEFAULT** returning `{}` |
| adapter | delegates to the pre-existing `GetProtoCached`, which already bounds the index |
| builder | `ResolveConstRef` resolves `kIndexMethodAndProtoRef` — method from `vB`, proto from `arg[4]` |
| dispatch | `BuildMethodRef` prefers the call-site proto; `BuildPolymorphicRegs` uses `{vC, arg[0..3]}`; both kinds route to the EXISTING virtual handlers |

**The defaulted virtual is what keeps this cheap.** `MockCodeSource` and all 29
parity suites are untouched, so extending the hexagonal port cost nothing on the
test side — and `scripts/check_dad_boundary.sh` stays clean, because the new method
is on the port rather than a DexKit include.

**beyond-DAD, with no `// DAD:` analogue**: androguard's own instruction table is
**227 entries** and stops before 0xFA, so there is nothing upstream to be faithful
to. Verified against the installed androguard, not assumed.

**Measured (a/b OFF=`49d30d4b9454` vs ON, SAME script, both md5-verified):** 63
entries x {class count, whole-source decompiled-Java sha256, `DECOMPILE ERROR`
count} -> **7 changed, all carriers** (4 distinct files): `method_handles.dex`
**6 -> 0** errors, `invoke-polymorphic.dex` **1 -> 0**, total **24 -> 10**. The
residual 10 are `invoke-custom` (0xFC), whose operand is a `call_site_ids` index —
the vendored slicer has no call-site reader at all, so modelling it is a separate
piece of work and a guard pins that boundary explicitly. **The bundled corpus is
byte-identical**: it carries 0 polymorphic sites, so the fixtures are the only
evidence the mechanism fires [[ab-must-prove-the-mechanism-fires]].

**The sister commit's HIGH was checked for here FIRST, and is absent.** `ce7a43d`
(the smali half) walked `arg[0..vA-1]` while `vA` is a 4-bit nibble and `arg` is
`u4 arg[5]` — a stack overread on a `verify()`-valid dex. `BuildPolymorphicRegs`
reads at most `arg[3]` whatever `vA` says, which a reviewer confirmed by crafting
`vA` = 6 and 15 (both verify VALID, since `kVerifyVarArgNonZero` is not enforced)
and finding the output byte-identical to the unpatched fixture. It is now pinned by
a crafted guard rather than left to inspection.

**A crafted proto index made the IR emit a plausible, silently WRONG argument list
— and it broke a rule this series had written down one commit earlier.** The smali
half's verifier comment justified leaving the proto operand unbounded because its
one reader yields `<bad-proto-idx>`, "a visible, distinguishable value rather than
the empty descriptor that made the METHOD half a wrong ANSWER". The IR is a SECOND
reader and cannot signal that way: an unresolvable proto falls back to
`MethodHandle.invoke`'s declaration, so a 4-argument call renders with ONE while the
smali view of the same instruction says `<bad-proto-idx>`. Constructed by a reviewer
on a **strict-verify-valid** dex. `VerifyInsns` now bounds the proto half on exactly
the terms dexllm#61 bounded the method half (`code: proto index out of range`; 0
false-reject over the corpus plus every AOSP dexdump/dexter dex), the comment is
rewritten to enumerate both readers, and the smali guard that pinned the sentinel was
**silently SKIPPING** afterwards — a skip is not a pass — so it is retargeted at
`lenient=True`, where `VerifyInsns` is off and the sentinel still earns its place.

**Review also found the ret-type half completely UNGUARDED.** A mutant forcing every polymorphic result to `int` turns
`Object v0 = ...CONSUME.invokeExact(p2, p3)` into uncompilable Java and **passed the
whole file**; a subtler one taking the return type from the DECLARATION passed too
AND produced byte-identical output, because the only live non-void call-site return
in the fixtures happens to BE `Object`. The first is now killed by an assertion on
that line; the second is **currently unkillable from the committed corpus** and is
recorded as a known gap in the test rather than papered over — closing it needs a
fixture with a live, non-`Object`, non-void polymorphic result. The void-site test's
docstring claimed to distinguish the ret half and did not (DCE removes an unread
value whatever its type); corrected.

**Also from review:** `#include <string>` had been deleted from a header that still
declares three `std::string` members (it compiled only transitively, through
libstdc++ internals and a vendored slicer header) — restored, and it was never part
of this change; `docs/architecture.md` called the port "Pure abstract (`= 0`)",
untrue since `IsAssignable` and now wrong for a third method; and the AST reports
the METHOD's proto beside call-site-derived params, which is deliberate (the triple
is identity) but was undocumented — now stated at the ABI, with a guard pinning that
the two emitters agree on the argument LIST even though the identity triple differs.

**Also from the adversarial pass:** deleting the arm that supplies the FIFTH
argument register passed the whole file while turning three real arguments into
`unknownType v` on both fixtures — the argument test checked only slots 0 and 1, so
the last slot was unasserted at every arity; it now pins every slot as a literal
list. Two comments disagreed about what the empty-proto fallback loses (grouping
only, vs grouping AND result type — the latter is right, demonstrated with a crafted
`(BB)B` call site). The crafted guards located their instruction with a bare
whole-file `0xFA` byte scan; they now assert the shape first, as the repo's own
crafting helpers do. And the non-range dispatch arm had been placed under the
`Invoke-range (3rc)` banner.

**14 mutants, each BUILT and RUN with a distinct `.so` md5:** 13 killed — the k35c
register walk, 0xFA undispatched, 0xFB undispatched, the `kIndexMethodAndProtoRef`
case removed, `GetProto` returning empty, the proto read from `arg[3]`, the register
window shifted so `vC` is dropped, `param_type` from the declaration, the receiver
treated as an argument, the result forced to `int`, an unclamped register walk, and the fifth argument
register dropped. The 14th is the declaration-vs-call-site RETURN type, proven
EQUIVALENT on these fixtures rather than escaping.

parity **29/29** (this touches `dad_cpp`, so it is the real gate), pytest **772
passed / 10 skipped**, corpus-less **366 / 416**, narrowed to
`tests/data/multidex.apk` **675**, both guard files green narrowed to each of the 38
bundled samples, sweep **25,309-class 0-crash 0-timeout**, determinism 3
`PYTHONHASHSEED`s -> one digest, `scripts/check_dad_boundary.sh` clean. The a/b was
re-captured on the FINAL build (with the verifier bound and every review fix) and is
**identical on all 63 entries** to the capture taken before them.

**`invoke-custom` (0xFC/0xFD) was left unmodelled here** — its operand names a call
site, not a method — and pinned by a guard saying a future change should delete it.
**dexllm#67 is that change** (see its section below); the guard is gone and its
replacement lives in `tests/test_invoke_custom_ir.py`. The claim that resolving one
needs a slicer accessor turned out to be FALSE: `core_ext` reads the section
directly, the way it already reads `type_list` and `static_values`.

### Every index operand is resolved or LABELLED, never a bare `@N` (dexllm#66, 2026-08-22)

`FormatOperands`' inner `emit_index` lambda had the same gap its format sibling
did: index kinds fell to `default:` and rendered a bare **`@N`**, which does not
even say what table `N` indexes — `invoke-custom {}, @0` where AOSP dexdump says
`call_site@0000`. The listing is a primary output, so `@0` is strictly less
informative than `call_site@0`: it does not distinguish a call site from a proto
from a method handle.

**The issue named three kinds; its own proposed guard does not close at three.**
Deriving "every index kind a named opcode can carry into `emit_index`" from the
VENDORED slicer table yields **five**: the three invoke-dynamic kinds plus
`kIndexFieldOffset` (14 opcodes) and `kIndexVtableOffset` (2) — the ODEX quick
forms. Modern ART DELETED those (0xE3-0xF2 are `unused-e3` there, and its own
dexdump has no arm for them, which is why dexdump could not be the oracle for
that half) but the vendored table still names all 16, and that table is what this
decoder consults. Their operand is an **OFFSET**, so `@N` there is not merely
uninformative but wrong — it reads as an id into a table. Handling them is what
makes the invariant a TOTAL function instead of one needing an exception list this
repo requires to be JUSTIFIED, not merely listed; and there is no justification
for rendering an offset as an index. They are reachable on a STRICT-verified dex
for the reason dexllm#32 already records (`VerifyInsns` has no opcode-legality
gate), so an odex-derived packer dump carries them.

| operand | before | after |
|---|---|---|
| `const-method-type` (`kIndexProtoRef`) | `@17` | **`(CSIJFDLjava/lang/Object;)Z`** — fully RESOLVED |
| `const-method-handle` | `@1` | `method_handle@1` |
| `invoke-custom[/range]` | `@45` | `call_site@45` |
| `iget/iput-*-quick` † | `@2` | `field_off@2` |
| `invoke-virtual[/range]-quick` † | `@182` | `vtable@182` |

† crafted — the two quick kinds have **0 incidence** anywhere in reach (the only
textual corpus hits are `"application/x-quicktime-tx3g"` string literals), so these
two rows are one-byte format-preserving retypes of a committed fixture
(`iget-wide` 0x53 -> `iget-wide-quick` 0xE4 and `invoke-virtual` 0x6E ->
`invoke-virtual-quick` 0xE9, both keeping their format and their operand), each
asserted STRICT-valid. Every row quotes a real operand a real site holds; the
guards additionally WRITE a distinctive one, see below.

`const-method-type` is the one that RESOLVES, and it is one line: its operand is a
`proto_ids` index — the same thing `invoke-polymorphic`'s HHHH is — so the
`FormatProto` dexllm#60 factored out renders it with the bound already inside. The
PROTO matches dexdump's own committed expected output for this fixture character
for character (`art/test/dexdump/const-method-handle.txt`); **the whole LINE does
not**, and is not meant to — dexdump appends a `// proto@0011` provenance comment,
which this renderer has no convention for on any operand. (An earlier draft said
"byte-for-byte as dexdump does" without that qualifier; a reviewer produced the
`.txt`.) The same divergence is deliberate on the two LABELS: dexdump spells them
`call_site@%0*x` / `method_handle@%0*x`, i.e. zero-padded HEX, and these are
decimal because the surrounding `string@N` / `type@N` fallbacks in the same lambda
are — house style beats matching a tool this listing is not otherwise shaped like
(it is baksmali-shaped). The other four are LABELS. A method handle and a
call site are not resolved because dexdump does not resolve them either ("too
large to detail in disassembly"), and a call site additionally needed a
`call_site_ids` reader nothing in the tree had (dexllm#67, which added one to
`core_ext` for the IR and left this listing as it is).

**No verifier change — but its comment had to be corrected, and that was a
precondition rather than tidying.** `VerifyInsns` leaves `kIndexProtoRef` in the
`default:` arm justified as *"nothing reads them"*, with the standing rule *"a
consumer that starts reading one bounds it in the same change, here or at the
reader."* This IS that consumer for 0xFF, so the claim became FALSE and is
rewritten. The obligation is discharged **at the reader**, which the rule permits
and which is the right tier here: `FormatProto` bounds the index itself and yields
the distinguishable `<bad-proto-idx>`, and it is the ONLY reader (`ResolveConstRef`
returns `monostate` for 0xFF). That is exactly where the polymorphic proto stood
before dexllm#60's IR half added a SECOND reader that could not signal — which is
what moved that one, and only that one, to the gate. The two LABEL kinds
dereference nothing, so "nothing reads them" still holds for them and is stated
per-kind rather than as a group. [[a-rule-you-wrote-binds-your-next-commit]].

**Fixture:** `tests/data/const-method-handle.dex` (2,524 B, AOSP
`art/test/dexdump/const-method-handle.dex`, Apache-2.0, provenance in
[tests/data/README.md](tests/data/README.md)). `const-method-type` has **0 sites**
across the gitignored corpus, all three existing fixtures and `multidex.apk`, and
it is the one kind that RESOLVES — so without a carrier the difference between
resolving the proto and printing another label was unobservable. **What it does
NOT close, checked rather than claimed:** dexllm#60 records a mutant it could not
kill (a polymorphic return type taken from the signature-polymorphic DECLARATION)
and says it needs "a fixture with a live, non-`Object`, non-void polymorphic
result". This file has exactly that shape — `(Ljava/lang/Object;)Ljava/lang/Class;`
+ `move-result-object` — and it still does not kill it: `RegisterPropagation`
inlines the result straight into a `StringBuilder.append(Object)` argument, so the
type never reaches a declaration and both return types render identically. The gap
STANDS; it was flagged as a likely bonus and the measurement refuted it.

**Measured (a/b OFF vs ON, SAME script, both `.so` md5-verified — `add228b2` OFF
and `d277837c` ON, and the ON build bit-reproducing its md5 after the halves were
swapped back):** 60 entries (34 bundled corpus + 5 committed fixtures + 10
`art/test/dexdump/*.dex` + 11 `tools/dexter/testdata/*.dex`; 55 loadable, the 5
others being resources-only containers and the dexter file this verifier rejects
for `outs_size > registers_size`) —
x {load verdict, class count, whole-source smali sha256, bare-`@N` count, per-kind
counts} = **6 changed, 0 load verdicts moved**, and the 6 are **3 distinct files**
each present at two paths (the committed copy and the AOSP original — keyed on the
full PATH, not the basename, which is the collision dexllm#61's diff harness hit).
Bare `@N` across all 60: **100 -> 0**. A LINE-LEVEL diff over those three files
(**4,504 lines**) resolves it exactly: **50 differing, 0 added, 0 removed**, every
one a line whose OFF form ended in a bare `@N` and whose prefix (mnemonic +
registers) is byte-identical — 46 `call_site@`, 3 `method_handle@`, 1 resolved
proto (the 4,504 is lines COMPARED — the a/b holds one list per class, and a
whole-file concatenation of the same text counts 4,467; a reviewer re-derived the
second and it is the same bytes, differently delimited). **The 54 unchanged entries include the entire bundled APK corpus**, which
carries 0 sites of all five kinds (the only textual hits are
`"application/x-quicktime-tx3g"` string literals), so the fixtures are the sole
evidence the mechanism fires [[ab-must-prove-the-mechanism-fires]].

**Guards** (18 new cases, appended to
[tests/test_smali_instruction_formats.py](tests/test_smali_instruction_formats.py)
— the file that already states the FORMAT invariant, which this is the INDEX-kind
analogue of; **16 -> 34** collected, 2 of them the pre-existing
`<unhandled-fmt-N>` sweep widened to the two fixtures it did not cover). The truth set is derived from TWO independent
places — slicer's table (which kind each opcode carries) and the format switch
(which arms actually call `emit_index`) — and **each is also PINNED as a literal**,
because a guard parametrised over the production source cannot catch an EDIT of it:
a format arm that stops calling `emit_index` would narrow the derivation and turn
the invariant vacuously green. The behavioural half pins the three real carriers'
lines as literals, asserts no fixture renders a residual `, @N` (which the literals
alone cannot say — a sixth kind added with no arm satisfies every one of them), and
CRAFTS the two quick kinds, which no dex in reach carries: one byte and
format-preserving (`iget-object` 0x54 -> `iget-object-quick` 0xE5, both k22c;
`invoke-virtual` 0x6E -> `invoke-virtual-quick` 0xE9, both k35c), located through
the declaring method's `code_off` rather than by scanning for a loose opcode byte,
with the craft asserted STRICT-valid — that it verifies is the point.

**16 mutants, each BUILT and RUN with a distinct `.so` md5, each killed.** Ten
from the diff: the pre-fix arm set (9 fail — and its `.so` md5 reproduces the OFF
build's exactly, which is also how the verifier edit is PROVEN comment-only), each
of the five kinds dropped alone (3 / 5 / 3 / 2 / 2), `kIndexProtoRef` LABELLED as
`proto@N` instead of resolved — the plausible half-fix (1), the two label strings
SWAPPED (3), and the derivation shrunk by gutting the `k21c` arm (7). Plus an
unmutated control.

**Six more the adversarial review CONSTRUCTED, every one of which passed the whole
file — and they are the finding.** `o << "<label>@" << v` has TWO halves and the
guards pinned only the half that is a constant: the crafted quick tests asserted
the label PREFIX (`want in line`), and its sibling `not _BARE_INDEX.search(...)`
was IMPLIED by it, so **`<< v` — the load-bearing half of both offset arms — had
no guard at all**. `<< 0` on either offset arm, `std::hex` on any arm, and
`call_site@ (v & 0xF)` all passed 30/30. The truncation is a genuine escape rather
than an equivalent mutant: `invoke-custom.dex` carries 46 distinct call-site
indices up to 45, so `& 0xF` moves **30 of the 46 rendered lines**, and the one
pinned literal is `call_site@0`, where `0 & 0xF == 0`. The hex mutants died only
by luck of that same value. `std::hex` is the realistic future commit, since
baksmali spells these `vtable@0x4`.

**The SECOND reviewer found the same gap independently**, with three more escapes
of its own (`call_site@ << 0`, and both offset arms emitting `insn.vA` — a register
number where an index belongs), and made the sharpest statement of why it matters:
under `call_site@ << 0` every one of `invoke-custom.dex`'s 46 sites renders the
same operand and the whole suite is byte-for-byte as green as the unmutated build.
That is **strictly worse output than the `@N` this change removes** — `@45` was
uninformative, `call_site@0` for call site 45 is confidently wrong, and the thesis
of the change is that the label makes `N` identifiable. All three die against the
fix below.

Closed at the CLASS rather than per mutant, two ways. (1) A VALUE ORACLE over
every labelled site in every carrier: the index operand is the u2 at code unit 1
for every format reaching `emit_index`, so the expected value is decoded from the
BYTES — located through the declaring method's `code_off`, never through the
renderer — and compared against what was rendered, at all 49 sites rather than
one. (2) The crafts now WRITE the operand (`_OPERAND = 10811 = 0x2A3B`: above 15
so a truncation shows, not round so a shift shows, decimal ≠ hex so a base change
shows) instead of hoping the fixture supplies a distinctive one — the first
`iget-object` in `method_handles.dex` carries **0**, exactly the value that cannot
separate a correct render from `<< 0` or from `& 0xF`. A THIRD craft was added for
`const-method-handle` (operand-only, no retype): its only two real sites hold 0
and 1, so `method_handle@ (v & 0xF)` was EQUIVALENT on the corpus as it stands and
that arm's value half was otherwise unguardable. **All nine value mutants across
both reviews now die**; the fixes are guards and prose only, so the `.so` md5 is
unchanged and the a/b above still stands.

**Three further review findings, all in the guards or a mirror:** `_BARE_INDEX` was
end-anchored, so the "no operand comes back as a bare `@N`" sweep covered 5 of the
7 emitting formats — k45cc / k4rcc append `, (proto)` after `emit_index`'s output
(not a live hole, since `_EXPECTED_LINES` pins both polymorphic operands, but the
sweep now matches its docstring); `_retype_first`'s docstring called its
`raw0[pos] != old` candidate FILTER an assertion, which would have named the wrong
cause on fixture drift; and **the dexllm#60 smali-half section 135 lines above
still said `invoke-custom` "renders its operand as `@N`"** — the one-mirror-updated
pattern this file records, corrected there rather than only here.

**Independently corroborated by the correctness review**, which built its own spec
decoder (`class_defs` -> `class_data` -> `code_off`, its own width table, the index
pulled from the format layout — never calling the code under test) and found **0
mismatches over 100 sites** across the fixtures, every `art/test/dexdump` and
`tools/dexter/testdata` dex and the whole 34-sample corpus (lenient where the
strict gate refuses, so `all.dex` is covered), on mnemonic, register operands AND
index value; plus **0 diff over 48 lines** against AOSP dexdump's own committed
expected output after normalising its hex and `// proto@` comment. It also
confirmed by CRAFT that `FormatProto`'s two un-bounded interior reads
(`return_type_idx`, the type_list entries) are unreachable — both are rejected in
`CheckIntraSection`, which is not gated on `check_insns_`, so they hold under
`lenient=True` too — and that the k21c caller therefore carries exactly the
guarantees the k45cc / k4rcc callers do.

parity 29/29, pytest **790 passed / 10 skipped**, narrowed to
`tests/data/multidex.apk` (689 passed), the guard file green narrowed to each of
the **34** bundled samples one at a time plus the committed `multidex.apk` (25
`.apk` + 9 bare `.dex` — the same 34 the a/b counts; a review caught this section
quoting 34 and 38 for one population, the other four entries under `test_apk/APK`
being a directory, two certificates and a jar), TRUE corpus-less (`test_apk` MOVED
aside) **384 passed / 416 skipped / 0 failed** — the whole new block is
corpus-independent, so all 34 of its cases run in the CI leg —
sweep 25,350-class 0-crash 0-timeout,
determinism (3 processes x 3 `PYTHONHASHSEED`s -> one digest), lint trio clean,
doc fences 78.

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

### 5. Don't silently break a documented principle — ask first
Before making a change that would **break, contradict, or weaken a principle or claim the README (or core docs) asserts** — e.g. "emits the exact UTF-16 code units ART builds in `mirror::String`", "1:1 DAD-faithful", "0-crash on malformed dex", "byte-identical to androguard", the perf headline numbers — **STOP and ask the user**, even if the change looks like a strict improvement. Name the specific claim and the conflict. A local usability/quality win is not worth quietly invalidating a headline property the project markets. (Origin: a C1/DEL-escaping "fix" diverged from the ART-code-unit claim and had to be reverted — `07f956c`/`76b1cc6`.) If a change *deliberately* diverges (a beyond-DAD production fix), that's allowed — but it must be an explicit, documented divergence with the dual-track/`*DADFaithful` pattern, not a silent redefinition of a claimed invariant.

## Workflow defaults

- **Language**: Korean for user-facing responses. Code/comments in English.
- **Tools allowed**: in-process androguard, custom C++. **Forbidden**: jadx, any JVM/subprocess decompiler, prebuild of full APK.
- **Decompile model**: lazy per-class on-demand (JEB-style). Cache results.
- **Permissions**: `--dangerously-skip-permissions` is set — no pre-approval for tool calls.
- **Docs gate**: a `PreToolUse(Bash)` hook ([.claude/docs-precommit-check.sh](.claude/docs-precommit-check.sh)) blocks `git commit` / `git push` until the project docs (`README.md`, `CLAUDE.md`, `docs/*.md`) have been reviewed for drift against the change and any inaccuracies fixed in the same commit. After reviewing, re-run the same command prefixed with `DOCS_CHECKED=1` to bypass (e.g. `DOCS_CHECKED=1 git commit -m "..."`).
- **Adversarial-review gate (MANDATORY after any fix)**: a `PreToolUse(Bash)` hook ([.claude/review-precommit-check.sh](.claude/review-precommit-check.sh)) blocks `git commit` / `git push` whose change touches production source (`native/**`, `vendor/dexkit_core/Core/**`, `src/dexllm/**` — `.cpp/.cc/.h/.hpp/.py`) until an **adversarial code review** has been run and its findings addressed. This is not optional: a decompiler type/dataflow change can be subtly wrong in a way tests miss. Required steps before committing a fix — **(0) HACK SELF-CHECK (root-cause, not output masking):** before reviewing, confirm the fix addresses the ROOT of the defect rather than masking a symptom at the output/late layer. A change that suppresses or rewrites **Writer / dast OUTPUT** to hide a defect whose true origin is the **IR builder / dataflow / control-flow** (opcode_ins, instruction, dataflow, graph, control_flow) is a **HACK** — even when the emitted text looks correct, the AST and other consumers still carry the defect. If it is a hack, **do NOT commit — RECONSIDER and redo it at the originating layer** ("structural defects must be fixed at the IR level, not in Writer output"). Only genuine beyond-DAD emit divergences (return-literal / catch-clamp / `<clinit>` `static{}`) legitimately live in the Writer; a defect with an earlier structural origin does not. Precedent: the v0.1.12 void-invoke "fix" masked in `Writer::visit_assign`, left `this = voidcall` in the AST, and was **rewritten at the IR builder** (v0.1.13). (1) spawn **≥2 INDEPENDENT reviewer agents** on the diff (Agent tool: `compound-engineering:ce-adversarial-reviewer` + `ce-correctness-reviewer`, or the `code-review` skill), each trying to CONSTRUCT a breaking input; (2) triage every finding (CONFIRMED/PLAUSIBLE/REFUTED) and fix the real ones; (3) re-verify — **a/b (fix on vs off) 0-regression on the relevant axes + parity 28/28 + 0-crash sweep**, and remove any temporary a/b env-gate (never ship a toggle for the fix). Then re-run the same command prefixed with `REVIEWED=1` (combine with the docs gate: `DOCS_CHECKED=1 REVIEWED=1 git commit -m "..."`). Docs-only / test-only / config-only commits are not gated. This codifies the established practice (the type-inference cascade + mirror fixes were all shipped this way; the v0.1.12→v0.1.13 void-invoke rewrite is the canonical hack→root-cause case). See [[feedback-adversarial-review-after-fix]] and [[feedback-no-hack-root-cause-fix]].

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

Default success criterion for any decompiler change: **29 C++ suites in `tests/parity/` must remain at 0 failures** (28 DAD/regression parity + the dexllm#50 `thread_pool_selfdestruct_test`), and end-to-end decompilation on `test_apk/APK/com.example.android.tvleanback.apk` must not crash.

Run parity sweep (build + run all 29 via CMake/CTest):
```bash
cd build/cp*-cp*-* && \
    ninja parity_tests && ctest --output-on-failure
```
Expected tail: `100% tests passed, 0 tests failed out of 29`.

End-to-end smoke check:
```bash
python -c "import dexllm; dk = dexllm.DexKit('test_apk/APK/com.example.android.tvleanback.apk'); print(dk.decompile_class('Landroid/support/v4/app/Fragment;'))" | head -50
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

### A narrowed corpus must SKIP, never fail (dexllm#46)

`$DEXLLM_TEST_APK` is a documented override that points the WHOLE pytest suite at
one sample — what an analyst wants while triaging. Running it that way went RED:
17 failures on `multidex.apk`, 6 on `hello-world.apk`, across 8 files that assert
a property of `a2dp.Vol_137.apk`. `tests/conftest.py` already states the rule
("an environment fact must produce a skip or no effect, never a failure") and
this repo had hit it three times before (`32f5695`, `14d7266`).

Three kinds of defect, fixed as three kinds:

1. **Non-vacuity floors** — a dozen guards assert a production pass ACTUALLY
   FIRED (a `switch` header carrying a pc-map entry, a `boolean v = false;`, a
   constant-only IOC, a `(Type) v` cast). Those floors are load-bearing and must
   NOT be deleted, so the decision moved into one helper,
   **`conftest.require_corpus_shape(present, shape, regression)`**: a missing
   shape on the BUNDLED corpus is a regression and FAILS; the same absence under
   a narrowing is a property of the sample and SKIPS. `corpus_is_narrowed()`
   requires the override to actually RESOLVE — a dangling path narrows nothing
   (`_candidate_apks` ignores it) so it must not soften a floor either. Where a
   test carried both a floor and a CEILING, the ceiling now runs first so a
   narrowed skip does not take it with it.
2. **Fixture quality (a code fact, keep the assert)** — `sample_method` accepted
   any truthy decompile, and an abstract method decompiles to a signature with no
   body, so an APK whose first class is an annotation interface handed four tests
   a bodyless method. It now requires a CODE ITEM (`.registers` in smali — a
   property INDEPENDENT of the `{`-in-source / non-null-AST the consumers assert,
   so the selection is not tautological). `test_stubs` took
   `list_class_methods(list_classes()[0])[0]` and IndexError'd on a first class
   with no methods; it uses the fixture now. `test_typed_search`'s needle is
   derived from a real class name (a hard-coded `"a"` matches nothing in
   `StringTests.dex`).
3. **Assertions that were simply wrong** — `identify()`'s `is_apk` is exactly
   "a zip carrying an AndroidManifest.xml" (`dexkit_ext.cpp`), so asserting it
   outright asserted a corpus fact; it is now the invariant
   `is_apk == (format == "zip" and has_manifest)`. An external method ref's owner
   may be an ARRAY (`[Ljava/lang/Object;->clone()`, 3 of hello-world's 3443) —
   the first-element-only check never sampled one. `_GOOD_MAT` (the reused-`this`
   seed) only matched the inline `<Class> v7 = this;`, missing the equivalent
   hoisted-declaration + bare `v2_1 = this;` that another support-library build
   produces.

**Verified:** the whole suite green on **every bundled sample one at a time** (25
APKs + 4 bare dexes), default corpus 419 passed / 5 skipped, corpus-less 114
passed / 310 skipped / 0 failed (the CI shape — and it caught a real defect: two
repro tests replaced a `pytest.skip` with a floor, which fails when there is no
corpus at all; they now skip when no APK bundles the repro class), parity 28/28,
lint trio clean. **Mutation matrix:** forcing `require_corpus_shape`'s `present`
to False fails exactly **21** tests on the bundled corpus — every floor site is
REACHED and HARD-FAILS there, so none of them went silently soft; reverting the
`sample_method` code-item filter reproduces 3 of the original failures.
`tests/test_corpus_shape_helper.py` pins the helper's own two-way behaviour
(fail vs skip vs dangling-override), since a helper that degraded to an
unconditional skip would take every floor with it while the suite stayed green.

**The rule is CI-guarded**, by the only APK this repo commits:
[tests/data/multidex.apk](tests/data/multidex.apk) (1,233 B, byte-identical to
androguard's own Apache-2.0 test data — provenance in
[tests/data/README.md](tests/data/README.md)). CI runs the suite a second time
narrowed to it, which is what the corpus-less run structurally cannot do — that
run skips at the FIXTURES, before a single floor is reached, so it stays green
against exactly the regression this section exists to prevent. The narrowed leg
reaches **254** tests in CI where the corpus-less one reaches 111 (260 / 114
locally, where the optional extras are installed), and the sample is
chosen as the WORST case (no `switch` header, no boolean-literal assignment, no
constant-only indicator, no interface method, no control-bearing literal, and
manifest-less so `identify().is_apk` is False). Verified discriminating: removing
the helper's narrowing branch turns that leg **16 failed**.

The `/upload` inconsistency this surfaced is now fixed — see the section below.

### `/upload` identifies a container by CONTENT, like every other entry point (dexllm#47)

The FastAPI `/upload` refused any upload whose FILENAME did not end in `.apk`,
**before looking at a single byte** — contradicting the headline input contract
("identified by content (PK / `dex\n` magic), not filename") that `DexKit(path)`,
`dexllm.identify`, the SDK's `open_apk` and the MCP tools all honour. So the one
input the project advertises it handles — a dumped or renamed container — was the
one the HTTP surface declined. It was not a safety property either: the bytes go
to a session tempdir and then to `DexKit`, whose **structural verifier is the
documented single gate**, and the endpoint never relied on the suffix (it saved
under the uploaded name and re-derived everything from content).

**The gate is REMOVED** (option 1 of the issue — it deletes a check rather than
adding cases), so a non-container is now refused for what it IS: `DexKit`'s own
error, surfaced as the same 400 with a strictly better reason (`failed to open
upload: RuntimeError: …` instead of `filename must end with .apk`). Three coupled
changes, all in [server.py](src/dexllm/server.py):

- **the filename stops being a path component** (`_STORED_NAME`, a constant).
  Removing the gate makes the basename fully client-controlled, and the old code
  fed it to the save path: `Path(x).name` is `''` for `""` / `"."` / `"/"` and
  `'..'` for `".."`, both of which resolve to the tempdir itself or its parent
  (`IsADirectoryError`), while a NUL or a 300-char name is a write failure. A
  sanitiser would have to get every one of those right; **storing under a fixed
  name means no filename decides where the bytes land**, which is the same claim
  the fix makes (the name is not load-bearing — the container is identified by
  content). The name comes back as `filename`, i.e. display metadata. Traversal
  was never reachable either way (`Path.name` drops the directory part), but the
  earlier variants failed the degenerate values differently.
- **the STORE gets its own try** — the write sat outside the existing one, so any
  write failure was an unhandled 500 that ALSO leaked the tempdir (pre-existing:
  a NUL byte or an over-long name passed the old suffix check too, and both now
  store fine since the name never reaches the filesystem). It is a **500** — a
  full or unwritable `$TMPDIR` is ours, not the caller's — while the loader's
  failure stays the caller's **400**. Merging the two into one 400, which an
  earlier cut did, reported a disk-full outage as a client error. `mkdtemp` is
  INSIDE that try with the write: it fails on the same condition, and a reviewer
  showed the version that left it outside answered the identical `ENOSPC` with a
  bare `500 Internal Server Error` and no reason, decided by which libc call
  happened to fail first. The response body is also read (`size_bytes`,
  `loaded_dex_count`) BEFORE `_sessions[sid] = sess`, so registration is the last
  statement that can fail — otherwise a raise orphans a session whose id the
  client never received. That ordering incidentally fixes a pre-existing
  unhandled 500: with `DEXKIT_SESSION_CACHE=0` the LRU evicts the new session
  inside the handler, and the old code then called `getsize` on the deleted file.
- **`loaded_dex_count` beside `identified`.** The probe's `dex_count` and the
  session's are NOT the same number: a concatenated packer dump — the case this
  endpoint now accepts — probes as ONE dex and loads as N (`ProbeContainer`'s
  raw-dex fast path never runs `LogicalDexSlices`), and a container whose sibling
  dex the verifier rejects loads FEWER than it declares. Returning only
  `identified` would have re-introduced the exact dexllm#38 defect on a new
  layer, so the two facts get two keys, with the same spelling #38 chose for MCP.
  The other three probe keys structurally cannot drift (`Identify()` and the
  constructor share one `ProbeContainer`). A partially-rejected container is a
  **200**, not a 400 — the survivors still load (dexllm#25) — and for a
  CONCATENATED one NEITHER count shows the drop (the probe's raw-dex fast path
  always says 1), so `verify_report()` remains the place the per-dex verdicts
  live. The docstring says exactly that; an earlier draft claimed a rejected dex
  is always a 400, which a reviewer falsified with a crafted sibling.

**Observable on the SUCCESS path, deliberately:** `apk_path` used to end in the
uploaded basename and now always ends in `upload`, so a consumer that recovered
a display name from it silently gets the constant — `filename` is where that
information lives now, echoed VERBATIM (unvalidated client input: markup, path
separators and C1 control characters all survive, so a UI escapes it; a lone
surrogate is unreachable — starlette decodes the header as latin-1 — so the
dexllm#29 `ensure_ascii=False` note still holds). Release-notes material (this
repo keeps no aliases, #24).

**Deliberately NOT renamed:** the multipart part is still `apk` and the response
key is still `apk_path`, both of which now say APK for a surface that takes any
container — the `api_descriptor` → `method_descriptor` shape dexllm#21 stage 4
removed one layer down, and the same one-concept-two-spellings gap as MCP's
`source`. Unlike the MCP catalog, this surface HAS an out-of-tree consumer
(dexllm-web), a rename would break it at the wire with no alias mechanism, and no
naming audit covers HTTP keys — so it is a decision to revisit with that consumer,
not an oversight.

Docs: no doc described the endpoint's filename contract, so the drift outside the
handler was the module docstring, the four sibling docstrings and the SYSTEM
PROMPT that still said APK (the prompt is behavioural — it told the model an APK
was uploaded for a session that may be a manifest-less dump), plus a README line
making the reach of the content-based claim explicit.

Guards ([tests/test_llm_backends.py](tests/test_llm_backends.py)), all
**corpus-independent** — they run on the committed `tests/data/multidex.apk`, so
they hold under a `$DEXLLM_TEST_APK` narrowing and in the corpus-less CI leg:
the dexllm#46 skip is gone; the non-container 400 asserts the loader's reason and
that the OLD message is gone *by its own words*; `test_fastapi_upload_is_content_based`
uploads the zip under a nameless `blob` and a bare `classes.dex` under `dump`
(full `identified` verdict + the session actually lists classes);
`test_fastapi_upload_lands_inside_the_session_tempdir` pins WHERE the bytes land
for `..` / `.` / `/` / a traversal path — asserting the containment, not merely
that the request succeeded, with the session tempdir redirected under pytest's
`tmp_path` so the escape oracle is a private path (a fixed name in the shared
`/tmp` fails on an ENVIRONMENT fact, this file's own #46 rule, and hard-codes the
traversal depth); `test_fastapi_upload_cleans_up_and_blames_the_right_side`
injects `ENOSPC` at BOTH `$TMPDIR` calls and pins 500-with-a-reason + no leaked
tempdir, and the loader's 400 + no leak;
`test_fastapi_upload_body_is_read_before_the_session_is_registered` pins the
ordering via `DEXKIT_SESSION_CACHE=0`;
`test_fastapi_upload_reports_probe_and_session_dex_counts_separately`
concatenates the dex with itself so the two counts genuinely disagree (1 vs 2);
and `test_fastapi_upload_refuses_a_zip_whose_dexes_do_not_start_at_classes_dex`
pins the accept-set the docstring promises — a `classes2.dex`-only zip matches
the `classes*.dex` glob an earlier wording used and is still refused.
Mutation-verified, 9/9 killed: restoring the suffix gate (9 failures), storing
under the raw client basename (all 4 containment cases), feeding
`loaded_dex_count` from the probe, dropping `filename`, flipping the store's 500
to 400, deleting either `rmtree`, moving `mkdtemp` back outside the try, and
reading the body after registration. **Three of those mutants survived the cut
that INTRODUCED the behaviours they guard** — the 500, the load-path cleanup and
the containment oracle all shipped unguarded in the review-response commit, and
two reviewers had to construct them: the repo's own
[[review-responses-are-the-weak-spot]] pattern, again.

## Test corpus

- Live corpus: `test_apk/APK/*.apk` (multi-APK)
- The old single `test.apk` no longer exists. Scripts that hardcode it must be updated.
- `lineageos_nexus5_framework-res.apk` — resources only, no dex.

## Skills available

- `/dexkit-build` — atomic ninja + pip install -e
- `/dexkit-sweep` — full-corpus regression sweep (crash/error/empty counts + throughput); primary success gate
- `/dexkit-decompile` — decompile one method or class via the DAD-aligned pipeline
- `/dexkit-diff` — side-by-side parity diff: androguard DAD (Python) vs DexKit-DAD (C++ port)
- `/jadx-diff` — side-by-side vs **jadx** (reference oracle) + the jadx-parity convergence gate (for porting jadx algorithms, Phase C onward)
- `/dexkit-bench` — head-to-head perf benchmark + output parity rate
- `/dexkit-trace` — reproduce + bisect + capture stack trace for crashes / hangs (gdb / py-spy)
- `/karpathy-guidelines` — four behavioral principles (re-read when needed)

### jadx-parity gate — MANDATORY when porting a jadx algorithm (Phase C onward)

Porting a jadx algorithm to C++ (the type-inference / structuring work the framework-classpath
oracle branch is the foundation for) must **validate against jadx as a test-time reference
oracle** — the exact pattern the DAD port uses with androguard. **jadx runtime stays forbidden
in the product** (embedded-only, no JVM/subprocess — [[feedback_decompiler_choice]]); jadx runs
ONLY in the dev/CI harness. Reimplementing jadx algorithms requires the **Apache-2.0 NOTICE**
attribution. Convergence is enforced **automatically** by a ratchet test, not a manual step:
- **`tests/test_jadx_parity.py`** — the AUTOMATIC gate. Runs the convergence metric (ours vs
  jadx) against the committed `tests/jadx_parity_baseline.json` and **FAILS on a regression**
  (`type_jaccard` drops below the floor, or `ours_invalid_java` rises above the ceiling). Runs as
  part of `pytest tests/`; jadx-availability + jadx-version gated (SKIPS in CI without jadx / on a
  version mismatch, like the AOSP-dataset-gated tests — never a false fail). A jadx-algorithm port
  that IMPROVES convergence raises `type_jaccard`; **ratchet the floor up in the baseline in the
  same change** (coverage-ratchet). Baseline pin: jadx 1.5.0, DAD-vs-jadx `type_jaccard ≈ 0.316`.
- Manual companions: `scripts/jadx_parity.py` (the metric, run ad-hoc), the `/jadx-diff` skill
  (per-method side-by-side while porting), and `scripts/jadx_ref.py` (the jadx CLI oracle).

So the gate (ON TOP of the standard a/b 0-regression + parity 28/28 + 0-crash sweep + ≥2-reviewer
adversarial + HACK self-check): the ratchet test must pass (**ported axis converged toward jadx,
no other axis regressed**), the targeted methods now match jadx in `/jadx-diff`, and you **pin
jadx-sourced fixtures** for the specific decisions ported. jadx is a test-time reference oracle
only — `IsAssignable`-style; it never enters a product path (embedded-only). See
[.claude/skills/jadx-diff/SKILL.md](.claude/skills/jadx-diff/SKILL.md) and [[feedback-jadx-parity-gate]].

## Known structural patterns (don't re-derive)

- **Pipeline shape** (replaces the old L6 structurer + post-pass scheme):
  `descriptor → DexItemCodeSource → MethodSnapshotBuilder → DvMethod → Construct → BuildDefUse → SplitVariables → DeadCodeElimination → RegisterPropagation → PlaceDeclarations → SplitIfNodes → Simplify → IdentifyStructures → Writer.WriteMethod → Java text`. All passes mirror DAD's `decompile.py:DvMethod.process` step-by-step.
- **IR layer is DAD-faithful**: each instruction class has `Accept(Visitor&)` that mirrors DAD's `IR.visit(visitor)`. Writer (subclass of Visitor) implements all 47 `visit_X` methods 1:1 from DAD writer.py.
- **No more text post-passes**: structural defects must be fixed at the IR / structurer level (control_flow.py / dataflow.py mirrors), not in Writer output.
- **Slicer's `SLICER_CHECK` failures** are thrown as `std::runtime_error` (not aborts) so a single bad method doesn't kill the process. Don't revert.
- **External method refs** (entries in MethodIds without a ClassData in this dex) are detected via empty `access_flags` and produce empty Java output (matches DAD's effective behavior — DAD crashes on ExternalMethod, caller's try/except swallows).
