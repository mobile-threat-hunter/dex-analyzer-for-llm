# Architecture — ports & adapters

This is the **static structure** — where each piece lives and the boundary between
them. For the *runtime* view (load → verify → search → decompile → agent, as
flow/sequence diagrams) see [workflow.md](workflow.md).

The decompiler already follows a **hexagonal (ports & adapters)** shape at the
boundary that matters: a domain core that knows nothing about how dex bytes are
loaded, talking to the outside world through one narrow port.

```mermaid
flowchart TB
    accTitle: Ports and Adapters Architecture
    accDescr: The Python API drives the decompiler facade and the DAD domain core, which reads dex only through the IDexCodeSource port. Production and test adapters implement that port, and every dex passes the VerifyDex structural verifier before the DexKit Core slicer parses it.

    python_api["Python API, MCP stdio, FastAPI/SSE"]
    pybind["pybind11 binding<br/>native/binding/module.cpp"]
    facade["Decompiler facade + LRU cache<br/>native/dad_cpp/decompiler.cpp"]
    raw_dex["raw .dex / classes*.dex"]
    verify_dex["VerifyDex structural verifier<br/>1:1 AOSP DexFileVerifier port"]
    dexkit_core["DexKit Core + slicer"]
    prod_adapter["DexItemCodeSource<br/>core_ext, production (wraps DexKit Core)"]
    mock_adapter["MockCodeSource<br/>tests, no DexKit"]
    port{{"IDexCodeSource port<br/>pure abstract"}}
    output["Java text | nested AST"]

    subgraph core["Domain core: native/dad_cpp - 1:1 androguard DAD port"]
        snapshot["MethodSnapshot, immutable DTO"]
        pipeline["graph, dataflow, control_flow"]
        emit["writer / dast"]
        snapshot --> pipeline --> emit
    end

    python_api --> pybind --> facade
    facade -->|drives| snapshot
    raw_dex --> verify_dex --> dexkit_core --> prod_adapter
    prod_adapter -->|implements| port
    mock_adapter -->|implements| port
    port -->|reads method code| snapshot
    emit --> output

    classDef io fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef guard fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d
    classDef boundary fill:#fef9c3,stroke:#ca8a04,stroke-width:2px,color:#713f12
    classDef domain fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a5f

    class raw_dex,output io
    class verify_dex guard
    class port boundary
    class snapshot,pipeline,emit domain
```

The same structure in detail (text fallback):

```
        ┌─────────────────── driving (primary) adapter ─────────────────┐
        │  native/binding/module.cpp        pybind11  C++ ↔ Python       │
        │  native/dad_cpp/decompiler.cpp    Decompiler facade + cache    │
        └───────────────────────────────┬───────────────────────────────┘
                                        │ drives
   ┌─────────────────────────────────────▼─────────────────────────────────┐
   │  DOMAIN CORE  —  native/dad_cpp/                                        │
   │                                                                        │
   │    MethodSnapshot (DTO)  →  graph → dataflow → control_flow            │
   │                          →  writer / dast  →  Java text | AST          │
   │                                                                        │
   │  Depends only on: the C++ stdlib, its own headers, the slicer dex      │
   │  value types (slicer/dex_*.h), and the IDexCodeSource port.            │
   │  Zero dependency on DexKit, FlatBuffers, the zip reader, or core_ext.  │
   └─────────────────────────────────────┬─────────────────────────────────┘
                                        │ depends on (points inward)
                        ┌────────────────▼─────────────────┐
                        │  PORT  —  IDexCodeSource          │
                        │  native/dad_cpp/include/          │
                        │      dex_code_source.h  (pure =0) │
                        └───────┬───────────────────┬───────┘
                  implements    │                   │   implements
        ┌──────────────────────▼───┐      ┌─────────▼────────────────────────┐
        │ DexItemCodeSource         │      │ MockCodeSource                    │
        │ native/core_ext/          │      │ native/dad_cpp/                   │
        │   production — wraps the   │      │   tests — hand-built snapshots,   │
        │   real DexKit Core         │      │   no DexKit needed                │
        └────────────────────────────┘      └───────────────────────────────────┘
```

## The three roles

| Role | What | Where |
|---|---|---|
| **Port** (driven) | `IDexCodeSource` — the only interface the domain uses to read method code, strings, types, and to locate methods. Mostly pure abstract — three methods carry a DEFAULT (`IsAssignable`, `GetFieldInfo`, and `GetProto` since dexllm#60) so that a source which cannot answer them, `MockCodeSource` included, needs no change and the 29 parity suites stay untouched. | [native/dad_cpp/include/dex_code_source.h](../native/dad_cpp/include/dex_code_source.h) |
| **Adapters** | `DexItemCodeSource` (production, wraps `dexkit::DexKit`) and `MockCodeSource` (tests). Both implement the port. | [core_ext/include/dexitem_code_source.h](../native/core_ext/include/dexitem_code_source.h), [dad_cpp/include/mock_code_source.h](../native/dad_cpp/include/mock_code_source.h) |
| **Domain core** | The DAD-aligned decompiler pipeline: graph / dataflow / control_flow / writer / dast. Consumes a `MethodSnapshot` DTO, emits Java text or the nested AST. | [native/dad_cpp/](../native/dad_cpp/) |
| **DTO** | `MethodSnapshot` — immutable, pointer-stable per-method snapshot (meta + decoded instructions + CFG blocks). The data the port hands across the boundary. | [native/dad_cpp/include/method_snapshot.h](../native/dad_cpp/include/method_snapshot.h) |

The payoff is concrete, not theoretical: because the domain only knows the port,
`MockCodeSource` lets the 25 DAD parity suites exercise the full pipeline **without a
real APK or DexKit** — the same property hexagonal architecture exists to provide.

## What else lives in `native/core_ext/`

Besides the adapter, `core_ext` is where dexllm's own analyses over DexKit live —
the ones the vendored Core has no business carrying:

| Analysis | What | Where |
|---|---|---|
| Structural verification | `VerifyDex` — the load-time gate, see below | [dex_verifier.h](../native/core_ext/include/dex_verifier.h) |
| L4 argument origins | `AnalyzeInvokes` — what value reaches each argument register at every invoke site of one method body. Backs `resolve_call_args`, and also the SITE IDENTITY (caller, offset, opcode) of `find_call_sites_from`, which calls it at depth 0 | [invoke_args.h](../native/core_ext/include/invoke_args.h) |
| Permission / capability join | `analysis.*` — the permission → gated-API → caller join over a loaded `DexKitExt` | [analysis.h](../native/core_ext/include/analysis.h) |

`AnalyzeInvokes` was written into `vendor/.../dex_item.cpp` as a `DexItem` member and
moved here in dexllm#32. It enlarged the vendor diff in the file that is hardest to
rebase, and it never needed to be a member: the whole input is one `dex::Code*` plus
the end of the image it lives in, both reachable through the public `GetMethodCode()`
/ `GetImage()`. The rule this records — **a dexllm analysis belongs in `core_ext`
unless it genuinely needs DexKit's privates** — is the outward-facing counterpart of
the `dad_cpp` boundary below, and it is why the vendored tree now carries ~860 fewer
dexllm lines.

Note this is a *different* boundary from the hexagonal one: `core_ext` may freely
include DexKit headers (that is its job), and `invoke_args.cpp` does — two decode
helpers it already used. Only `dad_cpp` is required to stay DexKit-free, which is why
the include directory that reaches those helpers is **PRIVATE** to `dexkit_ext`: made
PUBLIC it propagates to every `dad_cpp` TU, where a DexKit header would then compile
while `check_dad_boundary.sh` still reports clean (its FORBIDDEN pattern does not match
`utils/`). The compiler is half of that boundary's enforcement, and CMake visibility is
what keeps it.

## Load-time verification — anti-corruption at the input boundary

dexllm processes adversarial input, so before any dex reaches the core (let alone
the domain) the production load path screens it with a self-contained structural
verifier, `VerifyDex` ([native/core_ext/dex_verifier.h](../native/core_ext/include/dex_verifier.h)).
`DexKitExt` runs it on every raw `.dex` and every `classes*.dex` extracted from an
apk **before** `AddImage` hands the bytes to the DexKit Core / slicer — a reject
throws with a byte-level reason (surfaced by `dk.verify_report()`), so malformed or
crafted input never reaches the parser. It runs once per **logical** dex, not per
file: `AddImage` splits a concatenated / packer-dump image into one `DexItem` per
embedded header, so verifying the image once (at offset 0) would let every later
dex through unchecked (dexllm#25). `AssertLoadedDexesWereVerified` re-checks after
the load that the core parsed exactly the dexes the gate accepted.

It mirrors the boundary invariant from the input side: like `dad_cpp`, the verifier
depends only on the slicer dex value types (`slicer/dex_format.h`, `dex_bytecode.h`)
— no DexKit, FlatBuffers, or zip internals — so it is testable and auditable in
isolation. It is a readable 1:1 port of AOSP ART's `DexFileVerifier`, scoped to
**crash-safety** (never crash the analyzer on malformed input) rather than the
execution trust ART needs. Because it owns structural validity at the boundary, the
decode / IR paths downstream may assume verified input and drop their own redundant
bounds guards. Full per-check breakdown + the ART comparison:
[dexkit-vs-art-dex-handling.md](dexkit-vs-art-dex-handling.md) §1.

## The boundary invariant

> `native/dad_cpp/` must never `#include` DexKit Core, FlatBuffers schema, the zip
> reader, or `core_ext`. Anything it needs from the outside arrives through
> `IDexCodeSource`.

The slicer dex types (`slicer/dex_*.h`) are the one allowed inward dependency
beyond the stdlib — they are the shared *vocabulary* of the dex format (the value
types the port itself speaks, e.g. `const dex::Code*`), not an infrastructure
adapter.

Enforced by [scripts/check_dad_boundary.sh](../scripts/check_dad_boundary.sh):

```bash
./scripts/check_dad_boundary.sh   # exits non-zero on any leak
```

## Why we don't push hexagonal *deeper* into `dad_cpp`

The domain core is a **1:1 faithful port of androguard DAD** — every function
carries a `// DAD: <file.py>:<lineno>` trace, and the 25 DAD parity suites assert
byte-identical output so the port can be re-synced against DAD upstream.

Splitting the *internal* pipeline (graph / dataflow / writer) into further
domain/application/infrastructure layers would break that `// DAD:` traceability
and risk parity, for no real gain: the inner pipeline is a pure
`DTO → transforms → text` computation with no external I/O to isolate. Hexagonal
architecture earns its keep when there are many swappable integrations to keep at
arm's length; here there is exactly one (the dex data source), and it is already
behind the port. Adding more ports inside would be ceremony, not clarity.
