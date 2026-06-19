# Workflow — how dexllm operates, end to end

This is the **runtime view**: the flows a caller actually drives, from a file on
disk to findings or decompiled Java. For the *static* structure (the ports &
adapters boundary, where each piece lives) see [architecture.md](architecture.md);
for the API call recipes see [usage.md](usage.md).

All diagrams render on GitHub (Mermaid).

## 1. The big picture

A single in-process instance loads once, then serves many lazy analyses. Nothing
is decompiled until asked; results are cached.

```mermaid
flowchart TB
    accTitle: dexllm Operation Overview
    accDescr: A file is content-probed by identify, loaded and structurally verified by DexKit, then served lazily to search/analyze (L1-L4, L7), smali rendering (L5), and decompilation (L6); findings flow to the Python API, an MCP agent, or the FastAPI backend.

    source["APK / JAR / ZIP / bare .dex<br/>(disguised or extension-less OK)"]
    identify["identify() — content probe<br/>PK / dex magic, no load"]
    load["DexKit(apk) — load + structural verify"]
    source --> identify --> load

    load --> search["Search and analyze<br/>L1-L4, L7: APIs, call sites, strings, xrefs"]
    load --> smali["L5: smali rendering"]
    load --> decompile["L6: decompile to Java text / AST"]

    search --> findings["findings"]
    smali --> findings
    decompile --> findings
    findings --> consumer["Python API, MCP agent, FastAPI/SSE"]

    classDef io fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef gate fill:#fef9c3,stroke:#ca8a04,stroke-width:2px,color:#713f12

    class source,consumer io
    class load gate
```

## 2. Load and verify

The constructor identifies the container by **content, not filename**, then gates
**every** dex through the structural verifier before the core parses it. A
malformed dex is rejected with a byte-level reason; siblings in the same apk still
load. The load is lazy — no method is decompiled yet.

```mermaid
sequenceDiagram
    accTitle: APK Load and Verify Sequence
    accDescr: The caller constructs DexKit, which detects the container then loops over each classes dex; a valid dex is added to the core, a malformed one is rejected with a byte-level reason, and the instance returns ready without decompiling anything yet.
    autonumber
    participant caller as Caller (Python / agent)
    participant dexkit as DexKit (core_ext)
    participant verify as VerifyDex
    participant core as DexKit Core + slicer
    caller->>dexkit: DexKit(app.apk)
    dexkit->>dexkit: detect container (PK / dex magic)
    loop each classes*.dex
        dexkit->>verify: VerifyDex(bytes)
        alt structurally valid
            verify-->>dexkit: ok
            dexkit->>core: AddImage(dex)
        else malformed
            verify-->>dexkit: reject with byte-level reason
            dexkit-->>caller: raise (see verify_report)
        end
    end
    dexkit-->>caller: ready (lazy, nothing decompiled yet)
```

See [dexkit-vs-art-dex-handling.md](dexkit-vs-art-dex-handling.md) for the
verifier's per-check parity with AOSP ART `DexFileVerifier`.

## 3. The capability ladder (L1-L7)

`L` = **capability level** — a numbered grouping, not a strict abstraction
hierarchy. One search engine (L7) underpins the higher-level analyses (L1–L4);
L5/L6 are the render/decompile paths. Each level is independently callable.

```mermaid
flowchart LR
    accTitle: L1-L7 Capability Ladder
    accDescr: The L7 find/match engine is the bottom-layer search primitive that L1-L4 build on (API surface, call sites, permissions, dataflow); L5 and L6 are separate smali and Java decompile paths over the loaded dex.

    l7_engine["L7: find / match engine<br/>Aho-Corasick + matcher"]
    l7_engine --> l1_apis["L1: external API surface"]
    l7_engine --> l2_call_sites["L2: API call sites"]
    l1_apis --> l3_permissions["L3: permissions / categories"]
    l2_call_sites --> l4_dataflow["L4: intra-method dataflow"]
    loaded_dex["loaded dex"] --> l5_smali["L5: smali render"]
    loaded_dex --> l6_decompile["L6: Java decompile (DAD)"]

    classDef primitive fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a5f
    classDef decompile fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95

    class l7_engine primitive
    class l5_smali,l6_decompile decompile
```

| Level | Question it answers | Entry point |
|---|---|---|
| L1 | which Android framework APIs does this APK touch? | `find_used_apis` / class summary |
| L2 | where is a specific API called? | `find_call_sites_to_ref` |
| L3 | which permissions / categories are exercised? | permission mapping |
| L4 | what is actually passed at each call site? | intra-method dataflow |
| L5 | smali for a method/class (no JVM) | smali render |
| L6 | DAD-quality Java text / AST | `decompile_method_java` / `_class_java` / `_method_ast` |
| L7 | find classes/methods by name/string/literal/super/annotation | `find_*` family |

Full recipes: [usage.md](usage.md).

## 4. Decompile a method (L6)

The hot path. A cache hit returns immediately; a miss runs the DAD pipeline with
the **GIL released**, so many threads decompile in parallel on one shared instance.

```mermaid
sequenceDiagram
    accTitle: Method Decompile Sequence
    accDescr: A decompile request hits the facade's LRU cache; on a miss it releases the GIL, builds a method snapshot, runs the DAD pipeline, emits Java text or AST through the writer, caches the result, and returns it.
    autonumber
    participant caller as Caller
    participant facade as Decompiler facade (+ LRU cache)
    participant builder as MethodSnapshotBuilder
    participant pipeline as DAD pipeline (native/dad_cpp)
    participant writer as Writer / JSONWriter
    caller->>facade: decompile_method_java(descriptor)
    alt cache hit
        facade-->>caller: cached Java text
    else cache miss
        Note over facade: release GIL (parallel-safe)
        facade->>builder: build snapshot (decode + CFG)
        builder->>pipeline: Construct, BuildDefUse, ... , IdentifyStructures
        pipeline->>writer: emit
        writer-->>facade: Java text (or nested AST)
        facade-->>caller: result (now cached)
    end
```

The pipeline passes, each mirroring androguard `decompile.py:DvMethod.process`:

```mermaid
flowchart LR
    accTitle: DAD Decompile Pipeline
    accDescr: A method descriptor is located and turned into a snapshot, then run through the DAD IR pipeline (Construct through IdentifyStructures) before the writer emits Java text or AST. Each pass mirrors androguard decompile.py.

    descriptor["method<br/>descriptor"] --> locate["DexItemCodeSource<br/>locate"]
    locate --> snapshot_builder["MethodSnapshotBuilder<br/>decode, CFG, snapshot"]
    subgraph pipe["DAD IR pipeline: native/dad_cpp"]
        construct["Construct"] --> build_def_use["BuildDefUse"] --> split_variables["SplitVariables"] --> dead_code_elim["DeadCodeElimination"]
        dead_code_elim --> register_propagation["RegisterPropagation"] --> place_declarations["PlaceDeclarations"] --> split_if_nodes["SplitIfNodes"]
        split_if_nodes --> simplify["Simplify"] --> identify_structures["IdentifyStructures"]
    end
    snapshot_builder --> construct
    identify_structures --> writer["Writer / JSONWriter"]
    writer --> output["Java text | AST"]

    classDef io fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    class descriptor,output io
```

The text path (`Writer`) and AST path (`JSONWriter`/`dast`) share the same
processed graph but emit differently; `decompile_method_ast(include_source=False)`
skips the text emit for ~1.7x faster AST-only consumers.

## 5. Driving it from an agent (MCP / FastAPI)

Every entry in `dexllm.tools` is exposed as one MCP tool (stdio) and over the
FastAPI/SSE backend. MCP calls are stateless, so each tool takes an `apk_path`;
the server keeps an LRU of loaded instances. Decompile tools go through the **safe
wrappers** — a hung method returns a `// TIMEOUT` marker instead of locking the
server.

```mermaid
sequenceDiagram
    accTitle: Agent Integration Sequence
    accDescr: An LLM agent calls a dexllm MCP tool with an apk path; the server dispatches the schema-validated call to the tools layer, which runs a timeout-guarded analysis or decompile on the DexKit core and returns JSON back to the agent.
    autonumber
    participant llm as LLM / agent
    participant mcp_server as dexllm MCP server (stdio)
    participant tools as dexllm.tools (safe wrappers + LRU)
    participant core as DexKit core
    llm->>mcp_server: call tool (e.g. dexllm_decompile_class_java, apk_path=...)
    mcp_server->>tools: dispatch (JSON-Schema validated)
    tools->>core: analyze / decompile (timeout-guarded)
    core-->>tools: result
    tools-->>mcp_server: JSON
    mcp_server-->>llm: tool result
```

## Where to go next

- [usage.md](usage.md) — concrete API calls for every level above.
- [architecture.md](architecture.md) — the static ports & adapters structure.
- [dexkit-vs-art-dex-handling.md](dexkit-vs-art-dex-handling.md) — verification,
  multidex, and MUTF-8 vs AOSP/ART.
- [CLAUDE.md](../CLAUDE.md) — the decompiler port internals.
