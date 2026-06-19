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
    SRC["APK / JAR / ZIP / bare .dex<br/>(disguised or extension-less OK)"]
    ID["identify() — content probe<br/>PK / dex magic, no load"]
    LOAD["DexKit(apk) — load + structural verify"]
    SRC --> ID --> LOAD

    LOAD --> SEARCH["Search and analyze<br/>L1-L4, L7: APIs, call sites, strings, xrefs"]
    LOAD --> SMALI["L5: smali rendering"]
    LOAD --> DECOMP["L6: decompile to Java text / AST"]

    SEARCH --> OUT["findings"]
    SMALI --> OUT
    DECOMP --> OUT
    OUT --> CONSUMER["Python API · MCP agent · FastAPI/SSE"]
```

## 2. Load and verify

The constructor identifies the container by **content, not filename**, then gates
**every** dex through the structural verifier before the core parses it. A
malformed dex is rejected with a byte-level reason; siblings in the same apk still
load. The load is lazy — no method is decompiled yet.

```mermaid
sequenceDiagram
    autonumber
    participant U as Caller (Python / agent)
    participant K as DexKit (core_ext)
    participant V as VerifyDex
    participant C as DexKit Core + slicer
    U->>K: DexKit(app.apk)
    K->>K: detect container (PK / dex magic)
    loop each classes*.dex
        K->>V: VerifyDex(bytes)
        alt structurally valid
            V-->>K: ok
            K->>C: AddImage(dex)
        else malformed
            V-->>K: reject with byte-level reason
            K-->>U: raise (see verify_report)
        end
    end
    K-->>U: ready (lazy, nothing decompiled yet)
```

See [dexkit-vs-art-dex-handling.md](dexkit-vs-art-dex-handling.md) for the
verifier's per-check parity with AOSP ART `DexFileVerifier`.

## 3. The capability ladder (L1-L7)

`L` = **capability level** — a numbered grouping, not a strict abstraction
hierarchy. One search engine (L7) underpins the higher-level analyses (L1–L4);
L5/L6 are the render/decompile paths. Each level is independently callable.

```mermaid
flowchart LR
    L7["L7: find / match engine<br/>Aho-Corasick + matcher"]
    L7 --> L1["L1: external API surface"]
    L7 --> L2["L2: API call sites"]
    L1 --> L3["L3: permissions / categories"]
    L2 --> L4["L4: intra-method dataflow"]
    RAW["loaded dex"] --> L5["L5: smali render"]
    RAW --> L6["L6: Java decompile (DAD)"]
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
    autonumber
    participant U as Caller
    participant D as Decompiler facade (+ LRU cache)
    participant S as MethodSnapshotBuilder
    participant P as DAD pipeline (native/dad_cpp)
    participant W as Writer / JSONWriter
    U->>D: decompile_method_java(descriptor)
    alt cache hit
        D-->>U: cached Java text
    else cache miss
        Note over D: release GIL (parallel-safe)
        D->>S: build snapshot (decode + CFG)
        S->>P: Construct, BuildDefUse, ... , IdentifyStructures
        P->>W: emit
        W-->>D: Java text (or nested AST)
        D-->>U: result (now cached)
    end
```

The pipeline passes, each mirroring androguard `decompile.py:DvMethod.process`:

```mermaid
flowchart LR
    A["method<br/>descriptor"] --> B["DexItemCodeSource<br/>locate"]
    B --> C["MethodSnapshotBuilder<br/>decode, CFG, snapshot"]
    subgraph pipe["DAD IR pipeline: native/dad_cpp"]
        D["Construct"] --> E["BuildDefUse"] --> F["SplitVariables"] --> G["DeadCodeElimination"]
        G --> H["RegisterPropagation"] --> I["PlaceDeclarations"] --> J["SplitIfNodes"]
        J --> K["Simplify"] --> L["IdentifyStructures"]
    end
    C --> D
    L --> W["Writer / JSONWriter"]
    W --> O["Java text | AST"]
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
    autonumber
    participant LLM as LLM / agent
    participant M as dexllm MCP server (stdio)
    participant T as dexllm.tools (safe wrappers + LRU)
    participant K as DexKit core
    LLM->>M: call tool (e.g. dexllm_decompile_class_java, apk_path=...)
    M->>T: dispatch (JSON-Schema validated)
    T->>K: analyze / decompile (timeout-guarded)
    K-->>T: result
    T-->>M: JSON
    M-->>LLM: tool result
```

## Where to go next

- [usage.md](usage.md) — concrete API calls for every level above.
- [architecture.md](architecture.md) — the static ports & adapters structure.
- [dexkit-vs-art-dex-handling.md](dexkit-vs-art-dex-handling.md) — verification,
  multidex, and MUTF-8 vs AOSP/ART.
- [CLAUDE.md](../CLAUDE.md) — the decompiler port internals.
