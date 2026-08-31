// method_snapshot.h — DexKit-DAD per-method snapshot (immutable DTO).
//
// A `MethodSnapshot` carries everything DAD needs for a single method:
// metadata + decoded instruction stream + basic-block CFG + try/catch ranges.
// Built once by `MethodSnapshotBuilder::Build`, then read-only.
//
// OWNERSHIP & LIFETIME:
//   - Snapshot is non-copyable AND non-movable (its internal spans/pointers
//     are self-referential into ins_storage / blocks).
//   - Always heap-allocated via Build() which returns a unique_ptr.
//   - `std::string_view` members point into the IDexCodeSource's tables —
//     the source MUST outlive the snapshot. (In production, source =
//     DexItem, which lives for the process; trivially satisfied.)
//
// BYTE-OFFSET CONVENTION:
//   All offsets (`byte_off`, `start_byte`, `end_byte`, `branch_target`) are
//   in BYTES, relative to the start of the method's insns[] array.
//   `end_byte` is exclusive (one-past-last). `length_bytes` = 2 × code-units.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include "slicer/dex_bytecode.h"   // dex::Instruction, dex::Opcode

#include "dex_code_source.h"        // IDexCodeSource::CallSiteInfo (dexllm#67)

namespace dexkit::dad {

// ============================================================================
// Const-pool reference — populated by builder per instruction (when relevant).
// ============================================================================

struct StringConst   { std::string_view value;     uint32_t raw_idx = 0; };
struct TypeConst     { std::string_view descriptor;uint32_t raw_idx = 0; };
struct FieldConst    {
    std::array<std::string_view, 3> triple{};  // (cls, name, type)
    uint32_t raw_idx = 0;
};
struct MethodConst   {
    std::array<std::string_view, 3> triple{};  // (cls, name, proto)
    uint32_t raw_idx = 0;
    // dexllm#60: invoke-polymorphic's CALL-SITE proto (`proto_ids[HHHH]`), which
    // belongs to no method_id and so has no place in `triple`. A
    // signature-polymorphic method's own descriptor is the DECLARATION
    // (`([Ljava/lang/Object;)Ljava/lang/Object;`), while the argument grouping —
    // a `J`/`D` occupies two registers — and the result type come from this one.
    // A VIEW, like `triple` — the adapter returns it out of the same
    // pointer-stable proto cache, so it outlives the snapshot. Empty for every
    // other opcode, and empty for a source that cannot resolve protos.
    //
    // ASYMMETRY, deliberate: `triple` stays the METHOD's own descriptor because it
    // is the method's IDENTITY, so `decompile_method_ast` reports a proto naming
    // one `Object` parameter beside N actual params. The argument LIST is built
    // from this field and both emitters agree on it; only the identity triple
    // differs. Carrying the call-site proto into the AST node is a schema change
    // (androguard's nested-list shape has no slot for it) and is not done.
    std::string_view call_site_proto;
};
// dexllm#67: invoke-custom's operand is a `call_site_ids` index, which names
// no method — it names an encoded_array describing the BOOTSTRAP that links the
// call at runtime. Resolved once by the builder (see `IDexCodeSource::GetCallSite`)
// and OWNED here rather than viewed, unlike its siblings: the rendered method
// reference of a `Handle` argument is constructed, so there is no table for it to
// point into, and one owned copy per invoke-custom is free (0 corpus incidence).
struct CallSiteConst {
    IDexCodeSource::CallSiteInfo info;
    uint32_t raw_idx = 0;
};
using ConstRef = std::variant<std::monostate,
                              StringConst, TypeConst,
                              FieldConst, MethodConst, CallSiteConst>;

// ============================================================================
// Payload — fill-array-data / packed-switch / sparse-switch trailing data.
// Stored per RawBlock, keyed by the LOADING instruction's byte_off.
// ============================================================================

struct PayloadFillArray {
    uint16_t element_width = 0;
    uint32_t size = 0;
    std::vector<uint8_t> data;     // raw bytes; size = element_width * size
};
struct PayloadPackedSwitch {
    int32_t first_key = 0;
    std::vector<int32_t> targets;  // byte offsets relative to switch ins
};
struct PayloadSparseSwitch {
    std::vector<int32_t> keys;
    std::vector<int32_t> targets;  // byte offsets relative to switch ins
};
using PayloadVariant = std::variant<std::monostate,
                                    PayloadFillArray,
                                    PayloadPackedSwitch,
                                    PayloadSparseSwitch>;

// ============================================================================
// Instruction — decoded + const-pool-resolved.
// ============================================================================

struct RawIns {
    uint32_t byte_off = 0;          // byte offset within insns[]
    uint16_t length_bytes = 0;      // BYTE length (2 × code-units)
    dex::Opcode opcode = dex::OP_NOP;
    dex::Instruction decoded{};     // slicer-decoded: vA, vB, vC, arg[5]
    ConstRef const_ref;             // monostate when N/A
    // Absolute BYTE offset of branch target within insns[]; UINT32_MAX = N/A.
    // Pre-computed by builder for branch ops (goto, if-*, switch defaults).
    uint32_t branch_target = UINT32_MAX;
};

// ============================================================================
// Basic-block — raw form. Consumed by build_node_from_block to produce IR.
// ============================================================================

struct CatchInfo {
    std::string_view catch_type;    // empty = catch-all
    uint32_t handler_block_id = 0;
};

struct ChildEdge {
    enum class Kind : uint8_t {
        Fallthrough,   // sequential next
        Branch,        // if-test TRUE / goto
        BranchFalse,   // if-test FALSE (fall-through after branch)
        SwitchCase,    // packed/sparse switch case target
        SwitchDefault, // switch fall-through target
    };
    Kind kind = Kind::Fallthrough;
    uint32_t target_block_id = 0;
    int64_t label = 0;              // switch key (for SwitchCase); else unused
};

struct RawBlock {
    std::string name;               // "B@0x0042"
    // The block's LEADER. Usually, but NOT always, the offset of its first
    // instruction: a leader only has to be an in-range byte offset (dexllm#77),
    // so it can sit inside a payload or in the tail of a multi-unit
    // instruction, and the block then holds the first instruction AT OR AFTER
    // it that is still inside the span.
    uint32_t start_byte = 0;        // block leader (inclusive)
    uint32_t end_byte = 0;          // one-past-last byte offset (exclusive)
    uint32_t last_length_bytes = 0; // length of last ins in bytes
    std::span<const RawIns> ins;    // view into MethodSnapshot.ins_storage
    std::vector<ChildEdge> childs;
    std::vector<CatchInfo> exception_handlers;
    // Payload lookup: fill-array-data / *-switch insn → its payload data.
    std::unordered_map<uint32_t, PayloadVariant> payloads;
    // `start_byte` is not the offset of a decoded instruction (dexllm#77). The
    // RAW structural fact; what the emitters report is
    // `Graph::control_enters_non_instruction`, which additionally requires the
    // block to have been BUILT — reachability is not known until Construct's
    // bfs, so a leader off a boundary sitting in DEAD CODE sets this and marks
    // nothing.
    bool starts_off_instruction = false;
};

// ============================================================================
// Method metadata — populated from IDexCodeSource at build time.
// ============================================================================

struct MethodMeta {
    std::string cls_name;                       // "Lcom/X;" (Smali, owned)
    std::string name;                           // owned
    std::string proto;                          // "(I)V" (owned)
    std::string ret_type;                       // split: "V" / "I" / "Lcom/X;"
    std::vector<std::string> params_type;       // ["I", "Lcom/X;"]
    std::vector<int> lparams;                   // register IDs (this + params)
    std::vector<std::string> access;            // ["public", "static", ...]
    std::array<std::string, 3> triple{};        // {"com/X", "foo", "(I)V"}
                                                // class part is stripped
    uint16_t dex_id = 0;
    uint32_t method_idx = 0;
};

// ============================================================================
// MethodSnapshot — the immutable output of MethodSnapshotBuilder.
// ============================================================================

struct MethodSnapshot {
    MethodMeta meta;

    uint16_t registers_size = 0;
    uint16_t ins_size = 0;          // parameter register count

    // The method HAS a code item, but nothing decodable in it (dexllm#73).
    // Distinguishes "there is no body here" from abstract/native, which is
    // otherwise readable only as the ABSENCE of a modifier; the Writer marks
    // the declaration so the refusal is stated rather than implied.
    bool code_without_instructions = false;

    // The first decodable instruction is NOT at byte offset 0 (dexllm#75) — the
    // code item opens with a switch/fill-array payload, which DecodeAllInsns
    // skips. A VM starts at insns[0], so such a method cannot execute at all
    // (ART's runtime method_verifier rejects it; the STRUCTURAL verifier this
    // port mirrors does not, so it loads). We decompile from the first real
    // instruction, which is a REINTERPRETATION rather than what would run — the
    // Writer and the AST both mark it so that is stated, not implied.
    // Strictly weaker than the entry defect it was found through: a leader
    // BELOW the first instruction (a try-range start, a handler, or a plain
    // branch target) additionally made block 0 an empty span, and
    // `entry_block_id = 0` then named it, dropping the whole body. That is why
    // the entry is chosen by CONTENT (the block holding the first instruction)
    // rather than by position; the two coincide on every well-formed input.
    bool entry_not_at_offset_zero = false;


    // ★ POINTER-STABLE after Build() returns. RawBlock.ins spans into this.
    std::vector<RawIns> ins_storage;
    std::vector<RawBlock> blocks;

    // nullopt ⟺ `ins_storage` is empty: native/abstract (no code item), or a
    // code item with no decodable instruction (`insns_size == 0`, or payloads
    // only — DecodeAllInsns skips those). Note `blocks` may be NON-empty in that
    // second case, because a try-range start also seeds a leader; the predicate
    // is `ins_storage`, not `blocks`.
    // Else the id of the block that CONTAINS the first decodable instruction —
    // NOT necessarily block 0, whose span is the lowest LEADER and may hold no
    // instruction at all (dexllm#75). A value here PROMISES `blocks[value]`
    // exists. Construct consumes it six times without a bound of its own (one of
    // them a write), so it throws rather than proceed if a producer ever breaks
    // it (dexllm#73).
    std::optional<uint32_t> entry_block_id;

    // Method-level exception aggregation (DvMethod passes to construct()).
    struct ExceptionRange {
        uint32_t start_byte = 0;
        uint32_t end_byte = 0;      // exclusive
        std::vector<CatchInfo> handlers;
    };
    std::vector<ExceptionRange> exceptions;

    MethodSnapshot() = default;
    MethodSnapshot(const MethodSnapshot&) = delete;
    MethodSnapshot& operator=(const MethodSnapshot&) = delete;
    MethodSnapshot(MethodSnapshot&&) = delete;
    MethodSnapshot& operator=(MethodSnapshot&&) = delete;
    ~MethodSnapshot() = default;
};

// ============================================================================
// Builder — single-threaded per call; caller ensures DexItem warmed.
// ============================================================================

class MethodSnapshotBuilder {
public:
    // Always returns non-null. For a method with no CFG — native/abstract, or a
    // code item carrying no decodable instruction — returns a snapshot with
    // empty `blocks` and `entry_block_id == nullopt`. For malformed dex,
    // throws std::runtime_error.
    static std::unique_ptr<MethodSnapshot> Build(IDexCodeSource& source,
                                                 uint16_t dex_id,
                                                 uint32_t method_idx);

    // Convenience: shared_ptr<const MethodSnapshot> for cache / DvMethod.
    static std::shared_ptr<const MethodSnapshot>
    BuildShared(IDexCodeSource& src, uint16_t dex_id, uint32_t method_idx) {
        return std::shared_ptr<const MethodSnapshot>(
            Build(src, dex_id, method_idx));
    }
};

}  // namespace dexkit::dad
