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

namespace dexkit::dad {

class IDexCodeSource;  // dex_code_source.h

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
};
using ConstRef = std::variant<std::monostate,
                              StringConst, TypeConst,
                              FieldConst, MethodConst>;

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
    uint32_t start_byte = 0;        // first ins byte offset (inclusive)
    uint32_t end_byte = 0;          // one-past-last byte offset (exclusive)
    uint32_t last_length_bytes = 0; // length of last ins in bytes
    std::span<const RawIns> ins;    // view into MethodSnapshot.ins_storage
    std::vector<ChildEdge> childs;
    std::vector<CatchInfo> exception_handlers;
    // Payload lookup: fill-array-data / *-switch insn → its payload data.
    std::unordered_map<uint32_t, PayloadVariant> payloads;
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

    // ★ POINTER-STABLE after Build() returns. RawBlock.ins spans into this.
    std::vector<RawIns> ins_storage;
    std::vector<RawBlock> blocks;

    // nullopt = native/abstract (no code). Else 0 (first block).
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
    // Always returns non-null. For native/abstract methods, returns a snapshot
    // with empty `blocks` and `entry_block_id == nullopt`. For malformed dex,
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
