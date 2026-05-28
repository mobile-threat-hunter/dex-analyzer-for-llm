// method_snapshot_builder.cpp — turns DexItem (via IDexCodeSource) into an
// immutable MethodSnapshot for DAD consumption.
//
// Pipeline (single-pass per method):
//   1. Resolve metadata (cls/name/proto/access/lparams).
//   2. Walk insns[] linearly, decoding each instruction:
//        - skip payload sequences (0x0100/0x0200/0x0300 markers)
//        - resolve const-pool ref (string/type/method/field) per opcode
//        - pre-compute branch_target (byte-absolute) for branch ops
//   3. Locate fill-array-data / switch payloads (via signed offset field).
//   4. Compute basic-block leaders + split into RawBlocks (pointer-stable).
//   5. Compute CFG successor edges (Fallthrough / Branch / SwitchCase / ...).
//   6. Parse try/catch tables, attach handlers per block AND aggregate
//      method-level.
//
// All byte-offset conventions documented in method_snapshot.h.

#include "method_snapshot.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

#include "dex_code_source.h"
#include "slicer/dex_bytecode.h"
#include "slicer/dex_format.h"
#include "util.h"  // GetAccessMethod, GetTypeSize, GetParamsType

namespace dexkit::dad {

namespace {

// ─── small helpers ────────────────────────────────────────────────────────

inline size_t Align4(size_t off) { return (off + 3) & ~size_t{3}; }

inline std::string FormatBlockName(uint32_t byte_off) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "B@0x%04X", byte_off);
    return std::string(buf);
}

// uleb128 decoder — advances `p`.
uint32_t ReadUleb128(const uint8_t*& p) {
    uint32_t result = 0;
    int shift = 0;
    while (true) {
        uint8_t b = *p++;
        result |= static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

// sleb128 decoder — advances `p`.
int32_t ReadSleb128(const uint8_t*& p) {
    int32_t result = 0;
    int shift = 0;
    uint8_t b;
    do {
        b = *p++;
        result |= static_cast<int32_t>(b & 0x7F) << shift;
        shift += 7;
    } while (b & 0x80);
    if (shift < 32 && (b & 0x40)) {
        result |= -(int32_t{1} << shift);  // sign-extend
    }
    return result;
}

// Branch offset (code-units) for branch opcodes. Returns 0 for non-branches.
int32_t ExtractBranchOffsetCodeUnits(const dex::Instruction& ins,
                                     dex::Opcode op) {
    switch (dex::GetFormatFromOpcode(op)) {
        case dex::k10t: return static_cast<int32_t>(static_cast<int8_t>(ins.vA));
        case dex::k20t: return static_cast<int32_t>(static_cast<int16_t>(ins.vA));
        case dex::k21t: return static_cast<int32_t>(static_cast<int16_t>(ins.vB));
        case dex::k22t: return static_cast<int32_t>(static_cast<int16_t>(ins.vC));
        case dex::k30t: return static_cast<int32_t>(ins.vA);
        case dex::k31t: return static_cast<int32_t>(ins.vB);
        default: return 0;
    }
}

bool IsBranchOpcode(dex::Opcode op) {
    // goto, goto/16, goto/32, if-*, packed-switch, sparse-switch
    // Also fill-array-data — same k31t format with a 32-bit signed offset to
    // its payload. The offset itself is a data ref (not control flow), but
    // the offset-extraction + owner_to_payload wiring is shared with switches.
    return (op >= dex::OP_GOTO && op <= dex::OP_GOTO_32)
        || (op >= dex::OP_IF_EQ && op <= dex::OP_IF_LEZ)
        || op == dex::OP_PACKED_SWITCH || op == dex::OP_SPARSE_SWITCH
        || op == dex::OP_FILL_ARRAY_DATA;
}

bool IsConditionalBranch(dex::Opcode op) {
    return op >= dex::OP_IF_EQ && op <= dex::OP_IF_LEZ;
}

bool IsUnconditionalBranch(dex::Opcode op) {
    return op >= dex::OP_GOTO && op <= dex::OP_GOTO_32;
}

bool IsSwitch(dex::Opcode op) {
    return op == dex::OP_PACKED_SWITCH || op == dex::OP_SPARSE_SWITCH;
}

bool IsReturn(dex::Opcode op) {
    return op >= dex::OP_RETURN_VOID && op <= dex::OP_RETURN_OBJECT;
}

bool IsThrow(dex::Opcode op) { return op == dex::OP_THROW; }

// True if instruction terminates the block (no fall-through).
bool IsBlockTerminator(dex::Opcode op) {
    return IsReturn(op) || IsThrow(op) || IsUnconditionalBranch(op);
}

// Detect payload "instruction" markers (first code-unit value).
//   0x0100 = packed-switch-payload, 0x0200 = sparse, 0x0300 = fill-array-data.
bool IsPayloadMarker(dex::u2 first_unit) {
    return first_unit == 0x0100 || first_unit == 0x0200 || first_unit == 0x0300;
}

// ─── const-pool resolution ────────────────────────────────────────────────

ConstRef ResolveConstRef(const dex::Instruction& decoded, dex::Opcode op,
                         IDexCodeSource& src, uint16_t dex_id) {
    dex::InstructionIndexType idx_type = dex::GetIndexTypeFromOpcode(op);
    // Index lives in vB for most formats, but for k22c (iget/iput/instance-of
    // /new-array) the index is in vC (vB is a second register). Choose
    // based on instruction format.
    dex::InstructionFormat fmt = dex::GetFormatFromOpcode(op);
    auto pick_idx = [&]() -> uint32_t {
        if (fmt == dex::k22c || fmt == dex::k22cs) return decoded.vC;
        return decoded.vB;
    };
    switch (idx_type) {
        case dex::kIndexStringRef: {
            uint32_t i = pick_idx();
            return StringConst{src.GetString(dex_id, i), i};
        }
        case dex::kIndexTypeRef: {
            uint32_t i = pick_idx();
            return TypeConst{src.GetTypeName(dex_id, i), i};
        }
        case dex::kIndexMethodRef: {
            uint32_t i = pick_idx();
            return MethodConst{src.GetMethodRefTriple(dex_id, i), i};
        }
        case dex::kIndexFieldRef: {
            uint32_t i = pick_idx();
            return FieldConst{src.GetFieldRefTriple(dex_id, i), i};
        }
        default:
            return std::monostate{};
    }
}

// ─── payload extraction ───────────────────────────────────────────────────

PayloadVariant ParsePackedSwitchPayload(const dex::u2* p) {
    PayloadPackedSwitch ps;
    // layout: u2 ident=0x0100, u2 size, s4 first_key, s4 targets[size]
    uint16_t size = p[1];
    ps.first_key = *reinterpret_cast<const int32_t*>(p + 2);
    const int32_t* tgts = reinterpret_cast<const int32_t*>(p + 4);
    ps.targets.assign(tgts, tgts + size);
    return ps;
}

PayloadVariant ParseSparseSwitchPayload(const dex::u2* p) {
    PayloadSparseSwitch ss;
    // layout: u2 ident=0x0200, u2 size, s4 keys[size], s4 targets[size]
    uint16_t size = p[1];
    const int32_t* keys = reinterpret_cast<const int32_t*>(p + 2);
    const int32_t* tgts = keys + size;
    ss.keys.assign(keys, keys + size);
    ss.targets.assign(tgts, tgts + size);
    return ss;
}

PayloadVariant ParseFillArrayPayload(const dex::u2* p) {
    PayloadFillArray pa;
    // layout: u2 ident=0x0300, u2 element_width, u4 size, u1 data[size*ew]
    pa.element_width = p[1];
    pa.size = *reinterpret_cast<const uint32_t*>(p + 2);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(p + 4);
    size_t total = static_cast<size_t>(pa.element_width) * pa.size;
    pa.data.assign(data, data + total);
    return pa;
}

PayloadVariant ParsePayloadAt(const dex::u2* p) {
    switch (p[0]) {
        case 0x0100: return ParsePackedSwitchPayload(p);
        case 0x0200: return ParseSparseSwitchPayload(p);
        case 0x0300: return ParseFillArrayPayload(p);
        default: return std::monostate{};
    }
}

// ─── leader computation ───────────────────────────────────────────────────

struct DecodePass {
    std::vector<RawIns> ins;                  // pointer-stable after reserve
    std::set<uint32_t> leader_byte_offs;      // sorted leader byte offsets
    // payload_byte_off → owning instruction's byte_off (for back-mapping)
    std::unordered_map<uint32_t, uint32_t> payload_to_owner;
    // owner ins byte_off → payload byte_off
    std::unordered_map<uint32_t, uint32_t> owner_to_payload;
    uint32_t insns_byte_size = 0;
};

DecodePass DecodeAllInsns(const dex::Code* code, IDexCodeSource& src,
                          uint16_t dex_id) {
    DecodePass pass;
    pass.insns_byte_size = code->insns_size * 2;

    // First pass: count real instructions (skip payloads) to reserve storage.
    {
        const dex::u2* p = code->insns;
        const dex::u2* end_p = p + code->insns_size;
        size_t cnt = 0;
        while (p < end_p) {
            size_t w = dex::GetWidthFromBytecode(p);
            if (w == 0) {
                throw std::runtime_error(
                    "malformed dex: zero-width instruction at offset "
                    + std::to_string((p - code->insns) * 2));
            }
            if (!IsPayloadMarker(*p)) ++cnt;
            p += w;
        }
        pass.ins.reserve(cnt);
    }

    // Second pass: build RawIns (skipping payloads).
    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;
    while (p < end_p) {
        size_t w = dex::GetWidthFromBytecode(p);
        uint32_t byte_off = static_cast<uint32_t>((p - base) * 2);
        if (IsPayloadMarker(*p)) {
            p += w;
            continue;
        }
        RawIns ri;
        ri.byte_off = byte_off;
        ri.length_bytes = static_cast<uint16_t>(w * 2);
        ri.decoded = dex::DecodeInstruction(p);
        ri.opcode = ri.decoded.opcode;
        ri.const_ref = ResolveConstRef(ri.decoded, ri.opcode, src, dex_id);

        // Branch target pre-computation.
        if (IsBranchOpcode(ri.opcode)) {
            int32_t off_cu = ExtractBranchOffsetCodeUnits(ri.decoded, ri.opcode);
            int64_t target = static_cast<int64_t>(ri.byte_off)
                           + static_cast<int64_t>(off_cu) * 2;
            if (target < 0 || target >= static_cast<int64_t>(pass.insns_byte_size)) {
                throw std::runtime_error(
                    "malformed dex: branch target out of range");
            }
            // For switches and fill-array, target is the PAYLOAD location.
            if (IsSwitch(ri.opcode) || ri.opcode == dex::OP_FILL_ARRAY_DATA) {
                pass.payload_to_owner[static_cast<uint32_t>(target)] = ri.byte_off;
                pass.owner_to_payload[ri.byte_off] = static_cast<uint32_t>(target);
                // branch_target NOT used for the loader itself (it's a data ref)
            } else {
                ri.branch_target = static_cast<uint32_t>(target);
            }
        }
        pass.ins.push_back(ri);
        p += w;
    }

    return pass;
}

// Compute basic-block leader set.
//   - first instruction
//   - branch targets (if-*, goto)
//   - instruction immediately after a branch/return/throw
//   - switch case targets (need payload parse)
//   - exception handler entries (added later in BuildExceptions)
void ComputeLeaders(DecodePass& pass, const dex::Code* code) {
    if (pass.ins.empty()) return;
    pass.leader_byte_offs.insert(pass.ins.front().byte_off);

    for (size_t i = 0; i < pass.ins.size(); ++i) {
        const RawIns& ri = pass.ins[i];
        // Successor of block-terminator → leader
        if (i + 1 < pass.ins.size() && IsBlockTerminator(ri.opcode)) {
            pass.leader_byte_offs.insert(pass.ins[i + 1].byte_off);
        }
        // Conditional branch → next ins is leader (false branch)
        if (i + 1 < pass.ins.size() && IsConditionalBranch(ri.opcode)) {
            pass.leader_byte_offs.insert(pass.ins[i + 1].byte_off);
        }
        // Packed/sparse-switch → next ins is leader (default fall-through).
        // Without this the switch and the following instruction stay in the
        // same basic block, so BuildNodeFromBlock sees the post-switch op
        // as last_op and never picks the SwitchBlock subclass.
        if (i + 1 < pass.ins.size() && IsSwitch(ri.opcode)) {
            pass.leader_byte_offs.insert(pass.ins[i + 1].byte_off);
        }
        // Branch target → leader (if/goto only; switch/fill-array targets are
        // handled via payload parse below)
        if (ri.branch_target != UINT32_MAX) {
            pass.leader_byte_offs.insert(ri.branch_target);
        }
        // Switch / fill-array: parse payload to find case targets.
        auto it = pass.owner_to_payload.find(ri.byte_off);
        if (it != pass.owner_to_payload.end()) {
            uint32_t payload_byte_off = it->second;
            if (payload_byte_off + 4 > pass.insns_byte_size) continue;
            const dex::u2* pp = code->insns + (payload_byte_off / 2);
            PayloadVariant pv = ParsePayloadAt(pp);
            if (auto* ps = std::get_if<PayloadPackedSwitch>(&pv)) {
                for (int32_t off_cu : ps->targets) {
                    int64_t t = static_cast<int64_t>(ri.byte_off)
                              + static_cast<int64_t>(off_cu) * 2;
                    if (t >= 0 && t < pass.insns_byte_size)
                        pass.leader_byte_offs.insert(static_cast<uint32_t>(t));
                }
            } else if (auto* ss = std::get_if<PayloadSparseSwitch>(&pv)) {
                for (int32_t off_cu : ss->targets) {
                    int64_t t = static_cast<int64_t>(ri.byte_off)
                              + static_cast<int64_t>(off_cu) * 2;
                    if (t >= 0 && t < pass.insns_byte_size)
                        pass.leader_byte_offs.insert(static_cast<uint32_t>(t));
                }
            }
        }
    }
}

// ─── exception table parsing ──────────────────────────────────────────────

struct ParsedHandler {
    std::string_view type;     // empty for catch-all
    uint32_t handler_byte_off;
};
struct ParsedTry {
    uint32_t start_byte;
    uint32_t end_byte;          // exclusive
    std::vector<ParsedHandler> handlers;
};

std::vector<ParsedTry> ParseExceptions(const dex::Code* code,
                                       IDexCodeSource& src,
                                       uint16_t dex_id) {
    std::vector<ParsedTry> result;
    if (code->tries_size == 0) return result;

    const dex::u2* after_insns = code->insns + code->insns_size;
    size_t aligned = Align4(reinterpret_cast<size_t>(after_insns));
    const dex::TryBlock* tries =
        reinterpret_cast<const dex::TryBlock*>(aligned);
    const uint8_t* handlers_base =
        reinterpret_cast<const uint8_t*>(tries + code->tries_size);

    // handlers_size is uleb128 at handlers_base; advances pointer
    const uint8_t* hp = handlers_base;
    ReadUleb128(hp);  // handlers_size (used only as a sanity hint)

    for (uint16_t i = 0; i < code->tries_size; ++i) {
        const dex::TryBlock& tb = tries[i];
        ParsedTry pt;
        pt.start_byte = tb.start_addr * 2;
        pt.end_byte = (tb.start_addr + tb.insn_count) * 2;

        const uint8_t* p = handlers_base + tb.handler_off;
        // Re-read handlers_size? No — handler_off is from handlers_base.
        // Actually per DEX spec, handler_off is offset from start of
        // encoded_catch_handler_list (which begins with uleb128 size, then
        // raw handlers). Conventionally tools compute it relative to the
        // start of the list including the size prefix. Slicer behaves
        // identically. handler_off here points to the start of an
        // encoded_catch_handler.

        int32_t size = ReadSleb128(p);
        bool has_catch_all = (size <= 0);
        int32_t typed_count = std::abs(size);

        for (int32_t j = 0; j < typed_count; ++j) {
            uint32_t type_idx = ReadUleb128(p);
            uint32_t handler_addr_cu = ReadUleb128(p);
            ParsedHandler ph;
            ph.type = src.GetTypeName(dex_id, type_idx);
            ph.handler_byte_off = handler_addr_cu * 2;
            pt.handlers.push_back(ph);
        }
        if (has_catch_all) {
            uint32_t handler_addr_cu = ReadUleb128(p);
            ParsedHandler ph;
            ph.type = {};  // empty = catch-all
            ph.handler_byte_off = handler_addr_cu * 2;
            pt.handlers.push_back(ph);
        }
        result.push_back(std::move(pt));
    }
    return result;
}

// ─── block splitting ──────────────────────────────────────────────────────

// Compute block_id for a given byte_off; returns UINT32_MAX if not a leader.
uint32_t FindBlockIdForByteOff(const std::vector<RawBlock>& blocks,
                               uint32_t byte_off) {
    for (uint32_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i].start_byte == byte_off) return i;
    }
    return UINT32_MAX;
}

// Given a sorted leader set + ins_storage, partition into RawBlocks.
// MUST be called AFTER ins_storage is finalized (vector won't grow).
void SplitIntoBlocks(MethodSnapshot& snap, const DecodePass& pass) {
    std::vector<uint32_t> leaders(pass.leader_byte_offs.begin(),
                                  pass.leader_byte_offs.end());

    // Map byte_off → ins index (for span construction).
    std::vector<size_t> ins_idx_by_byte;
    if (!snap.ins_storage.empty()) {
        uint32_t max_off = snap.ins_storage.back().byte_off
                         + snap.ins_storage.back().length_bytes;
        ins_idx_by_byte.assign(max_off, SIZE_MAX);
        for (size_t i = 0; i < snap.ins_storage.size(); ++i) {
            ins_idx_by_byte[snap.ins_storage[i].byte_off] = i;
        }
    }

    snap.blocks.reserve(leaders.size());
    for (size_t li = 0; li < leaders.size(); ++li) {
        uint32_t start = leaders[li];
        uint32_t end = (li + 1 < leaders.size()) ? leaders[li + 1]
                                                  : pass.insns_byte_size;

        RawBlock blk;
        blk.start_byte = start;
        blk.end_byte = end;
        blk.name = FormatBlockName(start);

        // Locate ins range in ins_storage.
        size_t first_idx = (start < ins_idx_by_byte.size())
                             ? ins_idx_by_byte[start] : SIZE_MAX;
        size_t last_idx = first_idx;
        // Find last instruction with byte_off < end
        if (first_idx != SIZE_MAX) {
            for (size_t i = first_idx;
                 i < snap.ins_storage.size()
                   && snap.ins_storage[i].byte_off < end;
                 ++i) {
                last_idx = i;
            }
            blk.ins = std::span<const RawIns>(
                snap.ins_storage.data() + first_idx,
                last_idx - first_idx + 1);
            blk.last_length_bytes = snap.ins_storage[last_idx].length_bytes;
        }
        snap.blocks.push_back(std::move(blk));
    }
}

void ComputeChildEdges(MethodSnapshot& snap, const DecodePass& pass,
                       const dex::Code* code) {
    for (RawBlock& blk : snap.blocks) {
        if (blk.ins.empty()) continue;
        const RawIns& last = blk.ins.back();

        if (IsReturn(last.opcode) || IsThrow(last.opcode)) {
            // No successors.
            continue;
        }

        if (IsUnconditionalBranch(last.opcode)) {
            uint32_t tgt_id = FindBlockIdForByteOff(snap.blocks,
                                                    last.branch_target);
            if (tgt_id != UINT32_MAX) {
                blk.childs.push_back({ChildEdge::Kind::Branch, tgt_id});
            }
            continue;
        }

        if (IsConditionalBranch(last.opcode)) {
            uint32_t true_id = FindBlockIdForByteOff(snap.blocks,
                                                     last.branch_target);
            uint32_t false_id = FindBlockIdForByteOff(snap.blocks,
                                                      blk.end_byte);
            if (true_id != UINT32_MAX)
                blk.childs.push_back({ChildEdge::Kind::Branch, true_id});
            if (false_id != UINT32_MAX)
                blk.childs.push_back({ChildEdge::Kind::BranchFalse, false_id});
            continue;
        }

        if (IsSwitch(last.opcode)) {
            // Default = fall-through (next byte)
            uint32_t default_id = FindBlockIdForByteOff(snap.blocks,
                                                       blk.end_byte);
            if (default_id != UINT32_MAX)
                blk.childs.push_back({ChildEdge::Kind::SwitchDefault, default_id});
            // Cases from payload
            auto it = pass.owner_to_payload.find(last.byte_off);
            if (it != pass.owner_to_payload.end()) {
                uint32_t payload_byte_off = it->second;
                const dex::u2* pp = code->insns + (payload_byte_off / 2);
                PayloadVariant pv = ParsePayloadAt(pp);
                if (auto* ps = std::get_if<PayloadPackedSwitch>(&pv)) {
                    for (size_t k = 0; k < ps->targets.size(); ++k) {
                        int64_t t = static_cast<int64_t>(last.byte_off)
                                  + static_cast<int64_t>(ps->targets[k]) * 2;
                        uint32_t case_id = FindBlockIdForByteOff(snap.blocks,
                            static_cast<uint32_t>(t));
                        if (case_id != UINT32_MAX) {
                            blk.childs.push_back({
                                ChildEdge::Kind::SwitchCase, case_id,
                                ps->first_key + static_cast<int32_t>(k)});
                        }
                    }
                    blk.payloads[last.byte_off] = std::move(pv);
                } else if (auto* ss = std::get_if<PayloadSparseSwitch>(&pv)) {
                    for (size_t k = 0; k < ss->targets.size(); ++k) {
                        int64_t t = static_cast<int64_t>(last.byte_off)
                                  + static_cast<int64_t>(ss->targets[k]) * 2;
                        uint32_t case_id = FindBlockIdForByteOff(snap.blocks,
                            static_cast<uint32_t>(t));
                        if (case_id != UINT32_MAX) {
                            blk.childs.push_back({
                                ChildEdge::Kind::SwitchCase, case_id,
                                ss->keys[k]});
                        }
                    }
                    blk.payloads[last.byte_off] = std::move(pv);
                }
            }
            continue;
        }

        // Default: fall-through
        uint32_t fall_id = FindBlockIdForByteOff(snap.blocks, blk.end_byte);
        if (fall_id != UINT32_MAX) {
            blk.childs.push_back({ChildEdge::Kind::Fallthrough, fall_id});
        }
    }

    // Also resolve fill-array-data payloads (not branches, but need attaching)
    for (RawBlock& blk : snap.blocks) {
        for (const RawIns& ri : blk.ins) {
            if (ri.opcode != dex::OP_FILL_ARRAY_DATA) continue;
            auto it = pass.owner_to_payload.find(ri.byte_off);
            if (it == pass.owner_to_payload.end()) continue;
            uint32_t payload_byte_off = it->second;
            const dex::u2* pp = code->insns + (payload_byte_off / 2);
            blk.payloads[ri.byte_off] = ParsePayloadAt(pp);
        }
    }
}

void AttachExceptionHandlers(MethodSnapshot& snap,
                             const std::vector<ParsedTry>& tries) {
    // Build per-block handler lists by checking which try-ranges cover each
    // block's start_byte.
    for (RawBlock& blk : snap.blocks) {
        for (const auto& pt : tries) {
            if (blk.start_byte >= pt.start_byte && blk.start_byte < pt.end_byte) {
                for (const auto& ph : pt.handlers) {
                    uint32_t handler_id =
                        FindBlockIdForByteOff(snap.blocks, ph.handler_byte_off);
                    if (handler_id != UINT32_MAX) {
                        blk.exception_handlers.push_back(
                            {ph.type, handler_id});
                    }
                }
            }
        }
    }
    // Method-level aggregation
    for (const auto& pt : tries) {
        MethodSnapshot::ExceptionRange er;
        er.start_byte = pt.start_byte;
        er.end_byte = pt.end_byte;
        for (const auto& ph : pt.handlers) {
            uint32_t handler_id =
                FindBlockIdForByteOff(snap.blocks, ph.handler_byte_off);
            if (handler_id != UINT32_MAX) {
                er.handlers.push_back({ph.type, handler_id});
            }
        }
        snap.exceptions.push_back(std::move(er));
    }
}

// ─── metadata population ──────────────────────────────────────────────────

void FillMethodMeta(MethodMeta& meta, IDexCodeSource& src,
                    uint16_t dex_id, uint32_t method_idx) {
    meta.dex_id = dex_id;
    meta.method_idx = method_idx;
    meta.cls_name = std::string(src.GetMethodClassName(dex_id, method_idx));
    meta.name = std::string(src.GetMethodName(dex_id, method_idx));
    meta.proto = src.GetMethodProto(dex_id, method_idx);
    // Split return type: "(...)Type" → Type
    auto paren = meta.proto.rfind(')');
    meta.ret_type = (paren == std::string::npos) ? "V"
                                                  : meta.proto.substr(paren + 1);
    // Use the proper parser, not GetParamsType — see instruction_dispatch.cpp
    // for the rationale (DAD's GetParamsType whitespace-split quirk relies on
    // androguard's space-separated proto, our internal proto is spaceless).
    meta.params_type = ParseParamsType(meta.proto);
    uint32_t flags = src.GetMethodAccessFlags(dex_id, method_idx);
    meta.access = GetAccessMethod(flags);
    // triple: (cls_stripped, name, proto)
    // Strip "L...;" → "..."
    std::string stripped = meta.cls_name;
    if (stripped.size() >= 2 && stripped.front() == 'L'
        && stripped.back() == ';') {
        stripped = stripped.substr(1, stripped.size() - 2);
    }
    meta.triple = {stripped, meta.name, meta.proto};
}

void ComputeLparams(MethodMeta& meta, uint16_t registers_size,
                    uint16_t ins_size) {
    if (ins_size == 0) return;
    int start = static_cast<int>(registers_size) - static_cast<int>(ins_size);
    int num_param = 0;
    bool is_static = std::find(meta.access.begin(), meta.access.end(),
                                "static") != meta.access.end();
    if (!is_static) {
        meta.lparams.push_back(start);
        ++num_param;
    }
    for (const std::string& ptype : meta.params_type) {
        meta.lparams.push_back(start + num_param);
        num_param += static_cast<int>(GetTypeSize(ptype));
    }
}

}  // namespace

// ============================================================================
// MethodSnapshotBuilder::Build
// ============================================================================

std::unique_ptr<MethodSnapshot>
MethodSnapshotBuilder::Build(IDexCodeSource& source,
                             uint16_t dex_id,
                             uint32_t method_idx) {
    auto snap = std::make_unique<MethodSnapshot>();
    FillMethodMeta(snap->meta, source, dex_id, method_idx);

    const dex::Code* code = source.GetMethodCode(dex_id, method_idx);
    if (code == nullptr) {
        // Native/abstract: empty CFG, entry_block_id stays nullopt.
        return snap;
    }
    snap->registers_size = code->registers_size;
    snap->ins_size = code->ins_size;
    ComputeLparams(snap->meta, snap->registers_size, snap->ins_size);

    // 1. Decode all instructions + resolve const-pool.
    DecodePass pass = DecodeAllInsns(code, source, dex_id);

    // 2. Compute leaders.
    ComputeLeaders(pass, code);

    // 3. Parse exception table; handler entries are also leaders.
    auto tries = ParseExceptions(code, source, dex_id);
    for (const auto& pt : tries) {
        pass.leader_byte_offs.insert(pt.start_byte);
        for (const auto& ph : pt.handlers) {
            pass.leader_byte_offs.insert(ph.handler_byte_off);
        }
    }

    // 4. Finalize ins_storage (pointer-stable from here).
    snap->ins_storage = std::move(pass.ins);

    // 5. Split into blocks (uses ins_storage; spans become pointer-stable).
    SplitIntoBlocks(*snap, pass);

    // 6. Compute CFG edges and attach payloads.
    ComputeChildEdges(*snap, pass, code);

    // 7. Attach exception handlers per block + aggregate method-level.
    AttachExceptionHandlers(*snap, tries);

    snap->entry_block_id = 0;  // first block is entry (lowest byte_off)
    return snap;
}

}  // namespace dexkit::dad
