// L4 argument-origin analysis. Moved out of the vendored DexKit core (dexllm#32):
// see native/core_ext/include/invoke_args.h for the contract and the reasoning.
//
// Nothing here depends on DexKit — only on the slicer's decoder and opcode tables,
// which is what made the move a lift rather than a rewrite.

#include "invoke_args.h"

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "slicer/dex_bytecode.h"
#include "slicer/dex_format.h"
#include "utils/byte_code_util.h"
#include "utils/opcode_util.h"

namespace dexkit::ext {

using ::dexkit::GetBytecodeWidth;
using ::dexkit::ReadInt;
using ::dexkit::ReadLong;

namespace {

// The basic-block CFG of one code item, from a single linear pre-pass. Replaces the
// dexllm#16 `JoinPoints` sets: the analysis is no longer a linear scan that meets on
// arrival, so it needs real blocks and real predecessor lists rather than a
// classification of offsets into forward/backward/barrier.
struct Cfg {
    static constexpr uint32_t kNoBlock = UINT32_MAX;

    std::vector<uint32_t> starts;              // block leaders, ascending byte offset
    std::vector<std::vector<uint32_t>> preds;  // preds[b] = blocks with an edge into b
    std::vector<char> is_handler;              // catch handler: register file unknown
    std::vector<char> has_invoke;              // block contains at least one invoke*

    // The block owning `byte_off`. Callers only pass real instruction offsets.
    [[nodiscard]] uint32_t BlockOf(uint32_t byte_off) const {
        auto it = std::upper_bound(starts.begin(), starts.end(), byte_off);
        if (it == starts.begin()) return kNoBlock;
        return static_cast<uint32_t>((it - starts.begin()) - 1);
    }
    // One past the last byte of block b.
    [[nodiscard]] uint32_t EndOf(uint32_t b, uint32_t code_bytes) const {
        return b + 1 < starts.size() ? starts[b + 1] : code_bytes;
    }
};

// Bounded uleb128 (the encoded_catch_handler list is verified at load, but this
// read is bounded anyway — same posture as the snapshot builder's ParseExceptions).
uint32_t ReadUlebBounded(const dex::u1*& p, const dex::u1* end) {
    uint32_t result = 0;
    int shift = 0;
    while (p < end && shift < 32) {
        dex::u1 b = *p++;
        result |= static_cast<uint32_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}
int32_t ReadSlebBounded(const dex::u1*& p, const dex::u1* end) {
    int32_t result = 0;
    int shift = 0;
    dex::u1 b = 0;
    while (p < end && shift < 32) {
        b = *p++;
        result |= static_cast<int32_t>(b & 0x7f) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 32 && (b & 0x40)) result |= -(1 << shift);
    return result;
}

// One linear pre-pass over the code item builds the whole CFG: leaders, predecessor
// lists, catch-handler marks, and which blocks contain an invoke.
//
// Successors are decoded per instruction; a block boundary falls after any
// instruction that branches or does not fall through, and before any branch target
// or catch handler. Exception edges are deliberately NOT modelled — a handler is
// reachable from every instruction of its try region, so its entry state is unknown
// no matter which predecessors we could name, and `is_handler` says exactly that.
Cfg BuildCfg(const dex::Code* code, const dex::u1* img_end) {
    Cfg cfg;
    const dex::u2* base = code->insns;
    const dex::u2* end_p = base + code->insns_size;
    const int64_t code_bytes = static_cast<int64_t>(code->insns_size) * 2;

    struct Insn {
        uint32_t off = 0;
        uint32_t next = 0;   // byte offset of the following instruction
        bool falls = true;   // control may continue at `next`
        bool invoke = false;
        std::vector<uint32_t> targets;  // explicit branch targets
    };
    std::vector<Insn> insns;
    std::unordered_set<uint32_t> insn_offs;

    auto note = [&](Insn& in, int64_t target_byte) {
        if (target_byte < 0 || target_byte >= code_bytes) return;
        in.targets.push_back(static_cast<uint32_t>(target_byte));
    };

    const dex::u2* p = base;
    while (p < end_p) {
        uint8_t op = static_cast<uint8_t>(*p);
        size_t width = GetBytecodeWidth(p);
        if (width == 0) break;
        Insn in;
        in.off = static_cast<uint32_t>((p - base) * 2);
        in.next = static_cast<uint32_t>(in.off + width * 2);
        // Every opcode whose BBBB is a method_ids index: the 10 invoke-kind forms
        // plus invoke-polymorphic (0xFA/0xFB, dexllm#61). NOT invoke-custom
        // (0xFC/0xFD) — its BBBB is a call_site index, so the extractor below has
        // nothing to resolve there. This set is the same in all four gates that
        // spell it, and tests/test_invoke_opcode_gates.py derives it from slicer's
        // own table rather than trusting any of them.
        in.invoke = (op >= 0x6E && op <= 0x72) || (op >= 0x74 && op <= 0x78)
                    || op == 0xFA || op == 0xFB;
        const int64_t off = in.off;
        switch (op) {
            case 0x0E: case 0x0F: case 0x10: case 0x11:  // return*
            case 0x73:  // return-void-no-barrier (ART odex form of 0x0E)
            case 0x27:                                   // throw
                in.falls = false;
                break;
            case 0x28:  // goto +AA
                note(in, off + 2 * static_cast<int8_t>((*p >> 8) & 0xFF));
                in.falls = false;
                break;
            case 0x29:  // goto/16 +AAAA
                note(in, off + 2 * static_cast<int16_t>(*(p + 1)));
                in.falls = false;
                break;
            case 0x2A:  // goto/32 +AAAAAAAA
                note(in, off + 2 * static_cast<int64_t>(
                                  static_cast<int32_t>(ReadInt(p + 1))));
                in.falls = false;
                break;
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
            case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
                // if-eq..le +CCCC / if-*z +BBBB — the offset is the last unit
                note(in, off + 2 * static_cast<int16_t>(*(p + width - 1)));
                break;
            case 0x2B: case 0x2C: {  // packed-/sparse-switch +BBBBBBBB → payload
                int64_t pay = off + 2 * static_cast<int64_t>(
                                        static_cast<int32_t>(ReadInt(p + 1)));
                if (pay < 0 || pay + 4 > code_bytes) break;
                const dex::u2* t = base + pay / 2;
                uint16_t ident = *t;
                uint16_t size = *(t + 1);
                // packed-switch payload: ident 0x0100, [size][first_key][size targets]
                // sparse-switch payload: ident 0x0200, [size][size keys][size targets]
                const dex::u2* tbl = nullptr;
                if (op == 0x2B && ident == 0x0100) tbl = t + 4;          // skip first_key
                else if (op == 0x2C && ident == 0x0200) tbl = t + 2 + size * 2;
                if (tbl == nullptr) break;
                // Each target is a 32-bit offset RELATIVE TO THE SWITCH instruction.
                if (tbl + static_cast<size_t>(size) * 2 > end_p) break;  // malformed
                for (uint16_t i = 0; i < size; ++i)
                    note(in, off + 2 * static_cast<int64_t>(
                                     static_cast<int32_t>(ReadInt(tbl + i * 2))));
                break;
            }
            default:
                break;
        }
        insn_offs.insert(in.off);
        insns.push_back(std::move(in));
        p += width;
    }
    if (insns.empty()) return cfg;

    // Catch handlers: reachable from anywhere inside the try region, so the register
    // file at entry is unknown. (Mirrors ParseExceptions in the snapshot builder;
    // bounded against the mapped image.)
    std::unordered_set<uint32_t> handlers;
    if (code->tries_size != 0) {
        const dex::u2* after = code->insns + code->insns_size;
        size_t aligned = (reinterpret_cast<size_t>(after) + 3) & ~size_t(3);
        const auto* tries = reinterpret_cast<const dex::TryBlock*>(aligned);
        const auto* handlers_base =
            reinterpret_cast<const dex::u1*>(tries + code->tries_size);
        const dex::u1* end = img_end ? img_end : handlers_base + (1u << 16);
        if (handlers_base <= end) {
            for (uint16_t i = 0; i < code->tries_size; ++i) {
                const dex::u1* hp = handlers_base + tries[i].handler_off;
                if (hp < handlers_base || hp >= end) continue;
                int32_t size = ReadSlebBounded(hp, end);
                bool catch_all = (size <= 0);
                int64_t typed = std::abs(static_cast<int64_t>(size));
                for (int64_t j = 0; j < typed && hp < end; ++j) {
                    ReadUlebBounded(hp, end);  // type_idx
                    handlers.insert(ReadUlebBounded(hp, end) * 2);
                }
                if (catch_all && hp < end)
                    handlers.insert(ReadUlebBounded(hp, end) * 2);
            }
        }
    }

    // Leaders. A branch target that is not a real instruction start is dropped here
    // rather than silently splitting a block at a mid-instruction offset.
    std::unordered_set<uint32_t> leaders;
    leaders.insert(insns.front().off);
    for (auto& in : insns) {
        in.targets.erase(std::remove_if(in.targets.begin(), in.targets.end(),
                                        [&](uint32_t t) { return !insn_offs.count(t); }),
                         in.targets.end());
        for (uint32_t t : in.targets) leaders.insert(t);
        if ((!in.falls || !in.targets.empty()) && insn_offs.count(in.next))
            leaders.insert(in.next);
    }
    for (uint32_t h : handlers)
        if (insn_offs.count(h)) leaders.insert(h);

    cfg.starts.assign(leaders.begin(), leaders.end());
    std::sort(cfg.starts.begin(), cfg.starts.end());
    const size_t nb = cfg.starts.size();
    cfg.preds.resize(nb);
    cfg.is_handler.assign(nb, 0);
    cfg.has_invoke.assign(nb, 0);

    for (const auto& in : insns) {
        const uint32_t b = cfg.BlockOf(in.off);
        if (b == Cfg::kNoBlock) continue;
        if (in.invoke) cfg.has_invoke[b] = 1;
        for (uint32_t t : in.targets) cfg.preds[cfg.BlockOf(t)].push_back(b);
        // The fall-through edge is only an EDGE when it leaves the block; inside one
        // it is just the next instruction.
        if (in.falls && insn_offs.count(in.next)) {
            const uint32_t nb_idx = cfg.BlockOf(in.next);
            if (nb_idx != b) cfg.preds[nb_idx].push_back(b);
        }
    }
    for (auto& v : cfg.preds) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
    for (size_t b = 0; b < nb; ++b)
        if (handlers.count(cfg.starts[b])) cfg.is_handler[b] = 1;
    return cfg;
}

// Two tracked definitions are the same value iff kind and the kind-relevant payload
// agree. Used as the meet operator at a join: disagreement drops the register.
bool SameOrigin(const InvokeArg& a, const InvokeArg& b) {
    using K = ArgKind;
    if (a.kind != b.kind) return false;
    switch (a.kind) {
        case K::ConstString:  return a.string_idx == b.string_idx;
        case K::ConstInt:
        case K::ConstWide:    return a.int_value == b.int_value;
        case K::ConstClass:
        case K::NewInstance:
        case K::NewArray:     return a.type_idx == b.type_idx;
        case K::FieldRead:    return a.field_idx == b.field_idx;
        case K::MethodReturn: return a.method_idx == b.method_idx;
        case K::Parameter:    return a.parameter_index == b.parameter_index;
        case K::ConstNull:    return true;
        case K::Unknown:      return a.crossed_branch == b.crossed_branch;
    }
    return false;
}

}  // namespace
//
// Bounded-window register analysis. For every basic block holding an invoke, the
// WINDOW is the set of blocks within `depth` predecessor edges of it; a small forward
// dataflow over that window produces the block's incoming register state, the block is
// simulated from it, and each invoke reads its argument registers off the live state.
// Anything we don't decode (most arithmetic etc.) clears the destination register.
//
// `depth` counts predecessor LEVELS: 0 analyses the invoke's own block alone, and the
// default 2 adds two levels above it. The window is a block SET, not a per-path
// budget — every block inside it is analysed under the same boundary condition (an
// edge from outside carries nothing), so two paths that rejoin are compared with the
// same amount of history behind them. Spending the budget per path instead would
// tombstone registers the paths genuinely agree on, which is an artefact of the
// accounting rather than a fact about the code.
//
// The dexllm#16 guarantees hold WITHIN the window: a definition that reaches the site
// on every path of the window survives, and one that holds on only some path degrades
// to Unknown + crossed_branch instead of being reported as unconditional. Outside it
// nothing is asserted at all.
std::vector<InvokeSiteWithArgs> AnalyzeInvokes(const dex::Code* code,
                                               const dex::u1* img_end,
                                               uint32_t depth) {
    std::vector<InvokeSiteWithArgs> out;
    if (code == nullptr) return out;

    const Cfg cfg = BuildCfg(code, img_end);
    if (cfg.starts.empty()) return out;

    const dex::u2* base = code->insns;
    const uint32_t code_bytes = static_cast<uint32_t>(code->insns_size) * 2;
    using State = std::unordered_map<uint16_t, InvokeArg>;

    // Parameter registers sit at the high end of the file and are defined by the
    // method ENTRY, so they belong to the entry block's incoming state — reachable
    // only when the window actually reaches that block.
    const uint16_t total_regs = code->registers_size;
    const uint16_t param_regs = code->ins_size;
    const uint16_t first_param = total_regs > param_regs
                                     ? static_cast<uint16_t>(total_regs - param_regs)
                                     : 0;
    auto param_state = [&]() {
        State s;
        for (uint16_t i = 0; i < param_regs; ++i) {
            InvokeArg a;
            a.kind = ArgKind::Parameter;
            a.reg_num = static_cast<uint16_t>(first_param + i);
            a.parameter_index = static_cast<int16_t>(i);
            s[a.reg_num] = a;
        }
        return s;
    };

    // A register that HAD a definition which a merge discarded is tombstoned rather
    // than erased, so a consumer can tell "conditional / gave up" from "never tracked".
    auto tombstone = [](uint16_t r) {
        InvokeArg a;
        a.kind = ArgKind::Unknown;
        a.reg_num = r;
        a.crossed_branch = true;
        return a;
    };
    auto meet_into = [&](State& dst, const State& src) {
        for (auto& kv : dst) {
            auto s = src.find(kv.first);
            if (s == src.end() || !SameOrigin(kv.second, s->second))
                kv.second = tombstone(kv.first);  // differs / absent on one path
        }
        for (const auto& kv : src)
            if (dst.find(kv.first) == dst.end()) dst[kv.first] = tombstone(kv.first);
    };

    // Simulate one block over `st`. With `emit`, every invoke it contains appends a
    // site whose arguments are read off the live state. Returns the instruction count
    // (the work budget below is denominated in instructions).
    auto run_block = [&](uint32_t b, State& st, bool emit) -> uint64_t {
        const dex::u2* q = base + cfg.starts[b] / 2;
        const dex::u2* q_end = base + cfg.EndOf(b, code_bytes) / 2;
        uint64_t simulated = 0;

        uint32_t last_invoke_callee = 0;
        // move-result must directly follow its invoke, so it never crosses into this
        // block from another one.
        bool has_last_invoke = false;
        uint8_t cur_op = 0;

        // A 64-bit value occupies vN AND vN+1. The high half must lose any tracked
        // origin too, or a stale one is reported for it (invoke-*/range lists one arg
        // entry per register, so the high half IS surfaced). Table-driven off slicer's
        // own VerifyFlags rather than a hand-kept opcode list.
        auto is_wide_dest = [](uint8_t opcode) {
            return (dex::GetVerifyFlagsFromOpcode(static_cast<dex::Opcode>(opcode)) &
                    dex::kVerifyRegAWide) != 0;
        };
        // The ALIASING direction of the same fact, and the one the comment above does
        // NOT cover: a 64-bit value parked at vN-1 also owns vN, so ANY write to vN
        // destroys it — including a narrow one. Without this, `const-wide v0` followed
        // by `const/16 v1` still reported the whole original 64-bit constant for v0,
        // with crossed_branch FALSE, i.e. a confidently wrong value on a dex that
        // verifies strict-valid (dexllm#32 adversarial review). `wide` records that a
        // stored origin owns the next register; it is set from the DEFINING opcode, so
        // a `move-wide` / `move-result-wide` carries it without a second opcode list.
        auto kill_wide_alias = [&](uint16_t r) {
            if (r == 0) return;
            auto it = st.find(static_cast<uint16_t>(r - 1));
            if (it != st.end() && it->second.wide) st.erase(it);
        };
        auto set_reg_op = [&](uint16_t r, InvokeArg a, uint8_t opcode) {
            a.reg_num = r;
            a.wide = is_wide_dest(opcode);
            st[r] = a;
            if (a.wide) st.erase(static_cast<uint16_t>(r + 1));
            kill_wide_alias(r);
        };
        auto erase_reg_op = [&](uint16_t r, uint8_t opcode) {
            st.erase(r);
            if (is_wide_dest(opcode)) st.erase(static_cast<uint16_t>(r + 1));
            kill_wide_alias(r);
        };
        auto set_reg = [&](uint16_t r, InvokeArg a) { set_reg_op(r, a, cur_op); };

        while (q < q_end) {
            uint16_t insn = *q;
            uint8_t op = static_cast<uint8_t>(insn);
            cur_op = op;
            size_t width = GetBytecodeWidth(q);
            if (width == 0) break;
            ++simulated;

            const uint16_t AA = (insn >> 8) & 0xFF;
            const uint8_t A = (insn >> 8) & 0x0F;
            const uint8_t B = (insn >> 12) & 0x0F;

            switch (op) {
                // ---- transfers of control ----
                // They write no register. The block ends here (or at the instruction
                // after a conditional branch), and the CFG carries the successor
                // edges, so there is nothing to do beyond breaking the invoke →
                // move-result adjacency.
                case 0x0E: case 0x0F: case 0x10: case 0x11:  // return*
                case 0x27:                                    // throw
                case 0x28: case 0x29: case 0x2A:              // goto*
                case 0x2B: case 0x2C:                         // packed/sparse-switch
                case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
                case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
                    has_last_invoke = false;
                    break;

                // ---- move family: propagate state from src register ----
                case 0x01: case 0x04: case 0x07: {  // move{,-wide,-object} vA, vB
                    auto it = st.find(B);
                    if (it != st.end()) set_reg(A, it->second);
                    else erase_reg_op(A, op);
                    has_last_invoke = false;
                    break;
                }
                case 0x02: case 0x05: case 0x08: {  // move/from16
                    uint16_t src = *(q + 1);
                    auto it = st.find(src);
                    if (it != st.end()) set_reg(AA, it->second);
                    else erase_reg_op(AA, op);
                    has_last_invoke = false;
                    break;
                }
                case 0x03: case 0x06: case 0x09: {  // move/16
                    uint16_t dst = *(q + 1);
                    uint16_t src = *(q + 2);
                    auto it = st.find(src);
                    if (it != st.end()) set_reg(dst, it->second);
                    else erase_reg_op(dst, op);
                    has_last_invoke = false;
                    break;
                }

                // ---- move-result* ----
                case 0x0A: case 0x0B: case 0x0C: {
                    if (has_last_invoke) {
                        InvokeArg a;
                        a.kind = ArgKind::MethodReturn;
                        a.method_idx = last_invoke_callee;
                        set_reg(AA, a);
                    } else {
                        erase_reg_op(AA, op);
                    }
                    break;
                }

                // ---- const/4 vA, #+B ----
                case 0x12: {
                    int8_t v = static_cast<int8_t>(B);
                    if (v >= 8) v -= 16;
                    InvokeArg a;
                    a.kind = (v == 0) ? ArgKind::ConstNull : ArgKind::ConstInt;
                    a.int_value = v;
                    set_reg(A, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const/16 vAA, #+BBBB ----
                case 0x13: {
                    int16_t v = static_cast<int16_t>(*(q + 1));
                    InvokeArg a;
                    a.kind = (v == 0) ? ArgKind::ConstNull : ArgKind::ConstInt;
                    a.int_value = v;
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const vAA, #+BBBBBBBB ----
                case 0x14: {
                    int32_t v = static_cast<int32_t>(ReadInt(q + 1));
                    InvokeArg a;
                    a.kind = ArgKind::ConstInt;
                    a.int_value = v;
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const/high16 vAA, #+BBBB0000 ----
                case 0x15: {
                    int32_t v = static_cast<int32_t>(*(q + 1)) << 16;
                    InvokeArg a;
                    a.kind = ArgKind::ConstInt;
                    a.int_value = v;
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const-wide/* ----
                case 0x16: case 0x17: case 0x18: case 0x19: {
                    int64_t v = 0;
                    if (op == 0x16)       v = static_cast<int16_t>(*(q + 1));
                    else if (op == 0x17)  v = static_cast<int32_t>(ReadInt(q + 1));
                    else if (op == 0x18)  v = static_cast<int64_t>(ReadLong(q + 1));
                    else                  v = static_cast<int64_t>(*(q + 1)) << 48;
                    InvokeArg a;
                    a.kind = ArgKind::ConstWide;
                    a.int_value = v;
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const-string vAA, string@BBBB ----
                case 0x1A: {
                    InvokeArg a;
                    a.kind = ArgKind::ConstString;
                    a.string_idx = *(q + 1);
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const-string/jumbo vAA, string@BBBBBBBB ----
                case 0x1B: {
                    InvokeArg a;
                    a.kind = ArgKind::ConstString;
                    a.string_idx = ReadInt(q + 1);
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- const-class vAA, type@BBBB ----
                case 0x1C: {
                    InvokeArg a;
                    a.kind = ArgKind::ConstClass;
                    a.type_idx = *(q + 1);
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- new-instance vAA, type@BBBB ----
                case 0x22: {
                    InvokeArg a;
                    a.kind = ArgKind::NewInstance;
                    a.type_idx = *(q + 1);
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- new-array vA, vB, type@CCCC ----
                case 0x23: {
                    InvokeArg a;
                    a.kind = ArgKind::NewArray;
                    a.type_idx = *(q + 1);
                    set_reg(A, a);
                    has_last_invoke = false;
                    break;
                }

                // ---- iget* family: writes to vA from field@CCCC ----
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
                case 0x58: {
                    InvokeArg a;
                    a.kind = ArgKind::FieldRead;
                    a.field_idx = *(q + 1);
                    set_reg(A, a);
                    has_last_invoke = false;
                    break;
                }
                // ---- iget-*-quick: WRITES vA, and there is nothing to track ----
                // ART's runtime-only forms (k22c, dest vA like the iget* above, and
                // `iget-wide-quick` is kVerifyRegAWide so the high half goes too).
                // Their operand is a vtable/field OFFSET, not a field_idx, so the
                // value has no recoverable origin — but the register IS overwritten,
                // and `default:` clears nothing, so leaving them there let a stale
                // origin survive its own overwrite and be reported as an
                // UNCONDITIONAL value (no crossed_branch). They reach us because
                // VerifyInsns bounds registers and indices and has no opcode-legality
                // gate, so a dex carrying one verifies clean in BOTH strict and
                // lenient mode; an odex-derived packer dump is the realistic source.
                // The iput-*-quick siblings (0xE6-0xE8, 0xEB-0xEE) READ vA and so
                // must NOT be listed here.
                case 0xE3: case 0xE4: case 0xE5:
                case 0xEF: case 0xF0: case 0xF1: case 0xF2:
                    erase_reg_op(A, op);
                    has_last_invoke = false;
                    break;
                // ---- sget* family: writes to vAA from field@BBBB ----
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
                case 0x66: {
                    InvokeArg a;
                    a.kind = ArgKind::FieldRead;
                    a.field_idx = *(q + 1);
                    set_reg(AA, a);
                    has_last_invoke = false;
                    break;
                }

                // ---- invoke-kind {C..G}, method@BBBB (format 35c) ----
                // invoke-polymorphic (0xFA, k45cc) joins it: `AG op BBBB FEDC HHHH`
                // is byte-identical to 35c for units 0..2, and the extra proto unit
                // is not read here (GetBytecodeWidth already returns 4 for it).
                case 0x6E: case 0x6F: case 0x70: case 0x71: case 0x72: case 0xFA: {
                    uint8_t arg_count = B;  // high nibble of insn>>8
                    uint8_t G = A;          // low nibble of insn>>8
                    uint16_t callee_idx = *(q + 1);
                    uint16_t pack = *(q + 2);
                    uint8_t C = pack & 0x0F;
                    uint8_t D = (pack >> 4) & 0x0F;
                    uint8_t E = (pack >> 8) & 0x0F;
                    uint8_t F = (pack >> 12) & 0x0F;
                    std::vector<uint16_t> regs;
                    if (arg_count >= 1) regs.push_back(C);
                    if (arg_count >= 2) regs.push_back(D);
                    if (arg_count >= 3) regs.push_back(E);
                    if (arg_count >= 4) regs.push_back(F);
                    if (arg_count >= 5) regs.push_back(G);

                    if (emit) {
                        InvokeSiteWithArgs site;
                        site.method_idx = callee_idx;
                        site.bytecode_offset = static_cast<uint32_t>((q - base) * 2);
                        site.opcode = op;
                        for (auto r : regs) {
                            auto it = st.find(r);
                            InvokeArg a = (it != st.end()) ? it->second : InvokeArg{};
                            a.reg_num = r;
                            site.args.push_back(a);
                        }
                        out.push_back(std::move(site));
                    }
                    last_invoke_callee = callee_idx;
                    has_last_invoke = true;
                    break;
                }
                // ---- invoke-kind/range {CCCC..NNNN}, method@BBBB (format 3rc) ----
                // invoke-polymorphic/range (0xFB, k4rcc) joins it for the same reason
                // as 0xFA above: `AA op BBBB CCCC HHHH` matches 3rc on units 0..2.
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: case 0xFB: {
                    uint8_t arg_count = AA;
                    uint16_t callee_idx = *(q + 1);
                    uint16_t first_reg = *(q + 2);
                    if (emit) {
                        InvokeSiteWithArgs site;
                        site.method_idx = callee_idx;
                        site.bytecode_offset = static_cast<uint32_t>((q - base) * 2);
                        site.opcode = op;
                        for (uint8_t i = 0; i < arg_count; ++i) {
                            uint16_t r = static_cast<uint16_t>(first_reg + i);
                            auto it = st.find(r);
                            InvokeArg a = (it != st.end()) ? it->second : InvokeArg{};
                            a.reg_num = r;
                            site.args.push_back(a);
                        }
                        out.push_back(std::move(site));
                    }
                    last_invoke_callee = callee_idx;
                    has_last_invoke = true;
                    break;
                }

                // ---- Untracked writers to vAA (clear dest to avoid stale state) ----
                // move-exception (0x0D), cmp-* (0x2D-0x31), aget* (0x44-0x4A),
                // binary 23x (0x90-0xAF), binary/lit/8 (0xD8-0xE2, format k22b =
                // `vAA, vBB, #+CC`), const-method-handle/type (0xFE/0xFF, format 21c).
                case 0x0D:
                case 0x2D: case 0x2E: case 0x2F: case 0x30: case 0x31:
                case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A:
                case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
                case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
                case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4: case 0xA5: case 0xA6: case 0xA7:
                case 0xA8: case 0xA9: case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
                case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
                case 0xE0: case 0xE1: case 0xE2:
                case 0xFE: case 0xFF:
                    erase_reg_op(AA, op);
                    has_last_invoke = false;
                    break;

                // ---- Untracked writers to vA (clear dest) ----
                // instance-of (0x20), array-length (0x21), unary 12x (0x7B-0x8F),
                // binary/2addr (0xB0-0xCF), binary/lit/16 (0xD0-0xD7, format k22s =
                // `vA, vB, #+CCCC`).
                case 0x20: case 0x21:
                case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
                case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC4: case 0xC5: case 0xC6: case 0xC7:
                case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
                case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5: case 0xD6: case 0xD7:
                    erase_reg_op(A, op);
                    has_last_invoke = false;
                    break;

                // Reaching here must mean the opcode WRITES NO REGISTER, because this
                // branch clears nothing: an unhandled writer would let a stale origin
                // survive its own overwrite and be reported as an unconditional value.
                // The enumeration above is therefore a completeness obligation, not a
                // convenience, and it is machine-checked against slicer's own
                // instruction table by tests/test_arg_opcode_coverage.py.
                //
                // The opcodes that legitimately land here WITH a register in operand A
                // only READ it, so preserving the origin is correct and wanted:
                // monitor-enter/exit, fill-array-data, aput* (0x4B-0x51), iput*
                // (0x59-0x5F), sput* (0x67-0x6D), iput-*-quick (0xE6-0xE8, 0xEB-0xEE),
                // and check-cast (0x1F), whose whole point is that the VALUE is
                // unchanged — clearing it would lose the origin across every
                // `(String) x` cast.
                default:
                    has_last_invoke = false;
                    break;
            }
            q += width;
        }
        return simulated;
    };

    // Crafted-input backstop. A window is bounded by `depth`, but a block with a
    // pathological predecessor count (a switch with thousands of cases into one block)
    // makes every window large and every invoke-bearing block pays for its own.
    // `kMaxWork` bounds the time in simulated instructions across the whole method;
    // `kMaxWindowEntries` bounds the transient memory, since a window holds one
    // register-file copy per resolved block and `registers_size` goes up to 65535.
    // On exhaustion the window is abandoned and the block is emitted from an empty
    // state — the same fail-closed direction a boundary edge already takes. Both are
    // far above any real method.
    constexpr uint64_t kMaxWork = 1ull << 22;
    constexpr size_t kMaxWindowEntries = 1u << 16;
    uint64_t work = 0;

    for (uint32_t b = 0; b < cfg.starts.size(); ++b) {
        if (!cfg.has_invoke[b]) continue;

        State in;
        if (work <= kMaxWork) {
            // Backward BFS — the blocks within `depth` predecessor edges of b. The
            // walk stops AT a catch handler: its incoming state is empty whatever its
            // predecessors carry, so resolving them is work whose result is discarded.
            // (Purely a saving — not the guard that makes a handler safe; that is the
            // `is_handler` branch below.)
            std::unordered_map<uint32_t, uint32_t> dist{{b, 0}};
            std::vector<uint32_t> frontier{b};
            std::vector<uint32_t> window{b};
            for (uint32_t d = 0; d < depth && !frontier.empty(); ++d) {
                std::vector<uint32_t> next;
                for (uint32_t f : frontier) {
                    if (cfg.is_handler[f]) continue;
                    for (uint32_t pd : cfg.preds[f]) {
                        if (dist.emplace(pd, d + 1).second) {
                            next.push_back(pd);
                            window.push_back(pd);
                        }
                    }
                }
                frontier.swap(next);
            }
            // Farthest first, so a block's predecessors are resolved before it. An
            // edge from a block that is outside the window OR not yet resolved (a
            // cycle inside it) contributes nothing, which only removes information.
            std::sort(window.begin(), window.end(), [&](uint32_t x, uint32_t y) {
                if (dist[x] != dist[y]) return dist[x] > dist[y];
                return x < y;
            });

            const State nothing;
            std::unordered_map<uint32_t, State> outs;
            size_t stored = 0;
            for (uint32_t w : window) {
                State st;
                if (cfg.is_handler[w]) {
                    // Reachable from any instruction of its try region with the
                    // register file in an unknown state — nothing survives into it.
                } else {
                    bool first = true;
                    // The method ENTRY is an edge like any other, and it is the one
                    // that defines the parameter registers. A block that is BOTH the
                    // entry and a loop header therefore meets the parameters with
                    // whatever the back edge carries: taking only the back edge would
                    // report a loop-carried value as if it also held on the first
                    // iteration (`p0` vs `p0.getCause()` on a `while` that walks a
                    // cause chain), and taking only the parameters would do the
                    // converse.
                    if (w == 0) { st = param_state(); first = false; }
                    for (uint32_t pd : cfg.preds[w]) {
                        auto it = outs.find(pd);
                        const State& contrib = (it != outs.end()) ? it->second : nothing;
                        if (first) { st = contrib; first = false; }
                        else meet_into(st, contrib);
                    }
                }
                if (w == b) { in = std::move(st); break; }
                if (work > kMaxWork || stored + st.size() > kMaxWindowEntries) break;
                work += run_block(w, st, /*emit=*/false);
                stored += st.size();
                outs.emplace(w, std::move(st));
            }
        }
        run_block(b, in, /*emit=*/true);
    }

    return out;
}

}  // namespace dexkit::ext
