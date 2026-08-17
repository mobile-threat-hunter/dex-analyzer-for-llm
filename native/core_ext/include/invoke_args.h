#pragma once

// L4 argument-origin analysis — what value reaches each argument register at every
// invoke site of one method body.
//
// This is a dexllm analysis, not part of upstream DexKit. It used to live as
// `DexItem::AnalyzeMethodInvokes` inside `vendor/dexkit_core/Core/dexkit/dex_item.cpp`,
// which enlarged the vendor diff in the file that is hardest to rebase and put a
// dexllm-specific pass in code we want to keep pristine (dexllm#32). It needs nothing
// private from `DexItem`: the whole input is one `dex::Code*` plus the end of the
// image it lives in, both already reachable through the public `GetMethodCode()` /
// `GetImage()`. So it is a free function over the decoded code item. Of DexKit it
// keeps exactly two decode helpers it already used — `GetBytecodeWidth` (payload-aware
// instruction width) and the `ReadInt`/`ReadLong` operand readers; keeping those
// rather than substituting slicer equivalents is what makes the move a LIFT with no
// behaviour change rather than a rewrite. Everything else it needs is the slicer's.
//
// CONTRACT (dexllm#16 for the join semantics, dexllm#32 pre-work for the window):
//
// For each basic block holding an invoke, the WINDOW is that block plus every block
// within `depth` predecessor edges of it. A small forward dataflow over the window
// produces the block's incoming register state, the block is simulated from it, and
// each invoke reads its argument registers off the live state.
//
// A definition is reported only when it reaches the call on EVERY path of the window,
// so a reported value is never one path's value presented as unconditional. An edge
// from OUTSIDE the window carries nothing, so it tombstones a register some other
// in-window edge does define; a register no in-window edge defines is simply absent.
// It is deliberately not a fixed point: a catch handler is entered with an EMPTY
// register file, and a cycle inside the window is resolved by taking nothing from the
// not-yet-resolved edge. The method ENTRY counts as an edge of the entry block.
//
// SOUNDNESS RESTS ON A COMPLETENESS OBLIGATION: the opcode switch must enumerate every
// register-writing opcode, because the fall-through branch clears nothing. It is
// machine-checked against slicer's own instruction table by
// tests/test_arg_opcode_coverage.py, with the runtime half in
// tests/test_arg_quick_opcodes.py.

#include <cstdint>
#include <string>
#include <vector>

#include "slicer/dex_format.h"

namespace dexkit::ext {

enum class ArgKind : uint8_t {
    Unknown = 0,      // not tracked — see InvokeArg::crossed_branch
    ConstString = 1,  // string literal, value at string_idx
    ConstInt = 2,     // const/const-4/16 (32-bit), value at int_value
    ConstWide = 3,    // const-wide* (64-bit), value at int_value
    ConstClass = 4,   // const-class, type at type_idx
    ConstNull = 5,    // const v, 0 / const-null
    FieldRead = 6,    // iget*/sget*, field_idx
    MethodReturn = 7, // move-result after invoke, method_idx = callee
    Parameter = 8,    // method parameter (initial register state)
    NewInstance = 9,  // new-instance vAA, type@BBBB
    NewArray = 10,    // new-array vA, vB, type@CCCC
};

struct InvokeArg {
    ArgKind kind = ArgKind::Unknown;
    uint16_t reg_num = 0;
    uint32_t string_idx = 0;
    int64_t int_value = 0;
    uint32_t type_idx = 0;
    uint32_t field_idx = 0;
    uint32_t method_idx = 0;
    int16_t parameter_index = -1;
    // Only meaningful when kind == Unknown: this register HAD a tracked definition
    // that a control-flow merge discarded — either the paths carry different values
    // (a genuinely conditional argument) or one of the merged edges came from outside
    // the analysis window / from a block not yet resolved, which also tombstones
    // registers that happen to agree. So `true` means "a definition was discarded
    // here", NOT "two values provably reach". The complement (`false` on an Unknown)
    // means no tracked definition was FOUND WITHIN THE WINDOW — never tracked
    // (arithmetic, aget, …), cleared by a later untracked write, defined further back
    // than `depth` blocks with no merge in between, or inside a catch handler, which
    // is entered with an EMPTY register file and therefore tombstones nothing.
    // Raising `depth` can turn EITHER flavour into a value; neither flag is a promise
    // that it will (a handler is a hard stop, not a radius).
    bool crossed_branch = false;
    // Internal to the simulation: this origin is 64-bit, so it owns reg_num AND
    // reg_num+1 and any write to EITHER destroys it. Not surfaced to Python.
    bool wide = false;
};

struct InvokeSiteWithArgs {
    uint32_t method_idx;      // callee method_idx
    uint32_t bytecode_offset; // byte offset within insns
    uint8_t opcode;
    std::vector<InvokeArg> args;
};

// `depth` = predecessor levels of basic blocks searched above the invoke's own block.
// kDefaultArgDepth is the API-wide default; 0 restricts the analysis to the invoke's
// own block.
inline constexpr uint32_t kDefaultArgDepth = 2;

// PRECONDITION: `img_end` must be the end of the image `code` ITSELF lives in. While
// this was a DexItem member both were derived from `this` and could not disagree; as a
// free function that is now the caller's obligation (`AnalyzeInvokesOf` in
// dexkit_ext.cpp is the only one, and takes both from the same DexItem). It bounds the
// exception-handler reads — the encoded_catch_handler list is verified at load, but the
// walk is bounded anyway, the same posture as the snapshot builder's ParseExceptions.
// Pass nullptr when no bound is available; a fixed fallback span is used instead.
[[nodiscard]] std::vector<InvokeSiteWithArgs> AnalyzeInvokes(
    const ::dex::Code* code, const ::dex::u1* img_end,
    uint32_t depth = kDefaultArgDepth);

}  // namespace dexkit::ext
