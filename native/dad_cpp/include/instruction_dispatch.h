// instruction_dispatch.h — RawIns → typed IR via OpcodeKind switch.
//
// Bridges between MethodSnapshot's RawIns (operand-agnostic) and
// opcode_ins.h's typed handlers (each with bespoke signature). DAD's
// `INSTRUCTION_SET[opcode](ins, vmap, ...)` pattern is translated to a
// 256-case switch on OpcodeKind, with per-format operand extraction.

#pragma once

#include <string_view>

#include "instruction.h"     // IRFormPtr
#include "method_snapshot.h" // RawIns, PayloadVariant
#include "opcode_ins.h"      // Vmap, RetState, OpcodeKind

namespace dexkit::dad {

// Dispatch one instruction to its typed handler. Returns the produced IR
// node, or nullptr for instructions DAD treats as no-IR (monitor-enter/exit,
// payload markers, etc.).
//   payload: optional pointer to RawBlock.payloads[ri.byte_off] for
//            fill-array-data / *-switch. nullptr if N/A.
//   exception_type: for move-exception; descriptor of the catch's type.
IRFormPtr DispatchInstruction(const RawIns& ri,
                              Vmap& vmap,
                              RetState& gen_ret,
                              const PayloadVariant* payload = nullptr,
                              std::string_view exception_type = {});

// Register-name helper. Convention: register N → "vN".
inline std::string RegName(uint32_t n) {
    return "v" + std::to_string(n);
}

}  // namespace dexkit::dad
