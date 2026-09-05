// api_ref.h — POD types for L1 external reference enumeration.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dexkit::ext {

struct ExternalTypeRef {
    std::string descriptor;
    std::vector<uint16_t> referenced_in_dex_ids;
};

struct ExternalMethodRef {
    std::string class_descriptor;
    std::string name;
    std::string proto;  // "(II)Ljava/lang/String;"
    std::vector<uint16_t> referenced_in_dex_ids;
};

struct ExternalFieldRef {
    std::string class_descriptor;
    std::string name;
    std::string type;
    std::vector<uint16_t> referenced_in_dex_ids;
};

// L2 — a single invoke site in some caller method. bytecode_offset and
// invoke_opcode are populated by L2.5 (kOpSequence walking); L2 leaves them
// at sentinel values.
struct CallSite {
    uint16_t caller_dex_id = 0;
    uint32_t caller_method_idx = 0;        // index into caller dex's MethodIds
    std::string caller_descriptor;         // "Lcom/x/Y;->foo(I)V"
    std::string callee_descriptor;         // resolved full API signature
    int32_t bytecode_offset = -1;          // L2.5
    uint8_t invoke_opcode = 0;             // L2.5: 0x6E~0x72, 0x74~0x78, 0xFA/0xFB
};

// dexllm#84 — a single FIELD ACCESS site: one `iget*`/`iput*`/`sget*`/`sput*`
// instruction, in the method that executes it.
//
// The sibling of `CallSite` for the field cross-reference. That pair
// (find_field_read_sites / find_field_write_sites) used to return bare method
// descriptors with a documented per-INSTRUCTION contract, so a method reading the
// field four times produced FOUR IDENTICAL STRINGS: the contract was honoured in
// the count and lost in the value, and the instructions were unobtainable at any
// price (48% of the fields with a read in the bundled corpus returned such rows).
//
// Named for what it IS, not for how it was obtained (dexllm#69): `Site` is the
// established suffix for "one bytecode edge at one instruction" (CallSite,
// ResolvedCallSite) and "field access" is the noun this project already uses for
// one of these (`CapabilityReport.total_field_accesses`,
// `ApiUsage.field_access_count`).
//
// It deliberately does NOT reuse CallSite's `caller_*` role prefix: an `iget`
// calls nothing, so spelling the accessor a "caller" would give one word two
// grammars — the defect dexllm#68/#69 exist to prevent. `method_descriptor` and
// `field_descriptor` are existing spellings with exactly these meanings
// (`ResolvedArg`, `TlsTrustComponent`).
struct FieldAccessSite {
    // The method that performs the access, and its dex-local identity. `dex_id` is
    // the dex of THAT METHOD — which is what makes `method_idx` meaningful, and
    // which may DIFFER from the dex declaring the field (a cross-dex reference;
    // the core aggregates a field's accessors into the declaring dex tagged with
    // their origin).
    std::string method_descriptor;         // "Lcom/x/Y;->foo(I)V"
    uint16_t dex_id = 0;
    uint32_t method_idx = 0;               // index into that dex's MethodIds
    std::string field_descriptor;          // "Lcom/x/Y;->name:Ltype;"
    // Byte offset within the method's `insns`, i.e. the same base
    // render_method_smali prints — NOT relative to the code_item struct.
    int32_t bytecode_offset = -1;
    // 0x52~0x6D — the whole `kIndexFieldRef` family. Says both the direction
    // (iget*/sget* read, iput*/sput* write) and whether the access is static,
    // without resolving the field.
    uint8_t opcode = 0;
};

// L1.5 — convenience summary of a single class, suitable for source-style
// rendering. Works for both internal and external classes:
//   - internal: declared in at least one loaded dex; full member list from
//     ClassDef + class_data
//   - external: declared in no loaded dex; member list reflects only the
//     entries observed across all dexes' MethodIds/FieldIds tables
//
// `access_flags` is EMPTY (nullopt -> Python None) when it is unknown, which is
// the case for every member of an external class: there is no class_data to read
// modifiers from. It must NOT be reported as 0 (dexllm#41) — in dex, 0 is a legal
// and common value meaning "package-private, non-static, non-final, …" (5.1% of
// methods / 8.7% of fields / 34.9% of classes in the test corpus), so a 0 default
// makes "unknown" indistinguishable from a real declaration and reads the whole
// framework surface as package-private.
//
// `class_descriptor` is the class the member is declared on (dexllm#69 §3). It is
// what makes a `*Info` able to produce the IDENTITY string every other
// method-shaped record already carries — `MethodRef.descriptor`,
// `ExternalMethodRef.descriptor` and `ClassSummary.descriptor` all have one and
// `*Info` was the only one without, so a caller reading `class_methods()` had to
// re-assemble `Lcls;->name(proto)ret` by hand. The joined form is NOT stored: the
// binding exposes it as a computed `descriptor` property, so the struct pays one
// string per member rather than two.
struct MethodInfo {
    std::string name;
    std::string proto;
    std::optional<uint32_t> access_flags;  // empty = unknown (external)
    std::string class_descriptor;          // "Lcom/x/Y;" — the declaring class
};
struct FieldInfo {
    std::string name;
    std::string type;
    std::optional<uint32_t> access_flags;  // empty = unknown (external)
    std::string class_descriptor;          // "Lcom/x/Y;" — the declaring class
};
struct ClassSummary {
    std::string descriptor;                // "Lcom/x/Y;"
    bool is_internal = false;              // declared in some loaded dex
    int16_t dex_id = -1;                   // -1 for external
    std::optional<uint32_t> access_flags;  // empty = unknown (external)
    std::string superclass_descriptor;     // empty for external / java.lang.Object
    std::vector<std::string> interface_descriptors;
    std::vector<FieldInfo> fields;
    std::vector<MethodInfo> methods;
    std::string source_file;               // empty if absent
};

// A LOCATED REFERENCE to a dex entity: an identity plus where it lives. The
// suffix names WHAT THE RECORD IS, never how it was obtained (dexllm#69 §2) —
// these were `*Match` because a `find_*` query produced them, which is
// provenance, and provenance was spelled three ways (`Match` / `Hit` /
// `Origin`) across the API. `External*Ref` keeps its suffix for the same reason:
// there the STATUS ("declared in no loaded dex") is carried by the `External`
// prefix, which is where a status belongs.
//
// The ordinal is `_idx`, the dex spec's own word for a position in a `*_ids`
// table; `dex_id` stays `_id` because a dex id is a handle dexllm assigns by
// load order, not a position in any dex structure (dexllm#69 §5).
struct ClassRef {
    std::string descriptor;
    uint16_t dex_id = 0;
    uint32_t class_idx = 0;
};

// Method identity. `descriptor` is upstream's full "Lpkg/Cls;->name(...)Ret;".
struct MethodRef {
    std::string descriptor;                 // upstream's dex_descriptor form
    uint16_t dex_id = 0;
    uint32_t method_idx = 0;
};

// Field identity, from upstream's FindField.
struct FieldRef {
    std::string descriptor;
    uint16_t dex_id = 0;
    uint32_t field_idx = 0;
};

// L4 — what a single invoke argument RESOLVES TO. `kind` selects which value field
// is meaningful. All values are resolved to user-facing forms (string content,
// Dalvik descriptors) on the C++ side so Python clients don't have to reach back
// into dex tables.
struct ResolvedArg {
    std::string kind;       // "ConstString", "ConstInt", "ConstWide",
                            // "ConstClass", "ConstNull", "FieldRead",
                            // "MethodReturn", "Parameter", "Unknown"
    uint16_t register_index = 0;
    std::string string_value;       // ConstString
    int64_t int_value = 0;          // ConstInt / ConstWide
    std::string class_descriptor;   // ConstClass
    std::string field_descriptor;   // FieldRead — "Lcls;->name:Type"
    std::string method_descriptor;  // MethodReturn — "Lcls;->name(args)Ret"
    int16_t parameter_index = -1;   // Parameter
    // Unknown only (dexllm#16): the register HAD a tracked definition that a
    // control-flow merge discarded — the paths carry different values (a genuinely
    // conditional argument) or the analyzer gave up (loop header / catch handler).
    // Distinguishes that from "never tracked" (arithmetic, aget, …), which is
    // Unknown with crossed_branch == false.
    bool crossed_branch = false;
};

// CallSite + per-argument origins. Inherits the L2/L2.5 fields and adds the
// L4 dataflow result.
struct ResolvedCallSite {
    uint16_t caller_dex_id = 0;
    uint32_t caller_method_idx = 0;
    std::string caller_descriptor;
    std::string callee_descriptor;
    int32_t bytecode_offset = -1;
    uint8_t invoke_opcode = 0;
    std::vector<ResolvedArg> args;
};

}  // namespace dexkit::ext
