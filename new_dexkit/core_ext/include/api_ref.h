// api_ref.h — POD types for L1 external reference enumeration.

#pragma once

#include <cstdint>
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
    uint8_t invoke_opcode = 0;             // L2.5: 0x6E~0x72 family
};

// L1.5 — convenience summary of a single class, suitable for source-style
// rendering. Works for both internal and external classes:
//   - internal: declared in at least one loaded dex; full member list from
//     ClassDef + class_data
//   - external: declared in no loaded dex; member list reflects only the
//     entries observed across all dexes' MethodIds/FieldIds tables
struct ClassMemberMethod {
    std::string name;
    std::string proto;
    uint32_t access_flags = 0;             // 0 for external
};
struct ClassMemberField {
    std::string name;
    std::string type;
    uint32_t access_flags = 0;             // 0 for external
};
struct ClassSummary {
    std::string descriptor;                // "Lcom/x/Y;"
    bool is_internal = false;              // declared in some loaded dex
    int16_t dex_id = -1;                   // -1 for external
    uint32_t access_flags = 0;             // 0 for external
    std::string superclass_descriptor;     // empty for external / java.lang.Object
    std::vector<std::string> interface_descriptors;
    std::vector<ClassMemberField> fields;
    std::vector<ClassMemberMethod> methods;
    std::string source_file;               // empty if absent
};

// Find/Match result — lightweight class identity, matches what upstream's
// ClassMetaArrayHolder yields.
struct ClassMatch {
    std::string descriptor;
    uint16_t dex_id = 0;
    uint32_t class_id = 0;
};

// Find/Match result — method identity. dex_descriptor is upstream's full
// "Lpkg/Cls;->name(...)Ret;" form.
struct MethodMatch {
    std::string descriptor;                 // upstream's dex_descriptor form
    uint16_t dex_id = 0;
    uint32_t method_id = 0;
};

// Field match for upstream's FindField.
struct FieldMatch {
    std::string descriptor;
    uint16_t dex_id = 0;
    uint32_t field_id = 0;
};

// L4 — origin of a single invoke argument. `kind` selects which value field
// is meaningful. All values are resolved to user-facing forms (string content,
// descriptors, signatures) on the C++ side so Python clients don't have to
// reach back into dex tables.
struct ArgOrigin {
    std::string kind;       // "ConstString", "ConstInt", "ConstWide",
                            // "ConstClass", "ConstNull", "FieldRead",
                            // "MethodReturn", "Parameter", "Unknown"
    uint16_t reg_num = 0;
    std::string string_value;       // ConstString
    int64_t int_value = 0;          // ConstInt / ConstWide
    std::string class_descriptor;   // ConstClass
    std::string field_signature;    // FieldRead — "Lcls;->name:Type"
    std::string method_signature;   // MethodReturn — "Lcls;->name(args)Ret"
    int16_t parameter_index = -1;   // Parameter
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
    std::vector<ArgOrigin> args;
};

}  // namespace dexkit::ext
