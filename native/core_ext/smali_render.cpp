// dexllm — see smali_render.h for why this is not in the vendored tree.

#include "smali_render.h"

#include <cstdio>
#include <sstream>
#include <vector>

#include "dex_item.h"

#include "mutf8.h"
#include "slicer/dex_bytecode.h"
#include "slicer/dex_format.h"
#include "utils/opcode_util.h"

namespace dexkit::ext {

namespace {

// Escape a string literal for smali display (similar to baksmali rules).
// dexllm#22: DECODE the dex MUTF-8 first, then escape CHARACTERS.
//
// This used to escape raw BYTES, which is unsound for two reasons:
//
//  1. INJECTION. A non-NUL OVERLONG sequence was accepted by the structural
//     verifier (VerifyMutf8 checked lead/continuation shape only, believed to
//     match ART — it did NOT; dexllm#22 later ported ART's "Illegal
//     representation" check, so such a dex no longer loads and this escaping is
//     now defence in depth), and `C0 A2` decodes to `"`,
//     `C1 9C` to `\`, `C0 8A` to a newline. Escaping the BYTES let those through
//     untouched, so whoever decoded the assembled text afterwards MATERIALISED a
//     structural character inside the quoted literal — terminating it early or
//     forging an entire instruction line. The rendered listing is fed to an
//     analyst / LLM, so an analysed (hostile) app could write into that view.
//  2. Nothing decoded it at all, so a literal holding a surrogate pair
//     (supplementary-plane char) or an embedded NUL (`C0 80`) reached pybind's
//     strict-UTF-8 str conversion as raw bytes and RAISED UnicodeDecodeError —
//     29 of 201,079 methods and 25 of 26,938 classes in the bundled corpus.
//
// Escaping the DECODED characters fixes both at the origin: a decoded `"` is
// escaped like any other, and `C0 80` becomes `\x00` like every other control
// character instead of a raw NUL in the text.
//
// Decode semantics match the binding's DecodeMutf8ForPy so a rendered literal
// and list_method_strings() agree: a surrogate PAIR becomes one code point, a
// LONE surrogate collapses to U+FFFD (it has no UTF-8 form).
std::string EscapeSmaliString(std::string_view in) {
    std::string out;
    out.reserve(in.size() + 2);
    const std::vector<uint16_t> units = dexkit::dad::mutf8::Mutf8ToUtf16(in);
    for (size_t i = 0; i < units.size(); ++i) {
        uint32_t cp = units[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units.size() &&
            units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (units[i + 1] - 0xDC00);
            ++i;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;  // lone surrogate — no UTF-8 form
        }
        switch (cp) {
            case '\\': out += "\\\\"; continue;
            case '"':  out += "\\\""; continue;
            case '\n': out += "\\n";  continue;
            case '\r': out += "\\r";  continue;
            case '\t': out += "\\t";  continue;
            default: break;
        }
        if (cp < 0x20) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\x%02x", static_cast<unsigned>(cp));
            out += buf;
        } else if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

// dexllm#22 — an IDENTIFIER (type descriptor, member name) is pool MUTF-8 just
// like a literal is, so it needs the same decode before it enters the assembled
// listing. Without it a class or member carrying a supplementary-plane character
// (a surrogate PAIR in the pool — the verifier explicitly permits one in a name)
// reached pybind's strict UTF-8 str conversion as raw bytes and RAISED, so the
// method could not be rendered at all.
//
// Decoded, not escaped: an identifier is unquoted in smali, and after dexllm#23
// (every type_id descriptor is now syntax-checked, joining the member names that
// always were) a loadable dex cannot carry a structural character in one — the
// validity check runs on the DECODED code points, so an overlong that would
// decode to `"` or a newline is rejected at load, not rendered here.
std::string SmaliIdent(std::string_view raw) {
    return dexkit::dad::mutf8::Mutf8ToUtf8Lossy(raw);
}

// Format access flags into smali keyword sequence (subset relevant to fields
// and methods, e.g. "public static final ").
std::string FormatAccessFlags(uint32_t flags) {
    std::string out;
    if (flags & dex::kAccPublic)        out += "public ";
    if (flags & dex::kAccPrivate)       out += "private ";
    if (flags & dex::kAccProtected)     out += "protected ";
    if (flags & dex::kAccStatic)        out += "static ";
    if (flags & dex::kAccFinal)         out += "final ";
    if (flags & dex::kAccSynchronized)  out += "synchronized ";
    if (flags & dex::kAccVolatile)      out += "volatile ";
    if (flags & dex::kAccBridge)        out += "bridge ";
    if (flags & dex::kAccTransient)     out += "transient ";
    if (flags & dex::kAccVarargs)       out += "varargs ";
    if (flags & dex::kAccNative)        out += "native ";
    if (flags & dex::kAccInterface)     out += "interface ";
    if (flags & dex::kAccAbstract)      out += "abstract ";
    if (flags & dex::kAccStrict)        out += "strict ";
    if (flags & dex::kAccSynthetic)     out += "synthetic ";
    if (flags & dex::kAccAnnotation)    out += "annotation ";
    if (flags & dex::kAccEnum)          out += "enum ";
    if (flags & dex::kAccConstructor)   out += "constructor ";
    // dexllm: method flags now reach these formatters as the RAW dex bits (the
    // upstream 0x20000 → 0x20 rewrite was removed, see dex_item.h), so a Java
    // `synchronized` method arrives as kAccDeclaredSynchronized and would
    // otherwise render with no modifier at all.
    if (flags & dex::kAccDeclaredSynchronized) out += "declared_synchronized ";
    return out;
}

// Context-specific formatters. Dalvik's flag bits 0x40/0x80 are RE-USED
// across field/method (volatile/transient vs bridge/varargs) — render only
// the relevant subset for each.
std::string FormatFieldAccessFlags(uint32_t flags) {
    std::string out;
    if (flags & dex::kAccPublic)     out += "public ";
    if (flags & dex::kAccPrivate)    out += "private ";
    if (flags & dex::kAccProtected)  out += "protected ";
    if (flags & dex::kAccStatic)     out += "static ";
    if (flags & dex::kAccFinal)      out += "final ";
    if (flags & dex::kAccVolatile)   out += "volatile ";
    if (flags & dex::kAccTransient)  out += "transient ";
    if (flags & dex::kAccSynthetic)  out += "synthetic ";
    if (flags & dex::kAccEnum)       out += "enum ";
    return out;
}

std::string FormatMethodAccessFlags(uint32_t flags) {
    std::string out;
    if (flags & dex::kAccPublic)        out += "public ";
    if (flags & dex::kAccPrivate)       out += "private ";
    if (flags & dex::kAccProtected)     out += "protected ";
    if (flags & dex::kAccStatic)        out += "static ";
    if (flags & dex::kAccFinal)         out += "final ";
    if (flags & dex::kAccSynchronized)  out += "synchronized ";
    if (flags & dex::kAccBridge)        out += "bridge ";
    if (flags & dex::kAccVarargs)       out += "varargs ";
    if (flags & dex::kAccNative)        out += "native ";
    if (flags & dex::kAccAbstract)      out += "abstract ";
    if (flags & dex::kAccStrict)        out += "strict ";
    if (flags & dex::kAccSynthetic)     out += "synthetic ";
    // dexllm: see FormatAccessFlags — raw bits, so declared_synchronized must
    // be rendered explicitly or a `synchronized` method loses its modifier.
    if (flags & dex::kAccDeclaredSynchronized) out += "declared_synchronized ";
    return out;
}

// dexllm#60: format one proto as "(params)Ret". Factored out of FormatMethodRef
// because invoke-polymorphic renders a proto that belongs to no method_id — its
// HHHH operand is a proto_ids index naming the CALL SITE's signature, which for a
// signature-polymorphic method differs from the method_id's own descriptor.
std::string FormatProto(const dex::Reader& reader,
                        const std::vector<std::string_view>& type_names,
                        uint32_t proto_idx) {
    if (proto_idx >= reader.ProtoIds().size()) return "<bad-proto-idx>";
    const auto& proto = reader.ProtoIds()[proto_idx];
    std::string out = "(";
    if (proto.parameters_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(proto.parameters_off);
        if (type_list != nullptr) {
            for (uint32_t i = 0; i < type_list->size; ++i) {
                out += SmaliIdent(type_names[type_list->list[i].type_idx]);
            }
        }
    }
    out += ')';
    out += SmaliIdent(type_names[proto.return_type_idx]);
    return out;
}

// Format a method's full smali ref: "Lcls;->name(args)Ret".
std::string FormatMethodRef(const dex::Reader& reader,
                            const std::vector<std::string_view>& type_names,
                            const std::vector<std::string_view>& strings,
                            uint32_t method_idx) {
    if (method_idx >= reader.MethodIds().size()) return "<bad-method-idx>";
    const auto& m = reader.MethodIds()[method_idx];
    std::string out;
    out += SmaliIdent(type_names[m.class_idx]);
    out += "->";
    out += SmaliIdent(strings[m.name_idx]);
    out += FormatProto(reader, type_names, m.proto_idx);
    return out;
}

// Format a field's full smali ref: "Lcls;->name:Type".
std::string FormatFieldRef(const dex::Reader& reader,
                           const std::vector<std::string_view>& type_names,
                           const std::vector<std::string_view>& strings,
                           uint32_t field_idx) {
    if (field_idx >= reader.FieldIds().size()) return "<bad-field-idx>";
    const auto& f = reader.FieldIds()[field_idx];
    std::string out;
    out += SmaliIdent(type_names[f.class_idx]);
    out += "->";
    out += SmaliIdent(strings[f.name_idx]);
    out += ':';
    out += SmaliIdent(type_names[f.type_idx]);
    return out;
}

// Render a range-invoke's register window. A 0-count range would underflow
// `first + count - 1` and print `{v0 .. v4294967295}`; VerifyInsns' range branch
// is guarded on `d.vA > 0`, so such a dex verifies valid and reaches here.
void EmitRegisterRange(std::ostringstream& o, uint32_t first, uint32_t count) {
    if (count == 0) {
        o << "{}";
        return;
    }
    o << "{v" << first << " .. v" << (first + count - 1) << "}";
}

// Render the operand portion of one instruction based on its format and
// index type. The opcode mnemonic is emitted by the caller; this fills in
// what follows after a single space.
std::string FormatOperands(const dex::Instruction& insn,
                           const dex::Reader& reader,
                           const std::vector<std::string_view>& type_names,
                           const std::vector<std::string_view>& strings) {
    using namespace dex;
    InstructionFormat fmt = GetFormatFromOpcode(insn.opcode);
    InstructionIndexType idx = GetIndexTypeFromOpcode(insn.opcode);
    std::ostringstream o;

    auto emit_index = [&](uint32_t v) {
        switch (idx) {
            case kIndexStringRef:
                if (v < strings.size()) {
                    o << "\"" << EscapeSmaliString(strings[v]) << "\"";
                } else o << "string@" << v;
                break;
            case kIndexTypeRef:
                if (v < type_names.size()) o << SmaliIdent(type_names[v]);
                else o << "type@" << v;
                break;
            case kIndexFieldRef:
                o << FormatFieldRef(reader, type_names, strings, v);
                break;
            case kIndexMethodRef:
            case kIndexMethodAndProtoRef:  // dexllm#60 — BBBB half; the proto
                                           // (HHHH) is emitted by the k45cc /
                                           // k4rcc arms, which own that operand
                o << FormatMethodRef(reader, type_names, strings, v);
                break;
            // dexllm#66 — five kinds used to fall to `default:` and render a bare
            // `@N`, which does not even say what table N indexes. The listing is a
            // primary output, so `@0` is strictly less informative than
            // `call_site@0` for the same reason `<unhandled-fmt-N>` was.
            case kIndexProtoRef:
                // const-method-type. FULLY resolvable — its operand is a proto_ids
                // index, the same thing invoke-polymorphic's HHHH is, so the
                // FormatProto dexllm#60 factored out renders it exactly as AOSP
                // dexdump does. FormatProto owns the bound and yields
                // `<bad-proto-idx>`, which is why this reader needs no gate change:
                // the verifier's rule is "bounded here or AT THE READER", and this
                // is the only reader (ResolveConstRef returns monostate for 0xFF).
                o << FormatProto(reader, type_names, v);
                break;
            case kIndexMethodHandleRef:  // const-method-handle
                // A LABEL, not a resolution. Resolving it needs a kind→text mapping
                // over Reader::MethodHandles(); AOSP dexdump does not resolve it
                // either ("too large to detail in disassembly"). Nothing
                // DEREFERENCES the index here, so the gate's "nothing reads them"
                // still holds for this kind and for the call site below.
                o << "method_handle@" << v;
                break;
            case kIndexCallSiteRef:  // invoke-custom[/range]
                o << "call_site@" << v;
                break;
            // The two ODEX quick kinds. Modern ART deleted them (0xE3-0xF2 are
            // `unused-e3` there, and its dexdump has no arm for them), but the
            // VENDORED slicer table still names all 16 opcodes and that table is
            // what this decoder consults — so they are named opcodes here and the
            // index-kind invariant covers them. Their operand is an OFFSET, not an
            // index into any table, which makes a bare `@N` not merely uninformative
            // but wrong: it reads as an id. Reachable on a STRICT-verified dex —
            // VerifyInsns bounds registers and indices and has no opcode-legality
            // gate (there is none in ART's structural verifier either), so an
            // odex-derived packer dump carries them; see dexllm#32, which handles
            // the same opcodes in the argument analyzer for the same reason.
            case kIndexFieldOffset:   // iget/iput-*-quick
                o << "field_off@" << v;
                break;
            case kIndexVtableOffset:  // invoke-virtual[/range]-quick
                o << "vtable@" << v;
                break;
            default:
                // Unreachable for a named opcode once the five above are handled:
                // what is left is kIndexNone (emit_index is never called),
                // kIndexUnknown (the 15 `unused-*` rows) and kIndexVaries /
                // kIndexInlineMethod, which no row in the table uses. Kept as a
                // defence; the SOURCE guard is what fails closed on a future kind.
                o << "@" << v;
                break;
        }
    };

    switch (fmt) {
        case k10x: break;
        case k11n:  // const/4 vA, #+B (B is signed 4-bit)
            o << "v" << insn.vA << ", #" << static_cast<int32_t>(insn.vB); break;
        case k11x:
            o << "v" << insn.vA; break;
        case k12x:
            o << "v" << insn.vA << ", v" << insn.vB; break;
        case k10t:
        case k20t:
        case k30t:
            o << "+" << static_cast<int32_t>(insn.vA); break;
        case k21h:
            o << "v" << insn.vA << ", #0x" << std::hex << insn.vB << std::dec; break;
        case k21s:
            o << "v" << insn.vA << ", #" << static_cast<int32_t>(insn.vB); break;
        case k21t:
            o << "v" << insn.vA << ", +" << static_cast<int32_t>(insn.vB); break;
        case k21c:
            o << "v" << insn.vA << ", ";
            emit_index(insn.vB);
            break;
        case k22b:
            o << "v" << insn.vA << ", v" << insn.vB << ", #" << static_cast<int32_t>(insn.vC); break;
        case k22s:
            o << "v" << insn.vA << ", v" << insn.vB << ", #" << static_cast<int32_t>(insn.vC); break;
        case k22t:
            o << "v" << insn.vA << ", v" << insn.vB << ", +" << static_cast<int32_t>(insn.vC); break;
        case k22x:
            o << "v" << insn.vA << ", v" << insn.vB; break;
        case k22c:
            o << "v" << insn.vA << ", v" << insn.vB << ", ";
            emit_index(insn.vC);
            break;
        case k23x:
            o << "v" << insn.vA << ", v" << insn.vB << ", v" << insn.vC; break;
        case k31i:
            o << "v" << insn.vA << ", #" << static_cast<int32_t>(insn.vB); break;
        case k31t:
            o << "v" << insn.vA << ", +" << static_cast<int32_t>(insn.vB); break;
        case k31c:
            o << "v" << insn.vA << ", ";
            emit_index(insn.vB);
            break;
        case k32x:
            o << "v" << insn.vA << ", v" << insn.vB; break;
        case k35c: {
            o << "{";
            uint32_t cnt = insn.vA;
            for (uint32_t i = 0; i < cnt; ++i) {
                if (i) o << ", ";
                o << "v" << insn.arg[i];
            }
            o << "}, ";
            emit_index(insn.vB);
            break;
        }
        case k3rc: {
            EmitRegisterRange(o, insn.vC, insn.vA);
            o << ", ";
            emit_index(insn.vB);
            break;
        }
        // dexllm#60: invoke-polymorphic {vC, vD..vG}, meth@BBBB, proto@HHHH.
        // NOTE the register set differs from k35c even though the raw bytes do
        // not: slicer's DecodeInstruction puts C in `vC` and D..G in arg[0..3]
        // for k45cc, where k35c puts C..G in arg[0..4]. Reading arg[0..4] here
        // would emit the proto index as a register.
        case k45cc: {
            // CLAMP to 5. `insn.arg` is `u4 arg[5]` and vA is a 4-bit nibble, so
            // vA >= 6 indexes past the array — into the struct's own `opcode`
            // field and then off the end of a STACK object, printing process
            // addresses into the listing and making the render non-deterministic.
            // The k35c arm above needs no clamp for a different reason, not by
            // luck: slicer's DecodeInstruction ends its 35c count switch in
            // `SLICER_CHECK(!"Invalid arg count")`, so a >5 count throws before
            // this code runs. k45cc has NO such check, and VerifyInsns' own vararg
            // loop CLAMPS (`k < d.vA && k < 5`) rather than rejecting — so a dex
            // with vA = 15 here verifies VALID. 5 is exactly what the verifier
            // guarantees, which is why it is the bound. (Found by review; the
            // unclamped form leaked stack contents on a `verify()`-valid dex.)
            o << "{";
            for (uint32_t i = 0; i < insn.vA && i < 5; ++i) {
                if (i) o << ", ";
                o << "v" << (i == 0 ? insn.vC : insn.arg[i - 1]);
            }
            o << "}, ";
            emit_index(insn.vB);
            o << ", " << FormatProto(reader, type_names, insn.arg[4]);
            break;
        }
        case k4rcc: {
            // vA == 0 would underflow `vC + vA - 1`. VerifyInsns' range branch is
            // `if (d.vA > 0 && ...)`, so a 0-count range invoke verifies valid;
            // the k3rc arm above has the same expression and the same hole, and it
            // is corrected there too rather than left as the thing this one was
            // copied from. Output-only (no OOB), 0 corpus impact.
            EmitRegisterRange(o, insn.vC, insn.vA);
            o << ", ";
            emit_index(insn.vB);
            o << ", " << FormatProto(reader, type_names, insn.arg[4]);
            break;
        }
        case k51l:
            o << "v" << insn.vA << ", #" << static_cast<int64_t>(insn.vB_wide) << "L"; break;
        default:
            o << "<unhandled-fmt-" << static_cast<int>(fmt) << ">"; break;
    }
    return o.str();
}

}  // namespace

std::string RenderMethodSmali(const DexItem& item, uint32_t method_idx,
                              const std::string& indent) {
    if (method_idx >= item.GetReader().MethodIds().size()) return {};
    const dex::Code* code = item.GetMethodCode(method_idx);

    std::ostringstream out;
    out << FormatMethodRef(item.GetReader(), item.GetTypeNames(), item.GetStrings(), method_idx) << "\n";
    if (code == nullptr) {
        out << indent << "# (no code item)\n";
        return out.str();
    }
    out << indent << ".registers " << code->registers_size << "\n";

    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;
    while (p < end_p) {
        size_t width = dex::GetWidthFromBytecode(p);
        if (width == 0) break;
        dex::Instruction insn = dex::DecodeInstruction(p);
        uint32_t byte_off = static_cast<uint32_t>((p - base) * 2);
        const char* name = dex::GetOpcodeName(insn.opcode);
        out << indent << "0x" << std::hex << byte_off << std::dec
            << ": " << name;
        std::string ops = FormatOperands(insn, item.GetReader(), item.GetTypeNames(), item.GetStrings());
        if (!ops.empty()) out << " " << ops;
        out << "\n";
        p += width;
    }
    return out.str();
}


std::string RenderClassSmali(const DexItem& item, uint32_t type_idx) {
    if (type_idx >= item.GetTypeNames().size()) return {};
    if (!item.GetTypeDefFlags()[type_idx]) return {};
    const auto& class_def = item.GetReader().ClassDefs()[item.GetTypeDefIdx(type_idx)];

    std::ostringstream out;
    out << ".class " << FormatAccessFlags(class_def.access_flags)
        << SmaliIdent(item.GetTypeNames()[type_idx]) << "\n";
    out << ".super " << SmaliIdent(item.GetTypeNames()[class_def.superclass_idx]) << "\n";
    if (class_def.source_file_idx != dex::kNoIndex) {
        out << ".source \""
            << EscapeSmaliString(item.GetStrings()[class_def.source_file_idx])
            << "\"\n";
    }
    if (class_def.interfaces_off != 0) {
        const auto* il = item.GetReader().dataPtr<dex::TypeList>(class_def.interfaces_off);
        if (il != nullptr) {
            for (uint32_t i = 0; i < il->size; ++i) {
                out << ".implements " << SmaliIdent(item.GetTypeNames()[il->list[i].type_idx])
                    << "\n";
            }
        }
    }
    out << "\n";

    // dexllm #45: `class_field_ids` is keyed on the whole `field_ids` table, so it
    // also holds INHERITED fields this class only REFERENCES. baksmali emits a
    // `.field` line only for a class's own class_data entries, so emit only those
    // — `item.GetFieldAccessFlagsDeclared()` marks exactly them (#41).
    bool any_field = false;
    for (uint32_t field_idx : item.GetClassFieldIds(type_idx)) {
        if (field_idx >= item.GetFieldAccessFlagsDeclared().size() ||
            !item.GetFieldAccessFlagsDeclared()[field_idx]) {
            continue;
        }
        const auto& f = item.GetReader().FieldIds()[field_idx];
        out << ".field "
            << SmaliIdent(item.GetStrings()[f.name_idx])
            << ":" << SmaliIdent(item.GetTypeNames()[f.type_idx]) << "\n";
        any_field = true;
    }
    if (any_field) out << "\n";

    for (uint32_t m_idx : item.GetClassMethodIds(type_idx)) {
        out << ".method "
            << FormatMethodRef(item.GetReader(), item.GetTypeNames(), item.GetStrings(), m_idx) << "\n";
        const dex::Code* code = item.GetMethodCode(m_idx);
        if (code == nullptr) {
            out << "    # (no code item)\n";
        } else {
            out << "    .registers " << code->registers_size << "\n";
            const dex::u2* base = code->insns;
            const dex::u2* p = base;
            const dex::u2* end_p = base + code->insns_size;
            while (p < end_p) {
                size_t width = dex::GetWidthFromBytecode(p);
                if (width == 0) break;
                dex::Instruction insn = dex::DecodeInstruction(p);
                uint32_t byte_off = static_cast<uint32_t>((p - base) * 2);
                const char* name = dex::GetOpcodeName(insn.opcode);
                out << "    0x" << std::hex << byte_off << std::dec
                    << ": " << name;
                std::string ops = FormatOperands(insn, item.GetReader(), item.GetTypeNames(), item.GetStrings());
                if (!ops.empty()) out << " " << ops;
                out << "\n";
                p += width;
            }
        }
        out << ".end method\n\n";
    }

    return out.str();
}


}  // namespace dexkit::ext
