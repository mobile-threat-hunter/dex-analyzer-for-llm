// dex_code_source.h — pure interface between DexKit (data source) and
// DexKit-DAD (decompiler). The decompiler holds an `IDexCodeSource&` and
// queries only via the methods declared here. Implementations (production
// `DexItemCodeSource` in core_ext, `MockCodeSource` in tests) bridge to the
// underlying dex parser.
//
// LIFETIME CONTRACT: any `std::string_view` returned by this interface MUST
// remain valid for the lifetime of the implementation object. In production
// (`DexItemCodeSource`) views point into DexItem's string tables which live
// for the DexKit process lifetime — strictly longer than any MethodSnapshot.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Forward-declare slicer's dex::Code to avoid pulling its full header into
// the public interface. Implementations include the real header.
namespace dex { struct Code; }

namespace dexkit::dad {

class IDexCodeSource {
public:
    virtual ~IDexCodeSource() = default;

    // ─── Method metadata ─────────────────────────────────────────────────
    virtual uint32_t           GetMethodAccessFlags(uint16_t dex_id,
                                                    uint32_t method_idx) = 0;
    // Smali descriptor: "Lcom/X;"
    virtual std::string_view   GetMethodClassName(uint16_t dex_id,
                                                  uint32_t method_idx) = 0;
    virtual std::string_view   GetMethodName(uint16_t dex_id,
                                             uint32_t method_idx) = 0;
    // Raw proto: "(IL...)V" — caller splits return type internally.
    virtual std::string        GetMethodProto(uint16_t dex_id,
                                              uint32_t method_idx) = 0;

    // ─── Code item ───────────────────────────────────────────────────────
    // Returns nullptr if method has no code (native / abstract).
    virtual const dex::Code*   GetMethodCode(uint16_t dex_id,
                                             uint32_t method_idx) = 0;

    // Absolute [begin, end) of the mmap'd dex image backing `dex_id`. Used to
    // bound raw reads (exception tables) against malformed/crafted input. The
    // default {nullptr, nullptr} means "bounds unknown" (callers fall back to a
    // conservative local cap). Production/test sources override this.
    virtual std::pair<const uint8_t*, const uint8_t*>
    GetDexImageRange(uint16_t /*dex_id*/) { return {nullptr, nullptr}; }

    // ─── Class-hierarchy assignability (for sound type inference) ────────
    // True iff a value of type `sub` (Smali descriptor) is assignable to a
    // variable of type `super` — `sub <: super` in the Java subtype lattice
    // (equality, superclass chain, and transitively-implemented interfaces;
    // any reference is assignable to `Ljava/lang/Object;`; array covariance is
    // NOT modelled — array descriptors compare by equality). The default is the
    // CONSERVATIVE exact-equality fallback (`sub == super`): a source without a
    // class hierarchy (the test Mock) reports only the trivially-true case, so a
    // caller using this to *widen* what it accepts (vs. exact match) stays sound.
    // The production DexItemCodeSource overrides it with a real dex-hierarchy
    // walk. It is a PARTIAL oracle: a subtype relationship that transits a class
    // NOT present in the loaded dex (a framework chain, e.g. ArrayList <: List)
    // cannot be proven and returns false — callers must treat false as "unknown,
    // be conservative", never as a proof of non-assignability.
    virtual bool IsAssignable(std::string_view sub, std::string_view super) {
        return sub == super;
    }

    // ─── Const-pool resolution (string_views point into source's tables) ─
    virtual std::string_view   GetString(uint16_t dex_id, uint32_t idx) = 0;
    virtual std::string_view   GetTypeName(uint16_t dex_id, uint32_t idx) = 0;
    // Returns (class_descriptor, name, proto). Class is in Smali form
    // ("Lcom/X;"), proto is the full descriptor "(I)V".
    virtual std::array<std::string_view, 3>
                               GetMethodRefTriple(uint16_t dex_id,
                                                  uint32_t method_idx) = 0;
    // Returns (class_descriptor, name, type).
    virtual std::array<std::string_view, 3>
                               GetFieldRefTriple(uint16_t dex_id,
                                                 uint32_t field_idx) = 0;

    // ─── Lookup helpers (Decompiler façade) ─────────────────────────────
    struct MethodLocator { uint16_t dex_id; uint32_t method_idx; };
    // Resolve "Lcom/X;->name(proto)Ret" to (dex_id, method_idx).
    // Default returns nullopt (override in production source).
    virtual std::optional<MethodLocator>
    LocateMethod(std::string_view /*descriptor*/) { return std::nullopt; }
    // Enumerate all methods of a class. Default returns empty.
    virtual std::vector<MethodLocator>
    LocateClassMethods(std::string_view /*class_descriptor*/) { return {}; }

    // ─── Class metadata (for DvClass-style full-class decompile) ────────
    // DAD: decompile.py:258 DvClass.__init__ — supplies package, access,
    // superclass, interfaces, field list at class header emission time.
    struct ClassInfo {
        uint16_t                      dex_id = 0;
        uint32_t                      type_idx = 0;
        uint32_t                      access_flags = 0;     // raw dex access
        std::string_view              superclass;           // Smali "Ljava/lang/Object;" or empty
        std::vector<std::string_view> interfaces;           // Smali descriptors
        std::vector<uint32_t>         field_ids;            // per-class field_idxs
        // Parallel to field_ids — pre-rendered initializer RHS for static
        // fields that have an EncodedValue in static_values_off (e.g. "2",
        // "\"foo\"", "0x2a"). Empty string means no compile-time initializer
        // (the field will be emitted as `Type name;`). Always same size as
        // field_ids; non-static fields and unsupported value types stay empty.
        std::vector<std::string>      field_init_texts;
    };
    // Default returns nullopt — override in production source.
    virtual std::optional<ClassInfo>
    GetClassInfo(std::string_view /*class_descriptor*/) { return std::nullopt; }

    // ─── Field metadata (for class field declaration emit) ──────────────
    // DAD: decompile.py:354 DvClass.get_source — needs name + type + access
    // + optional initializer. init_text is the already-rendered RHS of the
    // declaration (`"foo"`, `42`, `0x2a`, `null`, …) or empty if no
    // EncodedValue / unsupported value type.
    struct FieldInfo {
        std::string_view name;
        std::string_view type;          // Smali descriptor "Ljava/lang/String;" / "I" / …
        uint32_t         access_flags = 0;
        std::string      init_text;     // empty when no compile-time initializer
    };
    virtual FieldInfo GetFieldInfo(uint16_t /*dex_id*/, uint32_t /*field_idx*/) {
        return {};
    }
};

}  // namespace dexkit::dad
