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
};

}  // namespace dexkit::dad
