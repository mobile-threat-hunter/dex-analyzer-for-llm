// dex_verifier.h — THE single safety contract for loading untrusted .dex images.
//
// ── WHY THIS FILE IS THE SINGLE SOURCE OF TRUTH ──────────────────────────────
// dexllm processes adversarial input (a malware analyst feeds it crafted dex).
// dexllm *parses/decompiles* dex, it never *executes* it, so the threat is a
// crash in the analyzer, not code execution. "Malformed dex must not crash
// dexllm" is the whole requirement. The danger of meeting it piecemeal is
// fragmentation: a maintainer hitting a malformed-dex crash has no findable
// answer to "where is this supposed to be caught, and what is guaranteed?".
// This header is that answer. Read THIS to understand the entire malformed-dex
// safety story; everything else is subordinate and pointed at from here.
//
// ── THE CONTRACT ─────────────────────────────────────────────────────────────
// `VerifyDex(data, size)` is the one load-time gate. DexKitExt (the production
// adapter, core_ext/dexkit_ext.cpp) calls it before the core parses ANY dex —
// raw .dex before AddImage, each classes*.dex before feeding the core. A reject
// throws with a human reason; siblings in an apk still load. Guarantees:
//   * VerifyDex is total on ANY input: it never reads outside [data, data+size),
//     never crashes, and never propagates an exception — every read goes through a
//     bounded primitive (CheckListSize / ReadUleb / OffsetToPtr+bounds / SafeWidth),
//     and the one slicer-logic call (the VerifyInsns decoder, which throws
//     SLICER_CHECK on malformed bytecode) is wrapped: any throw becomes a rejection.
//   * A dex that PASSES has valid structure for every section the core and the
//     decompile path dereference (see "covered" below) → no OOB in InitBaseCache
//     or the dad_cpp pipeline from structural malformation.
//   * Every reject carries a byte-level reason string (the first violation).
//
// ── PROVENANCE: mostly an ART port, one deliberate divergence ────────────────
// Structural phases are a 1:1 port of AOSP ART DexFileVerifier
// (art/libdexfile/dex/dex_file_verifier.cc — entry dex::Verify :3541), mirrored
// so coverage is auditable against ART. AOSP is the *spec reference*, NOT a
// runtime dependency (the opposite of vendoring ART verbatim — this is OUR
// readable code with `// ART :NNNN` anchors a maintainer can cross-check).
//   CheckHeader       :617   — magic/version/sizes/endian, section offset+size
//   CheckMap          :738   — map ordering/bounds/alignment, required sections
//   CheckIntraSection :2450  — per-item structure: ids, string_data(MUTF-8),
//                              type_list, class_def, class_data, code_item
//                              (VerifyCodeItem == ART CheckIntraCodeItem :1726),
//                              encoded_array/encoded_value (VerifyEncodedArrayAt
//                              == ART CheckEncodedArray :1225 — static_values_off)
//   CheckInterSection :3477  — cross-refs: id ordering/uniqueness; descriptor
//                              syntax + class_def semantics (see VerifyClassDefs)
//
//   ONE DELIBERATE DIVERGENCE — instruction-operand bounds (VerifyInsns, inside
//   VerifyCodeItem). ART's *structural* verifier does NOT check per-instruction
//   operands at all; that lives in the 6032-line *runtime* method_verifier.cc
//   (runtime/verifier/) — exactly the untraceable, runtime-coupled blob we
//   refuse to vendor. So VerifyInsns is NOT a dex_file_verifier port. It is OUR
//   bounded checker, anchored to the Dalvik bytecode spec via the slicer's
//   VerifyFlags/IndexType tables (dex_bytecode.h): per decoded instruction it
//   bounds-checks register operands (< registers_size), index operands (< the
//   id-table named by GetIndexTypeFromOpcode), and branch/switch/array-data
//   targets (in-bounds + aligned). This is the one spot where the verifier uses
//   slicer *logic* (DecodeInstruction/GetWidthFromBytecode), not just the
//   dex_format.h PODs — justified: hand-rolling a 256-opcode format table would
//   be larger AND less traceable than reusing the table the core already ships.
//   SCOPE LINE: layout/bounds only. Instruction *semantics* (type/dataflow
//   verification) are out of scope — that IS the runtime method verifier.
//
// ── OUT OF SCOPE (stated so the boundary is discoverable, not a silent gap) ──
//   * Instruction type/dataflow semantics — runtime method_verifier, not ported.
//   * annotations, call_site/method_handle — lazy-parsed by the core; left to the
//     guards below, not pre-verified. (encoded_array IS verified, see above.)
//   * debug_info — dexllm never parses it; not verified by design.
//   * adler32 checksum — intentionally not verified (project policy; ART itself
//     only warns when verify_checksum=false — aosp-wiki dexfileverifier.md).
//
// ── THE OTHER GUARDS: why each exists, and why none are redundant deletions ───
// VerifyDex is the single LOAD-TIME gate for malformed-dex *structure*. The guards
// elsewhere are NOT a second, fragmented copy of that — each serves a purpose the
// verifier does not, so deleting them would remove real protection (we audited
// this; the "just delete the redundant ones" intuition does not survive contact
// with what they actually guard). The honest taxonomy:
//
//  A. API-BOUNDARY guards — native/core_ext/dexitem_code_source.cpp inline
//     `if (idx >= table.size())` in GetMethodRefTriple / GetFieldRefTriple /
//     LocateMethod / GetProto* etc. These validate a CALLER-SUPPLIED index (search
//     APIs, the pybind layer, future callers), NOT the verified dex structure.
//     VerifyDex guarantees the dex's *internal* indices; it cannot guarantee what
//     an external caller passes. KEEP — removing couples every caller to "only
//     pass in-range indices" and reintroduces crashes unrelated to malformed dex.
//
//  B. SAFE-WRAPPER for an OOB-by-design API — native/dad_cpp/method_snapshot_
//     builder.cpp SafeWidth wraps dex::GetWidthFromBytecode, which OOB-reads a
//     truncated payload header by construction. This is not "re-validating the
//     verifier" — it is the only thing that makes calling that slicer function
//     safe at all. KEEP.
//
//  C. DATAFLOW guard the verifier structurally cannot replace —
//     native/dad_cpp/instruction.cpp:274 IR null-guard on move-result with no
//     preceding invoke. Whether an invoke reaches a move-result is a DATAFLOW
//     property, not byte structure; ART checks it only in the 6032-line runtime
//     method_verifier we deliberately do not vendor. KEEP (irreducibly primary).
//
//  D. CHEAP REDUNDANT belt — dexitem SafeAt() on already-verified dex contents
//     (field/method/type/superclass indices that CheckIntra/InterSection validate)
//     and builder branch/payload bounds (VerifyInsns now validates). These ARE
//     redundant with the verifier. We keep them anyway: they cost nothing, they
//     are the net that catches a hand-rolled-verifier false-accept (the verifier
//     is fuzz- and corpus-validated, not proven), and deleting them would couple
//     decode-path memory-safety to the non-local "VerifyDex always ran first"
//     invariant. Discoverability — the user's actual concern — is satisfied by
//     THIS file documenting them, not by physically deleting them.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dexkit::ext {

struct DexVerifyResult {
    bool ok = true;
    std::string reason;  // empty when ok; first structural violation otherwise
};

// Verify one logical dex image [data, data+size). Offsets in the dex are taken
// relative to `data` (a standard v35–40 dex, or one classes*.dex extracted from
// an apk). Never reads outside [data, data+size); never crashes.
//
// `check_insns` (default true) gates the ONE deliberate non-port: VerifyInsns
// (instruction-operand bounds), which ART's *structural* DexFileVerifier does not
// do. Set false for an "ART-structural-equivalent" pass that accepts a
// structurally-valid dex whose method bodies are garbage — e.g. a runtime-dumped,
// partially-decrypted dex from a packer, where only the currently-executing
// methods are decrypted. ART loads such a dex (it defers instruction validity to
// the runtime method_verifier, which packers skip); this lets the analyzer do the
// same WITHOUT relaxing any header/structure/bounds check.
DexVerifyResult VerifyDex(const uint8_t* data, size_t size, bool check_insns = true);

}  // namespace dexkit::ext
