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
//     That last clause RESTS ON A VENDOR DIVERGENCE: upstream slicer's
//     _checkFailed does log() + std::abort(), which no wrapper can contain. The
//     throw is dexllm's (divergence D1 in docs/dexkit-vendor-divergences.md),
//     and it predates the vendoring, so this totality guarantee is only as
//     durable as that patch surviving a rebase.
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
//   CheckMap          :738   — map ordering/bounds/alignment, required sections,
//                              the two fixed-size sections the HEADER does not
//                              describe (method_handle / call_site_id extents),
//                              and method_handle CONTENTS
//                              (VerifyMethodHandleSection = ART
//                              CheckIntraMethodHandleItem :1492 — dexllm#59 —
//                              PLUS a per-image memo and entry budget ART has no
//                              analogue for, docs/aosp-oob-divergences.md B2d.
//                              Deliberately not `==`, which this block uses for
//                              an exact port)
//   CheckIntraSection :2450  — per-item structure: ids, string_data(MUTF-8),
//                              type_list, class_def, class_data, code_item
//                              (VerifyCodeItem == ART CheckIntraCodeItem :1726),
//                              encoded_array/encoded_value (VerifyEncodedArrayAt
//                              == ART CheckEncodedArray :1225 — static_values_off),
//                              and the annotations subtree off annotations_off
//                              (VerifyAnnotationsDirectory == ART
//                              CheckIntraAnnotationsDirectoryItem :2111 +
//                              CheckIntraAnnotationItem :2056, fused with the
//                              offset-following of CheckInterAnnotationsDirectory
//                              Item :3276 — dexllm#56)
//   CheckInterSection :3477  — cross-refs: id ordering/uniqueness; descriptor
//                              syntax for EVERY type_id (CheckInterTypeIdItem
//                              :2735) as well as the field/method/class_def
//                              references to one; member-name validity;
//                              class_def semantics (see VerifyClassDefs); and
//                              EVERY class_data member's defining class
//                              (CheckClassDataDefiners == the definer half of
//                              ART CheckInterClassDataItem :3208 — dexllm#48).
//                              NOT ported from that ART function: member
//                              access-flag validation (CheckFieldAccessFlags /
//                              CheckMethodAccessFlags :934/:961),
//                              CheckStaticFieldTypes :1289, and the orphan
//                              class_data check ART gets by driving from the MAP
//                              where this port drives from class_defs.
//
//   ONE DELIBERATE DIVERGENCE — instruction-operand bounds (VerifyInsns, inside
//   VerifyCodeItem). ART's *structural* verifier does NOT check per-instruction
//   operands at all; that lives in the 6032-line *runtime* method_verifier.cc
//   (runtime/verifier/) — exactly the untraceable, runtime-coupled blob we
//   refuse to vendor. So VerifyInsns is NOT a dex_file_verifier port. It is OUR
//   bounded checker, anchored to the Dalvik bytecode spec via the slicer's
//   VerifyFlags/IndexType tables (dex_bytecode.h): per decoded instruction it
//   bounds-checks register operands (< registers_size), index operands (< the
//   id-table named by GetIndexTypeFromOpcode) and branch/switch/array-data
//   targets (in-bounds + aligned). The index half covers the kinds something
//   DEREFERENCES — string / type / field / method, and since dexllm#61
//   method-and-proto, because the invoke collectors began reading
//   invoke-polymorphic's operand; call_site / method_handle / proto are not
//   bounded here, and the rule for adding one is stated at the switch itself. This is the one spot where the verifier uses
//   slicer *logic* (DecodeInstruction/GetWidthFromBytecode), not just the
//   dex_format.h PODs — justified: hand-rolling a 256-opcode format table would
//   be larger AND less traceable than reusing the table the core already ships.
//   SCOPE LINE: layout/bounds only. Instruction *semantics* (type/dataflow
//   verification) are out of scope — that IS the runtime method verifier.
//   COUPLING TO WATCH (dexllm#58): reusing the slicer's decoder also inherits its
//   FIELD LAYOUT, and that layout is per-FORMAT, not per-flag. `Instruction::arg[]`
//   holds the argument registers for 35c, but for 45cc (invoke-polymorphic) it
//   ends with a second INDEX — proto@HHHH — while the first argument register
//   goes to vC. Reading arg[] uniformly for kVerifyVarArg therefore bounded a
//   proto index against registers_size (a spec-legal dex REJECTED, which is
//   strictly worse than any throw) and left vC bounded by nothing. A new operand
//   check must be read against dex_bytecode.cc's decode for EVERY format that
//   sets the flag, never against the flag's name.
//
// ── OUT OF SCOPE (stated so the boundary is discoverable, not a silent gap) ──
//   * Instruction type/dataflow semantics — runtime method_verifier, not ported.
//   * call_site CONTENTS. This line used to read "not dereferenced by the core",
//     which dexllm#67 made FALSE: modelling invoke-custom means the decompiler
//     resolves `call_site_ids[N]` and walks the encoded_array it points at
//     (`DexItemCodeSource::GetCallSite`), which transitively reads
//     method_handles / string_ids / proto_ids / type_ids. Its section EXTENT and
//     its 4-byte ALIGNMENT are still all this verifier checks — ART's
//     `CheckInterCallSiteIdItem` (the element-kind and index checks) is NOT
//     ported. The standing rule ("a consumer that starts reading one bounds it in
//     the same change, here or at the reader") is satisfied AT THE READER: every
//     offset, element kind and index inside is bounded there, and a failure
//     reports "unresolved" rather than a guess. That was not true until
//     dexllm#74 — the STRING arm alone guessed `""` for an out-of-table index,
//     which `GetCallSite` accepts, so a crafted name rendered the fabricated
//     `bsm(lookup(), "", methodType(Void.TYPE))` this file's own pristine-result
//     rule exists to prevent. Both reviewers found the sentence before the code
//     caught up with it. Porting the check would move
//     those from a silent skip to a load-time rejection; that is a new rejection
//     direction and needs its own a/b.
//   * method_handle — IN SCOPE as of dexllm#72: its extent, its alignment, its
//     entries' contents, and the encoded_value index INTO it are all checked.
//     What is still not applied to it is what is not applied to any data section
//     here — ART's CheckIntraSectionIterate rules (offset-0 rejection :2356 and
//     offset_to_type_map_), which belong to the map-driven intra pass this port
//     does not have; see the two bullets below. Kept here because the boundary
//     moved four times and the trail is the point. The bullet first read "call_site/method_handle —
//     not dereferenced by the core", which dexllm#57 made FALSE: implementing the
//     0x16 METHOD_HANDLE encoded_value means the core resolves a handle through
//     Reader::GetMethodHandle. Four commits closed it in pieces, each ART-anchored:
//       EXTENT  (:1493) — dexllm#57, in CheckMap. Without it ArrayView's index
//               check was against the map's own attacker-supplied count and read
//               past the file: a SIGSEGV on a verify()-valid dex.
//       ALIGN   (:798)  — dexllm#62, by restoring ART's own IsDataSectionType
//               (:82), which this port had returning false for both types.
//       CONTENTS(:1501/:1512/:1521) — dexllm#59, VerifyMethodHandleSection, also
//               in CheckMap (ART reaches it by iterating the map; this port has
//               no such pass, so the walk goes where the map item is in hand).
//       THE INDEX INTO IT (:1204 width cap + :1212 NumMethodHandles bound) —
//               dexllm#72, in VerifyEncodedValue's 0x16 arm, which now joins the
//               shared `idx` lambda. The count is not a header field, so CheckMap
//               carries it forward as method_handle_count_; it is 0 when the dex
//               declares no such section, which is ART's own value and therefore
//               rejects every 0x16 index there. That is what retired the vehicle
//               tests/test_cache_init_failure.py drove, on the belief — refuted by
//               ART — that closing it at the gate would be a false-reject.
//     ART's data_items_left budget stays unported on purpose
//     (docs/aosp-oob-divergences.md B2b).
//   * debug_info — dexllm never parses it; not verified by design.
//   * adler32 checksum — intentionally not verified (project policy; ART itself
//     only warns when verify_checksum=false — aosp-wiki dexfileverifier.md).
//   * ART's CheckIntraSectionIterate data-section rules (:2354) — a data-section
//     item at offset 0 is rejected (:2356) and every one is recorded in
//     offset_to_type_map_. Neither is ported: they belong to the map-driven intra
//     pass this port does not have (next bullet). dexllm#62 widened
//     IsDataSectionType to ART's own set, which does NOT bring these with it —
//     it only means ART applies them to three more types than we do.
//   * ART's offset_to_type_map_ / CheckOffsetToTypeMap (:2564) — NOT ported, and
//     the reason is structural rather than an omission: ART is MAP-driven (it
//     walks every section item by item and records offset -> map type, then
//     checks each reference against it), this port is REFERENCE-driven (it walks
//     from the header's tables and validates whatever each offset points AT).
//     The equivalent guarantee is therefore per-structure: every offset the core
//     dereferences — type_list, class_data, encoded_array, and since dexllm#56
//     the annotations subtree — is checked to decode as what its referrer claims
//     it is. What is genuinely lost is TYPE CONFUSION as a category: an offset
//     that happens to decode cleanly as the expected structure is accepted here
//     and rejected by ART.
//
//   ANNOTATIONS WERE ON THAT LIST UNTIL dexllm#56, and how they got off it is
//   the cautionary half. They were excused as "lazy-parsed by the core", which
//   was true and irrelevant: Reader::ExtractAnnotations runs off class_def.
//   annotations_off during cache init, so "lazy" meant "later", not "never", and
//   a 4-byte repoint of that offset produced a dex this gate called valid in
//   BOTH modes on which the slicer's ParseAnnotation walked off the end — a
//   SIGSEGV, which no catch(...) can contain. Combined with the paragraph above
//   the channel needed two omissions at once, so either one alone would have
//   blocked it. When adding a section to this list, the question is not whether
//   the core parses it EAGERLY; it is whether the core parses it AT ALL.
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
#include <map>
#include <string>
#include <utility>

namespace dexkit::ext {

struct DexVerifyResult {
    bool ok = true;
    std::string reason;  // empty when ok; first structural violation otherwise
};

// Verify ONE logical dex inside the image [data, data+size). `header_off` is
// where that dex's header sits in the image — 0 for a standalone dex or one
// classes*.dex extracted from an apk, nonzero for a later dex of a concatenated
// / packer-dump container or of a v41 multi-dex container. Never reads outside
// [data, data+size); never crashes.
//
// The image is passed WHOLE (rather than a pre-sliced sub-range) because the
// span a dex's offsets are relative to is not always the dex itself: a v41
// container dex addresses a data section SHARED with its siblings, so its base
// is the container. The verifier derives that span the way ART's
// DexFile::GetDataRange does — see ComputeDataRange.
//
// `check_insns` (default true) gates the ONE deliberate non-port: VerifyInsns
// (instruction-operand bounds), which ART's *structural* DexFileVerifier does not
// do. Set false for an "ART-structural-equivalent" pass that accepts a
// structurally-valid dex whose method bodies are garbage — e.g. a runtime-dumped,
// partially-decrypted dex from a packer, where only the currently-executing
// methods are decrypted. ART loads such a dex (it defers instruction validity to
// the runtime method_verifier, which packers skip); this lets the analyzer do the
// same WITHOUT relaxing any header/structure/bounds check.
// Per-IMAGE scratch, threaded across the slices of ONE image by
// ClassifyImageSlices (its only caller). It exists for one reason, and dexllm#59
// learned it the hard way: a v41 CONTAINER is verified once PER SLICE, with
// `size_` set to the whole container every time, so any per-slice walk of a
// SHARED section is paid once per sibling. Passing nullptr is safe — a lone
// VerifyDex call then gets a state of its own, which is exactly the one-slice
// case.
struct VerifyImageState {
    // The two numbers a walked method_handle section needs from its dex: the
    // SMALLEST field_ids_size and method_ids_size that accept every index in it
    // (i.e. one past the largest of each kind).
    struct HandleSectionNeeds {
        uint32_t field_ids;
        uint32_t method_ids;
    };
    // (offset, count) -> what that section needs. Keyed on the BYTES, not on the
    // dex that named them, which is what makes the memo work across the slices
    // of a v41 container: siblings have their own id tables, so a key carrying
    // those would miss on exactly the case this exists for (measured — it did,
    // and a legitimate 400-handle shared section was then rejected by the budget
    // below). The re-check for a later slice is O(1) and EXACTLY equivalent to
    // re-walking, because "every index < limit" is "max index < limit". This is
    // the dexllm#56 annotation memo one level up: the repetition is across
    // slices rather than across class_defs.
    std::map<std::pair<uint32_t, uint32_t>, HandleSectionNeeds> walked_method_handles;
    // Entries this image may still make the verifier walk. Seeded from the image
    // size, so the total is O(image/8) however the slices are arranged: real
    // sections occupy disjoint bytes, and a shared one is walked once thanks to
    // the memo above. Exhaustion is a rejection, and it is one a legitimate image
    // provably cannot reach.
    size_t method_handle_entries_left = 0;
};

DexVerifyResult VerifyDex(const uint8_t* data, size_t size, bool check_insns = true,
                          size_t header_off = 0, VerifyImageState* image = nullptr);

}  // namespace dexkit::ext
