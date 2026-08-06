// DexKit - An high-performance runtime parsing library for dex
// implemented in C++.
// Copyright (C) 2022-2023 LuckyPray
// https://github.com/LuckyPray/DexKit
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see
// <https://www.gnu.org/licenses/>.
// <https://github.com/LuckyPray/DexKit/blob/master/LICENSE>.

#include "dex_item.h"

#include <unordered_set>

#include "utils/byte_code_util.h"
#include "utils/opcode_util.h"
#include "utils/dex_descriptor_util.h"

// dexllm#22: the shared ART-faithful MUTF-8 codec (dexkit_mutf8 target). Used by
// EscapeSmaliString so a pool string is DECODED before it is escaped.
#include "mutf8.h"

namespace dexkit {

inline void PushEncodeNumber(dex::InstructionFormat op_format, uint8_t op, const uint16_t *ptr, std::vector<EncodeNumber> *using_numbers);

DexItem::DexItem(uint32_t id, std::shared_ptr<MemMap> mmap, uint32_t header_off, DexKit *dexkit) :
        _image(std::move(mmap)),
        dexkit(dexkit),
        // NOTE: the size passed here is just (mapped_length - header_off).
        // It is NOT the actual logical DEX size. Reader::ValidateHeader()
        // will parse the header and correct the size using header->file_size/
        // container_size. Do not rely on this initial size for bounds checks.
        reader(_image->data() + header_off, _image->len() - header_off),
        dex_id(id) {
    InitBaseCache();
}

void DexItem::InitBaseCache() {
    strings.resize(reader.StringIds().size());
    auto strings_it = strings.begin();
    for (auto &str: reader.StringIds()) {
        auto *str_ptr = reader.dataPtr<dex::u1>(str.string_data_off);
        ReadULeb128(&str_ptr);
        *strings_it++ = reinterpret_cast<const char *>(str_ptr);
    }
    if (!strings.empty() && strings[0].empty()) {
        empty_string_id = 0;
    }

    type_names.resize(reader.TypeIds().size());
    type_name_array_count.resize(reader.TypeIds().size());
    auto type_names_it = type_names.begin();
    int idx = 0;
    for (auto &type_id: reader.TypeIds()) {
        *type_names_it = strings[type_id.descriptor_idx];
        auto array_count = type_names_it->find_first_not_of('[');
        DEXKIT_CHECK(array_count != std::string::npos);
        type_name_array_count[idx] = array_count;
        type_ids_map[*type_names_it++] = idx++;
    }

    uint32_t element_type_idx = dex::kNoIndex;
    auto element_type_class_desc = "Ljava/lang/annotation/ElementType;";
    auto annotation_target_class_desc = "Ljava/lang/annotation/Target;";
    if (type_ids_map.contains(element_type_class_desc)) {
        element_type_idx = type_ids_map[element_type_class_desc];
    }
    if (type_ids_map.contains(annotation_target_class_desc)) {
        annotation_target_class_id = type_ids_map[annotation_target_class_desc];
    }

    uint32_t retention_policy_type_idx = dex::kNoIndex;
    auto retention_policy_class_desc = "Ljava/lang/annotation/RetentionPolicy;";
    auto annotation_retention_class_desc = "Ljava/lang/annotation/Retention;";
    if (type_ids_map.contains(retention_policy_class_desc)) {
        retention_policy_type_idx = type_ids_map[retention_policy_class_desc];
    }
    if (type_ids_map.contains(annotation_retention_class_desc)) {
        annotation_retention_class_id = type_ids_map[annotation_retention_class_desc];
    }

    proto_type_list.resize(reader.ProtoIds().size());
    auto proto_it = proto_type_list.begin();
    for (auto &proto: reader.ProtoIds()) {
        if (proto.parameters_off != 0) {
            auto *type_list_ptr = reader.dataPtr<dex::TypeList>(proto.parameters_off);
            *proto_it = type_list_ptr;
        }
        ++proto_it;
    }

    class_field_ids.resize(reader.TypeIds().size());
    pending_cross_ref_field_ids.resize(reader.TypeIds().size());
    int field_idx = 0;
    for (auto &field: reader.FieldIds()) {
        if (field.class_idx == element_type_idx) {
            auto name = strings[field.name_idx];
            if (name == "TYPE") {
                target_element_map[field_idx] = schema::TargetElementType::Type;
            } else if (name == "FIELD") {
                target_element_map[field_idx] = schema::TargetElementType::Field;
            } else if (name == "METHOD") {
                target_element_map[field_idx] = schema::TargetElementType::Method;
            } else if (name == "PARAMETER") {
                target_element_map[field_idx] = schema::TargetElementType::Parameter;
            } else if (name == "CONSTRUCTOR") {
                target_element_map[field_idx] = schema::TargetElementType::Constructor;
            } else if (name == "LOCAL_VARIABLE") {
                target_element_map[field_idx] = schema::TargetElementType::LocalVariable;
            } else if (name == "ANNOTATION_TYPE") {
                target_element_map[field_idx] = schema::TargetElementType::AnnotationType;
            } else if (name == "PACKAGE") {
                target_element_map[field_idx] = schema::TargetElementType::Package;
            } else if (name == "TYPE_PARAMETER") {
                target_element_map[field_idx] = schema::TargetElementType::TypeParameter;
            } else if (name == "TYPE_USE") {
                target_element_map[field_idx] = schema::TargetElementType::TypeUse;
            }
        } else if (field.class_idx == retention_policy_type_idx) {
            auto name = strings[field.name_idx];
            if (name == "SOURCE") {
                retention_map[field_idx] = schema::RetentionPolicyType::Source;
            } else if (name == "CLASS") {
                retention_map[field_idx] = schema::RetentionPolicyType::Class;
            } else if (name == "RUNTIME") {
                retention_map[field_idx] = schema::RetentionPolicyType::Runtime;
            }
        }
        class_field_ids[field.class_idx].emplace_back(field_idx);
        ++field_idx;
    }

    type_def_flag.resize(reader.TypeIds().size());
    type_def_idx.resize(reader.TypeIds().size());
    class_source_files.resize(reader.TypeIds().size());
    class_access_flags.resize(reader.TypeIds().size());
    class_interface_ids.resize(reader.TypeIds().size());
    class_method_ids.resize(reader.TypeIds().size());
    pending_cross_ref_method_ids.resize(reader.TypeIds().size());
    const auto method_count = reader.MethodIds().size();
    const auto field_count = reader.FieldIds().size();
    method_descriptors.resize(method_count);
    method_access_flags.resize(method_count);
    method_codes.resize(method_count);
    lazy_method_opcode_slots = std::make_unique<LazyMethodOpCodesSlot[]>(method_count);
    lazy_method_using_string_slots = std::make_unique<LazyMethodUsingStringsSlot[]>(method_count);
    lazy_using_numbers_slots = std::make_unique<LazyUsingNumbersSlot[]>(method_count);
    field_descriptors.resize(field_count);
    field_access_flags.resize(field_count);

    method_cross_info.resize(method_count);
    field_cross_info.resize(field_count);

    auto class_def_idx = 0;
    for (auto &class_def: reader.ClassDefs()) {
        auto def_idx = class_def_idx++;
        if (class_def.source_file_idx != dex::kNoIndex) {
            class_source_files[class_def.class_idx] = strings[class_def.source_file_idx];
        }
        type_def_flag[class_def.class_idx] = true;
        type_def_idx[class_def.class_idx] = def_idx;
        class_access_flags[class_def.class_idx] = class_def.access_flags;

        if (class_def.interfaces_off) {
            auto interface_type_list = this->reader.dataPtr<dex::TypeList>(class_def.interfaces_off);
            if (interface_type_list != nullptr) {
                auto &interfaces = this->class_interface_ids[class_def.class_idx];
                interfaces.reserve(interface_type_list->size);
                for (auto i = 0; i < interface_type_list->size; ++i) {
                    interfaces.emplace_back(interface_type_list->list[i].type_idx);
                }
            }
        }

        if (class_def.class_data_off == 0) {
            continue;
        }

        const auto *class_data = reader.dataPtr<dex::u1>(class_def.class_data_off);
        uint32_t static_fields_size = ReadULeb128(&class_data);
        uint32_t instance_fields_count = ReadULeb128(&class_data);
        uint32_t direct_methods_count = ReadULeb128(&class_data);
        uint32_t virtual_methods_count = ReadULeb128(&class_data);

        auto &methods = class_method_ids[class_def.class_idx];

        for (uint32_t i = 0, class_field_idx = 0; i < static_fields_size; ++i) {
            class_field_idx += ReadULeb128(&class_data);
            field_access_flags[class_field_idx] = ReadULeb128(&class_data);
        }

        for (uint32_t i = 0, class_field_idx = 0; i < instance_fields_count; ++i) {
            class_field_idx += ReadULeb128(&class_data);
            field_access_flags[class_field_idx] = ReadULeb128(&class_data);
        }

        for (uint32_t i = 0, class_method_idx = 0; i < direct_methods_count; ++i) {
            class_method_idx += ReadULeb128(&class_data);
            uint32_t access_flags = ReadULeb128(&class_data);
            // dexllm: stored VERBATIM. Upstream rewrote declared_synchronized
            // (0x20000) to synchronized (0x20) here for java.lang.reflect.Modifier
            // compatibility; that is lossy (dex 0x20 means JNI synchronized-native,
            // a different thing) and this is a dex analyzer, not a reflection shim.
            method_access_flags[class_method_idx] = access_flags;
            uint32_t code_off = ReadULeb128(&class_data);
            if (code_off) {
                method_codes[class_method_idx] = reader.dataPtr<const dex::Code>(code_off);
            }
            methods.emplace_back(class_method_idx);
        }
        for (uint32_t i = 0, class_method_idx = 0; i < virtual_methods_count; ++i) {
            class_method_idx += ReadULeb128(&class_data);
            uint32_t access_flags = ReadULeb128(&class_data);
            // dexllm: stored VERBATIM — see the direct-methods loop above.
            method_access_flags[class_method_idx] = access_flags;
            uint32_t code_off = ReadULeb128(&class_data);
            if (code_off) {
                method_codes[class_method_idx] = reader.dataPtr<const dex::Code>(code_off);
            }
            methods.emplace_back(class_method_idx);
        }
        std::sort(methods.begin(), methods.end());
    }
    for (uint32_t type_idx = 0; type_idx < type_def_flag.size(); ++type_idx) {
        if (!type_def_flag[type_idx]) {
            std::swap(pending_cross_ref_field_ids[type_idx], class_field_ids[type_idx]);
        }
    }

    auto method_idx = 0;
    for (auto &method_def: reader.MethodIds()) {
        if (!type_def_flag[method_def.class_idx]) {
            pending_cross_ref_method_ids[method_def.class_idx].emplace_back(method_idx);
        }
        ++method_idx;
    }
    {
        static std::mutex put_declare_class_mutex;
        std::lock_guard<std::mutex> lock(put_declare_class_mutex);
        for (auto &class_def: reader.ClassDefs()) {
            dexkit->PutDeclaredClass(type_names[class_def.class_idx], dex_id, class_def.class_idx);
        }
    }
}

bool DexItem::NeedInitCache(uint32_t need_flag) const {
    return (dex_flag.load(std::memory_order_acquire) & need_flag) != need_flag;
}

uint32_t DexItem::BeginInitCache(uint32_t init_flags) {
    std::unique_lock lock(init_cache_state_mutex);
    while (true) {
        auto ready_flags = dex_flag.load(std::memory_order_acquire);
        auto missing_flags = init_flags & ~ready_flags;
        if (missing_flags == 0) {
            return 0;
        }
        if (init_cache_inflight_flags == 0) {
            init_cache_inflight_flags = missing_flags;
            return missing_flags;
        }
        init_cache_state_cv.wait(lock, [this] {
            return init_cache_inflight_flags == 0;
        });
    }
}

void DexItem::FinishInitCache(uint32_t init_flags) {
    {
        std::lock_guard lock(init_cache_state_mutex);
        dex_flag.fetch_or(init_flags, std::memory_order_release);
        init_cache_inflight_flags &= ~init_flags;
    }
    init_cache_state_cv.notify_all();
}

void DexItem::WaitInitCache(uint32_t init_flags) const {
    std::unique_lock lock(init_cache_state_mutex);
    init_cache_state_cv.wait(lock, [this, init_flags] {
        auto ready_flags = dex_flag.load(std::memory_order_acquire);
        return (ready_flags & init_flags) == init_flags;
    });
}

void DexItem::InitCache(uint32_t init_flags) {
    bool need_foreach_method = false;
    bool need_op_seq = (init_flags & kOpSequence) != 0;
    bool need_method_using_string = (init_flags & kUsingString) != 0;
    bool need_method_using_field = (init_flags & kMethodUsingField) != 0;
    bool need_method_invoking = (init_flags & kMethodInvoking) != 0;
    bool need_method_caller = (init_flags & kCallerMethod) != 0;
    bool need_field_rw_method = (init_flags & kRwFieldMethod) != 0;
    bool need_class_annotation = (init_flags & kClassAnnotation) != 0;
    bool need_field_annotation = (init_flags & kFieldAnnotation) != 0;
    bool need_method_annotation = (init_flags & kMethodAnnotation) != 0;
    bool need_param_annotation = (init_flags & kParamAnnotation) != 0;
    bool need_annotation = need_class_annotation || need_field_annotation || need_method_annotation || need_param_annotation;
    // only used for full cache
    bool need_method_using_number = (init_flags & kUsingNumber) != 0;

    if (need_op_seq) {
        method_opcode_seq.resize(reader.MethodIds().size(), std::nullopt);
        need_foreach_method = true;
    }
    if (need_method_invoking) {
        method_invoking_ids.resize(reader.MethodIds().size());
        need_foreach_method = true;
    }
    if (need_method_caller) {
        method_caller_ids.resize(reader.MethodIds().size());
        need_foreach_method = true;
    }
    if (need_method_using_string) {
        method_using_string_ids.resize(reader.MethodIds().size());
        need_foreach_method = true;
    }
    if (need_method_using_field) {
        method_using_field_ids.resize(reader.MethodIds().size());
        need_foreach_method = true;
    }
    if (need_field_rw_method) {
        field_get_method_ids.resize(reader.FieldIds().size());
        field_put_method_ids.resize(reader.FieldIds().size());
        need_foreach_method = true;
    }
    if (need_method_using_number) {
        method_using_numbers.resize(reader.MethodIds().size());
        need_foreach_method = true;
    }

    if (need_foreach_method) {
        for (auto &class_def: reader.ClassDefs()) {
            for (auto method_id: class_method_ids[class_def.class_idx]) {
                auto code = method_codes[method_id];
                if (code == nullptr) {
                    continue;
                }

                std::optional<std::vector<uint8_t>> *op_seq_ptr = nullptr;
                std::vector<uint32_t> *method_using_string_ptr = nullptr;
                std::vector<std::pair<uint32_t, bool>> *method_using_field_ptr = nullptr;
                std::vector<uint32_t> *method_invoking_ptr = nullptr;
                std::vector<EncodeNumber> *method_using_number_ptr = nullptr;

                if (need_op_seq) {
                    op_seq_ptr = &method_opcode_seq[method_id];
                    *op_seq_ptr = std::vector<uint8_t>();
                }
                if (need_method_using_string) {
                    method_using_string_ptr = &method_using_string_ids[method_id];
                }
                if (need_method_using_field) {
                    method_using_field_ptr = &method_using_field_ids[method_id];
                }
                if (need_method_invoking) {
                    method_invoking_ptr = &method_invoking_ids[method_id];
                }
                if (need_method_using_number) {
                    method_using_number_ptr = &method_using_numbers[method_id];
                }

                auto p = code->insns;
                auto end_p = p + code->insns_size;
                while (p < end_p) {
                    auto op = (uint8_t) *p;
                    if (need_op_seq) {
                        op_seq_ptr->value().emplace_back(op);
                    }
                    auto ptr = p;
                    auto width = GetBytecodeWidth(ptr++);
                    auto op_format = ins_formats[op];

                    if (need_method_using_string) {
                        // dexllm: bound the operand index against the string pool.
                        // It is only guaranteed in-range by VerifyInsns, which the
                        // lenient load mode skips (partial-decrypt dumps). Dropping an
                        // OOB index here keeps method_using_string_ids consistent so
                        // EVERY consumer (GetUsingStrings / IsMethodUsingStringsMatched
                        // / ...) is safe; on verified input it never triggers.
                        if (op == 0x1a) { // const-string
                            auto index = ReadShort(ptr);
                            if (index < strings.size())
                                method_using_string_ptr->emplace_back(index);
                        } else if (op == 0x1b) { // const-string-jumbo
                            auto index = ReadInt(ptr);
                            if (index < strings.size())
                                method_using_string_ptr->emplace_back(index);
                        }
                    }

                    if (need_method_using_field) {
                        if (op >= 0x52 && op <= 0x6d) {
                            // iget, iget-wide, iget-object, iget-boolean, iget-byte, iget-char, iget-short
                            // sget, sget-wide, sget-object, sget-boolean, sget-byte, sget-char, sget-short
                            auto is_getter = ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66));
                            // iput, iput-wide, iput-object, iput-boolean, iput-byte, iput-char, iput-short
                            // sput, sput-wide, sput-object, sput-boolean, sput-byte, sput-char, sput-short
                            auto is_setter = ((op >= 0x59 && op <= 0x5f) || (op >= 0x67 && op <= 0x6d));
                            auto index = ReadShort(ptr);
                            // dexllm: bound the field operand. Unbounded under lenient
                            // (VerifyInsns-off), it would OOB-index field_get/put_method_ids
                            // during the load-time cross-ref build (need_field_rw_method)
                            // and the using-field matchers. On verified input never trips.
                            if (index < reader.FieldIds().size())
                                method_using_field_ptr->emplace_back(index, is_getter);
                        }
                    }

                    if (need_method_invoking) {
                        if ((op >= 0x6e && op <= 0x72) // invoke-kind
                            || (op >= 0x74 && op <= 0x78)) { // invoke-kind/range
                            auto index = ReadShort(ptr);
                            // dexllm: bound the method operand — same rationale as field;
                            // unbounded it OOB-indexes method_caller_ids at load time.
                            if (index < reader.MethodIds().size())
                                method_invoking_ptr->emplace_back(index);
                        }
                    }

                    if (need_method_using_number) {
                        PushEncodeNumber(op_format, op, ptr, method_using_number_ptr);
                    }

                    p += width;
                }
            }
        }
    }

    if (need_method_caller) {
        for (auto &class_def: reader.ClassDefs()) {
            for (auto method_id: class_method_ids[class_def.class_idx]) {
                for (auto invoke_id: method_invoking_ids[method_id]) {
                    method_caller_ids[invoke_id].emplace_back(dex_id, method_id);
                }
            }
        }
    }

    if (need_field_rw_method) {
        for (auto &class_def: reader.ClassDefs()) {
            for (auto method_id: class_method_ids[class_def.class_idx]) {
                for (auto &field_using: method_using_field_ids[method_id]) {
                    auto field_id = field_using.first;
                    auto is_getter = field_using.second;
                    if (is_getter) {
                        field_get_method_ids[field_id].emplace_back(dex_id, method_id);
                    } else {
                        field_put_method_ids[field_id].emplace_back(dex_id, method_id);
                    }
                }
            }
        }
    }

    if (need_annotation) {
        if (need_class_annotation) {
            class_annotations.resize(reader.TypeIds().size());
        }
        if (need_field_annotation) {
            field_annotations.resize(reader.FieldIds().size());
        }
        if (need_method_annotation) {
            method_annotations.resize(reader.MethodIds().size());
        }
        if (need_param_annotation) {
            method_parameter_annotations.resize(reader.MethodIds().size());
        }

        for (auto &class_def: reader.ClassDefs()) {
            if (class_def.annotations_off == 0) {
                continue;
            }
            auto dex_annotations = reader.dataPtr<dex::AnnotationsDirectoryItem>(class_def.annotations_off);
            if (need_class_annotation) {
                class_annotations[class_def.class_idx] = reader.ExtractAnnotationSet(dex_annotations->class_annotations_off);
            }
            auto *ptr = reinterpret_cast<const dex::u1 *>(dex_annotations + 1);
            if (need_field_annotation) {
                for (dex::u4 i = 0; i < dex_annotations->fields_size; ++i) {
                    auto dex_field_annotation = reinterpret_cast<const dex::FieldAnnotationsItem *>(ptr);
                    field_annotations[dex_field_annotation->field_idx] = reader.ExtractAnnotationSet(dex_field_annotation->annotations_off);
                    ptr += sizeof(dex::FieldAnnotationsItem);
                }
            } else {
                ptr += dex_annotations->fields_size * sizeof(dex::FieldAnnotationsItem);
            }
            if (need_method_annotation) {
                for (dex::u4 i = 0; i < dex_annotations->methods_size; ++i) {
                    auto dex_method_annotation = reinterpret_cast<const dex::MethodAnnotationsItem *>(ptr);
                    method_annotations[dex_method_annotation->method_idx] = reader.ExtractAnnotationSet(dex_method_annotation->annotations_off);
                    ptr += sizeof(dex::MethodAnnotationsItem);
                }
            } else {
                ptr += dex_annotations->methods_size * sizeof(dex::MethodAnnotationsItem);
            }
            if (need_param_annotation) {
                for (dex::u4 i = 0; i < dex_annotations->parameters_size; ++i) {
                    auto dex_parameter_annotation = reinterpret_cast<const dex::ParameterAnnotationsItem *>(ptr);
                    auto dex_annotation_set_ref_list = reader.dataPtr<dex::AnnotationSetRefList>(dex_parameter_annotation->annotations_off);
                    for (dex::u4 j = 0; j < dex_annotation_set_ref_list->size; ++j) {
                        auto dex_annotation_set_ref_item = dex_annotation_set_ref_list->list[j];
                        method_parameter_annotations[dex_parameter_annotation->method_idx].emplace_back(reader.ExtractAnnotationSet(dex_annotation_set_ref_item.annotations_off));
                    }
                    ptr += sizeof(dex::ParameterAnnotationsItem);
                }
            }
        }
    }
}

bool DexItem::NeedPutCrossRef(uint32_t need_cross_flag) const {
    DEXKIT_CHECK((need_cross_flag & ~(kCallerMethod | kRwFieldMethod)) == 0);
    return (dex_cross_flag.load(std::memory_order_acquire) & need_cross_flag) != need_cross_flag;
}

uint32_t DexItem::BeginPutCrossRef(uint32_t put_cross_flag) {
    DEXKIT_CHECK((put_cross_flag & ~(kCallerMethod | kRwFieldMethod)) == 0);
    std::unique_lock lock(cross_ref_state_mutex);
    while (true) {
        auto ready_flags = dex_cross_flag.load(std::memory_order_acquire);
        auto missing_flags = put_cross_flag & ~ready_flags;
        if (missing_flags == 0) {
            return 0;
        }
        if (cross_ref_inflight_flags == 0) {
            cross_ref_inflight_flags = missing_flags;
            return missing_flags;
        }
        cross_ref_state_cv.wait(lock, [this] {
            return cross_ref_inflight_flags == 0;
        });
    }
}

void DexItem::FinishPutCrossRef(uint32_t put_cross_flag) {
    {
        std::lock_guard lock(cross_ref_state_mutex);
        dex_cross_flag.fetch_or(put_cross_flag, std::memory_order_release);
        cross_ref_inflight_flags &= ~put_cross_flag;
    }
    cross_ref_state_cv.notify_all();
}

void DexItem::WaitPutCrossRef(uint32_t put_cross_flag) const {
    std::unique_lock lock(cross_ref_state_mutex);
    cross_ref_state_cv.wait(lock, [this, put_cross_flag] {
        auto ready_flags = dex_cross_flag.load(std::memory_order_acquire);
        return (ready_flags & put_cross_flag) == put_cross_flag;
    });
}

void DexItem::PutCrossRef(uint32_t put_cross_flag) {
    DEXKIT_CHECK((put_cross_flag & ~(kCallerMethod | kRwFieldMethod)) == 0);
    bool need_caller_cross = (put_cross_flag & kCallerMethod) != 0;
    bool need_rw_field_cross = (put_cross_flag & kRwFieldMethod) != 0;

    for (int type_idx = 0; type_idx < type_names.size(); ++type_idx) {
        if (!this->type_def_flag[type_idx] && type_names[type_idx][0] != '[') {
            auto declared_pair = dexkit->GetClassDeclaredPair(type_names[type_idx]);
            auto origin_dex = declared_pair.first;
            auto origin_type_idx = declared_pair.second;

            // no declared in any dex
            if (origin_dex == nullptr) {
                continue;
            }
            auto &mutex = origin_dex->GetTypeDefMutex(origin_type_idx);
            std::lock_guard lock(mutex);

            if (need_caller_cross) {
                const auto &method_ids = this->pending_cross_ref_method_ids[type_idx];

                auto &origin_method_ids = origin_dex->class_method_ids[origin_type_idx];
                for (int ori_i = 0, cur_i = 0; ori_i < origin_method_ids.size() && cur_i < method_ids.size(); ++ori_i) {
                    auto origin_method_idx = origin_method_ids[ori_i];
                    auto curr_method_idx = method_ids[cur_i];
                    auto origin_method_descriptor = origin_dex->GetMethodDescriptor(origin_method_idx);
                    auto curr_method_descriptor = this->GetMethodDescriptor(curr_method_idx);
                    if (curr_method_descriptor != origin_method_descriptor) {
                        continue;
                    }
                    method_cross_info[curr_method_idx] = {origin_dex->dex_id, origin_method_idx};
                    if (!method_caller_ids[curr_method_idx].empty()) {
                        pending_aggregate_method_work_items.emplace_back(PendingAggregateMethodWorkItem{
                                .source_method_idx = curr_method_idx,
                                .target_dex_id = static_cast<uint16_t>(origin_dex->dex_id),
                                .target_method_idx = origin_method_idx
                        });
                    }
                    ++cur_i;
                }
            }

            if (need_rw_field_cross) {
                const auto &field_ids = this->pending_cross_ref_field_ids[type_idx];

                auto &origin_field_ids = origin_dex->class_field_ids[origin_type_idx];
                for (int ori_i = 0, cur_i = 0; ori_i < origin_field_ids.size() && cur_i < field_ids.size(); ++ori_i) {
                    auto origin_field_idx = origin_field_ids[ori_i];
                    auto curr_field_idx = field_ids[cur_i];
                    auto origin_field_descriptor = origin_dex->GetFieldDescriptor(origin_field_idx);
                    auto curr_field_descriptor = this->GetFieldDescriptor(curr_field_idx);
                    if (origin_field_descriptor != curr_field_descriptor) {
                        continue;
                    }
                    field_cross_info[curr_field_idx] = {origin_dex->dex_id, origin_field_idx};
                    if (!field_get_method_ids[curr_field_idx].empty() || !field_put_method_ids[curr_field_idx].empty()) {
                        pending_aggregate_field_work_items.emplace_back(PendingAggregateFieldWorkItem{
                                .source_field_idx = curr_field_idx,
                                .target_dex_id = static_cast<uint16_t>(origin_dex->dex_id),
                                .target_field_idx = origin_field_idx
                        });
                    }
                    ++cur_i;
                }
            }
        }
    }

    if (need_caller_cross) {
        pending_cross_ref_method_ids.clear();
        pending_cross_ref_method_ids.shrink_to_fit();
    }
    if (need_rw_field_cross) {
        pending_cross_ref_field_ids.clear();
        pending_cross_ref_field_ids.shrink_to_fit();
    }
}

std::mutex &DexItem::GetTypeDefMutex(uint32_t type_idx) {
    return (*type_def_mutexes)[type_idx % type_def_mutexes->size()];
}

// NOLINTNEXTLINE
ClassBean DexItem::GetClassBean(uint32_t type_idx) {
    if (!this->type_def_flag[type_idx]) {
        auto pair = dexkit->GetClassDeclaredPair(this->type_names[type_idx]);
        if (pair.first) {
            return pair.first->GetClassBean(pair.second);
        }
    }
    ClassBean bean;
    bean.id = type_idx;
    bean.dex_id = this->dex_id;
    bean.dex_descriptor = this->type_names[type_idx];
    if (this->type_def_flag[type_idx]) {
        auto &class_def = this->reader.ClassDefs()[this->type_def_idx[type_idx]];
        bean.source_file = this->class_source_files[type_idx];
        bean.access_flags = class_def.access_flags;
        bean.super_class_id = class_def.superclass_idx;
        bean.interface_ids = this->class_interface_ids[type_idx];
        bean.field_ids = this->class_field_ids[type_idx];
        bean.method_ids = this->class_method_ids[type_idx];
    }
    return bean;
}

// NOLINTNEXTLINE
MethodBean DexItem::GetMethodBean(uint32_t method_idx) {
    auto &method_def = this->reader.MethodIds()[method_idx];
    if (!this->type_def_flag[method_def.class_idx]) {
        auto cross_info = this->method_cross_info[method_idx];
        if (cross_info.has_value()) {
            return this->dexkit->GetDexItem(cross_info->first)->GetMethodBean(cross_info->second);
        }
    }
    auto &proto_def = this->reader.ProtoIds()[method_def.proto_idx];
    auto &type_list = this->proto_type_list[method_def.proto_idx];
    MethodBean bean;
    bean.id = method_idx;
    bean.dex_id = this->dex_id;
    bean.class_id = method_def.class_idx;
    bean.access_flags = this->method_access_flags[method_idx];
    bean.dex_descriptor = this->GetMethodDescriptor(method_idx);
    bean.return_type = proto_def.return_type_idx;
    std::vector<uint32_t> parameter_type_ids;
    auto len = type_list ? type_list->size : 0;
    parameter_type_ids.reserve(len);
    for (int i = 0; i < len; ++i) {
        parameter_type_ids.emplace_back(type_list->list[i].type_idx);
    }
    bean.parameter_types = parameter_type_ids;
    return bean;
}

// NOLINTNEXTLINE
FieldBean DexItem::GetFieldBean(uint32_t field_idx) {
    auto &field_def = this->reader.FieldIds()[field_idx];
    if (!this->type_def_flag[field_def.class_idx]) {
        auto cross_info = this->field_cross_info[field_idx];
        if (cross_info.has_value()) {
            return this->dexkit->GetDexItem(cross_info->first)->GetFieldBean(cross_info->second);
        }
    }
    FieldBean bean;
    bean.id = field_idx;
    bean.dex_id = this->dex_id;
    bean.class_id = field_def.class_idx;
    bean.access_flags = this->field_access_flags[field_idx];
    bean.dex_descriptor = this->GetFieldDescriptor(field_idx);
    bean.type_id = field_def.type_idx;
    return bean;
}

std::optional<MethodBean> DexItem::GetMethodBean(uint32_t type_idx, std::string_view method_descriptor) {
    auto &methods = this->class_method_ids[type_idx];
    for (auto method_idx: methods) {
        if (this->GetMethodDescriptor(method_idx) == method_descriptor) {
            return this->GetMethodBean(method_idx);
        }
    }
    return std::nullopt;
}

std::optional<FieldBean> DexItem::GetFieldBean(uint32_t type_idx, std::string_view method_descriptor) {
    auto &fields = this->class_field_ids[type_idx];
    for (auto field_idx: fields) {
        if (this->GetFieldDescriptor(field_idx) == method_descriptor) {
            return this->GetFieldBean(field_idx);
        }
    }
    return std::nullopt;
}

// NOLINTNEXTLINE
AnnotationBean DexItem::GetAnnotationBean(ir::Annotation *annotation) {
    AnnotationBean bean;
    bean.dex_id = this->dex_id;
    bean.type_id = annotation->type->orig_index;
    bean.type_descriptor = type_names[annotation->type->orig_index];
    bean.visibility = ((int8_t) annotation->visibility == -1)
            ? schema::AnnotationVisibilityType::None
            : (schema::AnnotationVisibilityType) annotation->visibility;
    for (auto &element : annotation->elements) {
        bean.elements.emplace_back(GetAnnotationElementBean(element));
    }
    return bean;
}

// NOLINTNEXTLINE
AnnotationEncodeValueBean DexItem::GetAnnotationEncodeValueBean(ir::EncodedValue *encoded_value) {
    AnnotationEncodeValueBean bean;
    switch (encoded_value->type) {
        case 0x00: bean.type = schema::AnnotationEncodeValueType::ByteValue; break;
        case 0x02: bean.type = schema::AnnotationEncodeValueType::ShortValue; break;
        case 0x03: bean.type = schema::AnnotationEncodeValueType::CharValue; break;
        case 0x04: bean.type = schema::AnnotationEncodeValueType::IntValue; break;
        case 0x06: bean.type = schema::AnnotationEncodeValueType::LongValue; break;
        case 0x10: bean.type = schema::AnnotationEncodeValueType::FloatValue; break;
        case 0x11: bean.type = schema::AnnotationEncodeValueType::DoubleValue; break;
        case 0x17: bean.type = schema::AnnotationEncodeValueType::StringValue; break;
        case 0x18: bean.type = schema::AnnotationEncodeValueType::TypeValue; break;
        case 0x1a: bean.type = schema::AnnotationEncodeValueType::MethodValue; break;
        case 0x1b: bean.type = schema::AnnotationEncodeValueType::EnumValue; break;
        case 0x1c: bean.type = schema::AnnotationEncodeValueType::ArrayValue; break;
        case 0x1d: bean.type = schema::AnnotationEncodeValueType::AnnotationValue; break;
        case 0x1e: bean.type = schema::AnnotationEncodeValueType::NullValue; break;
        case 0x1f: bean.type = schema::AnnotationEncodeValueType::BoolValue; break;
        default: break;
    }
    switch (encoded_value->type) {
        case 0x00: bean.value = encoded_value->u.byte_value; break;
        case 0x02: bean.value = encoded_value->u.short_value; break;
        case 0x03: bean.value = encoded_value->u.char_value; break;
        case 0x04: bean.value = encoded_value->u.int_value; break;
        case 0x06: bean.value = encoded_value->u.long_value; break;
        case 0x10: bean.value = encoded_value->u.float_value; break;
        case 0x11: bean.value = encoded_value->u.double_value; break;
        case 0x17: bean.value = encoded_value->u.string_value->c_str(); break;
        case 0x18: bean.value = std::make_unique<ClassBean>(GetClassBean(encoded_value->u.type_value->orig_index)); break;
        case 0x1a: bean.value = std::make_unique<MethodBean>(GetMethodBean(encoded_value->u.method_value->orig_index)); break;
        case 0x1b: bean.value = std::make_unique<FieldBean>(GetFieldBean(encoded_value->u.enum_value->orig_index)); break;
        case 0x1c: bean.value = std::make_unique<AnnotationEncodeArrayBean>(GetAnnotationEncodeArrayBean(encoded_value->u.array_value)); break;
        case 0x1d: bean.value = std::make_unique<AnnotationBean>(GetAnnotationBean(encoded_value->u.annotation_value)); break;
        case 0x1e: bean.value = 0; break;
        case 0x1f: bean.value = encoded_value->u.bool_value; break;
        default: break;
    }
    return bean;
}

// NOLINTNEXTLINE
AnnotationElementBean DexItem::GetAnnotationElementBean(ir::AnnotationElement *annotation_element) {
    AnnotationElementBean bean;
    bean.name = annotation_element->name->c_str();
    bean.value = GetAnnotationEncodeValueBean(annotation_element->value);
    return bean;
}

// NOLINTNEXTLINE
AnnotationEncodeArrayBean DexItem::GetAnnotationEncodeArrayBean(ir::EncodedArray *encoded_array) {
    AnnotationEncodeArrayBean array;
    for (auto value: encoded_array->values) {
        array.values.emplace_back(GetAnnotationEncodeValueBean(value));
    }
    return array;
}

std::vector<AnnotationBean>
DexItem::GetClassAnnotationBeans(uint32_t class_idx) {
    if ((dex_flag.load(std::memory_order_acquire) & kClassAnnotation) == 0) {
        auto class_def = reader.ClassDefs()[type_def_idx[class_idx]];
        auto annotationsDirectory = reader.ExtractAnnotations(class_def.annotations_off);
        if (!annotationsDirectory) return {};
        auto annotationSet = annotationsDirectory->class_annotation
                             ? annotationsDirectory->class_annotation->annotations
                             : std::vector<ir::Annotation *>();
        std::vector<AnnotationBean> beans;
        for (auto annotation: annotationSet) {
            AnnotationBean bean = GetAnnotationBean(annotation);
            beans.emplace_back(std::move(bean));
        }
        return beans;
    }
    std::vector<AnnotationBean> beans;
    auto annotationSet = this->class_annotations[class_idx];
    if (annotationSet) {
        for (auto annotation: annotationSet->annotations) {
            AnnotationBean bean = GetAnnotationBean(annotation);
            beans.emplace_back(std::move(bean));
        }
    }
    return beans;
}

std::vector<AnnotationBean>
DexItem::GetMethodAnnotationBeans(uint32_t method_idx) {
    if ((dex_flag.load(std::memory_order_acquire) & kMethodAnnotation) == 0) {
        auto method_def = reader.MethodIds()[method_idx];
        auto class_def = reader.ClassDefs()[type_def_idx[method_def.class_idx]];
        auto annotationsDirectory = reader.ExtractAnnotations(class_def.annotations_off);
        if (!annotationsDirectory) return {};
        for (auto ann_ptr: annotationsDirectory->method_annotations) {
            auto method_decl = ann_ptr->method_decl;
            if (method_decl->orig_index != method_idx) {
                continue;
            }
            auto annotationSet = ann_ptr->annotations
                                 ? ann_ptr->annotations->annotations
                                 : std::vector<ir::Annotation *>();
            std::vector<AnnotationBean> beans;
            for (auto annotation: annotationSet) {
                AnnotationBean bean = GetAnnotationBean(annotation);
                beans.emplace_back(std::move(bean));
            }
            return beans;
        }
        return {};
    }
    auto annotationSet = this->method_annotations[method_idx];
    if (annotationSet == nullptr) {
        return {};
    }
    std::vector<AnnotationBean> beans;
    for (auto annotation: annotationSet->annotations) {
        AnnotationBean bean = GetAnnotationBean(annotation);
        beans.emplace_back(std::move(bean));
    }
    return beans;
}

std::vector<AnnotationBean>
DexItem::GetFieldAnnotationBeans(uint32_t field_idx) {
    if ((dex_flag.load(std::memory_order_acquire) & kFieldAnnotation) == 0) {
        auto field_def = reader.FieldIds()[field_idx];
        auto class_def = reader.ClassDefs()[type_def_idx[field_def.class_idx]];
        auto annotationsDirectory = reader.ExtractAnnotations(class_def.annotations_off);
        if (!annotationsDirectory) return {};
        for (auto ann_ptr: annotationsDirectory->field_annotations) {
            auto field_decl = ann_ptr->field_decl;
            if (field_decl->orig_index != field_idx) {
                continue;
            }
            auto annotationSet = ann_ptr->annotations
                                 ? ann_ptr->annotations->annotations
                                 : std::vector<ir::Annotation *>();
            std::vector<AnnotationBean> beans;
            for (auto annotation: annotationSet) {
                AnnotationBean bean = GetAnnotationBean(annotation);
                beans.emplace_back(std::move(bean));
            }
            return beans;
        }
        return {};
    }
    auto annotationSet = this->field_annotations[field_idx];
    if (annotationSet == nullptr) {
        return {};
    }
    std::vector<AnnotationBean> beans;
    for (auto annotation: annotationSet->annotations) {
        AnnotationBean bean = GetAnnotationBean(annotation);
        beans.emplace_back(std::move(bean));
    }
    return beans;
}

std::vector<std::vector<AnnotationBean>>
DexItem::GetParameterAnnotationBeans(uint32_t method_idx) {
    if ((dex_flag.load(std::memory_order_acquire) & kParamAnnotation) == 0) {
        auto method_def = reader.MethodIds()[method_idx];
        auto class_def = reader.ClassDefs()[type_def_idx[method_def.class_idx]];
        auto annotationsDirectory = reader.ExtractAnnotations(class_def.annotations_off);
        if (!annotationsDirectory) return {};
        std::vector<std::vector<AnnotationBean>> beans;
        for (auto params_ann_ptr: annotationsDirectory->param_annotations) {
            auto method_decl = params_ann_ptr->method_decl;
            if (method_decl->orig_index != method_idx) {
                continue;
            }
            if (params_ann_ptr->annotations == nullptr) {
                return {};
            }
            for (auto ann_ptr : params_ann_ptr->annotations->annotations) {
                auto annotationSet = ann_ptr
                                     ? ann_ptr->annotations
                                     : std::vector<ir::Annotation *>();

                std::vector<AnnotationBean> annotationBeans;
                for (auto annotation: annotationSet) {
                    AnnotationBean bean = GetAnnotationBean(annotation);
                    annotationBeans.emplace_back(std::move(bean));
                }
                beans.emplace_back(std::move(annotationBeans));
            }
            return beans;
        }
        return {};
    }
    std::vector<std::vector<AnnotationBean>> beans;
    auto param_annotations = this->method_parameter_annotations[method_idx];
    if (param_annotations.empty()) {
        return {};
    }
    for (auto annotationSet: param_annotations) {
        std::vector<AnnotationBean> annotationBeans;
        if (annotationSet) {
            for (auto annotation: annotationSet->annotations) {
                AnnotationBean bean = GetAnnotationBean(annotation);
                annotationBeans.emplace_back(std::move(bean));
            }
        }
        beans.emplace_back(std::move(annotationBeans));
    }
    return beans;
}

std::optional<std::vector<std::optional<std::string_view>>>
DexItem::GetParameterNames(uint32_t method_idx) {
    auto code = method_codes[method_idx];
    if (code == nullptr || code->debug_info_off == 0) {
        return {};
    }
    auto *ptr = reader.dataPtr<dex::u1>(code->debug_info_off);
    ReadULeb128(&ptr); // line_start
    auto parameter_count = ReadULeb128(&ptr);
    std::vector<std::optional<std::string_view>> names;
    names.reserve(parameter_count);
    for (auto i = 0; i < parameter_count; ++i) {
        auto name_idx = ReadULeb128(&ptr) - 1;
        if (name_idx == dex::kNoIndex) {
            names.emplace_back(std::nullopt);
        } else {
            names.emplace_back(strings[name_idx]);
        }
    }
    return names;
}

std::vector<uint8_t>
DexItem::GetMethodOpCodes(uint32_t method_idx) {
    // OpCodes stay as a per-method lazy exception: cold metadata reads should not force
    // bridge-level kOpSequence warm-up for the whole DexKit instance.
    if ((dex_flag.load(std::memory_order_acquire) & kOpSequence) != 0) {
        const auto &op_seq = method_opcode_seq[method_idx];
        return op_seq.has_value() ? op_seq.value() : std::vector<uint8_t>();
    }
    return GetLazyMethodOpCodes(method_idx);
}

std::vector<MethodBean> DexItem::GetCallMethods(uint32_t method_idx) {
    DEXKIT_CHECK(!method_caller_ids.empty());
    const auto &method_caller = this->method_caller_ids[method_idx];
    std::vector<MethodBean> beans;
    beans.reserve(method_caller.size());
    for (auto &[ori_dex_id, caller_id]: method_caller) {
        if (ori_dex_id == this->dex_id) {
            beans.emplace_back(GetMethodBean(caller_id));
        } else {
            auto dex = dexkit->GetDexItem(ori_dex_id);
            beans.emplace_back(dex->GetMethodBean(caller_id));
        }
    }
    return beans;
}

std::vector<MethodBean> DexItem::GetInvokeMethods(uint32_t method_idx) {
    DEXKIT_CHECK(!method_invoking_ids.empty());
    const auto &method_invoking = this->method_invoking_ids[method_idx];
    std::vector<MethodBean> beans;
    beans.reserve(method_invoking.size());
    for (auto invoking_id: method_invoking) {
        beans.emplace_back(GetMethodBean(invoking_id));
    }
    return beans;
}

std::vector<std::string_view> DexItem::GetUsingStrings(uint32_t method_idx) {
    // Using-strings follows the same rule as opcodes: per-method lazy fallback is allowed
    // for metadata getters, while matcher/query hot paths rely on the outer ready barrier.
    std::vector<std::string_view> using_strings;
    const std::vector<uint32_t> *method_using_strings = nullptr;
    if ((dex_flag.load(std::memory_order_acquire) & kUsingString) != 0) {
        method_using_strings = &method_using_string_ids[method_idx];
    } else {
        method_using_strings = &GetLazyMethodUsingStringIds(method_idx);
    }
    using_strings.reserve(method_using_strings->size());
    for (auto string_id: *method_using_strings) {
        // dexllm: string_id is bounded at collection (InitBaseCache /
        // GetUsingStringsFromCode), so method_using_string_ids never holds an
        // OOB index even under lenient (VerifyInsns-off) loads. Safe to index.
        using_strings.emplace_back(this->strings[string_id]);
    }
    return using_strings;
}

std::vector<UsingFieldBean> DexItem::GetUsingFields(uint32_t method_idx) {
    // Cross-ref accessors intentionally have no fallback: callers must enter through the
    // DexKit barrier so these final shared indexes are already published.
    DEXKIT_CHECK(!method_using_field_ids.empty());
    const auto &method_using_fields = this->method_using_field_ids[method_idx];
    std::vector<UsingFieldBean> using_fields;
    using_fields.reserve(method_using_fields.size());
    for (auto [method_id, is_getting]: method_using_fields) {
        UsingFieldBean bean;
        bean.field = GetFieldBean(method_id);
        bean.is_getting = is_getting;
        using_fields.emplace_back(bean);
    }
    return using_fields;
}

std::vector<MethodBean> DexItem::FieldGetMethods(uint32_t field_idx) {
    DEXKIT_CHECK(!field_get_method_ids.empty());
    const auto &method_ids = this->field_get_method_ids[field_idx];
    std::vector<MethodBean> beans;
    beans.reserve(method_ids.size());
    for (auto &[ori_dex_id, method_id]: method_ids) {
        if (ori_dex_id == this->dex_id) {
            beans.emplace_back(GetMethodBean(method_id));
        } else {
            auto dex = dexkit->GetDexItem(ori_dex_id);
            beans.emplace_back(dex->GetMethodBean(method_id));
        }
    }
    return beans;
}

std::vector<MethodBean> DexItem::FieldPutMethods(uint32_t field_idx) {
    DEXKIT_CHECK(!field_put_method_ids.empty());
    const auto &method_ids = this->field_put_method_ids[field_idx];
    std::vector<MethodBean> beans;
    beans.reserve(method_ids.size());
    for (auto &[ori_dex_id, method_id]: method_ids) {
        if (ori_dex_id == this->dex_id) {
            beans.emplace_back(GetMethodBean(method_id));
        } else {
            auto dex = dexkit->GetDexItem(ori_dex_id);
            beans.emplace_back(dex->GetMethodBean(method_id));
        }
    }
    return beans;
}

std::string_view DexItem::GetMethodDescriptor(uint32_t method_idx) {
    auto &method_desc = this->method_descriptors[method_idx];
    if (method_desc != std::nullopt) {
        return method_desc.value();
    }
    auto &method_def = this->reader.MethodIds()[method_idx];
    auto &proto_def = this->reader.ProtoIds()[method_def.proto_idx];
    auto &type_list = this->proto_type_list[method_def.proto_idx];
    auto type_defs = this->reader.TypeIds();

    std::string descriptor(this->type_names[method_def.class_idx]);
    descriptor += "->";
    descriptor += this->strings[method_def.name_idx];
    descriptor += "(";
    auto len = type_list ? type_list->size : 0;
    for (int i = 0; i < len; ++i) {
        descriptor += strings[type_defs[type_list->list[i].type_idx].descriptor_idx];
    }
    descriptor += ')';
    descriptor += strings[type_defs[proto_def.return_type_idx].descriptor_idx];

    method_desc = descriptor;
    return method_desc.value();
}

std::string_view DexItem::GetFieldDescriptor(uint32_t field_idx) {
    auto &field_desc = this->field_descriptors[field_idx];
    if (field_desc != std::nullopt) {
        return field_desc.value();
    }
    auto &field_id = this->reader.FieldIds()[field_idx];
    auto &type_id = this->reader.TypeIds()[field_id.type_idx];

    std::string descriptor(this->type_names[field_id.class_idx]);
    descriptor += "->";
    descriptor += this->strings[field_id.name_idx];
    descriptor += ":";
    descriptor += this->strings[type_id.descriptor_idx];

    field_desc = descriptor;
    return field_desc.value();
}

std::vector<uint8_t> DexItem::GetOpSeqFromCode(uint32_t method_idx) {
    auto code = method_codes[method_idx];
    if (code == nullptr) {
        return {};
    }
    std::vector<uint8_t> op_seq;
    auto p = code->insns;
    auto end_p = p + code->insns_size;
    while (p < end_p) {
        op_seq.emplace_back((uint8_t) *p);
        p += GetBytecodeWidth(p);
    }
    return std::move(op_seq);
}

std::vector<uint32_t> DexItem::GetUsingStringsFromCode(uint32_t method_idx) {
    auto code = method_codes[method_idx];
    if (code == nullptr) {
        return {};
    }
    std::vector<uint32_t> using_strings;
    auto p = code->insns;
    auto end_p = p + code->insns_size;
    while (p < end_p) {
        auto op = (uint8_t) *p;
        auto ptr = p;
        auto width = GetBytecodeWidth(ptr++);
        if (op == 0x1a) { // const-string
            auto index = ReadShort(ptr);
            if (index < strings.size())  // dexllm: bound — see InitBaseCache scan
                using_strings.emplace_back(index);
        } else if (op == 0x1b) { // const-string-jumbo
            auto index = ReadInt(ptr);
            if (index < strings.size())  // dexllm: bound — lenient skips VerifyInsns
                using_strings.emplace_back(index);
        }
        p += width;
    }
    return std::move(using_strings);
}

const std::vector<uint8_t> &DexItem::GetLazyMethodOpCodes(uint32_t method_idx) {
    auto &slot = lazy_method_opcode_slots[method_idx];
    auto state = slot.state.load(std::memory_order_acquire);
    if (state == static_cast<uint8_t>(LazyMethodFeatureState::Ready)) {
        return *slot.data;
    }

    uint8_t expected = static_cast<uint8_t>(LazyMethodFeatureState::Empty);
    if (slot.state.compare_exchange_strong(expected,
                                           static_cast<uint8_t>(LazyMethodFeatureState::Building),
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
        auto built_data = std::make_unique<const std::vector<uint8_t>>(GetOpSeqFromCode(method_idx));
        auto stripe = method_idx % lazy_method_wait_mutexes->size();
        {
            std::lock_guard lock((*lazy_method_wait_mutexes)[stripe]);
            slot.data = std::move(built_data);
            slot.state.store(static_cast<uint8_t>(LazyMethodFeatureState::Ready), std::memory_order_release);
        }
        (*lazy_method_wait_cvs)[stripe].notify_all();
        return *slot.data;
    }

    auto stripe = method_idx % lazy_method_wait_mutexes->size();
    std::unique_lock lock((*lazy_method_wait_mutexes)[stripe]);
    (*lazy_method_wait_cvs)[stripe].wait(lock, [&slot] {
        return slot.state.load(std::memory_order_acquire) == static_cast<uint8_t>(LazyMethodFeatureState::Ready);
    });
    return *slot.data;
}

const std::vector<uint32_t> &DexItem::GetLazyMethodUsingStringIds(uint32_t method_idx) {
    auto &slot = lazy_method_using_string_slots[method_idx];
    auto state = slot.state.load(std::memory_order_acquire);
    if (state == static_cast<uint8_t>(LazyMethodFeatureState::Ready)) {
        return *slot.data;
    }

    uint8_t expected = static_cast<uint8_t>(LazyMethodFeatureState::Empty);
    if (slot.state.compare_exchange_strong(expected,
                                           static_cast<uint8_t>(LazyMethodFeatureState::Building),
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
        auto built_data = std::make_unique<const std::vector<uint32_t>>(GetUsingStringsFromCode(method_idx));
        auto stripe = method_idx % lazy_method_wait_mutexes->size();
        {
            std::lock_guard lock((*lazy_method_wait_mutexes)[stripe]);
            slot.data = std::move(built_data);
            slot.state.store(static_cast<uint8_t>(LazyMethodFeatureState::Ready), std::memory_order_release);
        }
        (*lazy_method_wait_cvs)[stripe].notify_all();
        return *slot.data;
    }

    auto stripe = method_idx % lazy_method_wait_mutexes->size();
    std::unique_lock lock((*lazy_method_wait_mutexes)[stripe]);
    (*lazy_method_wait_cvs)[stripe].wait(lock, [&slot] {
        return slot.state.load(std::memory_order_acquire) == static_cast<uint8_t>(LazyMethodFeatureState::Ready);
    });
    return *slot.data;
}

std::vector<uint32_t> DexItem::GetInvokeMethodsFromCode(uint32_t method_idx) {
    auto code = method_codes[method_idx];
    if (code == nullptr) {
        return {};
    }
    std::vector<uint32_t> invoke_methods;
    auto p = code->insns;
    auto end_p = p + code->insns_size;
    while (p < end_p) {
        auto op = (uint8_t) *p;
        auto ptr = p;
        auto width = GetBytecodeWidth(ptr++);
        auto op_format = ins_formats[op];
        if (op_format == dex::k35c // invoke-kind
            || op_format == dex::k3rc) { // invoke-kind/range
            auto index = ReadShort(ptr);
            // dexllm: bound — method_codes is sized to MethodIds().size(); lenient
            // skips VerifyInsns so an OOB invoke operand must not reach consumers.
            if (index < method_codes.size())
                invoke_methods.emplace_back(index);
        }
        p += width;
    }
    return std::move(invoke_methods);
}

void PushEncodeNumber(dex::InstructionFormat op_format, uint8_t op, const uint16_t *ptr, std::vector<EncodeNumber> *using_numbers) {
    switch (op_format) {
        // using number
        case dex::k11n: { // const/4
            uint8_t value = *(ptr - 1) >> 12;
            if (value & 0x8) {
                value |= 0xf0;
            }
            using_numbers->emplace_back(EncodeNumber{.type = BYTE, .value = {.L8 = (int8_t) value}});
            break;
        }
        case dex::k21s: { // const/16, const-wide/16
            uint16_t value = *ptr;
            if (value & 0x8000) {
                value |= 0xffff0000;
            }
            using_numbers->emplace_back(EncodeNumber{.type = SHORT, .value = {.L16 = (int16_t) value}});
            break;
        }
        case dex::k21h: { // const/high16, const-wide/high16
            if (op == 0x15) {
                using_numbers->emplace_back(EncodeNumber{.type = FLOAT, .value = {.L32 = {.int_value = (int32_t) (*ptr << 16)}}});
            } else { // 0x19
                using_numbers->emplace_back(EncodeNumber{.type = DOUBLE, .value = {.L64 = {.long_value = (int64_t) (((uint64_t) *ptr) << 48)}}});
            }
            break;
        }
        case dex::k31i: { // const, const-wide/32
            if (op == 0x14) {
                using_numbers->emplace_back(EncodeNumber{.type = FLOAT, .value = {.L32 = {.int_value = (int32_t) ReadInt(ptr)}}});
            } else { // 0x17
                using_numbers->emplace_back(EncodeNumber{.type = INT, .value = {.L32 = {.int_value = (int32_t) ReadInt(ptr)}}});
            }
            break;
        }
        case dex::k51l: // const-wide
            using_numbers->emplace_back(EncodeNumber{.type = LONG, .value = {.L64 = {.long_value = (int64_t) ReadLong(ptr)}}});
            break;
        case dex::k22s: // binop/lit16
            using_numbers->emplace_back(EncodeNumber{.type = SHORT, .value = {.L16 = (int16_t) *ptr}});
            break;
        case dex::k22b: // binop/lit8
            using_numbers->emplace_back(EncodeNumber{.type = BYTE, .value = {.L8 = (int8_t) (*ptr >> 8)}});
            break;
        default:
            break;
    }
}

std::vector<EncodeNumber> DexItem::ParseUsingNumbersFromCode(uint32_t method_idx) {
    auto code = method_codes[method_idx];
    if (code == nullptr) {
        return {};
    }
    std::vector<EncodeNumber> using_numbers;
    auto p = code->insns;
    auto end_p = p + code->insns_size;
    while (p < end_p) {
        auto op = (uint8_t) *p;
        auto ptr = p;
        auto width = GetBytecodeWidth(ptr++);
        auto op_format = ins_formats[op];
        PushEncodeNumber(op_format, op, ptr, &using_numbers);
        p += width;
    }
    return using_numbers;
}

const std::vector<EncodeNumber> &DexItem::GetUsingNumbers(uint32_t method_idx) {
    if ((dex_flag.load(std::memory_order_acquire) & kUsingNumber) != 0) {
        return method_using_numbers[method_idx];
    }

    // Using-numbers remains a sparse per-method lazy cache because full warm-up cost and
    // resident memory are too high for the typical "read one method's metadata" path.
    auto &slot = lazy_using_numbers_slots[method_idx];
    auto state = slot.state.load(std::memory_order_acquire);
    if (state == static_cast<uint8_t>(LazyMethodFeatureState::Ready)) {
        return *slot.data;
    }

    uint8_t expected = static_cast<uint8_t>(LazyMethodFeatureState::Empty);
    if (slot.state.compare_exchange_strong(expected,
                                           static_cast<uint8_t>(LazyMethodFeatureState::Building),
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
        auto built_data = std::make_unique<const std::vector<EncodeNumber>>(ParseUsingNumbersFromCode(method_idx));
        auto stripe = method_idx % lazy_method_wait_mutexes->size();
        {
            std::lock_guard lock((*lazy_method_wait_mutexes)[stripe]);
            slot.data = std::move(built_data);
            slot.state.store(static_cast<uint8_t>(LazyMethodFeatureState::Ready), std::memory_order_release);
        }
        (*lazy_method_wait_cvs)[stripe].notify_all();
        return *slot.data;
    }

    auto stripe = method_idx % lazy_method_wait_mutexes->size();
    std::unique_lock lock((*lazy_method_wait_mutexes)[stripe]);
    (*lazy_method_wait_cvs)[stripe].wait(lock, [&slot] {
        return slot.state.load(std::memory_order_acquire) == static_cast<uint8_t>(LazyMethodFeatureState::Ready);
    });
    return *slot.data;
}

bool DexItem::CheckAllTypeNamesDeclared(std::vector<std::string_view> &types) {
    for (auto &type: types) { // NOLINT
        if (!this->type_ids_map.contains(NameToDescriptor(type))) {
            return false;
        }
    }
    return true;
}

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

// Format a method's full smali ref: "Lcls;->name(args)Ret".
std::string FormatMethodRef(const dex::Reader& reader,
                            const std::vector<std::string_view>& type_names,
                            const std::vector<std::string_view>& strings,
                            uint32_t method_idx) {
    if (method_idx >= reader.MethodIds().size()) return "<bad-method-idx>";
    const auto& m = reader.MethodIds()[method_idx];
    const auto& proto = reader.ProtoIds()[m.proto_idx];

    std::string out;
    out += SmaliIdent(type_names[m.class_idx]);
    out += "->";
    out += SmaliIdent(strings[m.name_idx]);
    out += '(';
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
                o << FormatMethodRef(reader, type_names, strings, v);
                break;
            default:
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
            o << "{v" << insn.vC << " .. v" << (insn.vC + insn.vA - 1) << "}, ";
            emit_index(insn.vB);
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

std::string
DexItem::RenderMethodSmali(uint32_t method_idx, const std::string& indent) const {
    if (method_idx >= reader.MethodIds().size()) return {};
    const dex::Code* code = (method_idx < method_codes.size())
                                ? method_codes[method_idx] : nullptr;

    std::ostringstream out;
    out << FormatMethodRef(reader, type_names, strings, method_idx) << "\n";
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
        std::string ops = FormatOperands(insn, reader, type_names, strings);
        if (!ops.empty()) out << " " << ops;
        out << "\n";
        p += width;
    }
    return out.str();
}

std::string DexItem::RenderClassSmali(uint32_t type_idx) const {
    if (type_idx >= type_names.size()) return {};
    if (!type_def_flag[type_idx]) return {};
    const auto& class_def = reader.ClassDefs()[type_def_idx[type_idx]];

    std::ostringstream out;
    out << ".class " << FormatAccessFlags(class_def.access_flags)
        << SmaliIdent(type_names[type_idx]) << "\n";
    out << ".super " << SmaliIdent(type_names[class_def.superclass_idx]) << "\n";
    if (class_def.source_file_idx != dex::kNoIndex) {
        out << ".source \""
            << EscapeSmaliString(strings[class_def.source_file_idx])
            << "\"\n";
    }
    if (class_def.interfaces_off != 0) {
        const auto* il = reader.dataPtr<dex::TypeList>(class_def.interfaces_off);
        if (il != nullptr) {
            for (uint32_t i = 0; i < il->size; ++i) {
                out << ".implements " << SmaliIdent(type_names[il->list[i].type_idx])
                    << "\n";
            }
        }
    }
    out << "\n";

    for (uint32_t field_idx : class_field_ids[type_idx]) {
        const auto& f = reader.FieldIds()[field_idx];
        out << ".field "
            << SmaliIdent(strings[f.name_idx])
            << ":" << SmaliIdent(type_names[f.type_idx]) << "\n";
    }
    if (!class_field_ids[type_idx].empty()) out << "\n";

    for (uint32_t m_idx : class_method_ids[type_idx]) {
        out << ".method "
            << FormatMethodRef(reader, type_names, strings, m_idx) << "\n";
        const dex::Code* code = (m_idx < method_codes.size())
                                    ? method_codes[m_idx] : nullptr;
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
                std::string ops = FormatOperands(insn, reader, type_names, strings);
                if (!ops.empty()) out << " " << ops;
                out << "\n";
                p += width;
            }
        }
        out << ".end method\n\n";
    }

    return out.str();
}


namespace {

// dexllm#16 — the control-flow join points of one code item, from a single linear
// pre-pass. `targets` are offsets reached by a FORWARD branch (mergeable: every
// predecessor's state is known by the time the scan arrives). `barriers` are offsets
// the linear scan cannot meet — a loop header (some predecessor is a BACKWARD edge,
// not yet seen) or a catch handler (reachable from any instruction of the try, with
// the register file in an unknown state) — and clear the file instead.
struct JoinPoints {
    std::unordered_set<uint32_t> targets;   // forward-only: merge on arrival
    std::unordered_set<uint32_t> back;      // has a backward edge: needs pass 2
    std::unordered_set<uint32_t> barriers;  // catch handlers: never mergeable
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

JoinPoints CollectJoinPoints(const dex::Code* code, const dex::u1* img_end) {
    JoinPoints jp;
    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;

    auto note = [&](int64_t from_byte, int64_t target_byte) {
        if (target_byte < 0 ||
            target_byte >= static_cast<int64_t>(code->insns_size) * 2) return;
        uint32_t t = static_cast<uint32_t>(target_byte);
        // A BACKWARD edge reaches its target from later in the scan (a loop, or
        // just a compiler-emitted shared tail). Its contribution is only known
        // after one full pass, so those targets are resolved on the second pass.
        if (target_byte <= from_byte) jp.back.insert(t);
        else jp.targets.insert(t);
    };

    while (p < end_p) {
        uint8_t op = static_cast<uint8_t>(*p);
        size_t width = GetBytecodeWidth(p);
        if (width == 0) break;
        int64_t off = (p - base) * 2;  // byte offset of this instruction
        switch (op) {
            case 0x28:  // goto +AA
                note(off, off + 2 * static_cast<int8_t>((*p >> 8) & 0xFF));
                break;
            case 0x29:  // goto/16 +AAAA
                note(off, off + 2 * static_cast<int16_t>(*(p + 1)));
                break;
            case 0x2A:  // goto/32 +AAAAAAAA
                note(off, off + 2 * static_cast<int64_t>(
                                    static_cast<int32_t>(ReadInt(p + 1))));
                break;
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
            case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
                // if-eq..le +CCCC / if-*z +BBBB — the offset is the last unit
                note(off, off + 2 * static_cast<int16_t>(*(p + width - 1)));
                break;
            case 0x2B: case 0x2C: {  // packed-/sparse-switch +BBBBBBBB → payload
                int64_t pay = off + 2 * static_cast<int64_t>(
                                        static_cast<int32_t>(ReadInt(p + 1)));
                if (pay < 0 || pay + 4 > static_cast<int64_t>(code->insns_size) * 2)
                    break;
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
                    note(off, off + 2 * static_cast<int64_t>(
                                      static_cast<int32_t>(ReadInt(tbl + i * 2))));
                break;
            }
            default:
                break;
        }
        p += width;
    }

    // Catch handlers: reachable from anywhere inside the try region, so the register
    // file at entry is unknown → barrier. (Mirrors ParseExceptions in the snapshot
    // builder; bounded against the mapped image.)
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
                    jp.barriers.insert(ReadUlebBounded(hp, end) * 2);
                }
                if (catch_all && hp < end)
                    jp.barriers.insert(ReadUlebBounded(hp, end) * 2);
            }
        }
    }
    // Precedence: a catch handler is never mergeable; a target with any backward
    // edge is resolved by the second pass even if it also has forward edges.
    for (uint32_t b : jp.back) jp.targets.erase(b);
    for (uint32_t b : jp.barriers) { jp.targets.erase(b); jp.back.erase(b); }
    return jp;
}

// Two tracked definitions are the same value iff kind and the kind-relevant payload
// agree. Used as the meet operator at a join: disagreement drops the register.
bool SameOrigin(const DexItem::InvokeArg& a, const DexItem::InvokeArg& b) {
    using K = DexItem::ArgKind;
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

// dexllm L4 extension — see header for contract.
//
// Light-weight forward register simulation with a MEET at control-flow joins
// (dexllm#16). Tracks the last definition of each register; at a branch target the
// fall-through state is intersected with every forward predecessor's state, so a
// definition survives only if it reaches the site on every path, and a per-path value
// degrades to Unknown+crossed_branch instead of being reported as unconditional.
// Anything we don't decode (most arithmetic etc.) clears the destination register.
std::vector<DexItem::InvokeSiteWithArgs>
DexItem::AnalyzeMethodInvokes(uint32_t method_idx) const {
    std::vector<InvokeSiteWithArgs> out;
    if (method_idx >= method_codes.size()) return out;
    const auto* code = method_codes[method_idx];
    if (code == nullptr) return out;

    // Per-register state (last known definition).
    std::unordered_map<uint16_t, InvokeArg> reg_state;
    reg_state.reserve(code->registers_size);

    // Initialise parameter registers — they sit at the high end of the file.
    uint16_t total_regs = code->registers_size;
    uint16_t param_regs = code->ins_size;
    uint16_t first_param = total_regs > param_regs
                              ? static_cast<uint16_t>(total_regs - param_regs)
                              : 0;
    auto entry_state = [&]() {
        std::unordered_map<uint16_t, InvokeArg> s;
        for (uint16_t i = 0; i < param_regs; ++i) {
            InvokeArg a;
            a.kind = ArgKind::Parameter;
            a.reg_num = static_cast<uint16_t>(first_param + i);
            a.parameter_index = static_cast<int16_t>(i);
            s[a.reg_num] = a;
        }
        return s;
    };
    reg_state = entry_state();

    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;

    uint32_t last_invoke_callee = 0;
    bool has_last_invoke = false;

    // A 64-bit value occupies vN AND vN+1. The high half must lose any tracked origin
    // too, or a stale one is reported for it (invoke-*/range lists one arg entry per
    // register, so the high half IS surfaced). Table-driven off slicer's own
    // VerifyFlags rather than a hand-kept opcode list.
    auto is_wide_dest = [](uint8_t opcode) {
        return (dex::GetVerifyFlagsFromOpcode(static_cast<dex::Opcode>(opcode)) &
                dex::kVerifyRegAWide) != 0;
    };
    auto set_reg_op = [&](uint16_t r, InvokeArg a, uint8_t opcode) {
        a.reg_num = r;
        reg_state[r] = a;
        if (is_wide_dest(opcode)) reg_state.erase(static_cast<uint16_t>(r + 1));
    };
    auto erase_reg_op = [&](uint16_t r, uint8_t opcode) {
        reg_state.erase(r);
        if (is_wide_dest(opcode)) reg_state.erase(static_cast<uint16_t>(r + 1));
    };
    uint8_t cur_op = 0;  // opcode being processed (for the wide-dest check above)
    auto set_reg = [&](uint16_t r, InvokeArg a) { set_reg_op(r, a, cur_op); };

    // dexllm#16 — join handling. `pending[T]` accumulates the MEET of every forward
    // predecessor of T seen so far (intersect-on-arrival, so one state per pending
    // target, not one per edge). `fall_through_live` is false right after an
    // unconditional transfer, where the next instruction is reachable only by branch.
    const dex::u1* img_end = nullptr;
    if (_image != nullptr)
        img_end = reinterpret_cast<const dex::u1*>(_image->data()) + _image->len();
    const JoinPoints jp = CollectJoinPoints(code, img_end);
    std::unordered_map<uint32_t, std::unordered_map<uint16_t, InvokeArg>> pending;
    bool fall_through_live = true;

    // A register that HAD a definition which a merge discarded is tombstoned rather
    // than erased, so a consumer can tell "conditional / gave up" from "never tracked".
    auto tombstone = [](uint16_t r) {
        InvokeArg a;
        a.kind = ArgKind::Unknown;
        a.reg_num = r;
        a.crossed_branch = true;
        return a;
    };
    auto meet_into = [&](std::unordered_map<uint16_t, InvokeArg>& dst,
                         const std::unordered_map<uint16_t, InvokeArg>& src) {
        for (auto it = dst.begin(); it != dst.end();) {
            auto s = src.find(it->first);
            if (s != src.end() && SameOrigin(it->second, s->second)) {
                ++it;
            } else {
                it->second = tombstone(it->first);  // differs / absent on one path
                ++it;
            }
        }
        for (const auto& kv : src)
            if (dst.find(kv.first) == dst.end()) dst[kv.first] = tombstone(kv.first);
    };
    // Crafted-input backstop: a method with a pathological number of live forward
    // branches would otherwise hold one register-file copy per pending target. Far
    // above any real method (max observed on the corpus is double digits).
    // Resource budget. `kMaxPending` bounds how many join targets may be in flight;
    // `kMaxStateEntries` bounds the TOTAL number of saved register entries, because
    // each saved state is a full copy of the register file and `registers_size` goes
    // up to 65535 — bounding only the map COUNT let a 142 KB crafted dex allocate
    // gigabytes (adversarial review). Both are far above any real method (corpus max
    // is 3 orders of magnitude below), so they bite only on crafted input.
    constexpr size_t kMaxPending = 4096;
    constexpr size_t kMaxStateEntries = 1u << 16;
    size_t saved_entries = 0;
    // A target whose predecessor state could NOT be recorded (budget exhausted). It
    // must be tombstoned wholesale at arrival: dropping an edge silently would let the
    // meet run with an INCOMPLETE predecessor set and report a one-path value as
    // unconditional — the exact defect this change removes. `pending` entries are
    // erased as the scan consumes them, so the table drains and a later edge to the
    // same target would otherwise resurrect it with only that later predecessor
    // (adversarial review: reproducible at exactly 4096 live targets). Fail CLOSED.
    std::unordered_set<uint32_t> poisoned;
    // Contribution of every BACKWARD edge, collected in pass 1 and consumed in pass 2
    // (see the two-pass loop below).
    std::unordered_map<uint32_t, std::unordered_map<uint16_t, InvokeArg>> back_in;
    std::unordered_map<uint32_t, std::unordered_map<uint16_t, InvokeArg>> back_out;
    bool collecting = true;  // pass 1 fills back_out; pass 2 reads back_in
    auto record_branch = [&](int64_t from_byte, int64_t target_byte) {
        if (target_byte < 0 ||
            target_byte >= static_cast<int64_t>(code->insns_size) * 2) return;
        uint32_t t = static_cast<uint32_t>(target_byte);
        // A forward edge into a target that ALSO has a backward edge is resolved
        // through back_out/back_in like the backward ones, so it goes to that table.
        const bool to_back = (target_byte <= from_byte) || jp.back.count(t);
        if (!to_back && !jp.targets.count(t)) return;  // catch-handler barrier
        if (to_back && !jp.back.count(t)) return;      // ditto
        auto& tbl = to_back ? back_out : pending;
        auto it = tbl.find(t);
        if (it != tbl.end()) {
            meet_into(it->second, reg_state);
            return;
        }
        if (tbl.size() >= kMaxPending ||
            saved_entries + reg_state.size() > kMaxStateEntries) {
            poisoned.insert(t);  // cannot record this predecessor → tombstone at T
            return;
        }
        saved_entries += reg_state.size();
        tbl.emplace(t, reg_state);
    };

    // dexllm#16 — TWO passes. Pass 1 resolves forward-only joins and records what each
    // backward edge carries; pass 2 replays the scan and meets that recorded state in
    // at the backward-edge targets, so a value that survives a compiler-emitted shared
    // tail (a backward `goto` that is not a loop) is recovered instead of dropped.
    // Sound by monotonicity: pass 1's states are ⊑ the true fixed point (barriers only
    // remove entries), and meeting with a ⊑ state can only remove more — never invent
    // a value. Only pass 2 emits sites. Two passes, not a fixed point: a value defined
    // only BEFORE a genuine loop does not survive its header (pass 1 tombstoned the
    // header, so the back edge carries that tombstone); a value the loop re-establishes
    // identically does survive.
  for (int pass = 0; pass < 2; ++pass) {
    collecting = (pass == 0);
    if (pass == 1) {
        back_in = std::move(back_out);
        back_out.clear();
        out.clear();
        reg_state = entry_state();
        pending.clear();
        saved_entries = 0;  // `poisoned` is NOT reset — poisoning is monotone (safe)
        fall_through_live = true;
        has_last_invoke = false;
        p = base;
    }

    while (p < end_p) {
        const uint32_t cur_off = static_cast<uint32_t>((p - base) * 2);
        if (jp.barriers.count(cur_off)) {
            // Catch handler: reachable from any point of the try with the register
            // file in an unknown state → drop everything, tombstoned so the reason
            // stays visible.
            for (auto& kv : reg_state) kv.second = tombstone(kv.first);
            has_last_invoke = false;
            fall_through_live = true;
        } else if (jp.back.count(cur_off)) {
            // Target of a backward edge. Pass 1 has no information about it yet; pass 2
            // meets in everything recorded for it (both its backward and forward edges).
            auto it = back_in.find(cur_off);
            if (collecting || poisoned.count(cur_off) || it == back_in.end()) {
                for (auto& kv : reg_state) kv.second = tombstone(kv.first);
            } else if (fall_through_live) {
                meet_into(reg_state, it->second);
            } else {
                reg_state = it->second;
            }
            has_last_invoke = false;
            fall_through_live = true;
        } else if (jp.targets.count(cur_off)) {
            auto it = pending.find(cur_off);
            const size_t freed = (it == pending.end()) ? 0 : it->second.size();
            if (poisoned.count(cur_off) || it == pending.end()) {
                // An unrecorded predecessor exists (budget) — nothing may be asserted.
                for (auto& kv : reg_state) kv.second = tombstone(kv.first);
            } else if (fall_through_live) {
                meet_into(reg_state, it->second);
            } else {
                reg_state = std::move(it->second);
            }
            if (it != pending.end()) {
                saved_entries -= std::min(saved_entries, freed);
                pending.erase(it);
            }
            has_last_invoke = false;  // move-result must follow its invoke directly
            fall_through_live = true;
        }

        uint16_t insn = *p;
        uint8_t op = static_cast<uint8_t>(insn);
        cur_op = op;
        size_t width = GetBytecodeWidth(p);
        if (width == 0) break;

        const uint16_t AA = (insn >> 8) & 0xFF;
        const uint8_t A = (insn >> 8) & 0x0F;
        const uint8_t B = (insn >> 12) & 0x0F;

        switch (op) {
            // ---- transfers of control (dexllm#16) ----
            // The state is no longer wiped here: a definition made BEFORE a branch
            // still reaches uses that the branch dominates. It is published to the
            // target's pending meet, and the meet happens AT the target (above).
            case 0x0E: case 0x0F: case 0x10: case 0x11:  // return*
            case 0x27:                                    // throw
                reg_state.clear();          // nothing falls through
                has_last_invoke = false;
                fall_through_live = false;
                break;
            case 0x28:                                    // goto +AA
                record_branch(cur_off, cur_off + 2 * static_cast<int8_t>(AA));
                reg_state.clear();
                has_last_invoke = false;
                fall_through_live = false;
                break;
            case 0x29:                                    // goto/16 +AAAA
                record_branch(cur_off, cur_off + 2 * static_cast<int16_t>(*(p + 1)));
                reg_state.clear();
                has_last_invoke = false;
                fall_through_live = false;
                break;
            case 0x2A:                                    // goto/32 +AAAAAAAA
                record_branch(cur_off,
                              cur_off + 2 * static_cast<int64_t>(
                                              static_cast<int32_t>(ReadInt(p + 1))));
                reg_state.clear();
                has_last_invoke = false;
                fall_through_live = false;
                break;
            case 0x2B: case 0x2C: {                       // packed/sparse-switch
                // Case targets come from the payload table; the switch itself falls
                // through when no case matches (that is the default edge).
                int64_t pay = cur_off + 2 * static_cast<int64_t>(
                                            static_cast<int32_t>(ReadInt(p + 1)));
                if (pay >= 0 && pay + 4 <= static_cast<int64_t>(code->insns_size) * 2) {
                    const dex::u2* t = base + pay / 2;
                    uint16_t ident = *t, size = *(t + 1);
                    const dex::u2* tbl = nullptr;
                    if (op == 0x2B && ident == 0x0100) tbl = t + 4;
                    else if (op == 0x2C && ident == 0x0200) tbl = t + 2 + size * 2;
                    if (tbl != nullptr &&
                        tbl + static_cast<size_t>(size) * 2 <= end_p) {
                        for (uint16_t i = 0; i < size; ++i)
                            record_branch(cur_off,
                                          cur_off + 2 * static_cast<int64_t>(
                                                        static_cast<int32_t>(
                                                            ReadInt(tbl + i * 2))));
                    }
                }
                has_last_invoke = false;
                break;
            }
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:  // if-eq..le
            case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:  // if-*z
                record_branch(cur_off,
                              cur_off + 2 * static_cast<int16_t>(*(p + width - 1)));
                has_last_invoke = false;  // fall-through keeps the register file
                break;

            // ---- move family: propagate state from src register ----
            case 0x01: case 0x04: case 0x07: {  // move{,-wide,-object} vA, vB
                auto it = reg_state.find(B);
                if (it != reg_state.end()) set_reg(A, it->second);
                else erase_reg_op(A, op);
                has_last_invoke = false;
                break;
            }
            case 0x02: case 0x05: case 0x08: {  // move/from16
                uint16_t src = *(p + 1);
                auto it = reg_state.find(src);
                if (it != reg_state.end()) set_reg(AA, it->second);
                else erase_reg_op(AA, op);
                has_last_invoke = false;
                break;
            }
            case 0x03: case 0x06: case 0x09: {  // move/16
                uint16_t dst = *(p + 1);
                uint16_t src = *(p + 2);
                auto it = reg_state.find(src);
                if (it != reg_state.end()) set_reg(dst, it->second);
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
                int16_t v = static_cast<int16_t>(*(p + 1));
                InvokeArg a;
                a.kind = (v == 0) ? ArgKind::ConstNull : ArgKind::ConstInt;
                a.int_value = v;
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- const vAA, #+BBBBBBBB ----
            case 0x14: {
                int32_t v = static_cast<int32_t>(ReadInt(p + 1));
                InvokeArg a;
                a.kind = ArgKind::ConstInt;
                a.int_value = v;
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- const/high16 vAA, #+BBBB0000 ----
            case 0x15: {
                int32_t v = static_cast<int32_t>(*(p + 1)) << 16;
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
                if (op == 0x16)       v = static_cast<int16_t>(*(p + 1));
                else if (op == 0x17)  v = static_cast<int32_t>(ReadInt(p + 1));
                else if (op == 0x18)  v = static_cast<int64_t>(ReadLong(p + 1));
                else                  v = static_cast<int64_t>(*(p + 1)) << 48;
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
                a.string_idx = *(p + 1);
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- const-string/jumbo vAA, string@BBBBBBBB ----
            case 0x1B: {
                InvokeArg a;
                a.kind = ArgKind::ConstString;
                a.string_idx = ReadInt(p + 1);
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- const-class vAA, type@BBBB ----
            case 0x1C: {
                InvokeArg a;
                a.kind = ArgKind::ConstClass;
                a.type_idx = *(p + 1);
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- new-instance vAA, type@BBBB ----
            case 0x22: {
                InvokeArg a;
                a.kind = ArgKind::NewInstance;
                a.type_idx = *(p + 1);
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }
            // ---- new-array vA, vB, type@CCCC ----
            case 0x23: {
                InvokeArg a;
                a.kind = ArgKind::NewArray;
                a.type_idx = *(p + 1);
                set_reg(A, a);
                has_last_invoke = false;
                break;
            }

            // ---- iget* family: writes to vA from field@CCCC ----
            case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                InvokeArg a;
                a.kind = ArgKind::FieldRead;
                a.field_idx = *(p + 1);
                set_reg(A, a);
                has_last_invoke = false;
                break;
            }
            // ---- sget* family: writes to vAA from field@BBBB ----
            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                InvokeArg a;
                a.kind = ArgKind::FieldRead;
                a.field_idx = *(p + 1);
                set_reg(AA, a);
                has_last_invoke = false;
                break;
            }

            // ---- invoke-kind {C..G}, method@BBBB (format 35c) ----
            case 0x6E: case 0x6F: case 0x70: case 0x71: case 0x72: {
                uint8_t arg_count = B;  // high nibble of insn>>8
                uint8_t G = A;          // low nibble of insn>>8
                uint16_t callee_idx = *(p + 1);
                uint16_t pack = *(p + 2);
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

                InvokeSiteWithArgs site;
                site.method_idx = callee_idx;
                site.bytecode_offset = static_cast<uint32_t>((p - base) * 2);
                site.opcode = op;
                for (auto r : regs) {
                    auto it = reg_state.find(r);
                    InvokeArg a = (it != reg_state.end()) ? it->second : InvokeArg{};
                    a.reg_num = r;
                    site.args.push_back(a);
                }
                out.push_back(std::move(site));
                last_invoke_callee = callee_idx;
                has_last_invoke = true;
                break;
            }
            // ---- invoke-kind/range {CCCC..NNNN}, method@BBBB (format 3rc) ----
            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                uint8_t arg_count = AA;
                uint16_t callee_idx = *(p + 1);
                uint16_t first_reg = *(p + 2);
                InvokeSiteWithArgs site;
                site.method_idx = callee_idx;
                site.bytecode_offset = static_cast<uint32_t>((p - base) * 2);
                site.opcode = op;
                for (uint8_t i = 0; i < arg_count; ++i) {
                    uint16_t r = static_cast<uint16_t>(first_reg + i);
                    auto it = reg_state.find(r);
                    InvokeArg a = (it != reg_state.end()) ? it->second : InvokeArg{};
                    a.reg_num = r;
                    site.args.push_back(a);
                }
                out.push_back(std::move(site));
                last_invoke_callee = callee_idx;
                has_last_invoke = true;
                break;
            }

            // ---- Untracked writers to vAA (clear dest to avoid stale state) ----
            // move-exception (0x0D), cmp-* (0x2D-0x31), aget* (0x44-0x4A),
            // binary 23x (0x90-0xAF), binary/lit/8 (0xD8-0xE2, format k22b = `vAA, vBB, #+CC`),
            // const-method-handle/type (0xFE/0xFF, format 21c = `vAA, …`).
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
            // binary/2addr (0xB0-0xCF), binary/lit/16 (0xD0-0xD7, format k22s = `vA, vB, #+CCCC`).
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

            default:
                has_last_invoke = false;
                break;
        }
        p += width;
    }
    // Nothing carries a backward edge → pass 2 would replay identically.
    if (pass == 0 && back_out.empty() && jp.back.empty()) break;
  }

    return out;
}

// dexllm L2.5 extension — see header for contract.
std::vector<DexItem::InvokeSite>
DexItem::EnumerateInvokeSites(uint32_t method_idx) const {
    std::vector<InvokeSite> out;
    if (method_idx >= method_codes.size()) return out;
    const auto* code = method_codes[method_idx];
    if (code == nullptr) return out;

    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;
    while (p < end_p) {
        uint8_t op = static_cast<uint8_t>(*p);
        const dex::u2* ptr = p;
        size_t width = GetBytecodeWidth(ptr++);
        if (width == 0) break;  // malformed / NOP-data
        if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
            InvokeSite site;
            site.method_idx = ReadShort(ptr);
            site.bytecode_offset = static_cast<uint32_t>((p - base) * 2);
            site.opcode = op;
            out.push_back(site);
        }
        p += width;
    }
    return out;
}

}
