// instruction.cpp — DAD instruction.py port (chunk 1).
// See include/instruction.h for status and per-class DAD references.
//
// DAD: androguard/decompiler/instruction.py

#include "instruction.h"

#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include "util.h"

namespace dexkit::dad {

namespace {

// list(set(used_vars)) helper — Python set dedupe then list() conversion.
// Order of resulting list is implementation-defined in Python (insertion in
// 3.7+ but set is unordered); we match the dedup semantics, not the order.
std::vector<std::string> Dedup(std::vector<std::string>&& src) {
    std::unordered_set<std::string> seen;
    seen.reserve(src.size());
    std::vector<std::string> out;
    out.reserve(src.size());
    for (auto& s : src) {
        if (seen.insert(s).second) out.push_back(std::move(s));
    }
    return out;
}

}  // namespace

// ---- IRForm ----------------------------------------------------------------

// DAD: instruction.py:53 replace
void IRForm::replace(const std::string& /*old*/, const IRFormPtr& /*new_*/) {
    throw std::logic_error("replace not implemented");
}
// DAD: instruction.py:56 replace_lhs
void IRForm::replace_lhs(const IRFormPtr& /*new_*/) {
    throw std::logic_error("replace_lhs not implemented");
}
// DAD: instruction.py:59 replace_var
void IRForm::replace_var(const std::string& /*old*/, const IRFormPtr& /*new_*/) {
    throw std::logic_error("replace_var not implemented");
}

// ---- Constant --------------------------------------------------------------

namespace {

// Match Python's repr() output for ints/floats/strings closely enough for
// __str__ parity. DAD's __str__ is 'CST_%s' % repr(self.cst).
std::string PyReprLike(const ConstantValue& v) {
    return std::visit([](auto&& x) -> std::string {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, std::string>) {
            // Python repr() of a string wraps in single quotes.
            return "'" + x + "'";
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(x);
        } else { // double
            std::ostringstream os;
            os << x;
            return os.str();
        }
    }, v);
}

// Build the leading 'c<value>' v-field for Constant/BaseClass.
// Python's `'c%s' % value` uses str(value), which differs from repr() for
// strings (no quotes). Reproduce here.
std::string PyStrLike(const ConstantValue& v) {
    return std::visit([](auto&& x) -> std::string {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, std::string>) {
            return x;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(x);
        } else {
            std::ostringstream os;
            os << x;
            return os.str();
        }
    }, v);
}

}  // namespace

// DAD: instruction.py:75 Constant.__init__
Constant::Constant(ConstantValue value,
                   std::string_view atype,
                   std::optional<int64_t> int_value,
                   std::string_view descriptor) {
    cst_ = value;
    v_ = "c" + PyStrLike(value);
    if (int_value.has_value()) {
        cst2_ = *int_value;
    } else {
        // Python's `cst2 = value` keeps whatever value was; we coerce to
        // int64_t when possible, else 0.
        cst2_ = std::visit([](auto&& x) -> int64_t {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, int64_t>) {
                return x;
            } else if constexpr (std::is_same_v<T, double>) {
                return static_cast<int64_t>(x);
            } else {
                // For string-typed constants the Python code keeps the
                // string in .cst2 (since `cst2 = value`); we lose the
                // value but most code paths use get_int_value() only for
                // primitive constants where int_value is supplied or value
                // itself is numeric. Document the deviation.
                return 0;
            }
        }, value);
    }
    type = std::string{atype};
    clsdesc_ = std::string{descriptor};
}

// DAD: instruction.py:119 __str__
std::string Constant::ToString() const {
    return "CST_" + PyReprLike(cst_);
}

// ---- BaseClass -------------------------------------------------------------

// DAD: instruction.py:123 BaseClass.__init__(name, descriptor=None)
BaseClass::BaseClass(std::string_view name, std::string_view descriptor) {
    v_ = "c" + std::string{name};
    cls_ = std::string{name};
    clsdesc_ = std::string{descriptor};
}

// DAD: instruction.py:136 __str__
std::string BaseClass::ToString() const {
    return "BASECLASS_" + cls_;
}

// ---- Variable --------------------------------------------------------------

// DAD: instruction.py:140 Variable.__init__(value)
Variable::Variable(std::string_view value)
    : v_(value) {
    declared = false;
    type.clear();  // DAD sets self.type = None — empty string is our nearest.
    name = std::string{value};
}

// DAD: instruction.py:162 __str__
std::string Variable::ToString() const {
    return "VAR_" + name;
}

// ---- Param -----------------------------------------------------------------

// DAD: instruction.py:166 Param.__init__(value, atype)
Param::Param(std::string_view value, std::string_view atype)
    : Variable(value) {
    declared = true;
    type = std::string{atype};
    this_flag = false;
}

// DAD: instruction.py:179 __str__
std::string Param::ToString() const {
    return "PARAM_" + name;
}

// ---- ThisParam -------------------------------------------------------------

// DAD: instruction.py:183 ThisParam.__init__(value, atype)
ThisParam::ThisParam(std::string_view value, std::string_view atype)
    : Param(value, atype) {
    this_flag = true;
    super_flag = false;
}

// DAD: instruction.py:194 __str__
std::string ThisParam::ToString() const {
    return "THIS";
}

// ---- AssignExpression ------------------------------------------------------

// DAD: instruction.py:199 AssignExpression.__init__(lhs, rhs)
AssignExpression::AssignExpression(IRFormPtr lhs, IRFormPtr rhs) {
    if (lhs) {
        std::string vid = lhs->Vid();
        lhs_ = vid;
        var_map[vid] = lhs;
        // DAD: instruction.py:204 lhs.set_type(rhs.get_type())
        lhs->set_type(rhs->get_type());
    }
    rhs_ = std::move(rhs);
}

// DAD: instruction.py:209
bool AssignExpression::is_propagable() const noexcept {
    return rhs_ ? rhs_->is_propagable() : true;
}
// DAD: instruction.py:212
bool AssignExpression::is_call() const noexcept {
    return rhs_ ? rhs_->is_call() : false;
}
// DAD: instruction.py:215
bool AssignExpression::has_side_effect() const noexcept {
    return rhs_ ? rhs_->has_side_effect() : false;
}
// DAD: instruction.py:218 — DAD returns the single rhs IRForm; the
// base IRForm::get_rhs() shape returns a vector, so we wrap.
std::vector<IRFormPtr> AssignExpression::get_rhs() const {
    if (!rhs_) return {};
    return {rhs_};
}
// DAD: instruction.py:221
std::optional<std::string> AssignExpression::GetLhsId() const {
    return lhs_;
}
// DAD: instruction.py:224
std::vector<std::string> AssignExpression::get_used_vars() const {
    return rhs_ ? rhs_->get_used_vars() : std::vector<std::string>{};
}
// DAD: instruction.py:227 — `self.lhs = None`
void AssignExpression::remove_defined_var() {
    lhs_.reset();
}
// DAD: instruction.py:230 — recurse into rhs.
void AssignExpression::replace(const std::string& old_v,
                               const IRFormPtr& new_node) {
    if (rhs_) rhs_->replace(old_v, new_node);
}
// DAD: instruction.py:233
void AssignExpression::replace_lhs(const IRFormPtr& new_node) {
    if (!new_node) {
        lhs_.reset();
        return;
    }
    std::string vid = new_node->Vid();
    lhs_ = vid;
    var_map[vid] = new_node;
}
// DAD: instruction.py:237
void AssignExpression::replace_var(const std::string& old_v,
                                   const IRFormPtr& new_node) {
    if (rhs_) rhs_->replace_var(old_v, new_node);
}
// DAD: instruction.py:243 — `'ASSIGN({}, {})'.format(self.var_map.get(self.lhs), self.rhs)`
// Python's `var_map.get(lhs)` returns None when lhs is None or missing; we
// match by emitting "None" (Python's default str(None)) in that case.
std::string AssignExpression::ToString() const {
    std::string lhs_text = "None";
    if (lhs_.has_value()) {
        auto it = var_map.find(*lhs_);
        if (it != var_map.end() && it->second) {
            lhs_text = it->second->ToString();
        }
    }
    std::string rhs_text = "None";
    if (rhs_) rhs_text = rhs_->ToString();
    return "ASSIGN(" + lhs_text + ", " + rhs_text + ")";
}

// ---- MoveExpression --------------------------------------------------------

// DAD: instruction.py:248 MoveExpression.__init__(lhs, rhs)
MoveExpression::MoveExpression(IRFormPtr lhs, IRFormPtr rhs) {
    // Malformed bytecode (e.g. move-result with no preceding invoke) can leave
    // an operand null. DAD raises AttributeError on None here and the caller
    // skips the method; throw to match (a segfault would be a divergence).
    if (!lhs || !rhs) {
        throw std::runtime_error("malformed bytecode: null operand to MoveExpression");
    }
    lhs_ = lhs->Vid();
    rhs_ = rhs->Vid();
    var_map[lhs->Vid()] = lhs;
    var_map[rhs->Vid()] = rhs;
    // DAD: instruction.py:253 lhs.set_type(rhs.get_type())
    lhs->set_type(rhs->get_type());
}

// DAD: instruction.py:258
bool MoveExpression::is_call() const noexcept {
    auto it = var_map.find(rhs_);
    return (it != var_map.end() && it->second) ? it->second->is_call() : false;
}
// DAD: instruction.py:261
std::vector<std::string> MoveExpression::get_used_vars() const {
    auto it = var_map.find(rhs_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}
// DAD: instruction.py:264
std::vector<IRFormPtr> MoveExpression::get_rhs() const {
    auto it = var_map.find(rhs_);
    if (it != var_map.end() && it->second) return {it->second};
    return {};
}
// DAD: instruction.py:267
std::optional<std::string> MoveExpression::GetLhsId() const {
    return lhs_;
}
// DAD: instruction.py:274 — context-sensitive replace.
void MoveExpression::replace(const std::string& old_v,
                             const IRFormPtr& new_node) {
    auto it = var_map.find(rhs_);
    IRFormPtr current_rhs = (it != var_map.end()) ? it->second : nullptr;
    if (!current_rhs) return;
    if (!(current_rhs->is_const() || current_rhs->is_ident())) {
        // Non-trivial rhs: recurse so the deeper expression handles the swap.
        current_rhs->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            // Re-point rhs at the new identifier.
            std::string new_vid = new_node->Vid();
            var_map[new_vid] = new_node;
            rhs_ = new_vid;
        } else {
            // Constant-fold style: install new under the OLD key so existing
            // references keep working.
            var_map[old_v] = new_node;
        }
    }
}
// DAD: instruction.py:286
void MoveExpression::replace_lhs(const IRFormPtr& new_node) {
    if (lhs_ != rhs_) var_map.erase(lhs_);
    if (new_node) {
        lhs_ = new_node->Vid();
        var_map[new_node->Vid()] = new_node;
    }
}
// DAD: instruction.py:292
void MoveExpression::replace_var(const std::string& old_v,
                                 const IRFormPtr& new_node) {
    if (lhs_ != old_v) var_map.erase(old_v);
    if (new_node) {
        rhs_ = new_node->Vid();
        var_map[new_node->Vid()] = new_node;
    }
}
// DAD: instruction.py:298 — `'{} = {}'.format(v_m.get(lhs), v_m.get(rhs))`
std::string MoveExpression::ToString() const {
    auto lhs_it = var_map.find(lhs_);
    auto rhs_it = var_map.find(rhs_);
    std::string lhs_text = (lhs_it != var_map.end() && lhs_it->second)
                               ? lhs_it->second->ToString() : "None";
    std::string rhs_text = (rhs_it != var_map.end() && rhs_it->second)
                               ? rhs_it->second->ToString() : "None";
    return lhs_text + " = " + rhs_text;
}

// ---- MoveResultExpression --------------------------------------------------

// DAD: instruction.py:304
MoveResultExpression::MoveResultExpression(IRFormPtr lhs, IRFormPtr rhs)
    : MoveExpression(std::move(lhs), std::move(rhs)) {}

// DAD: instruction.py:307
bool MoveResultExpression::is_propagable() const noexcept {
    auto it = var_map.find(rhs_);
    return (it != var_map.end() && it->second)
            ? it->second->is_propagable() : true;
}
// DAD: instruction.py:310
bool MoveResultExpression::has_side_effect() const noexcept {
    auto it = var_map.find(rhs_);
    return (it != var_map.end() && it->second)
            ? it->second->has_side_effect() : false;
}
// DAD: instruction.py:317 — same shape as MoveExpression.
std::string MoveResultExpression::ToString() const {
    return MoveExpression::ToString();
}

// ---- ArrayStoreInstruction -------------------------------------------------

// DAD: instruction.py:323
ArrayStoreInstruction::ArrayStoreInstruction(IRFormPtr rhs, IRFormPtr array,
                                             IRFormPtr index,
                                             std::string_view atype) {
    rhs_   = rhs->Vid();
    array_ = array->Vid();
    index_ = index->Vid();
    var_map[rhs_]   = rhs;
    var_map[array_] = array;
    var_map[index_] = index;
    type = std::string{atype};
}

// DAD: instruction.py:334
std::vector<std::string> ArrayStoreInstruction::get_used_vars() const {
    auto a = var_map.find(array_), i = var_map.find(index_),
         r = var_map.find(rhs_);
    std::vector<std::string> tmp;
    if (a != var_map.end() && a->second) {
        auto v = a->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (i != var_map.end() && i->second) {
        auto v = i->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (r != var_map.end() && r->second) {
        auto v = r->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

// DAD: instruction.py:347
void ArrayStoreInstruction::replace_var(const std::string& old_v,
                                        const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (rhs_   == old_v) rhs_   = new_v;
    if (array_ == old_v) array_ = new_v;
    if (index_ == old_v) index_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

// DAD: instruction.py:357
void ArrayStoreInstruction::replace(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_const() || arg->is_ident())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (rhs_   == old_v) rhs_   = new_v;
                if (array_ == old_v) array_ = new_v;
                // DAD: instruction.py:371 — known DAD bug: assigns to .array
                // when matching .index. We replicate exactly (deferred fix).
                if (index_ == old_v) array_ = new_v;
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const std::string& v : {array_, index_, rhs_}) {
            auto it2 = var_map.find(v);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_const() || it2->second->is_ident())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

// DAD: instruction.py:379
std::string ArrayStoreInstruction::ToString() const {
    auto a = var_map.find(array_), i = var_map.find(index_),
         r = var_map.find(rhs_);
    std::string at = (a != var_map.end() && a->second) ? a->second->ToString() : "None";
    std::string it_ = (i != var_map.end() && i->second) ? i->second->ToString() : "None";
    std::string rt = (r != var_map.end() && r->second) ? r->second->ToString() : "None";
    return at + "[" + it_ + "] = " + rt;
}

// ---- StaticInstruction -----------------------------------------------------

// DAD: instruction.py:387
StaticInstruction::StaticInstruction(IRFormPtr rhs, std::string_view klass,
                                     std::string_view ftype,
                                     std::string_view name) {
    rhs_ = rhs->Vid();
    cls_ = GetType(klass);             // DAD: util.get_type(klass)
    ftype_ = std::string{ftype};
    name_ = std::string{name};
    var_map[rhs_] = rhs;
    clsdesc_ = std::string{klass};
}

// DAD: instruction.py:400
std::vector<std::string> StaticInstruction::get_used_vars() const {
    auto it = var_map.find(rhs_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

// DAD: instruction.py:411
void StaticInstruction::replace_var(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    rhs_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

// DAD: instruction.py:416
void StaticInstruction::replace(const std::string& old_v,
                                const IRFormPtr& new_node) {
    auto it = var_map.find(rhs_);
    IRFormPtr rhs = (it != var_map.end()) ? it->second : nullptr;
    if (!rhs) return;
    if (!(rhs->is_const() || rhs->is_ident())) {
        rhs->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            rhs_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// DAD: instruction.py:428
std::string StaticInstruction::ToString() const {
    auto it = var_map.find(rhs_);
    std::string rhs_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return cls_ + "." + name_ + " = " + rhs_text;
}

// ---- InstanceInstruction ---------------------------------------------------

// DAD: instruction.py:433
InstanceInstruction::InstanceInstruction(IRFormPtr rhs, IRFormPtr lhs,
                                         std::string_view klass,
                                         std::string_view atype,
                                         std::string_view name) {
    lhs_ = lhs->Vid();
    rhs_ = rhs->Vid();
    atype_ = std::string{atype};
    cls_ = GetType(klass);
    name_ = std::string{name};
    var_map[lhs_] = lhs;
    var_map[rhs_] = rhs;
    clsdesc_ = std::string{klass};
}

// DAD: instruction.py:447
std::vector<std::string> InstanceInstruction::get_used_vars() const {
    auto l = var_map.find(lhs_), r = var_map.find(rhs_);
    std::vector<std::string> tmp;
    if (l != var_map.end() && l->second) {
        auto v = l->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (r != var_map.end() && r->second) {
        auto v = r->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

// DAD: instruction.py:462
void InstanceInstruction::replace_var(const std::string& old_v,
                                      const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (lhs_ == old_v) lhs_ = new_v;
    if (rhs_ == old_v) rhs_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

// DAD: instruction.py:470
void InstanceInstruction::replace(const std::string& old_v,
                                  const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_const() || arg->is_ident())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (lhs_ == old_v) lhs_ = new_v;
                if (rhs_ == old_v) rhs_ = new_v;
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const std::string& v : {lhs_, rhs_}) {
            auto it2 = var_map.find(v);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_const() || it2->second->is_ident())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

// DAD: instruction.py:490
std::string InstanceInstruction::ToString() const {
    auto l = var_map.find(lhs_), r = var_map.find(rhs_);
    std::string lt = (l != var_map.end() && l->second) ? l->second->ToString() : "None";
    std::string rt = (r != var_map.end() && r->second) ? r->second->ToString() : "None";
    return lt + "." + name_ + " = " + rt;
}

// ---- NewInstance -----------------------------------------------------------

// DAD: instruction.py:496
NewInstance::NewInstance(std::string_view ins_type) {
    type = std::string{ins_type};
}

// DAD: instruction.py:512
std::string NewInstance::ToString() const {
    return "NEW(" + type + ")";
}

// ---- InvokeInstruction -----------------------------------------------------

// DAD: instruction.py:517
InvokeInstruction::InvokeInstruction(std::string_view clsname,
                                     std::string_view name,
                                     IRFormPtr base,
                                     std::string_view rtype,
                                     const std::vector<std::string>& ptype,
                                     const std::vector<IRFormPtr>& args,
                                     const Triple& triple) {
    cls_ = std::string{clsname};
    name_ = std::string{name};
    base_ = base->Vid();
    rtype_ = std::string{rtype};
    ptype_ = ptype;
    for (const auto& a : args) args_.push_back(a->Vid());
    var_map[base_] = base;
    for (const auto& a : args) var_map[a->Vid()] = a;
    triple_ = triple;
    // DAD: instruction.py:530 assert triple[1] == name
    if (triple_[1] != name_) {
        throw std::logic_error("InvokeInstruction: triple[1] != name");
    }
}

// DAD: instruction.py:532
std::string InvokeInstruction::get_type() const {
    if (name_ == "<init>") {
        auto it = var_map.find(base_);
        if (it != var_map.end() && it->second) return it->second->get_type();
    }
    return rtype_;
}

// DAD: instruction.py:543
void InvokeInstruction::replace_var(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (base_ == old_v) base_ = new_v;
    std::vector<std::string> new_args;
    new_args.reserve(args_.size());
    for (const auto& a : args_) {
        new_args.push_back(a == old_v ? new_v : a);
    }
    args_ = std::move(new_args);
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

// DAD: instruction.py:556
void InvokeInstruction::replace(const std::string& old_v,
                                const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_ident() || arg->is_const())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (base_ == old_v) base_ = new_v;
                std::vector<std::string> new_args;
                new_args.reserve(args_.size());
                for (const auto& a : args_) {
                    new_args.push_back(a == old_v ? new_v : a);
                }
                args_ = std::move(new_args);
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        auto base_it = var_map.find(base_);
        if (base_it != var_map.end() && base_it->second &&
            !(base_it->second->is_ident() || base_it->second->is_const())) {
            base_it->second->replace(old_v, new_node);
        }
        for (const auto& arg_id : args_) {
            auto a_it = var_map.find(arg_id);
            if (a_it == var_map.end() || !a_it->second) continue;
            if (!(a_it->second->is_ident() || a_it->second->is_const())) {
                a_it->second->replace(old_v, new_node);
            }
        }
    }
}

// DAD: instruction.py:585
std::vector<std::string> InvokeInstruction::get_used_vars() const {
    std::vector<std::string> tmp;
    for (const auto& arg_id : args_) {
        auto it = var_map.find(arg_id);
        if (it != var_map.end() && it->second) {
            auto v = it->second->get_used_vars();
            tmp.insert(tmp.end(), v.begin(), v.end());
        }
    }
    auto b = var_map.find(base_);
    if (b != var_map.end() && b->second) {
        auto v = b->second->get_used_vars();
        tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

// DAD: instruction.py:600
std::string InvokeInstruction::ToString() const {
    auto b = var_map.find(base_);
    std::string base_text = (b != var_map.end() && b->second)
                                ? b->second->ToString() : "None";
    std::string args_text;
    for (size_t i = 0; i < args_.size(); ++i) {
        if (i > 0) args_text += ", ";
        auto it = var_map.find(args_[i]);
        args_text += (it != var_map.end() && it->second)
                         ? it->second->ToString() : "None";
    }
    return base_text + "." + name_ + "(" + args_text + ")";
}

// ---- InvokeRangeInstruction ------------------------------------------------

// DAD: instruction.py:610 — args.pop(0) → base; the remainder passes through.
InvokeRangeInstruction::InvokeRangeInstruction(
        std::string_view clsname, std::string_view name,
        std::string_view rtype,
        const std::vector<std::string>& ptype,
        std::vector<IRFormPtr> args, const Triple& triple)
    : InvokeInstruction(clsname, name,
                        args.empty() ? nullptr : args.front(),
                        rtype, ptype,
                        args.empty()
                            ? std::vector<IRFormPtr>{}
                            : std::vector<IRFormPtr>(args.begin() + 1,
                                                     args.end()),
                        triple) {}

// ---- InvokeStaticInstruction (override get_used_vars) ----------------------

// DAD: instruction.py:624 — args only, no base.
std::vector<std::string> InvokeStaticInstruction::get_used_vars() const {
    std::vector<std::string> tmp;
    for (const auto& arg_id : args_) {
        auto it = var_map.find(arg_id);
        if (it != var_map.end() && it->second) {
            auto v = it->second->get_used_vars();
            tmp.insert(tmp.end(), v.begin(), v.end());
        }
    }
    return Dedup(std::move(tmp));
}

// ---- ReturnInstruction -----------------------------------------------------

// DAD: instruction.py:633
ReturnInstruction::ReturnInstruction(IRFormPtr arg) {
    if (arg) {
        arg_ = arg->Vid();
        var_map[*arg_] = arg;
    }
}

// DAD: instruction.py:640
std::vector<std::string> ReturnInstruction::get_used_vars() const {
    if (!arg_.has_value()) return {};
    auto it = var_map.find(*arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

// DAD: instruction.py:654
void ReturnInstruction::replace_var(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    if (!new_node) return;
    arg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[*arg_] = new_node;
}

// DAD: instruction.py:659
void ReturnInstruction::replace(const std::string& old_v,
                                const IRFormPtr& new_node) {
    if (!arg_.has_value()) return;
    auto it = var_map.find(*arg_);
    IRFormPtr arg = (it != var_map.end()) ? it->second : nullptr;
    if (!arg) return;
    if (!(arg->is_const() || arg->is_ident())) {
        arg->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            arg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// DAD: instruction.py:671
std::string ReturnInstruction::ToString() const {
    if (!arg_.has_value()) return "RETURN";
    auto it = var_map.find(*arg_);
    std::string arg_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "RETURN(" + arg_text + ")";
}

// ---- SwitchExpression ------------------------------------------------------

// DAD: instruction.py:692
SwitchExpression::SwitchExpression(IRFormPtr src, int32_t branch)
    : branch_(branch) {
    src_ = src->Vid();
    var_map[src_] = src;
}

// DAD: instruction.py:698
std::vector<std::string> SwitchExpression::get_used_vars() const {
    auto it = var_map.find(src_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

// DAD: instruction.py:704
void SwitchExpression::replace_var(const std::string& old_v,
                                   const IRFormPtr& new_node) {
    if (!new_node) return;
    src_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[src_] = new_node;
}

// DAD: instruction.py:709
void SwitchExpression::replace(const std::string& old_v,
                               const IRFormPtr& new_node) {
    auto it = var_map.find(src_);
    IRFormPtr src = (it != var_map.end()) ? it->second : nullptr;
    if (!src) return;
    if (!(src->is_const() || src->is_ident())) {
        src->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            src_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// DAD: instruction.py:721
std::string SwitchExpression::ToString() const {
    auto it = var_map.find(src_);
    std::string src_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "SWITCH(" + src_text + ")";
}

// ---- CheckCastExpression ---------------------------------------------------

// DAD: instruction.py:726
CheckCastExpression::CheckCastExpression(IRFormPtr arg,
                                         std::string_view /*atype*/,
                                         std::string_view descriptor) {
    arg_ = arg->Vid();
    var_map[arg_] = arg;
    // DAD: instruction.py:730 self.type = descriptor (not the `atype` param —
    // upstream DAD assigns descriptor for both fields).
    type = std::string{descriptor};
    clsdesc_ = std::string{descriptor};
}

// DAD: instruction.py:734
bool CheckCastExpression::is_const() const noexcept {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second) ? it->second->is_const() : false;
}

// DAD: instruction.py:737
std::vector<std::string> CheckCastExpression::get_used_vars() const {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

// DAD: instruction.py:745
void CheckCastExpression::replace_var(const std::string& old_v,
                                      const IRFormPtr& new_node) {
    if (!new_node) return;
    arg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[arg_] = new_node;
}

// DAD: instruction.py:750
void CheckCastExpression::replace(const std::string& old_v,
                                  const IRFormPtr& new_node) {
    auto it = var_map.find(arg_);
    IRFormPtr arg = (it != var_map.end()) ? it->second : nullptr;
    if (!arg) return;
    if (!(arg->is_const() || arg->is_ident())) {
        arg->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            arg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// DAD: instruction.py:762
std::string CheckCastExpression::ToString() const {
    auto it = var_map.find(arg_);
    std::string arg_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "CAST(" + type + ") " + arg_text;
}

// ---- ArrayLoadExpression ---------------------------------------------------

ArrayLoadExpression::ArrayLoadExpression(IRFormPtr arg, IRFormPtr index,
                                         std::string_view atype) {
    array_ = arg->Vid();
    idx_ = index->Vid();
    var_map[array_] = arg;
    var_map[idx_] = index;
    type = std::string{atype};
}

// DAD: instruction.py:789 — strip one leading '[' from array's type.
// Python: `self.var_map[self.array].get_type().replace('[', '', 1)`.
std::string ArrayLoadExpression::get_type() const {
    auto it = var_map.find(array_);
    if (it == var_map.end() || !it->second) return {};
    std::string at = it->second->get_type();
    auto pos = at.find('[');
    if (pos != std::string::npos) at.erase(pos, 1);
    return at;
}

std::vector<std::string> ArrayLoadExpression::get_used_vars() const {
    auto a = var_map.find(array_), i = var_map.find(idx_);
    std::vector<std::string> tmp;
    if (a != var_map.end() && a->second) {
        auto v = a->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (i != var_map.end() && i->second) {
        auto v = i->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

void ArrayLoadExpression::replace_var(const std::string& old_v,
                                      const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (array_ == old_v) array_ = new_v;
    if (idx_ == old_v) idx_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

void ArrayLoadExpression::replace(const std::string& old_v,
                                  const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_ident() || arg->is_const())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (array_ == old_v) array_ = new_v;
                if (idx_ == old_v) idx_ = new_v;
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const std::string& v : {array_, idx_}) {
            auto it2 = var_map.find(v);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_ident() || it2->second->is_const())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

std::string ArrayLoadExpression::ToString() const {
    auto a = var_map.find(array_), i = var_map.find(idx_);
    std::string at = (a != var_map.end() && a->second) ? a->second->ToString() : "None";
    std::string it_ = (i != var_map.end() && i->second) ? i->second->ToString() : "None";
    return "ARRAYLOAD(" + at + ", " + it_ + ")";
}

// ---- ArrayLengthExpression -------------------------------------------------

ArrayLengthExpression::ArrayLengthExpression(IRFormPtr array) {
    array_ = array->Vid();
    var_map[array_] = array;
}

std::vector<std::string> ArrayLengthExpression::get_used_vars() const {
    auto it = var_map.find(array_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

void ArrayLengthExpression::replace_var(const std::string& old_v,
                                        const IRFormPtr& new_node) {
    if (!new_node) return;
    array_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[array_] = new_node;
}

void ArrayLengthExpression::replace(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    auto it = var_map.find(array_);
    IRFormPtr array = (it != var_map.end()) ? it->second : nullptr;
    if (!array) return;
    if (!(array->is_const() || array->is_ident())) {
        array->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            array_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

std::string ArrayLengthExpression::ToString() const {
    auto it = var_map.find(array_);
    std::string at = (it != var_map.end() && it->second)
                          ? it->second->ToString() : "None";
    return "ARRAYLEN(" + at + ")";
}

// ---- NewArrayExpression ----------------------------------------------------

NewArrayExpression::NewArrayExpression(IRFormPtr asize,
                                       std::string_view atype) {
    size_ = asize->Vid();
    type = std::string{atype};
    var_map[size_] = asize;
}

std::vector<std::string> NewArrayExpression::get_used_vars() const {
    auto it = var_map.find(size_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

void NewArrayExpression::replace_var(const std::string& old_v,
                                     const IRFormPtr& new_node) {
    if (!new_node) return;
    size_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[size_] = new_node;
}

void NewArrayExpression::replace(const std::string& old_v,
                                 const IRFormPtr& new_node) {
    auto it = var_map.find(size_);
    IRFormPtr size = (it != var_map.end()) ? it->second : nullptr;
    if (!size) return;
    if (!(size->is_const() || size->is_ident())) {
        size->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            size_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

std::string NewArrayExpression::ToString() const {
    auto it = var_map.find(size_);
    std::string size_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "NEWARRAY_" + type + "[" + size_text + "]";
}

// ---- FilledArrayExpression -------------------------------------------------

// DAD: instruction.py:900 — note quirk: size stored DIRECTLY, not via .v.
FilledArrayExpression::FilledArrayExpression(int64_t asize,
                                             std::string_view atype,
                                             const std::vector<IRFormPtr>& args) {
    size_ = asize;
    type = std::string{atype};
    for (const auto& a : args) {
        var_map[a->Vid()] = a;
        args_.push_back(a->Vid());
    }
}

std::vector<std::string> FilledArrayExpression::get_used_vars() const {
    std::vector<std::string> tmp;
    for (const auto& a : args_) {
        auto it = var_map.find(a);
        if (it != var_map.end() && it->second) {
            auto v = it->second->get_used_vars();
            tmp.insert(tmp.end(), v.begin(), v.end());
        }
    }
    return Dedup(std::move(tmp));
}

void FilledArrayExpression::replace_var(const std::string& old_v,
                                        const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    std::vector<std::string> new_args;
    new_args.reserve(args_.size());
    for (const auto& a : args_) new_args.push_back(a == old_v ? new_v : a);
    args_ = std::move(new_args);
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

void FilledArrayExpression::replace(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_ident() || arg->is_const())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                std::vector<std::string> new_args;
                new_args.reserve(args_.size());
                for (const auto& a : args_) new_args.push_back(a == old_v ? new_v : a);
                args_ = std::move(new_args);
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const auto& a : args_) {
            auto it2 = var_map.find(a);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_ident() || it2->second->is_const())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

// ---- FillArrayExpression ---------------------------------------------------

FillArrayExpression::FillArrayExpression(IRFormPtr reg,
                                         std::vector<int64_t> value)
    : value_(std::move(value)) {
    reg_ = reg->Vid();
    var_map[reg_] = reg;
}

std::vector<std::string> FillArrayExpression::get_used_vars() const {
    auto it = var_map.find(reg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

void FillArrayExpression::replace_var(const std::string& old_v,
                                      const IRFormPtr& new_node) {
    if (!new_node) return;
    reg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[reg_] = new_node;
}

void FillArrayExpression::replace(const std::string& old_v,
                                  const IRFormPtr& new_node) {
    auto it = var_map.find(reg_);
    IRFormPtr reg = (it != var_map.end()) ? it->second : nullptr;
    if (!reg) return;
    if (!(reg->is_const() || reg->is_ident())) {
        reg->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            reg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// ---- RefExpression ---------------------------------------------------------

RefExpression::RefExpression(IRFormPtr ref) {
    ref_ = ref->Vid();
    var_map[ref_] = ref;
}

std::vector<std::string> RefExpression::get_used_vars() const {
    auto it = var_map.find(ref_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars()
            : std::vector<std::string>{};
}

void RefExpression::replace_var(const std::string& old_v,
                                const IRFormPtr& new_node) {
    if (!new_node) return;
    ref_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[ref_] = new_node;
}

void RefExpression::replace(const std::string& old_v,
                            const IRFormPtr& new_node) {
    auto it = var_map.find(ref_);
    IRFormPtr ref = (it != var_map.end()) ? it->second : nullptr;
    if (!ref) return;
    if (!(ref->is_const() || ref->is_ident())) {
        ref->replace(old_v, new_node);
    } else {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            ref_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

// ---- MoveExceptionExpression -----------------------------------------------

MoveExceptionExpression::MoveExceptionExpression(IRFormPtr ref,
                                                 std::string_view atype)
    : RefExpression(ref) {
    type = std::string{atype};
    ref->set_type(atype);
}

void MoveExceptionExpression::replace_lhs(const IRFormPtr& new_node) {
    if (!new_node) return;
    var_map.erase(ref_);
    ref_ = new_node->Vid();
    var_map[ref_] = new_node;
}

std::string MoveExceptionExpression::ToString() const {
    auto it = var_map.find(ref_);
    std::string ref_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "MOVE_EXCEPT " + ref_text;
}

// ---- ThrowExpression -------------------------------------------------------

std::string ThrowExpression::ToString() const {
    auto it = var_map.find(ref_);
    std::string ref_text = (it != var_map.end() && it->second)
                                ? it->second->ToString() : "None";
    return "Throw " + ref_text;
}

// ---- BinaryExpression ------------------------------------------------------

BinaryExpression::BinaryExpression(std::string_view op, IRFormPtr arg1,
                                   IRFormPtr arg2, std::string_view atype)
    : op_(op) {
    arg1_ = arg1->Vid();
    arg2_ = arg2->Vid();
    var_map[arg1_] = arg1;
    var_map[arg2_] = arg2;
    type = std::string{atype};
}

bool BinaryExpression::has_side_effect() const noexcept {
    auto a1 = var_map.find(arg1_), a2 = var_map.find(arg2_);
    bool e1 = (a1 != var_map.end() && a1->second) ? a1->second->has_side_effect() : false;
    bool e2 = (a2 != var_map.end() && a2->second) ? a2->second->has_side_effect() : false;
    return e1 || e2;
}

std::vector<std::string> BinaryExpression::get_used_vars() const {
    auto a1 = var_map.find(arg1_), a2 = var_map.find(arg2_);
    std::vector<std::string> tmp;
    if (a1 != var_map.end() && a1->second) {
        auto v = a1->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (a2 != var_map.end() && a2->second) {
        auto v = a2->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

void BinaryExpression::replace_var(const std::string& old_v,
                                   const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (arg1_ == old_v) arg1_ = new_v;
    if (arg2_ == old_v) arg2_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

void BinaryExpression::replace(const std::string& old_v,
                               const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_const() || arg->is_ident())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (arg1_ == old_v) arg1_ = new_v;
                if (arg2_ == old_v) arg2_ = new_v;
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const std::string& v : {arg1_, arg2_}) {
            auto it2 = var_map.find(v);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_ident() || it2->second->is_const())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

std::string BinaryExpression::ToString() const {
    auto a1 = var_map.find(arg1_), a2 = var_map.find(arg2_);
    std::string s1 = (a1 != var_map.end() && a1->second) ? a1->second->ToString() : "None";
    std::string s2 = (a2 != var_map.end() && a2->second) ? a2->second->ToString() : "None";
    return "(" + op_ + " " + s1 + " " + s2 + ")";
}

// ---- BinaryExpressionLit ---------------------------------------------------

BinaryExpressionLit::BinaryExpressionLit(std::string_view op, IRFormPtr arg1,
                                         IRFormPtr arg2)
    : BinaryExpression(op, std::move(arg1), std::move(arg2), "I") {}

// ---- UnaryExpression -------------------------------------------------------

UnaryExpression::UnaryExpression(std::string_view op, IRFormPtr arg,
                                 std::string_view atype)
    : op_(op) {
    arg_ = arg->Vid();
    var_map[arg_] = arg;
    type = std::string{atype};
}

std::string UnaryExpression::get_type() const {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_type() : std::string{};
}

std::vector<std::string> UnaryExpression::get_used_vars() const {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars() : std::vector<std::string>{};
}

void UnaryExpression::replace_var(const std::string& old_v,
                                  const IRFormPtr& new_node) {
    if (!new_node) return;
    arg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[arg_] = new_node;
}

void UnaryExpression::replace(const std::string& old_v,
                              const IRFormPtr& new_node) {
    auto it = var_map.find(arg_);
    IRFormPtr arg = (it != var_map.end()) ? it->second : nullptr;
    if (!arg) return;
    if (!(arg->is_const() || arg->is_ident())) {
        arg->replace(old_v, new_node);
    } else if (var_map.find(old_v) != var_map.end()) {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            arg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

std::string UnaryExpression::ToString() const {
    auto it = var_map.find(arg_);
    std::string s = (it != var_map.end() && it->second)
                        ? it->second->ToString() : "None";
    return "(" + op_ + ", " + s + ")";
}

// ---- CastExpression --------------------------------------------------------

// DAD: instruction.py:1198 __init__(op, atype, arg)
CastExpression::CastExpression(std::string_view op, std::string_view atype,
                               IRFormPtr arg)
    : UnaryExpression(op, std::move(arg), atype),
      clsdesc_(atype) {}

bool CastExpression::is_const() const noexcept {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second) ? it->second->is_const() : false;
}

std::string CastExpression::ToString() const {
    auto it = var_map.find(arg_);
    std::string s = (it != var_map.end() && it->second)
                        ? it->second->ToString() : "None";
    return "CAST_" + op_ + "(" + s + ")";
}

// ---- CONDS table -----------------------------------------------------------

// DAD: instruction.py:1218
const std::unordered_map<std::string, std::string>& CondsTable() {
    static const std::unordered_map<std::string, std::string> kTable = {
        {"==", "!="},
        {"!=", "=="},
        {"<",  ">="},
        {"<=", ">"},
        {">=", "<"},
        {">",  "<="},
    };
    return kTable;
}

// ---- ConditionalExpression -------------------------------------------------

ConditionalExpression::ConditionalExpression(std::string_view op,
                                             IRFormPtr arg1, IRFormPtr arg2)
    : op_(op) {
    arg1_ = arg1->Vid();
    arg2_ = arg2->Vid();
    var_map[arg1_] = arg1;
    var_map[arg2_] = arg2;
}

std::vector<std::string> ConditionalExpression::get_used_vars() const {
    auto a1 = var_map.find(arg1_), a2 = var_map.find(arg2_);
    std::vector<std::string> tmp;
    if (a1 != var_map.end() && a1->second) {
        auto v = a1->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    if (a2 != var_map.end() && a2->second) {
        auto v = a2->second->get_used_vars(); tmp.insert(tmp.end(), v.begin(), v.end());
    }
    return Dedup(std::move(tmp));
}

void ConditionalExpression::Neg() {
    auto it = CondsTable().find(op_);
    if (it != CondsTable().end()) op_ = it->second;
}

void ConditionalExpression::replace_var(const std::string& old_v,
                                        const IRFormPtr& new_node) {
    std::string new_v = new_node ? new_node->Vid() : std::string{};
    if (arg1_ == old_v) arg1_ = new_v;
    if (arg2_ == old_v) arg2_ = new_v;
    var_map.erase(old_v);
    if (new_node) var_map[new_v] = new_node;
}

void ConditionalExpression::replace(const std::string& old_v,
                                    const IRFormPtr& new_node) {
    auto it = var_map.find(old_v);
    if (it != var_map.end()) {
        IRFormPtr arg = it->second;
        if (arg && !(arg->is_const() || arg->is_ident())) {
            arg->replace(old_v, new_node);
        } else {
            if (new_node && new_node->is_ident()) {
                std::string new_v = new_node->Vid();
                var_map[new_v] = new_node;
                if (arg1_ == old_v) arg1_ = new_v;
                if (arg2_ == old_v) arg2_ = new_v;
            } else {
                var_map[old_v] = new_node;
            }
        }
    } else {
        for (const std::string& v : {arg1_, arg2_}) {
            auto it2 = var_map.find(v);
            if (it2 == var_map.end() || !it2->second) continue;
            if (!(it2->second->is_ident() || it2->second->is_const())) {
                it2->second->replace(old_v, new_node);
            }
        }
    }
}

std::string ConditionalExpression::ToString() const {
    auto a1 = var_map.find(arg1_), a2 = var_map.find(arg2_);
    std::string s1 = (a1 != var_map.end() && a1->second) ? a1->second->ToString() : "None";
    std::string s2 = (a2 != var_map.end() && a2->second) ? a2->second->ToString() : "None";
    return "COND(" + op_ + ", " + s1 + ", " + s2 + ")";
}

// ---- ConditionalZExpression ------------------------------------------------

ConditionalZExpression::ConditionalZExpression(std::string_view op,
                                               IRFormPtr arg)
    : op_(op) {
    arg_ = arg->Vid();
    var_map[arg_] = arg;
}

std::vector<std::string> ConditionalZExpression::get_used_vars() const {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars() : std::vector<std::string>{};
}

void ConditionalZExpression::Neg() {
    auto it = CondsTable().find(op_);
    if (it != CondsTable().end()) op_ = it->second;
}

void ConditionalZExpression::replace_var(const std::string& old_v,
                                         const IRFormPtr& new_node) {
    if (!new_node) return;
    arg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[arg_] = new_node;
}

void ConditionalZExpression::replace(const std::string& old_v,
                                     const IRFormPtr& new_node) {
    auto it = var_map.find(arg_);
    IRFormPtr arg = (it != var_map.end()) ? it->second : nullptr;
    if (!arg) return;
    if (!(arg->is_const() || arg->is_ident())) {
        arg->replace(old_v, new_node);
    } else if (var_map.find(old_v) != var_map.end()) {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            arg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

std::string ConditionalZExpression::ToString() const {
    auto it = var_map.find(arg_);
    std::string s = (it != var_map.end() && it->second)
                        ? it->second->ToString() : "None";
    return "(IS" + op_ + "0, " + s + ")";
}

// ---- InstanceExpression ----------------------------------------------------

InstanceExpression::InstanceExpression(IRFormPtr arg, std::string_view klass,
                                       std::string_view ftype,
                                       std::string_view name) {
    arg_ = arg->Vid();
    cls_ = GetType(klass);             // DAD: util.get_type(klass)
    ftype_ = std::string{ftype};
    name_ = std::string{name};
    var_map[arg_] = arg;
    clsdesc_ = std::string{klass};
}

std::vector<std::string> InstanceExpression::get_used_vars() const {
    auto it = var_map.find(arg_);
    return (it != var_map.end() && it->second)
            ? it->second->get_used_vars() : std::vector<std::string>{};
}

void InstanceExpression::replace_var(const std::string& old_v,
                                     const IRFormPtr& new_node) {
    if (!new_node) return;
    arg_ = new_node->Vid();
    var_map.erase(old_v);
    var_map[arg_] = new_node;
}

void InstanceExpression::replace(const std::string& old_v,
                                 const IRFormPtr& new_node) {
    auto it = var_map.find(arg_);
    IRFormPtr arg = (it != var_map.end()) ? it->second : nullptr;
    if (!arg) return;
    if (!(arg->is_const() || arg->is_ident())) {
        arg->replace(old_v, new_node);
    } else if (var_map.find(old_v) != var_map.end()) {
        if (new_node && new_node->is_ident()) {
            std::string new_v = new_node->Vid();
            var_map[new_v] = new_node;
            arg_ = new_v;
        } else {
            var_map[old_v] = new_node;
        }
    }
}

std::string InstanceExpression::ToString() const {
    auto it = var_map.find(arg_);
    std::string s = (it != var_map.end() && it->second)
                        ? it->second->ToString() : "None";
    return s + "." + name_;
}

// ---- StaticExpression ------------------------------------------------------

StaticExpression::StaticExpression(std::string_view cls_name,
                                   std::string_view field_type,
                                   std::string_view field_name) {
    cls_ = GetType(cls_name);
    ftype_ = std::string{field_type};
    name_ = std::string{field_name};
    clsdesc_ = std::string{cls_name};
}

std::string StaticExpression::ToString() const {
    return cls_ + "." + name_;
}

}  // namespace dexkit::dad
