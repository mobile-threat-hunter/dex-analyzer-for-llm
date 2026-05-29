// Parity test for basic_blocks.cpp.
// Mirrors androguard DAD basic_blocks.py behaviour for the 11 class-hierarchy
// entities (build_node_from_block is deferred — needs RawIns/RawBlock ABI).
#include "basic_blocks.h"
#include "instruction.h"
#include <cstdio>
#include <memory>
namespace dad = dexkit::dad;
static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-30lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                static_cast<long long>(got), static_cast<long long>(want));
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-44s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

// Minimal CondBlock-flavoured Operand for Condition tests — visits the
// underlying writer (no-op) and prints a tag string.
class TagOperand : public dad::Condition::Operand {
public:
    explicit TagOperand(std::string tag) : tag_(std::move(tag)) {}
    std::vector<dad::IRFormPtr> get_ins() const override { return {tag_marker()}; }
    std::vector<std::pair<int, dad::IRFormPtr>>
    get_loc_with_ins() const override {
        return {{loc_, tag_marker()}};
    }
    void neg() override { negged_ = !negged_; }
    void visit(dad::Visitor&) override {}
    void visit_cond(dad::Visitor&) override {}
    std::string to_string() const override {
        return std::string(negged_ ? "!" : "") + tag_;
    }
    void set_loc(int l) { loc_ = l; }
    bool negged() const { return negged_; }

private:
    dad::IRFormPtr tag_marker() const {
        // Return a fresh Variable to play the role of a unique IR token.
        return std::make_shared<dad::Variable>(tag_);
    }
    std::string tag_;
    int loc_ = 0;
    bool negged_ = false;
};

int main() {
    using namespace dad;

    // --- BasicBlock subclasses: ToString / type flags ---------------------
    StatementBlock stmt("B0", {});
    stmt.num = 1;
    check_str("StatementBlock.ToString", stmt.ToString(), "1-Statement(B0)");
    check("StatementBlock.type.is_stmt", stmt.type.is_stmt(), true);

    ReturnBlock ret("B1", {});
    ret.num = 2;
    check_str("ReturnBlock.ToString", ret.ToString(), "2-Return(B1)");
    check("ReturnBlock.type.is_return", ret.type.is_return(), true);

    ThrowBlock thr("B2", {});
    thr.num = 3;
    check_str("ThrowBlock.ToString", thr.ToString(), "3-Throw(B2)");
    check("ThrowBlock.type.is_throw", thr.type.is_throw(), true);

    SwitchBlock sw("B3", nullptr, {});
    sw.num = 4;
    check_str("SwitchBlock.ToString", sw.ToString(), "4-Switch(B3)");
    check("SwitchBlock.type.is_switch", sw.type.is_switch(), true);

    CondBlock cnd("B4", {});
    cnd.num = 5;
    check_str("CondBlock.ToString", cnd.ToString(), "5-If(B4)");
    check("CondBlock.type.is_cond", cnd.type.is_cond(), true);

    // --- BasicBlock.number_ins / get_loc_with_ins -------------------------
    auto v0 = std::make_shared<Variable>("v0");
    auto v1 = std::make_shared<Variable>("v1");
    auto v2 = std::make_shared<Variable>("v2");
    StatementBlock body("Body", {v0, v1, v2});
    const int next = body.number_ins(10);
    check("number_ins returns end (10+3)", next, 13);
    const auto& locs = body.get_loc_with_ins();
    check("get_loc_with_ins size", static_cast<int>(locs.size()), 3);
    check("get_loc_with_ins[0].first", locs[0].first, 10);
    check("get_loc_with_ins[2].first", locs[2].first, 12);
    // remove_ins (loc=11 ↦ v1)
    body.remove_ins(11, v1);
    check("after remove ins size", static_cast<int>(body.get_ins().size()), 2);
    check("after remove loc_ins size",
          static_cast<int>(body.get_loc_with_ins().size()), 2);
    // add_ins
    auto v3 = std::make_shared<Variable>("v3");
    body.add_ins({v3});
    check("add_ins → ins size 3", static_cast<int>(body.get_ins().size()), 3);
    // add_variable_declaration (dup ignored)
    body.add_variable_declaration(v0);
    body.add_variable_declaration(v0);
    check("var_to_declare dedup", static_cast<int>(body.var_to_declare.size()),
          1);

    // --- Condition: ToString / neg ----------------------------------------
    auto a = std::make_shared<TagOperand>("A");
    auto b = std::make_shared<TagOperand>("B");
    Condition c(a, b, /*isand=*/true, /*isnot=*/false);
    check_str("Condition A && B", c.ToString(), "A && B");
    c.neg();
    // After neg: isand flipped (true→false ⇒ '||'), each child negged (!A, !B).
    check_str("Condition.neg → !A || !B", c.ToString(), "!A || !B");
    // isnot stays unchanged; only isand toggles.
    check("Condition.isnot still false", c.isnot, false);
    check("Condition.isand toggled", c.isand, false);

    Condition cn(std::make_shared<TagOperand>("X"),
                 std::make_shared<TagOperand>("Y"),
                 /*isand=*/false, /*isnot=*/true);
    check_str("Condition isnot=True", cn.ToString(), "!X || Y");

    // get_ins / get_loc_with_ins concat
    auto a2 = std::make_shared<TagOperand>("A");
    auto b2 = std::make_shared<TagOperand>("B");
    a2->set_loc(7);
    b2->set_loc(8);
    Condition c2(a2, b2, true, false);
    check("Condition.get_ins size", static_cast<int>(c2.get_ins().size()), 2);
    auto loc2 = c2.get_loc_with_ins();
    check("Condition.get_loc_with_ins size", static_cast<int>(loc2.size()), 2);
    check("loc[0]=7", loc2[0].first, 7);
    check("loc[1]=8", loc2[1].first, 8);

    // --- ShortCircuitBlock -----------------------------------------------
    auto sc_cond = std::make_shared<Condition>(
        std::make_shared<TagOperand>("P"), std::make_shared<TagOperand>("Q"),
        true, false);
    ShortCircuitBlock sc("SC0", sc_cond);
    sc.num = 6;
    check_str("ShortCircuitBlock.ToString", sc.ToString(), "6-SC(P && Q)");
    sc.neg();
    check_str("SC after neg", sc.ToString(), "6-SC(!P || !Q)");

    // --- LoopBlock: looptype branches ------------------------------------
    auto lp_cond = std::make_shared<Condition>(
        std::make_shared<TagOperand>("L"), std::make_shared<TagOperand>("R"),
        true, false);
    LoopBlock lp("L0", lp_cond);
    lp.num = 7;
    // No looptype set → WhileNoType, no [cond] suffix.
    check_str("LoopBlock.ToString (no type)", lp.ToString(),
              "7-WhileNoType(L0)");
    lp.looptype.set_is_pretest(true);
    check_str("LoopBlock pretest, false∉loop", lp.ToString(),
              "7-While(L0)[L && R]");
    // false ∈ loop_nodes → '!'-prefixed.
    StatementBlock dummy_false("F", {});
    lp.false_branch = &dummy_false;
    lp.loop_nodes.push_back(&dummy_false);
    check_str("LoopBlock pretest, false∈loop", lp.ToString(),
              "7-While(!L0)[L && R]");
    lp.looptype.set_is_posttest(true);
    check_str("LoopBlock posttest", lp.ToString(), "7-DoWhile(L0)[L && R]");
    lp.looptype.set_is_endless(true);
    check_str("LoopBlock endless", lp.ToString(), "7-WhileTrue(L0)[L && R]");

    // --- TryBlock --------------------------------------------------------
    StatementBlock try_start("TStart", {});
    try_start.num = 99;
    TryBlock tb(&try_start);
    check_str("TryBlock.name", tb.name, "Try-TStart");
    check("TryBlock.Num delegates", tb.Num(), 99);
    StatementBlock catch1("CH1", {});
    StatementBlock catch2("CH2", {});
    tb.add_catch_node(&catch1);
    tb.add_catch_node(&catch2);
    check_str("TryBlock.ToString", tb.ToString(), "Try(Try-TStart)[CH1, CH2]");

    // --- CatchBlock with MoveExceptionExpression head --------------------
    auto exc_ref = std::make_shared<Variable>("exc");
    auto mex = std::make_shared<MoveExceptionExpression>(exc_ref, "Ljava/lang/Throwable;");
    auto v_keep = std::make_shared<Variable>("v_keep");
    StatementBlock raw_with_mex("CRaw", {mex, v_keep});
    raw_with_mex.catch_type = "Ljava/lang/Throwable;";
    CatchBlock cb1(raw_with_mex);
    check("CatchBlock pops head when MEX present",
          static_cast<int>(raw_with_mex.get_ins().size()), 1);
    check("CatchBlock.exception_ins captured",
          (cb1.exception_ins != nullptr), true);
    check("CatchBlock.ins size after pop",
          static_cast<int>(cb1.get_ins().size()), 1);
    check_str("CatchBlock.name", cb1.name, "Catch-CRaw");
    check_str("CatchBlock.catch_type propagated", cb1.catch_type,
              "Ljava/lang/Throwable;");
    // DAD self.name is 'Catch-CRaw' (set via super('Catch-%s' % node.name)),
    // so __str__ formats as 'Catch(Catch-CRaw)'. Faithful to DAD.
    check_str("CatchBlock.ToString", cb1.ToString(), "Catch(Catch-CRaw)");

    // --- CatchBlock without MEX head -------------------------------------
    StatementBlock raw_no_mex("CR2", {v_keep, v_keep});
    raw_no_mex.catch_type = "Ljava/io/IOException;";
    CatchBlock cb2(raw_no_mex);
    check("no-MEX: source preserved", static_cast<int>(raw_no_mex.get_ins().size()),
          2);
    check("no-MEX: exception_ins null", (cb2.exception_ins == nullptr), true);
    check("no-MEX: ins copied",
          static_cast<int>(cb2.get_ins().size()), 2);

    // --- CondBlock.update_attribute_with ---------------------------------
    StatementBlock t_old("TO", {});
    StatementBlock t_new("TN", {});
    StatementBlock f_old("FO", {});
    StatementBlock f_new("FN", {});
    CondBlock cc("C", {});
    cc.true_branch = &t_old;
    cc.false_branch = &f_old;
    std::unordered_map<NodeBase*, NodeBase*> nm = {
        {&t_old, &t_new}, {&f_old, &f_new}};
    cc.UpdateAttributeWith(nm);
    check("CondBlock.update true remapped",
          (cc.true_branch == &t_new), true);
    check("CondBlock.update false remapped",
          (cc.false_branch == &f_new), true);

    // --- SwitchBlock.update_attribute_with -------------------------------
    StatementBlock case_old("CO", {});
    StatementBlock case_new("CN", {});
    SwitchBlock sb("S", nullptr, {});
    sb.cases.push_back(&case_old);
    sb.node_to_case[&case_old] = {1, 2, 3};
    std::unordered_map<NodeBase*, NodeBase*> nm2 = {{&case_old, &case_new}};
    sb.UpdateAttributeWith(nm2);
    check("SwitchBlock.cases remapped",
          (sb.cases[0] == &case_new), true);
    check("node_to_case re-keyed",
          (sb.node_to_case.count(&case_new) == 1 &&
           sb.node_to_case.count(&case_old) == 0),
          true);
    check("node_to_case values preserved",
          static_cast<int>(sb.node_to_case[&case_new].size()), 3);

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
