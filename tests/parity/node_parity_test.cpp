// Standalone parity test for dad_cpp/node.cpp against androguard DAD node.py.
// Compile:
//   g++ -std=gnu++20 -I native/dad_cpp/include \
//       /tmp/node_parity_test.cpp \
//       build/cp*-cp*-*/libdexkit_dad.a \
//       -o /tmp/node_parity_test && /tmp/node_parity_test

#include "node.h"

#include <cstdio>
#include <vector>

namespace dad = dexkit::dad;

static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %s — got=%d want=%d\n",
                eq ? "[ok]  " : "[FAIL]", label, (int)got, (int)want);
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %s — got=%s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

int main() {
    // LoopType — exclusive-on / all-off-on-false semantics.
    dad::LoopType lt;
    lt.set_is_pretest(true);
    check("LoopType pretest(T): pretest",  lt.is_pretest(),  true);
    check("LoopType pretest(T): posttest", lt.is_posttest(), false);
    check("LoopType pretest(T): endless",  lt.is_endless(),  false);
    lt.set_is_endless(true);
    check("LoopType endless(T): pretest",  lt.is_pretest(),  false);
    check("LoopType endless(T): posttest", lt.is_posttest(), false);
    check("LoopType endless(T): endless",  lt.is_endless(),  true);
    lt.set_is_endless(false);
    check("LoopType endless(F): pretest",  lt.is_pretest(),  false);
    check("LoopType endless(F): posttest", lt.is_posttest(), false);
    check("LoopType endless(F): endless",  lt.is_endless(),  false);

    // NodeType — same semantics, 5-way.
    dad::NodeType nt;
    nt.set_is_cond(true);
    nt.set_is_switch(true);
    check("NodeType cond+switch: cond",   nt.is_cond(),   false);
    check("NodeType cond+switch: switch", nt.is_switch(), true);
    check("NodeType cond+switch: stmt",   nt.is_stmt(),   false);
    check("NodeType cond+switch: return", nt.is_return(), false);
    check("NodeType cond+switch: throw",  nt.is_throw(),  false);

    // Node init
    dad::Node n("foo");
    check_str("Node.name", n.name, "foo");
    check("Node.num", n.num, 0);
    check("Node.follow has 'if'",     n.follow.count("if"),     (size_t)1);
    check("Node.follow has 'loop'",   n.follow.count("loop"),   (size_t)1);
    check("Node.follow has 'switch'", n.follow.count("switch"), (size_t)1);
    check("Node.follow['if'] null",     n.follow["if"]     == nullptr, true);
    check("Node.in_catch", n.in_catch, false);
    check("Node.startloop", n.startloop, false);

    // Interval basics
    dad::Node a("a");
    dad::Node b("b");
    dad::Interval iv(&a);
    check_str("Interval.name", iv.name, "Interval-a");
    check("Interval head == &a", iv.head() == &a, true);
    check("Interval len 1", iv.size(), (size_t)1);
    check("a.interval == &iv", a.interval == &iv, true);
    check("AddNode(b) true",  iv.AddNode(&b), true);
    check("Interval len 2",   iv.size(), (size_t)2);
    check("b.interval == &iv", b.interval == &iv, true);
    check("AddNode(b) again false", iv.AddNode(&b), false);
    check("Contains(a)", iv.Contains(&a), true);
    check("Contains(b)", iv.Contains(&b), true);
    dad::Node c("c");
    check("Contains(c) false", iv.Contains(&c), false);

    // Nested intervals — Contains recurses.
    dad::Interval iv2(&c);
    iv.AddNode(&iv2);
    check("Outer Contains(c via nested)", iv.Contains(&c), true);

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
