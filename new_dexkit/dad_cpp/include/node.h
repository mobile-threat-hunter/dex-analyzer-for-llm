// node.h — C++ port of androguard DAD node.py
// DAD: androguard/decompiler/node.py
//
// MakeProperties is a Python metaclass that synthesises mutually-exclusive
// boolean properties from `_get_X` / `_set_X` markers. In C++ we just write
// the setters explicitly. The semantics being preserved:
//   set_is_X(true)  -> is_X becomes true, all sibling flags become false
//   set_is_X(false) -> ALL flags (including is_X) become false
//
// PORT STATUS:
//   Ported:
//     - LoopType / NodeType (the metaclass-driven flag classes)
//     - Node
//     - Interval (except compute_end which needs graph.h)
//   Deferred:
//     - Interval::ComputeEnd  — needs graph.h's Graph::sucs(node) iterator

#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dexkit::dad {

// DAD: node.py:60 LoopType — 3-way mutually-exclusive flags via MakeProperties.
class LoopType {
public:
    bool is_pretest()  const noexcept { return is_pretest_;  }
    bool is_posttest() const noexcept { return is_posttest_; }
    bool is_endless()  const noexcept { return is_endless_;  }
    void set_is_pretest(bool v)  noexcept { Reset(); if (v) is_pretest_  = true; }
    void set_is_posttest(bool v) noexcept { Reset(); if (v) is_posttest_ = true; }
    void set_is_endless(bool v)  noexcept { Reset(); if (v) is_endless_  = true; }
    LoopType copy() const noexcept { return *this; }
private:
    void Reset() noexcept { is_pretest_ = is_posttest_ = is_endless_ = false; }
    bool is_pretest_  = false;
    bool is_posttest_ = false;
    bool is_endless_  = false;
};

// DAD: node.py:71 NodeType — 5-way mutually-exclusive flags via MakeProperties.
class NodeType {
public:
    bool is_cond()   const noexcept { return is_cond_;   }
    bool is_switch() const noexcept { return is_switch_; }
    bool is_stmt()   const noexcept { return is_stmt_;   }
    bool is_return() const noexcept { return is_return_; }
    bool is_throw()  const noexcept { return is_throw_;  }
    void set_is_cond(bool v)   noexcept { Reset(); if (v) is_cond_   = true; }
    void set_is_switch(bool v) noexcept { Reset(); if (v) is_switch_ = true; }
    void set_is_stmt(bool v)   noexcept { Reset(); if (v) is_stmt_   = true; }
    void set_is_return(bool v) noexcept { Reset(); if (v) is_return_ = true; }
    void set_is_throw(bool v)  noexcept { Reset(); if (v) is_throw_  = true; }
    NodeType copy() const noexcept { return *this; }
private:
    void Reset() noexcept {
        is_cond_ = is_switch_ = is_stmt_ = is_return_ = is_throw_ = false;
    }
    bool is_cond_ = false, is_switch_ = false, is_stmt_ = false;
    bool is_return_ = false, is_throw_ = false;
};

class Interval;  // fwd: Node holds a back-pointer to its enclosing Interval.

// Common base — Python uses duck typing; Node and Interval share `name`,
// `num`, `in_catch`, `interval`, `get_head()`, `get_end()`. This base
// captures the shared surface so Interval::content can hold either.
class NodeBase {
public:
    virtual ~NodeBase() = default;
    virtual NodeBase* GetHead() = 0;
    virtual NodeBase* GetEnd() = 0;
    virtual bool IsInterval() const noexcept = 0;

    // DAD: node.py:108 update_attribute_with — virtual on NodeBase so the
    // Graph (which keeps NodeBase*) can dispatch into BasicBlock subclasses
    // (CondBlock / SwitchBlock) that override the behaviour. Default
    // implementation is a no-op (Interval doesn't override).
    virtual void UpdateAttributeWith(
        const std::unordered_map<NodeBase*, NodeBase*>& /*n_map*/) {}

    std::string name;
    int num = 0;
    // DAD: graph.py:167 post_order — assigns node.po = cnt; later read by
    // compute_rpo (graph.py:152) as `nb - node.po`. 0 marks "unvisited".
    int po = 0;
    bool in_catch = false;
    Interval* interval = nullptr;  // back-pointer set by Interval::AddNode
};

// DAD: node.py:84 Node.
class Node : public NodeBase {
public:
    explicit Node(std::string n);

    bool IsInterval() const noexcept override { return false; }
    NodeBase* GetHead() override { return this; }  // DAD: node.py:114
    NodeBase* GetEnd() override  { return this; }  // DAD: node.py:117

    // DAD: node.py:97 copy_from
    void CopyFrom(const Node& other);

    // DAD: node.py:108 update_attribute_with(n_map) — overrides NodeBase's
    // no-op default with Node-level logic; further overridden by CondBlock /
    // SwitchBlock for branch-target remapping.
    void UpdateAttributeWith(
        const std::unordered_map<NodeBase*, NodeBase*>& n_map) override;

    // Public fields — matching Python visibility (everything is public).
    std::unordered_map<std::string, NodeBase*> follow;  // 'if' / 'loop' / 'switch'
    LoopType looptype;
    NodeType type;
    bool startloop = false;
    NodeBase* latch = nullptr;
    std::vector<NodeBase*> loop_nodes;
};

// DAD: node.py:124 Interval.
class Interval : public NodeBase {
public:
    explicit Interval(NodeBase* head);

    bool IsInterval() const noexcept override { return true; }
    // DAD: node.py:159 — head should never be None post-construction. C++
    // guard returns nullptr just in case (mirrors DAD's AttributeError as
    // null rather than crashing).
    NodeBase* GetHead() override {
        return head_ ? head_->GetHead() : nullptr;
    }
    // DAD: node.py:156 — end_ is None until compute_end finds an external
    // successor. For "complete" intervals (no exit), end_ stays None and
    // DAD would AttributeError. We return nullptr; callers must guard.
    NodeBase* GetEnd() override {
        return end_ ? end_->GetEnd() : nullptr;
    }

    // DAD: node.py:133 __contains__ (recursive into nested intervals).
    bool Contains(NodeBase* item) const noexcept;

    // DAD: node.py:142 add_node — returns true if added (was not already in).
    bool AddNode(NodeBase* node);

    // DAD: node.py:149 compute_end — uses Graph::sucs; implemented in
    // graph.cpp (forward-declared here to avoid a node.h ↔ graph.h cycle).
    void ComputeEnd(class Graph& graph);

    // DAD: node.py:162 __len__
    size_t size() const noexcept { return content_.size(); }

    NodeBase* head() const noexcept { return head_; }
    NodeBase* end()  const noexcept { return end_;  }
    void set_end(NodeBase* e) noexcept { end_ = e; }

    const std::unordered_set<NodeBase*>& content() const noexcept {
        return content_;
    }

private:
    NodeBase* head_ = nullptr;
    NodeBase* end_  = nullptr;
    std::unordered_set<NodeBase*> content_;
};

}  // namespace dexkit::dad
