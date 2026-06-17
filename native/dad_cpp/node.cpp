// node.cpp — DAD node.py port.
// See include/node.h for status and per-class DAD references.
//
// DAD: androguard/decompiler/node.py

#include "node.h"

#include <algorithm>

namespace dexkit::dad {

// DAD: node.py:84 Node.__init__
Node::Node(std::string n) {
    name = std::move(n);
    num = 0;
    follow.emplace("if",     nullptr);
    follow.emplace("loop",   nullptr);
    follow.emplace("switch", nullptr);
    in_catch = false;
    interval = nullptr;
    startloop = false;
    latch = nullptr;
}

// DAD: node.py:97 copy_from
void Node::CopyFrom(const Node& other) {
    num        = other.num;
    looptype   = other.looptype.copy();
    interval   = other.interval;
    startloop  = other.startloop;
    type       = other.type.copy();
    follow     = other.follow;     // copies the {'if','loop','switch'} map
    latch      = other.latch;
    loop_nodes = other.loop_nodes;
    in_catch   = other.in_catch;
}

// DAD: node.py:108 update_attribute_with(n_map)
// Rewrites self.latch, self.follow[*], and self.loop_nodes through n_map
// (each lookup defaults to the original value if not in the map).
void Node::UpdateAttributeWith(
        const std::unordered_map<NodeBase*, NodeBase*>& n_map) {
    if (auto it = n_map.find(latch); it != n_map.end()) {
        latch = it->second;
    }
    for (auto& [key, val] : follow) {
        if (auto it = n_map.find(val); it != n_map.end()) {
            val = it->second;
        }
    }
    // {n_map.get(n, n) for n in loop_nodes} then list(...) — set dedupes.
    std::unordered_set<NodeBase*> dedup;
    dedup.reserve(loop_nodes.size());
    for (NodeBase* n : loop_nodes) {
        auto it = n_map.find(n);
        dedup.insert(it != n_map.end() ? it->second : n);
    }
    // DETERMINISM: `dedup` is a pointer-keyed unordered_set, so assigning its
    // iteration order to loop_nodes is ASLR-dependent. loop_nodes is consumed as
    // a membership set (order-independent), but pin a stable order (post-order
    // num) anyway so no downstream order-dependence can leak non-determinism.
    loop_nodes.assign(dedup.begin(), dedup.end());
    std::sort(loop_nodes.begin(), loop_nodes.end(),
              [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
}

// DAD: node.py:124 Interval.__init__
Interval::Interval(NodeBase* h) {
    head_ = h;
    end_  = nullptr;
    in_catch = h->in_catch;
    name = "Interval-" + h->name;
    content_.insert(h);
    h->interval = this;
}

// DAD: node.py:133 __contains__
bool Interval::Contains(NodeBase* item) const noexcept {
    if (content_.count(item) > 0) return true;
    // Recurse into nested intervals.
    for (NodeBase* n : content_) {
        if (n->IsInterval()) {
            if (static_cast<Interval*>(n)->Contains(item)) return true;
        }
    }
    return false;
}

// DAD: node.py:142 add_node — returns true if added (was not already present).
bool Interval::AddNode(NodeBase* node) {
    if (content_.count(node) > 0) return false;
    content_.insert(node);
    node->interval = this;
    return true;
}

}  // namespace dexkit::dad
