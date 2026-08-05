"""composer.fanout_tree — the read-only fan-out observability surface (Mission Control's
Flows tab). Built over a synthetic queue dir: a waiting parent with mixed-state children
(terminal / waiting / error-with-reason), one nested fan-out, one gated join, and a
non-fan-out checkpoint that must be excluded. The builder must never write."""
import json
import os

from prismpath import composer


def _write(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc.setdefault("version", 1)
    with open(path, "w") as f:
        json.dump(doc, f)


def _parent(flow="flows/review.md", node="dispatch", spawn=None, stopped="waiting",
            state=None):
    return {"flow_path": flow, "flow_hash": "x", "stopped": stopped, "pending_node": node,
            "saved_at": 1700000000.0, "path": ["start", node], "state": state or {},
            "pending_decision": {"node": node, "wait": True, "spawn": spawn}
            if spawn is not None else {}}


def _child(iid, stopped, node=None, error=None, outcomes=None):
    doc = {"flow_path": "flows/review_one.md", "flow_hash": "y", "stopped": stopped,
           "pending_node": node, "saved_at": 1700000100.0, "path": ["work"],
           "state": {"_item_id": iid, "_outcomes": outcomes or {}}}
    if error:
        doc["child_error"] = error
    return doc


def build_queue(tmp_path):
    q = str(tmp_path / "queue")
    # fan-out parent with three children in different states
    _write(os.path.join(q, "run1.json"),
           _parent(spawn={"child": "review_one.md", "join": "quorum:2", "items": [1, 2, 3]}))
    _write(os.path.join(q, "run1.children", "1.json"), _child("1", "terminal"))
    _write(os.path.join(q, "run1.children", "2.json"), _child("2", "waiting", node="await"))
    _write(os.path.join(q, "run1.children", "3.json"),
           _child("3", "error", error="child state not checkpointable"))
    # nested: child 2 is itself a fan-out with one terminal grandchild
    nested = _parent(flow="flows/review_one.md", node="fan2",
                     spawn={"child": "leaf.md", "items": ["a"]})
    nested["state"] = {"_item_id": "2"}
    _write(os.path.join(q, "run1.children", "2.json"), nested)
    _write(os.path.join(q, "run1.children", "2.children", "a.json"), _child("a", "terminal"))
    # a gated parent: terminal child WITHOUT the gate field -> not done
    _write(os.path.join(q, "run2.json"),
           _parent(node="fan", spawn={"child": "c.md", "join": "all_done", "gate": "ok",
                                      "items": ["x"]}))
    _write(os.path.join(q, "run2.children", "x.json"),
           _child("x", "terminal", outcomes={"work": {"ok": False}}))
    # an ordinary needs_human checkpoint — NOT a fan-out, must not appear
    _write(os.path.join(q, "solo.json"),
           {"flow_path": "flows/plain.md", "flow_hash": "z", "stopped": "needs_human",
            "pending_node": "review", "saved_at": 1.0, "path": [], "state": {},
            "pending_decision": {"node": "review"}})
    return q


def test_tree_shape_and_progress(tmp_path):
    q = build_queue(tmp_path)
    tree = composer.fanout_tree(q)
    assert [os.path.basename(t["path"]) for t in tree] == ["run1.json", "run2.json"], \
        "both fan-outs present, the plain needs_human checkpoint excluded"

    r1 = tree[0]
    assert r1["node"] == "dispatch" and r1["stopped"] == "waiting"
    assert r1["join"] == "quorum:2" and r1["join_event"] == "quorum"
    assert r1["progress"] == {"n": 3, "done": 1, "terminal": 1}
    by_id = {c["item_id"]: c for c in r1["children"]}
    assert by_id["1"]["stopped"] == "terminal" and by_id["1"]["done"] is True
    assert by_id["3"]["child_error"] == "child state not checkpointable"
    assert by_id["3"]["done"] is False


def test_nested_fanout_recursion(tmp_path):
    q = build_queue(tmp_path)
    r1 = composer.fanout_tree(q)[0]
    nested = next(c for c in r1["children"] if c["item_id"] == "2")["fanout"]
    assert nested["node"] == "fan2"
    assert nested["progress"] == {"n": 1, "done": 1, "terminal": 1}
    assert nested["children"][0]["item_id"] == "a"


def test_gate_counts_success_not_mere_termination(tmp_path):
    q = build_queue(tmp_path)
    r2 = composer.fanout_tree(q)[1]
    assert r2["gate"] == "ok"
    assert r2["progress"] == {"n": 1, "done": 0, "terminal": 1}, \
        "a terminal child failing the gate is finished but NOT done"


def test_read_only(tmp_path):
    q = build_queue(tmp_path)
    before = {}
    for root, _dirs, files in os.walk(q):
        for fn in files:
            p = os.path.join(root, fn)
            before[p] = (os.path.getmtime(p), open(p).read())
    composer.fanout_tree(q)
    for p, (mt, content) in before.items():
        assert os.path.getmtime(p) == mt and open(p).read() == content, f"{p} was modified"
    assert set(os.listdir(q)) == {"run1.json", "run1.children", "run2.json",
                                  "run2.children", "solo.json"}


def test_empty_and_missing_dir():
    assert composer.fanout_tree("/nonexistent/queue/dir") == []
