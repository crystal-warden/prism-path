package comparison.document_sharing_rebac

decision := {"outcome": "allow", "rule": "r1"} if {
    graph_set := {k: {x | x := v[_]} | some k, v in data.graph}
    target := sprintf("%s#%s", [input.object, input.relation])
    target in graph.reachable(graph_set, {input.user})
}
else := {"outcome": "deny", "rule": "r2"}
