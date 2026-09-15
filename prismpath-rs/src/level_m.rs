// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Level M proof layer and capability reporting.

use crate::condition::{error_expr, expr_of, is_deterministic, is_error, parse_expr, Ast};
use crate::engine::portability_violations;
use crate::parser::Graph;
use crate::value::Value;

mod lm_reason {
    pub const CHAINED: &str = "chained-comparison";
    pub const FIELD_VS_FIELD: &str = "field-vs-field";
    pub const SUBSTRING: &str = "substring-in";
    pub const NONLITERAL: &str = "non-literal-collection";
    pub const STRING_ORDER: &str = "string-ordering";
    pub const CONSTANT: &str = "constant-only";
    pub const NESTED: &str = "nested-container";
    pub const SYNTAX: &str = "disallowed-or-unparseable";
}

fn lm_is_order_op(op: &str) -> bool {
    matches!(op, "<" | "<=" | ">" | ">=")
}

fn lm_scalar_const(node: &Ast) -> bool {
    matches!(
        node,
        Ast::Const(Value::Null, _)
            | Ast::Const(Value::Bool(_), _)
            | Ast::Const(Value::Str(_), _)
            | Ast::Const(Value::Num(_), false)
    )
}

fn lm_desugar_chains(node: Ast) -> Ast {
    match node {
        Ast::And(vals) => Ast::And(vals.into_iter().map(lm_desugar_chains).collect()),
        Ast::Or(vals) => Ast::Or(vals.into_iter().map(lm_desugar_chains).collect()),
        Ast::Not(val) => Ast::Not(Box::new(lm_desugar_chains(*val))),
        Ast::Cmp { left, ops, rights } if ops.len() > 1 => {
            let operands: Vec<Ast> = std::iter::once(*left).chain(rights).collect();
            let vals = ops
                .iter()
                .enumerate()
                .map(|(idx, op)| Ast::Cmp {
                    left: Box::new(operands[idx].clone()),
                    ops: vec![op.clone()],
                    rights: vec![operands[idx + 1].clone()],
                })
                .collect();
            Ast::And(vals)
        }
        other => other,
    }
}

fn lm_atom_reason(node: &Ast) -> Option<&'static str> {
    match node {
        Ast::Name(_) => None,
        Ast::Const(..) => Some(lm_reason::CONSTANT),
        Ast::Cmp { left, ops, rights } => {
            if ops.len() != 1 {
                return Some(lm_reason::CHAINED);
            }
            let op = ops[0].as_str();
            let right = &rights[0];
            if op == "in" || op == "not in" {
                match left.as_ref() {
                    Ast::Name(_) => {}
                    Ast::Const(..) => return Some(lm_reason::CONSTANT),
                    _ => return Some(lm_reason::FIELD_VS_FIELD),
                }
                if let Ast::Const(Value::Str(_), _) = right {
                    return Some(lm_reason::SUBSTRING);
                }
                if let Ast::List(elts) = right {
                    for elem in elts {
                        if let Ast::List(_) = elem {
                            return Some(lm_reason::NESTED);
                        }
                        if !lm_scalar_const(elem) {
                            return Some(lm_reason::NONLITERAL);
                        }
                    }
                    return None;
                }
                return Some(lm_reason::NONLITERAL);
            }
            let left_is_name = matches!(left.as_ref(), Ast::Name(_));
            let right_is_name = matches!(right, Ast::Name(_));
            let var_const: &Ast = if left_is_name && lm_scalar_const(right) {
                right
            } else if right_is_name && lm_scalar_const(left) {
                left
            } else if left_is_name && right_is_name {
                return Some(lm_reason::FIELD_VS_FIELD);
            } else {
                return Some(if lm_scalar_const(left) && lm_scalar_const(right) {
                    lm_reason::CONSTANT
                } else {
                    lm_reason::SYNTAX
                });
            };
            if lm_is_order_op(op) {
                if let Ast::Const(Value::Str(_), _) = var_const {
                    return Some(lm_reason::STRING_ORDER);
                }
            }
            None
        }
        _ => Some(lm_reason::SYNTAX),
    }
}

fn lm_classify(node: &Ast) -> Option<&'static str> {
    match node {
        Ast::And(vals) | Ast::Or(vals) => {
            for item in vals {
                if let Some(reason_str) = lm_classify(item) {
                    return Some(reason_str);
                }
            }
            None
        }
        Ast::Not(val) => lm_classify(val),
        _ => lm_atom_reason(node),
    }
}

pub fn is_level_m(cond: &str) -> (bool, Option<String>) {
    if !is_deterministic(cond) {
        if is_error(cond) {
            let mut expr = error_expr(cond);
            if expr.is_empty() {
                return (true, None);
            }
            if !expr.to_lowercase().starts_with("when ") {
                expr = format!("when {expr}");
            }
            return is_level_m(&expr);
        }
        return (false, Some("not-deterministic".to_string()));
    }
    let expr = expr_of(cond);
    let low = expr.to_lowercase();
    if ["always", "true", "else", "otherwise", "default", "_"].contains(&low.as_str())
        || ["false", "never"].contains(&low.as_str())
    {
        return (true, None);
    }
    let node = match parse_expr(&expr) {
        Ok(n_ast) => lm_desugar_chains(n_ast),
        Err(_) => return (false, Some(lm_reason::SYNTAX.to_string())),
    };
    match lm_classify(&node) {
        None => (true, None),
        Some(reason_str) => (false, Some(reason_str.to_string())),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NonMemberEdge {
    pub node: String,
    pub target: String,
    pub condition: String,
    pub level_m: bool,
    pub reason: Option<String>,
}

pub fn flow_level_m(graph: &Graph) -> (bool, Vec<NonMemberEdge>) {
    let mut bad = Vec::new();
    let mut names = crate::engine::reachable(graph);
    names.sort();
    for name in names {
        let Some(node) = graph.nodes.get(&name) else { continue };
        for (target, cond) in &node.edges {
            if !is_deterministic(cond) {
                continue;
            }
            let (level_m_ok, reason) = is_level_m(cond);
            if !level_m_ok {
                bad.push(NonMemberEdge {
                    node: name.clone(),
                    target: target.clone(),
                    condition: cond.clone(),
                    level_m: false,
                    reason,
                });
            }
        }
    }
    (bad.is_empty(), bad)
}

pub fn capability_report(graph: &Graph) -> serde_json::Value {
    let semantic = portability_violations(graph);
    let p0 = semantic.is_empty();
    let (lm_ok, non_member) = flow_level_m(graph);
    let hw_ok = p0 && lm_ok;

    let semantic_json: Vec<serde_json::Value> = semantic
        .iter()
        .map(|violation| serde_json::json!({ "node": violation.node, "target": violation.target, "condition": violation.condition }))
        .collect();
    let non_member_json =
        serde_json::to_value(&non_member).unwrap_or(serde_json::Value::Array(vec![]));

    let portable_reason = if p0 {
        serde_json::Value::Null
    } else {
        serde_json::json!(format!(
            "{} reachable semantic edge(s) \u{2014} P0 runs unconditionally; lock them for P1",
            semantic.len()
        ))
    };
    let hw_reason = if hw_ok {
        serde_json::Value::Null
    } else if !p0 {
        serde_json::json!(format!(
            "{} reachable semantic edge(s) \u{2014} not deterministic",
            semantic.len()
        ))
    } else {
        serde_json::json!(format!(
            "{} deterministic edge(s) outside the match-action fragment",
            non_member.len()
        ))
    };

    serde_json::json!({
        "tier": if p0 { "P0" } else { "P1/P2" },
        "level_m": lm_ok,
        "targets": {
            "python": { "status": "yes", "reason": null, "blocking_edges": [] },
            "portable": {
                "status": if p0 { "yes" } else { "needs-lockfile" },
                "reason": portable_reason,
                "blocking_edges": if p0 { serde_json::json!([]) } else { serde_json::json!(semantic_json) },
            },
            "level_m_hardware": {
                "status": if hw_ok { "yes" } else { "no" },
                "reason": hw_reason,
                "blocking_edges": if !p0 {
                    serde_json::json!(semantic_json)
                } else if hw_ok {
                    serde_json::json!([])
                } else {
                    non_member_json
                },
            },
        },
    })
}
