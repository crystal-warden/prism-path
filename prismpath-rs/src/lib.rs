use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub name: String,
    pub start: String,
    pub nodes: HashMap<String, Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub target: String,
    pub condition: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }
}

pub struct Engine {
    pub flow: Flow,
}

impl Engine {
    pub fn new(flow: Flow) -> Self {
        Self { flow }
    }

    /// Executes the flow starting from the given node (or the flow's start node)
    /// using the provided context, returning the path of nodes visited.
    pub fn run(
        &self,
        start_node: Option<&str>,
        context: &HashMap<String, Value>,
    ) -> Result<Vec<String>, String> {
        let mut current_node_name = start_node
            .unwrap_or(&self.flow.start)
            .to_string();
        let mut path = vec![current_node_name.clone()];
        let mut steps = 0;
        const MAX_STEPS: usize = 100;

        while steps < MAX_STEPS {
            steps += 1;
            let node = match self.flow.nodes.get(&current_node_name) {
                Some(n) => n,
                None => return Err(format!("Node {} not found in flow", current_node_name)),
            };

            // Evaluate edges
            let mut transitioned = false;
            for edge in &node.edges {
                if self.evaluate_condition(&edge.condition, context) {
                    current_node_name = edge.target.clone();
                    path.push(current_node_name.clone());
                    transitioned = true;
                    break;
                }
            }

            if !transitioned {
                // No matching edge, stopped (e.g. at a terminal node)
                break;
            }

            // Check if we hit a node with no outgoing edges (terminal)
            if let Some(n) = self.flow.nodes.get(&current_node_name) {
                if n.edges.is_empty() {
                    break;
                }
            }
        }

        if steps >= MAX_STEPS {
            return Err("Execution exceeded maximum step limit (infinite loop protection)".to_string());
        }

        Ok(path)
    }

    fn evaluate_condition(&self, condition: &str, context: &HashMap<String, Value>) -> bool {
        let cond = condition.trim();
        let cond_lower = cond.to_lowercase();

        if cond_lower == "always" || cond_lower == "true" || cond_lower == "else" || cond_lower == "otherwise" || cond_lower == "default" || cond_lower == "_" {
            return true;
        }
        if cond_lower == "false" || cond_lower == "never" {
            return false;
        }

        if cond.starts_with("when ") {
            let expr = &cond[5..];
            return self.evaluate_expression(expr, context).unwrap_or(false);
        }

        false
    }

    fn evaluate_expression(&self, expr: &str, context: &HashMap<String, Value>) -> Result<bool, String> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(false);
        }

        // Simple binary comparisons: e.g. "x == True", "flag == 1", "visits < 2"
        if parts.len() == 3 {
            let left_var = parts[0];
            let op = parts[1];
            let right_val = parts[2];

            let left = context.get(left_var).cloned().unwrap_or(Value::Null);
            let right = self.parse_value_literal(right_val, context);

            match op {
                "==" => return Ok(self.compare_values(&left, &right) == Some(std::cmp::Ordering::Equal)),
                "!=" => return Ok(self.compare_values(&left, &right) != Some(std::cmp::Ordering::Equal)),
                "<" => return Ok(self.compare_values(&left, &right) == Some(std::cmp::Ordering::Less)),
                "<=" => {
                    let cmp = self.compare_values(&left, &right);
                    return Ok(cmp == Some(std::cmp::Ordering::Less) || cmp == Some(std::cmp::Ordering::Equal));
                }
                ">" => return Ok(self.compare_values(&left, &right) == Some(std::cmp::Ordering::Greater)),
                ">=" => {
                    let cmp = self.compare_values(&left, &right);
                    return Ok(cmp == Some(std::cmp::Ordering::Greater) || cmp == Some(std::cmp::Ordering::Equal));
                }
                "in" => {
                    if let Value::Array(arr) = &right {
                        return Ok(arr.contains(&left));
                    }
                    if let Value::String(s_right) = &right {
                        if let Value::String(s_left) = &left {
                            return Ok(s_right.contains(s_left));
                        }
                    }
                    return Ok(false);
                }
                _ => {}
            }
        }

        // If it's a single variable check, evaluate truthiness
        if parts.len() == 1 {
            let var = parts[0];
            if let Some(val) = context.get(var) {
                return Ok(val.is_truthy());
            }
        }

        Ok(false)
    }

    fn parse_value_literal(&self, lit: &str, context: &HashMap<String, Value>) -> Value {
        if lit == "True" {
            return Value::Bool(true);
        }
        if lit == "False" {
            return Value::Bool(false);
        }
        if lit == "None" || lit == "null" {
            return Value::Null;
        }
        if let Ok(n) = lit.parse::<f64>() {
            return Value::Number(n);
        }
        if (lit.starts_with('"') && lit.ends_with('"')) || (lit.starts_with('\'') && lit.ends_with('\'')) {
            return Value::String(lit[1..lit.len() - 1].to_string());
        }
        // Fallback: look up in context as a field reference
        context.get(lit).cloned().unwrap_or(Value::Null)
    }

    fn compare_values(&self, left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
        match (left, right) {
            (Value::Null, Value::Null) => Some(std::cmp::Ordering::Equal),
            (Value::Bool(l), Value::Bool(r)) => l.partial_cmp(r),
            (Value::Number(l), Value::Number(r)) => l.partial_cmp(r),
            // Cross type bool to number comparison (True == 1, False == 0)
            (Value::Bool(l), Value::Number(r)) => {
                let ln = if *l { 1.0 } else { 0.0 };
                ln.partial_cmp(r)
            }
            (Value::Number(l), Value::Bool(r)) => {
                let rn = if *r { 1.0 } else { 0.0 };
                l.partial_cmp(&rn)
            }
            (Value::String(l), Value::String(r)) => l.partial_cmp(r),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_execution() {
        let mut nodes = HashMap::new();

        // Node A: Start node
        nodes.insert(
            "node_a".to_string(),
            Node {
                name: "node_a".to_string(),
                edges: vec![
                    Edge {
                        target: "node_b".to_string(),
                        condition: "when visits < 2".to_string(),
                    },
                    Edge {
                        target: "node_c".to_string(),
                        condition: "else".to_string(),
                    },
                ],
            },
        );

        // Node B
        nodes.insert(
            "node_b".to_string(),
            Node {
                name: "node_b".to_string(),
                edges: vec![
                    Edge {
                        target: "node_d".to_string(),
                        condition: "always".to_string(),
                    },
                ],
            },
        );

        // Node C
        nodes.insert(
            "node_c".to_string(),
            Node {
                name: "node_c".to_string(),
                edges: vec![],
            },
        );

        // Node D (Terminal)
        nodes.insert(
            "node_d".to_string(),
            Node {
                name: "node_d".to_string(),
                edges: vec![],
            },
        );

        let flow = Flow {
            name: "test_flow".to_string(),
            start: "node_a".to_string(),
            nodes,
        };

        let engine = Engine::new(flow);

        // Case 1: visits = 1 -> should go node_a -> node_b -> node_d
        let mut context = HashMap::new();
        context.insert("visits".to_string(), Value::Number(1.0));
        let path = engine.run(None, &context).unwrap();
        assert_eq!(path, vec!["node_a", "node_b", "node_d"]);

        // Case 2: visits = 3 -> should go node_a -> node_c
        let mut context2 = HashMap::new();
        context2.insert("visits".to_string(), Value::Number(3.0));
        let path2 = engine.run(None, &context2).unwrap();
        assert_eq!(path2, vec!["node_a", "node_c"]);
    }
}

