// CI gate worker (Rust) — the same job as ci_gate.py, to show one job porting across languages with no
// change to the flow. Read the build report from stdin, decide pass/coverage, print ONE JSON object,
// exit 0. A nonzero exit routes to the flow's error tier. This scans stdin for the report's fields; a
// worker needing structured input would parse the [context] JSON block (see ci_gate.py).
// Build once (rustc -O ci_gate.rs), then wire it in with:  cli_agent(["./ci_gate"], pass_state=["report"])
use std::io::{self, Read};

fn field(text: &str, key: &str) -> Option<i64> {
    let at = text.find(key)?;
    let digits: String = text[at + key.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    match (field(&text, "failed="), field(&text, "coverage=")) {
        (Some(failed), Some(coverage)) => print!(
            "{{\"passed\":{},\"failed\":{},\"coverage\":{}}}",
            failed == 0,
            failed,
            coverage
        ),
        _ => {
            eprint!("unparseable build report"); // -> the flow's error tier
            std::process::exit(1);
        }
    }
}
