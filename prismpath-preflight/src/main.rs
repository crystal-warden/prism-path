// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
use std::collections::HashMap;
use std::process::ExitCode;

use prismpath_preflight::{run, Config};

const USAGE: &str = "\
prismpath-preflight: report how a sample of real events fares under the Facet codec for a given flow.

Usage:
  prismpath-preflight FLOW.md SAMPLE.ndjson [--map FIELD=PATH ...] [--on-missing error|skip]
                  [--route-node NODE] [--limit N] [--json OUT.json]

  FLOW.md          policy flow the codebook derives from
  SAMPLE.ndjson    sample events, one JSON object per line; '-' for stdin
  --map            map a flow field to a dot path in the event (repeatable);
                   same as the codec's field_paths
  --on-missing     codec behavior for events missing a decision field (default: error)
  --route-node     report the route distribution from this node only
  --limit          scan at most N events
  --json           also write the full report as JSON

Exit status: 0 = ready (everything encodable, routes preserved), 1 = findings need attention.";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("prismpath-preflight: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut positional: Vec<String> = Vec::new();
    let mut field_paths: HashMap<String, String> = HashMap::new();
    let mut on_missing_skip = false;
    let mut route_node: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut json_out: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--map" => match args.next().as_deref().map(|m| m.split_once('=')) {
                Some(Some((f, p))) => {
                    field_paths.insert(f.to_string(), p.to_string());
                }
                _ => return usage_err("--map wants FIELD=PATH"),
            },
            "--on-missing" => match args.next().as_deref() {
                Some("error") => on_missing_skip = false,
                Some("skip") => on_missing_skip = true,
                _ => return usage_err("--on-missing wants error|skip"),
            },
            "--route-node" => match args.next() {
                Some(n) => route_node = Some(n),
                None => return usage_err("--route-node wants a node name"),
            },
            "--limit" => match args.next().and_then(|n| n.parse().ok()) {
                Some(n) => limit = Some(n),
                None => return usage_err("--limit wants a number"),
            },
            "--json" => match args.next() {
                Some(p) => json_out = Some(p),
                None => return usage_err("--json wants an output path"),
            },
            other if other.starts_with('-') && other != "-" => {
                return usage_err(&format!("unknown flag {other:?}"));
            }
            other => positional.push(other.to_string()),
        }
    }
    if positional.len() != 2 {
        return usage_err("expected exactly FLOW.md and SAMPLE.ndjson");
    }

    let cfg = Config {
        flow: positional[0].clone(),
        sample: positional[1].clone(),
        field_paths,
        on_missing_skip,
        route_node,
        limit,
    };
    match run(&cfg) {
        Ok(outcome) => {
            println!("{}", outcome.markdown);
            if let Some(path) = json_out {
                let body = serde_json::to_string_pretty(&outcome.report).unwrap() + "\n";
                if let Err(e) = std::fs::write(&path, body) {
                    eprintln!("prismpath-preflight: cannot write {path:?}: {e}");
                    return ExitCode::FAILURE;
                }
                println!("\nwrote {path}");
            }
            if outcome.ready { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(msg) => {
            println!("{msg}");
            ExitCode::FAILURE
        }
    }
}
