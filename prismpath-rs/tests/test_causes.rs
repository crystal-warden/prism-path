//! The cause registry is generated from `prismpath/kernel/causes.py` (`prismpath/portable/gen_causes_rs.py`),
//! and this test holds the generated table to the frozen corpus and to the live Python registry.
//!
//! The live check runs when `PRISMPATH_PYTHON` names an interpreter with the package importable; with
//! `PRISMPATH_REQUIRE_CROSS_LANGUAGE` set a missing interpreter is a failure, not a skip.

use prismpath_rs::causes;
use serde_json::Value;
use std::process::Command;

fn corpus() -> Value {
    let text = std::fs::read_to_string("tests/fixtures/causes.json").expect("read causes.json");
    serde_json::from_str(&text).expect("parse causes.json")
}

#[test]
fn the_table_is_the_frozen_registry_row_for_row() {
    let doc = corpus();
    let rows = doc["registry"].as_array().unwrap();
    assert_eq!(rows.len(), causes::REGISTRY.len());
    for (want, got) in rows.iter().zip(causes::REGISTRY) {
        assert_eq!(want["code"].as_u64().unwrap(), got.code as u64);
        assert_eq!(want["name"].as_str().unwrap(), got.name);
        assert_eq!(want["class"].as_str().unwrap(), got.class.as_str());
        assert_eq!(want["description"].as_str().unwrap(), got.description);
    }
}

#[test]
fn the_registry_hash_matches_python_s() {
    let doc = corpus();
    let python_hash = doc["registry_sha256"].as_str().unwrap();
    assert_eq!(causes::registry_sha256(), python_hash, "the Rust hash over the table");
    assert_eq!(causes::REGISTRY_SHA256, python_hash, "the constant the generator wrote");
}

#[test]
fn the_registry_hash_matches_a_live_python_registry() {
    let python = match std::env::var("PRISMPATH_PYTHON") {
        Ok(path) => path,
        Err(_) => {
            assert!(
                std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_err(),
                "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but PRISMPATH_PYTHON is not"
            );
            eprintln!("SKIP: PRISMPATH_PYTHON not set; the frozen corpus check above still ran");
            return;
        }
    };
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new(python)
        .args(["-c", "from prismpath.kernel import causes; print(causes.registry_sha256())"])
        .env("PYTHONPATH", repo_root)
        .output()
        .expect("run python");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), causes::registry_sha256());
}

#[test]
fn codes_and_names_are_unique_and_fit_a_byte_above_zero() {
    let mut codes: Vec<u8> = causes::REGISTRY.iter().map(|row| row.code).collect();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), causes::REGISTRY.len());
    assert!(!codes.contains(&causes::CAUSE_NONE));
    let mut names: Vec<&str> = causes::REGISTRY.iter().map(|row| row.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), causes::REGISTRY.len());
}

#[test]
fn lookups_answer_as_python_does() {
    let doc = corpus();
    for probe in doc["by_code"].as_array().unwrap() {
        let code = probe["code"].as_u64().unwrap() as u8;
        assert_eq!(causes::name(code), probe["name"].as_str(), "name of {code}");
        assert_eq!(causes::cause_class(code).map(|class| class.as_str()), probe["class"].as_str(), "class of {code}");
    }
    for probe in doc["by_name"].as_array().unwrap() {
        let name = probe["name"].as_str().unwrap();
        assert_eq!(causes::code(name).map(u64::from), probe["code"].as_u64(), "code of {name:?}");
    }
}

#[test]
fn the_engine_stop_mapping_is_pythons_and_clean_stops_have_no_cause() {
    let doc = corpus();
    let mapping = doc["engine_stop_to_cause"].as_object().unwrap();
    assert_eq!(mapping.len(), causes::ENGINE_STOP_TO_CAUSE.len());
    for (stop, want) in mapping {
        assert_eq!(causes::engine_stop_cause(stop) as u64, want.as_u64().unwrap(), "{stop}");
    }
    for stop in doc["clean_stops"].as_array().unwrap() {
        assert_eq!(causes::engine_stop_cause(stop.as_str().unwrap()), causes::CAUSE_NONE);
    }
    assert_eq!(causes::engine_stop_cause("no such stop"), causes::CAUSE_NONE);
}
