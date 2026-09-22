# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The architecture guard enforces the Dictionary's contract: a prohibited domain noun in core, a
declared module that is missing, a deprecated identifier outside its allowed paths, and a vocabulary
term the dictionary does not explain each fail with an explanation that names the file and the fix;
a deprecated identifier inside an allowed or certified path does not; and the real tree passes."""
import importlib.util
import json
from pathlib import Path

from prismpath.tests._repo import repo_file

_spec = importlib.util.spec_from_file_location("arch_guard", repo_file("tools", "arch_guard.py"))
arch_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(arch_guard)

VOCABULARY = {
    "domains": {"sensor": {"nouns": ["quaternion", "\\bimu\\b"], "reason": "adapter vocabulary"}},
    "deprecated": [{"identifier": "cli_agent", "canonical": "cli_worker", "term": "worker",
                    "allowed_paths": ["pkg/workers/shim.py"], "note": "the shim"}],
    "certified": {"paths": ["pkg/certified/"], "identifiers": [{"identifier": "next_node", "term": "route", "note": "wire key"}]},
}
DICTIONARY = "# Dictionary\n\nThe enforceable half is docs/vocabulary.json. The sensor domain stays out of core.\n\n**worker**: does the work. Layer: control plane.\n\n**route**: the edge taken. Layer: kernel evaluation.\n"


def _tree(tmp_path, core_text="x = 1\n", shim_text="cli_agent = 1\n", extra=None, dictionary=DICTIONARY, vocabulary=VOCABULARY, core_modules=None):
    root = tmp_path / "repo"
    (root / "pkg" / "kernel").mkdir(parents=True)
    (root / "pkg" / "workers").mkdir()
    (root / "pkg" / "certified").mkdir()
    (root / "docs").mkdir()
    (root / "tools").mkdir()
    (root / "pkg" / "kernel" / "engine.py").write_text(core_text)
    (root / "pkg" / "workers" / "shim.py").write_text(shim_text)
    (root / "pkg" / "certified" / "frozen.py").write_text("cli_agent = 'kept, certified'\n")
    for path, text in (extra or {}).items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    (root / "docs" / "vocabulary.json").write_text(json.dumps(vocabulary))
    (root / "docs" / "DICTIONARY.md").write_text(dictionary)
    config = {"package_dir": "pkg", "core_modules": core_modules or ["kernel/engine.py"], "adapters": {}, "vocabulary": "docs/vocabulary.json",
              "dictionary": "docs/DICTIONARY.md", "scan_roots": ["pkg"]}
    (root / "tools" / "arch_guard.config.json").write_text(json.dumps(config))
    return root


def _run(root):
    return arch_guard.run(str(root), str(root / "tools" / "arch_guard.config.json"))


def test_clean_tree_passes(tmp_path):
    result, failures = _run(_tree(tmp_path))
    assert failures == 0, result


def test_prohibited_domain_noun_in_core_fails_with_the_domain_named(tmp_path):
    result, failures = _run(_tree(tmp_path, core_text="orientation = quaternion(1, 0, 0, 0)\n"))
    assert failures == 1
    violation = result["signal_1_core_purity"]["violations"][0]
    assert violation["file"] == "kernel/engine.py" and violation["line"] == 1 and violation["domain"] == "sensor"
    assert "sensor adapter" in violation["fix"]


def test_removing_a_declared_module_fails_naming_the_path(tmp_path):
    result, failures = _run(_tree(tmp_path, core_modules=["kernel/engine.py", "kernel/gone.py"]))
    assert failures == 1
    assert result["declared_paths"]["missing"] == ["kernel/gone.py"]
    assert "removed from tools/arch_guard.config.json" in result["declared_paths"]["fix"]


def test_deprecated_identifier_outside_allowed_paths_fails_with_the_canonical_name(tmp_path):
    result, failures = _run(_tree(tmp_path, extra={"pkg/workers/other.py": "worker = cli_agent(['x'])\n"}))
    assert failures == 1
    finding = result["deprecated_identifiers"]["findings"][0]
    assert finding["file"] == "pkg/workers/other.py" and finding["identifier"] == "cli_agent" and finding["canonical"] == "cli_worker"
    assert "use cli_worker" in finding["fix"] and "allowed_paths" in finding["fix"]


def test_deprecated_identifier_in_allowed_and_certified_paths_is_fine(tmp_path):
    result, failures = _run(_tree(tmp_path))
    assert failures == 0 and result["deprecated_identifiers"]["findings"] == []


def test_vocabulary_drift_fails_when_the_dictionary_lacks_the_term_or_the_domain(tmp_path):
    result, failures = _run(_tree(tmp_path, dictionary="# Dictionary\n\nSee docs/vocabulary.json.\n\n**route**: the edge taken.\n"))
    assert failures == 2
    problems = result["vocabulary_drift"]["problems"]
    assert any("'worker'" in problem and "no such entry" in problem for problem in problems)
    assert any("'sensor'" in problem and "never names it" in problem for problem in problems)


def test_the_real_tree_passes():
    root = repo_file("tools", "arch_guard.config.json").parent.parent
    result, failures = arch_guard.run(str(root), str(root / "tools" / "arch_guard.config.json"))
    assert failures == 0, {key: value for key, value in result.items() if isinstance(value, dict) and not value.get("PASS", True)}
