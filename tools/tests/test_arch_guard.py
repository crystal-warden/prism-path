# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The architecture guard's layer contract, its ratchet and its frozen paths, tried on small planted trees.

Each test builds a tiny package in a temporary directory, runs the real guard over it, and plants one fault."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import arch_guard

ROOT = Path(arch_guard.ROOT)
GUARD = ROOT / "tools" / "arch_guard.py"

FILES = {
    "__init__.py": ("surface", ""),
    "kernel/__init__.py": ("kernel", ""),
    "kernel/core.py": ("kernel", "def decide():\n    return 1\n\n\ndef _hidden():\n    return 2\n"),
    "ports/__init__.py": ("ports", ""),
    "ports/target.py": ("ports", "from prismpath.kernel import core\n"),
    "onion/__init__.py": ("onion", ""),
    "onion/governor.py": ("onion", "from prismpath.kernel import core\n\n\ndef govern(policy, journal, raw):\n    d = policy.decide(raw)\n    journal.append(raw, d)\n"),
    "alpha/__init__.py": ("adapter", ""),
    "alpha/one.py": ("adapter", "from prismpath.onion import governor\n"),
    "beta/__init__.py": ("adapter", ""),
    "beta/two.py": ("adapter", "from prismpath.kernel.core import decide\n"),
    "cli.py": ("surface", "from prismpath.alpha import one\nfrom prismpath.beta import two\n"),
    "tools_gen.py": ("tooling", "from prismpath import cli\n"),
}


def make_tree(root: Path, extra=None, replace=None):
    """A small repository under `root`: a package with one file per layer, the two docs the guard reads, a config
    that declares every file, an empty baseline and the frozen list."""
    files = {name: value for name, value in FILES.items()}
    files.update(extra or {})
    for name, (_layer, source) in {**files, **(replace or {})}.items():
        path = root / "prismpath" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    (root / "docs").mkdir(exist_ok=True)
    for name in ("vocabulary.json", "DICTIONARY.md"):
        shutil.copy(ROOT / "docs" / name, root / "docs" / name)
    (root / "tools").mkdir(exist_ok=True)
    layers = {layer: [] for layer in arch_guard.LAYER_RANK}
    for name, (layer, _source) in files.items():
        layers[layer].append(name)
    config = {"package_dir": "prismpath", "core_modules": [], "adapters": {}, "orchestration_fallback": [], "console": [],
              "vocabulary": "docs/vocabulary.json", "dictionary": "docs/DICTIONARY.md", "scan_roots": ["prismpath"],
              "layers": {layer: sorted(names) for layer, names in layers.items()}, "layer_exempt_dirs": ["tests"],
              "adapter_allowed_pairs": [], "baseline": "tools/arch_baseline.json", "frozen_paths": "tools/frozen_paths.txt"}
    (root / "tools" / "arch_guard.config.json").write_text(json.dumps(config, indent=2))
    (root / "tools" / "frozen_paths.txt").write_text("prismpath/tests/fixtures/\n")
    if not (root / "tools" / "arch_baseline.json").exists():
        arch_guard.write_baseline(str(root / "tools" / "arch_baseline.json"), {s: [] for s in arch_guard.BASELINE_SECTIONS})
    return root


def configure(root: Path, **changes):
    path = root / "tools" / "arch_guard.config.json"
    config = json.loads(path.read_text())
    config.update(changes)
    path.write_text(json.dumps(config, indent=2))
    return config


def guard(root: Path, *args, branch="main"):
    """Run the guard as a process over `root`, and answer (exit code, the summary it printed)."""
    done = subprocess.run([sys.executable, str(GUARD), "--root", str(root), "--config", str(root / "tools" / "arch_guard.config.json"),
                           "--branch", branch, *args], capture_output=True, text=True, cwd=str(root), timeout=120)
    try:
        summary = json.loads(done.stdout[done.stdout.index("{"):done.stdout.rindex("}") + 1])
    except ValueError:
        summary = {}
    return done.returncode, summary, done.stdout + done.stderr


def baseline_of(root: Path) -> dict:
    return arch_guard.read_baseline(str(root / "tools" / "arch_baseline.json"))


def adopt(root: Path):
    """Write the baseline from the tree, as the contract package does."""
    code, _summary, out = guard(root, "--regenerate-baseline")
    assert "baseline written" in out, out


@pytest.fixture()
def tree(tmp_path):
    return make_tree(tmp_path)


# ------------------------------------------------------------------------------------------ the clean tree
def test_a_clean_tree_passes(tree):
    code, summary, out = guard(tree)
    assert code == 0, out
    assert summary["layer_problems"] == [] and summary["baseline_new"] == {s: [] for s in arch_guard.BASELINE_SECTIONS}


def test_the_real_repository_passes_with_its_baseline():
    result, failures = arch_guard.run(str(ROOT), str(ROOT / "tools" / "arch_guard.config.json"), branch="main")
    assert failures == 0, json.dumps({"layers": result["layers"], "ratchet": result["ratchet"]}, indent=1)[:2000]


# ------------------------------------------------------------------------------- S1, every file in one layer
def test_a_planted_undeclared_file_fails(tree):
    (tree / "prismpath" / "kernel" / "planted.py").write_text("X = 1\n")
    code, summary, out = guard(tree)
    assert code == 1
    assert any("kernel/planted.py is in no layer" in problem for problem in summary["layer_problems"])


def test_a_file_in_two_layers_fails(tree):
    config = configure(tree)
    config["layers"]["onion"].append("kernel/core.py")
    configure(tree, layers=config["layers"])
    code, summary, _ = guard(tree)
    assert code == 1 and any("two layers" in problem for problem in summary["layer_problems"])


def test_a_declared_file_that_is_gone_fails(tree):
    (tree / "prismpath" / "beta" / "two.py").unlink()
    code, summary, _ = guard(tree)
    assert code == 1 and any("beta/two.py is declared in a layer and does not exist" in p for p in summary["layer_problems"])


def test_a_tests_directory_is_not_production(tree):
    (tree / "prismpath" / "tests").mkdir()
    (tree / "prismpath" / "tests" / "test_x.py").write_text("from prismpath.cli import main\n")
    assert guard(tree)[0] == 0


# ------------------------------------------------------------------------------------ S2 and S3, direction
def test_a_planted_wrong_way_import_fails(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath.onion import governor\n")
    code, summary, _ = guard(tree)
    assert code == 1
    assert summary["baseline_new"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]


def test_a_function_level_import_counts(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("def late():\n    from prismpath.onion import governor\n    return governor\n")
    assert guard(tree)[0] == 1


def test_an_import_of_a_name_resolves_to_the_module_that_holds_it_and_an_import_of_a_module_to_that_module(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath.onion.governor import govern\n")
    code, summary, _ = guard(tree)
    assert summary["baseline_new"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath.onion import govern\n")
    code, summary, _ = guard(tree)
    assert summary["baseline_new"]["import_direction"] == ["kernel/core.py -> onion/__init__.py (kernel -> onion)"]


def test_a_relative_import_is_resolved(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("from ..onion import governor\n")
    assert guard(tree)[1]["baseline_new"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]


def test_a_type_checking_import_and_a_main_block_are_exempt(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from prismpath.onion import governor\n"
        "if __name__ == '__main__':\n    from prismpath.cli import main\n")
    assert guard(tree)[0] == 0


def test_an_adapter_importing_another_adapter_package_fails_unless_listed(tree):
    (tree / "prismpath" / "alpha" / "one.py").write_text("from prismpath.beta import two\n")
    code, summary, _ = guard(tree)
    assert code == 1 and summary["baseline_new"]["import_direction"] == \
        ["alpha/one.py -> beta/two.py (adapter -> adapter, another package)"]
    configure(tree, adapter_allowed_pairs=[["alpha", "beta"]])
    assert guard(tree)[0] == 0


def test_an_adapter_importing_its_own_package_is_fine(tree):
    (tree / "prismpath" / "alpha" / "one.py").write_text("from prismpath.alpha import __init__\n")
    assert guard(tree)[0] == 0


def test_tooling_is_imported_by_nothing(tree):
    (tree / "prismpath" / "cli.py").write_text("from prismpath import tools_gen\n")
    assert guard(tree)[1]["baseline_new"]["import_direction"] == ["cli.py -> tools_gen.py (surface -> tooling)"]


def test_an_alias_module_is_judged_as_the_module_it_names(tree):
    alias = ("# moved\nimport sys as _sys\nfrom prismpath.onion import governor as _m\n_sys.modules[__name__] = _m\n")
    make_tree(tree, extra={"old_gov.py": ("onion", alias)})
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath import old_gov\n")
    assert guard(tree)[1]["baseline_new"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]


# ------------------------------------------------------------------------------------------- S7, private
def test_a_planted_new_private_use_fails(tree):
    (tree / "prismpath" / "beta" / "two.py").write_text("from prismpath.kernel import core\n\n\ndef f():\n    return core._hidden()\n")
    code, summary, _ = guard(tree)
    assert code == 1
    assert summary["baseline_new"]["private_use"] == ["beta/two.py -> kernel/core.py :: _hidden #1"]


def test_a_private_name_imported_by_name_fails_and_each_site_is_a_line(tree):
    (tree / "prismpath" / "beta" / "two.py").write_text(
        "from prismpath.kernel.core import _hidden\nfrom prismpath.kernel import core\n\n\ndef f():\n    return core._hidden(), core._hidden()\n")
    new = guard(tree)[1]["baseline_new"]["private_use"]
    assert new == [f"beta/two.py -> kernel/core.py :: _hidden #{n}" for n in (1, 2, 3)]


def test_a_module_may_use_its_own_private_names_and_a_dunder_is_not_private(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("def _a():\n    return 1\n\n\nB = _a()\n")
    (tree / "prismpath" / "beta" / "two.py").write_text("from prismpath.kernel import core\n\nNAME = core.__name__\n")
    assert guard(tree)[0] == 0


# ------------------------------------------------------------------------------------------- S5, the governor
def test_a_file_outside_the_onion_that_decides_and_appends_fails(tree):
    (tree / "prismpath" / "alpha" / "one.py").write_text(
        "def hook(policy, run, raw):\n    verdict = policy.decide(raw)\n    return run.append(raw, verdict)\n")
    assert guard(tree)[1]["baseline_new"]["decides_outside_onion"] == ["alpha/one.py"]


def test_a_list_append_alone_or_a_decide_alone_is_not_the_sequence(tree):
    (tree / "prismpath" / "alpha" / "one.py").write_text(
        "def hook(policy, raw, items):\n    items.append(raw)\n    return policy.decide(raw)\n")
    assert guard(tree)[0] == 0


# ---------------------------------------------------------------------------------------- the ratchet
def test_a_baselined_fault_passes_and_a_fixed_one_must_leave_the_baseline(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath.onion import governor\n")
    assert guard(tree)[0] == 1
    adopt(tree)
    assert guard(tree)[0] == 0
    (tree / "prismpath" / "kernel" / "core.py").write_text("X = 1\n")           # fixed, the line is now stale
    code, summary, _ = guard(tree)
    assert code == 1 and summary["baseline_stale"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]
    assert guard(tree, "--shrink-baseline")[0] == 0
    assert baseline_of(tree)["import_direction"] == []


def test_a_line_added_to_the_baseline_fails(tree):
    adopt(tree)
    sections = baseline_of(tree)
    sections["import_direction"].append("kernel/core.py -> onion/governor.py (kernel -> onion)")
    arch_guard.write_baseline(str(tree / "tools" / "arch_baseline.json"), sections)
    code, summary, _ = guard(tree)
    assert code == 1 and summary["baseline_stale"]["import_direction"] == ["kernel/core.py -> onion/governor.py (kernel -> onion)"]


def test_shrink_only_deletes_and_never_adds(tree):
    (tree / "prismpath" / "kernel" / "core.py").write_text("from prismpath.onion import governor\n")
    before = (tree / "tools" / "arch_baseline.json").read_bytes()
    code, summary, _ = guard(tree, "--shrink-baseline")
    assert code == 1 and (tree / "tools" / "arch_baseline.json").read_bytes() == before     # the new fault stays a fault
    adopt(tree)
    (tree / "prismpath" / "kernel" / "core.py").write_text("X = 1\n")
    sections = baseline_of(tree)
    sections["private_use"].append("beta/two.py -> kernel/core.py :: _hidden #1")            # a planted line too
    arch_guard.write_baseline(str(tree / "tools" / "arch_baseline.json"), sections)
    assert guard(tree, "--shrink-baseline")[0] == 0
    assert baseline_of(tree) == {s: [] for s in arch_guard.BASELINE_SECTIONS}


def test_the_baseline_is_sorted_with_one_line_per_entry(tree):
    sections = {"import_direction": ["b -> c", "a -> b"], "private_use": ["z", "y"], "decides_outside_onion": []}
    path = tree / "tools" / "arch_baseline.json"
    arch_guard.write_baseline(str(path), sections)
    text = path.read_text().splitlines()
    assert json.loads(path.read_text())["import_direction"] == ["a -> b", "b -> c"]
    assert text[2:5] == ['  "import_direction": [', '    "a -> b",', '    "b -> c"']


def test_the_real_baseline_is_sorted_and_has_one_entry_per_line():
    path = ROOT / "tools" / "arch_baseline.json"
    data = json.loads(path.read_text())
    lines = path.read_text().splitlines()
    for section in arch_guard.BASELINE_SECTIONS:
        assert data[section] == sorted(set(data[section]))
        assert all(("    " + json.dumps(entry)).rstrip(",") in [line.rstrip(",") for line in lines] for entry in data[section])


# -------------------------------------------------------------------------------------- G8, frozen paths
def git(root, *args):
    return subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                          capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "tools").mkdir()
    (tmp_path / "prismpath" / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "prismpath" / "p").mkdir()
    (tmp_path / "tools" / "frozen_paths.txt").write_text(
        "# frozen\nprismpath/tests/fixtures/\n:(glob)prismpath/**/*.core.json\n")
    (tmp_path / "prismpath" / "tests" / "fixtures" / "golden.json").write_text("{}\n")
    (tmp_path / "prismpath" / "p" / "x.core.json").write_text("{}\n")
    (tmp_path / "prismpath" / "p" / "free.py").write_text("A = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def frozen(repo, branch):
    return arch_guard.frozen_findings(str(repo), str(repo / "tools" / "frozen_paths.txt"), branch=branch, base_ref="main")[0]


def test_a_frozen_path_edit_on_a_refactor_branch_fails(repo):
    git(repo, "checkout", "-q", "-b", "refactor-r9")
    (repo / "prismpath" / "tests" / "fixtures" / "golden.json").write_text('{"a": 1}\n')
    git(repo, "commit", "-q", "-am", "edit")
    assert [line.split()[0] for line in frozen(repo, "refactor-r9")] == ["M"]


def test_a_delete_and_a_rename_of_a_frozen_path_fail(repo):
    git(repo, "checkout", "-q", "-b", "refactor-r9")
    git(repo, "rm", "-q", "prismpath/p/x.core.json")
    git(repo, "mv", "prismpath/tests/fixtures/golden.json", "prismpath/p/moved.json")
    git(repo, "commit", "-q", "-m", "gone")
    # a rename out of a frozen path is a deletion of it as far as the frozen paths can see
    assert sorted(line.split()[0] for line in frozen(repo, "refactor-r9")) == ["D", "D"]


def test_an_added_frozen_file_and_a_free_edit_pass_on_a_refactor_branch(repo):
    git(repo, "checkout", "-q", "-b", "refactor-r9")
    (repo / "prismpath" / "tests" / "fixtures" / "new.json").write_text("{}\n")
    (repo / "prismpath" / "p" / "y.core.json").write_text("{}\n")
    (repo / "prismpath" / "p" / "free.py").write_text("A = 2\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add")
    assert frozen(repo, "refactor-r9") == []


def test_a_frozen_edit_on_any_other_branch_is_not_held(repo):
    git(repo, "checkout", "-q", "-b", "feature-x")
    (repo / "prismpath" / "tests" / "fixtures" / "golden.json").write_text('{"a": 1}\n')
    git(repo, "commit", "-q", "-am", "edit")
    assert frozen(repo, "feature-x") == []


def test_the_frozen_check_fails_the_guard_run_on_a_refactor_branch(tree):
    git(tree, "init", "-q", "-b", "main")
    (tree / "prismpath" / "tests" / "fixtures").mkdir(parents=True)
    (tree / "prismpath" / "tests" / "fixtures" / "golden.json").write_text("{}\n")
    git(tree, "add", "-A")
    git(tree, "commit", "-q", "-m", "base")
    git(tree, "checkout", "-q", "-b", "refactor-r9")
    (tree / "prismpath" / "tests" / "fixtures" / "golden.json").write_text('{"a": 1}\n')
    git(tree, "commit", "-q", "-am", "edit")
    code, summary, _ = guard(tree, branch="refactor-r9")
    assert code == 1 and summary["frozen_paths_changed"] == ["M prismpath/tests/fixtures/golden.json"]
    assert guard(tree, branch="feature-y")[0] == 0


def test_the_real_frozen_list_names_what_the_plan_names():
    text = (ROOT / "tools" / "frozen_paths.txt").read_text().splitlines()
    specs = [line for line in text if line and not line.startswith("#")]
    for needed in ("prismpath/portable/conformance/", "prismpath/telemetry/conformance/", "prismpath/tests/fixtures/",
                   "prismpath/policies/", "prismpath-hw/TABLE_FORMAT.md"):
        assert needed in specs
    assert any(spec.endswith("*.core.json") for spec in specs) and any(spec.endswith("*.ppt") for spec in specs)
    listed = git(ROOT, "ls-files", "--", *specs).split()
    assert "prismpath/tests/fixtures/core_evidence/cases.jsonl" in listed
