# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The command line's failure handling: an ordinary mistake is one line on stderr and exit 2.

A missing or unreadable file, a flow that cannot run, a missing optional extra, a missing external
program, and ci-report outside a git repository each print `prismpath <command>: <message>` and no
traceback. A real bug keeps its traceback, and PRISMPATH_DEBUG=1 shows one for the ordinary cases
too. The subprocess tests run the CLI the way a person does, so a traceback cannot hide behind
pytest's own exception capture.
"""
import os
import subprocess
import sys

import pytest

import prismpath
from prismpath import cli, extras

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(prismpath.__file__)))

FLOW = """---
name: t
start: a
---

## a
Do the thing.
-> b: when ok

## b
Done.
"""

SEMANTIC_FLOW = """---
name: s
start: a
---

## a
Read the report.
-> b: the report describes an outage
-> c: the report is a routine request

## b
Page someone.

## c
Answer it.
"""


def _main(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def _cli(*argv, block=(), env=None, cwd=None):
    """Run the CLI in a fresh interpreter. `block` names modules made unimportable, the way a plain
    install without the extra leaves them."""
    script = ("import sys\n"
              f"for name in {list(block)!r}:\n"
              "    sys.modules[name] = None\n"
              "from prismpath.cli import main\n"
              "raise SystemExit(main(sys.argv[1:]))\n")
    run_env = {**os.environ, **(env or {})}
    run_env["PYTHONPATH"] = REPO_ROOT + os.pathsep + run_env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-c", script, *argv], capture_output=True, text=True,
                          env=run_env, cwd=cwd)


# ------------------------------------------------------------------ files and directories

@pytest.mark.parametrize("command", ["run", "validate", "graph", "context", "verify", "lint", "contract"])
def test_a_missing_flow_is_one_line(command, tmp_path, capsys):
    missing = str(tmp_path / "nope.md")
    code, out, err = _main(capsys, command, missing)
    assert code == 2
    assert err.strip() == f"prismpath {command}: {missing}: No such file or directory"


def test_a_directory_or_a_path_through_a_file_is_one_line(tmp_path, capsys):
    code, _out, err = _main(capsys, "validate", str(tmp_path))
    assert code == 2 and err.strip() == f"prismpath validate: {tmp_path}: Is a directory"
    afile = tmp_path / "flow.md"
    afile.write_text(FLOW)
    code, _out, err = _main(capsys, "validate", str(afile / "x.md"))
    assert code == 2 and "Not a directory" in err


def test_an_unreadable_file_is_one_line(tmp_path, capsys):
    if os.geteuid() == 0:
        pytest.skip("root reads every file")
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    flow.chmod(0)
    try:
        code, _out, err = _main(capsys, "validate", str(flow))
    finally:
        flow.chmod(0o644)
    assert code == 2 and err.strip() == f"prismpath validate: {flow}: Permission denied"


@pytest.mark.parametrize("argv", [["resume", "nope.json"], ["kappa", "a.jsonl", "b.jsonl"],
                                  ["import", "nope.py"], ["centroids", "nope.jsonl"],
                                  ["ledger", "verify", "--leaf", "ab", "--out", "nope"]])
def test_other_inputs_missing_are_one_line(argv, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shutil.which", lambda program: f"/usr/bin/{program}")   # `ots` "installed"
    code, _out, err = _main(capsys, *argv)
    assert code == 2
    assert err.startswith(f"prismpath {argv[0]}: ") and "No such file or directory" in err
    assert len(err.strip().splitlines()) == 1


@pytest.mark.parametrize("argv", [["calibrate", "nope.jsonl"], ["label", "nope.jsonl"], ["trail", "nope.log"]])
def test_a_missing_log_is_refused_not_read_as_empty(argv, tmp_path, monkeypatch, capsys):
    # these read a missing log as empty, which printed a calibrated tau of 0 and an empty audit
    # trail that "verifies"; a typo in the path has to say so instead
    monkeypatch.chdir(tmp_path)
    code, out, err = _main(capsys, *argv)
    assert code == 2 and out == ""
    assert err.strip() == f"prismpath {argv[0]}: {argv[1]}: No such file or directory"


def test_a_binary_flow_is_one_line(tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_bytes(b"\xff\xfe\x00binary")
    code, _out, err = _main(capsys, "validate", str(flow))
    assert code == 2 and "not UTF-8 text" in err


def test_malformed_json_input_is_one_line(tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    code, _out, err = _main(capsys, "facet", "encode", str(flow), "{not json")
    assert code == 2 and "not valid JSON" in err


# ------------------------------------------------------------------ malformed flows

def test_a_flow_with_no_nodes_does_not_run(tmp_path, capsys):
    # before: `run` stopped on a bare `KeyError: ''` from the engine
    flow = tmp_path / "flow.md"
    flow.write_text("just some prose, no headings\n")
    code, out, err = _main(capsys, "run", str(flow))
    assert code == 2 and out == ""
    assert "defines no nodes" in err and "prismpath validate" in err


def test_an_undefined_start_does_not_run(tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW.replace("start: a", "start: nowhere"))
    code, _out, err = _main(capsys, "run", str(flow))
    assert code == 2 and "start node 'nowhere' is not defined" in err


def test_an_undefined_target_does_not_run(tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW.replace("-> b: when ok", "-> nowhere: when ok"))
    code, _out, err = _main(capsys, "run", str(flow))
    assert code == 2 and "[a] edge -> 'nowhere' points at an undefined node" in err


def test_a_flow_over_its_bounds_is_a_parse_error_line(tmp_path, monkeypatch, capsys):
    from prismpath.kernel import parser
    monkeypatch.setattr(parser, "MAX_FLOW_BYTES", 10)
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    code, _out, err = _main(capsys, "validate", str(flow))
    assert code == 2
    assert err.startswith("prismpath validate: the flow document cannot be parsed: ")


def test_a_runnable_flow_still_runs(tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW.replace("when ok", "always"))
    code, out, _err = _main(capsys, "run", str(flow))
    assert code == 0 and "Path: ['a', 'b']" in out


# ------------------------------------------------------------------ real bugs stay visible

def test_an_unexpected_exception_keeps_its_traceback(tmp_path, monkeypatch):
    def broken(_path):
        raise KeyError("a real bug")
    monkeypatch.setattr(cli, "parse_file", broken)
    with pytest.raises(KeyError, match="a real bug"):
        cli.main(["validate", str(tmp_path / "flow.md")])


def test_an_import_error_that_is_not_an_extra_keeps_its_traceback():
    try:
        import prismpath_no_such_module  # noqa: F401
    except ImportError as exc:
        assert extras.from_exception(exc) is None
        assert cli._user_error(exc) is None


def test_prismpath_debug_shows_the_traceback(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMPATH_DEBUG", "1")
    with pytest.raises(FileNotFoundError):
        cli.main(["validate", str(tmp_path / "nope.md")])


# ------------------------------------------------------------------ optional extras

def test_every_extra_module_maps_to_an_extra_pyproject_declares():
    tomllib = pytest.importorskip("tomllib")
    pyproject = os.path.join(REPO_ROOT, "pyproject.toml")
    if not os.path.isfile(pyproject):
        pytest.skip("pyproject.toml is not shipped in the wheel")
    with open(pyproject, "rb") as handle:
        declared = tomllib.load(handle)["project"]["optional-dependencies"]
    for module, (extra, package) in extras.EXTRAS.items():
        assert extra in declared, module
        assert any(req.split()[0].split(";")[0].strip() == package for req in declared[extra]), module


def test_a_missing_module_of_an_extra_is_named_by_its_extra():
    try:
        raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
    except ModuleNotFoundError as exc:
        missing = extras.from_exception(exc)
    assert missing.extra == "control-plane"
    assert missing.install == "needs fastapi (the control-plane extra): pip install 'prismpath[control-plane]'"


def test_the_embedder_absence_is_a_missing_extra(monkeypatch):
    import builtins
    from prismpath.routing import embedder
    real_import = builtins.__import__

    def block(name, *args, **kw):
        if name.startswith("sentence_transformers"):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", block)
    monkeypatch.setattr(embedder, "_model", None)
    with pytest.raises(ImportError, match=r"pip install 'prismpath\[embeddings\]'") as raised:
        embedder.embed(["x"])
    assert isinstance(raised.value, extras.MissingExtra) and raised.value.extra == "embeddings"


@pytest.mark.parametrize("command", ["run", "lock", "test", "lint"])
def test_no_embedder_is_one_install_line(command, tmp_path):
    flow = tmp_path / "s.md"
    flow.write_text(SEMANTIC_FLOW)
    (tmp_path / "s.tests.md").write_text(
        "| node | outcome | fields | expect |\n|---|---|---|---|\n| a | the site is down | | b |\n")
    res = _cli(command, str(flow), block=["sentence_transformers"], cwd=tmp_path)
    assert res.returncode == 2, res.stderr
    assert "Traceback" not in res.stderr
    assert res.stderr.strip() == (f"prismpath {command}: needs sentence-transformers (the embeddings "
                                  f"extra): pip install 'prismpath[embeddings]'")


@pytest.mark.parametrize("action", ["keygen", "envelope"])
def test_no_cryptography_is_one_install_line(action, tmp_path):
    argv = ["swap", action, "--out", str(tmp_path / "out")]
    if action == "envelope":
        argv += ["--priv", "k.key", "--pub", "k.pub", "--fields", "temp:int"]
    res = _cli(*argv, block=["cryptography"], cwd=tmp_path)
    assert res.returncode == 2
    assert "Traceback" not in res.stderr
    assert res.stderr.strip() == "policy signing needs cryptography (the signing extra): pip install 'prismpath[signing]'"


def test_no_traceback_for_a_missing_file_from_a_real_process(tmp_path):
    res = _cli("run", str(tmp_path / "nope.md"))
    assert res.returncode == 2
    assert "Traceback" not in res.stderr
    assert res.stderr.strip() == f"prismpath run: {tmp_path / 'nope.md'}: No such file or directory"


def test_python_dash_m_prismpath_cli_reports_the_same_line(tmp_path):
    # `python -m prismpath.cli` loads the module twice (as __main__ and as prismpath.cli); the
    # CliError ci_report raises has to be the class main catches
    env = {**os.environ, "PYTHONPATH": REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "GIT_CEILING_DIRECTORIES": str(tmp_path.parent)}
    res = subprocess.run([sys.executable, "-m", "prismpath.cli", "ci-report", "--base", "HEAD"],
                         capture_output=True, text=True, cwd=tmp_path, env=env)
    assert res.returncode == 2 and "Traceback" not in res.stderr
    assert res.stderr.startswith("prismpath ci-report: must run inside a git working tree")


# ------------------------------------------------------------------ external programs

@pytest.mark.parametrize("action,program", [("anchor", "ots"), ("upgrade", "ots"), ("verify", "ots"),
                                            ("relay-stamp", "ots"), ("rfc3161", "openssl")])
def test_a_missing_ledger_program_is_named(action, program, monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda _program: None)
    code, out, err = _main(capsys, "ledger", action)
    assert code == 2 and out == ""
    assert err.startswith(f"prismpath ledger: {action} needs the `{program}` program on PATH (")
    if program == "ots":
        assert "pip install opentimestamps-client" in err


def test_ci_report_outside_a_git_repository(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    code, out, err = _main(capsys, "ci-report", "--base", "HEAD")
    assert code == 2 and out == ""
    assert err.strip() == ("prismpath ci-report: must run inside a git working tree "
                           "(it reports the flows changed since --base)")


def test_ci_report_without_git(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _program: None)
    code, _out, err = _main(capsys, "ci-report", "--base", "HEAD")
    assert code == 2 and err.startswith("prismpath ci-report: needs the `git` program on PATH")


def test_ci_report_with_a_bad_base_ref(tmp_path, monkeypatch, capsys):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    code, _out, err = _main(capsys, "ci-report", "--base", "no-such-ref")
    assert code == 2
    assert err.startswith("prismpath ci-report: git could not diff against 'no-such-ref'")


# ------------------------------------------------------------------ init

def test_init_name_writes_a_markdown_flow(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out, _err = _main(capsys, "init", "demo")
    assert code == 0
    assert sorted(os.listdir(tmp_path)) == ["demo.md", "demo.tests.md"]
    assert "prismpath validate demo.md" in out and "prismpath test demo.md" in out
    assert _main(capsys, "test", "demo.md")[0] == 0


def test_init_keeps_a_name_that_already_ends_in_md(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert _main(capsys, "init", "triage.md")[0] == 0
    assert sorted(os.listdir(tmp_path)) == ["triage.md", "triage.tests.md"]


def test_init_bare_writes_flow_md(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert _main(capsys, "init")[0] == 0
    assert sorted(os.listdir(tmp_path)) == ["flow.md", "flow.tests.md"]


def test_init_refuses_to_overwrite_the_md_it_would_write(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "demo.md").write_text("mine\n")
    code, out, _err = _main(capsys, "init", "demo")
    assert code == 1 and "demo.md already exists" in out
    assert (tmp_path / "demo.md").read_text() == "mine\n"
