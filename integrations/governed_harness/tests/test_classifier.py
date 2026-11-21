# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The classifier on its own: raw calls in, the reading's fields out. It is trusted code outside the
verified core, so these tests are the only thing that stands behind a reading saying what a call does."""
import os

import pytest

from integrations.governed_harness import classifier
from integrations.governed_harness.classifier import Config, classify


@pytest.fixture()
def world(tmp_path):
    ws = tmp_path / "ws"
    decoy = tmp_path / "decoy"
    (ws / ".toolchain" / "bin").mkdir(parents=True)
    (ws / "logs").mkdir()
    (ws / "logs" / "a.log").write_text("a")
    (ws / "notes.txt").write_text("n")
    decoy.mkdir()
    (decoy / "sentinel.txt").write_text("s")
    os.symlink(decoy, ws / "link_out")
    os.symlink(decoy / "sentinel.txt", ws / "cfg")
    os.symlink("notes.txt", ws / "inner_link")
    return Config.for_workspace(ws), ws, decoy


def fields(reading, *names):
    return tuple(reading[name] for name in names)


def test_every_reading_holds_every_field_with_its_kind(world):
    config, _ws, _decoy = world
    for call in ({"tool": "list_dir", "args": {}}, {"tool": "nope"}, {"tool": "git", "args": {"subcommand": "push"}},
                 {"tool": "run_command", "args": {"argv": ["ls"]}}, None, "text", 3):
        reading = classify(call, config)
        assert set(reading) == set(classifier.base_reading())
        assert reading["classifier_version"] == classifier.CLASSIFIER_VERSION
        assert all(type(value) in (int, bool, str) for value in reading.values())


@pytest.mark.parametrize("call", [
    None, [], "list_dir", {"tool": "http_get", "args": {"url": "x"}}, {"tool": "list_dir", "args": [], },
    {"tool": "read_file", "args": {}}, {"tool": "read_file", "args": {"path": 3}},
    {"tool": "read_file", "args": {"path": "a", "mode": "r"}}, {"tool": "write_file", "args": {"path": "a"}},
    {"tool": "write_file", "args": {"path": "a", "content": 1.5}}, {"tool": "run_command", "args": {"argv": "ls -la"}},
    {"tool": "git", "args": {"args": ["status"]}}, {"tool": "list_dir", "args": {}, "extra": 1},
])
def test_a_call_it_cannot_read_is_unknown(world, call):
    assert classify(call, world[0])["tool"] == "unknown"


@pytest.mark.parametrize("path", ["", "a\x00b", "x" * 5000])
def test_a_path_it_cannot_read_is_unknown(world, path):
    assert classify({"tool": "read_file", "args": {"path": path}}, world[0])["path_scope"] == "unknown"


def test_paths_inside_the_workspace(world):
    config, ws, _ = world
    for path in ("notes.txt", "/workspace/notes.txt", str(ws / "notes.txt"), "logs/new.log", ".", "/workspace"):
        reading = classify({"tool": "write_file", "args": {"path": path, "content": ""}}, config)
        assert fields(reading, "path_scope", "path_glob", "path_traversal", "path_symlink", "path_in_toolchain") == \
            ("workspace", False, False, False, False), path


def test_paths_outside_the_workspace(world):
    config, _ws, decoy = world
    for path in (str(decoy / "sentinel.txt"), "/etc/hosts", "/home", "../decoy/sentinel.txt", "/workspace/../x"):
        assert classify({"tool": "delete_path", "args": {"path": path}}, config)["path_scope"] == "outside", path


def test_traversal_is_flagged_even_when_it_lands_inside(world):
    reading = classify({"tool": "delete_path", "args": {"path": "logs/../notes.txt"}}, world[0])
    assert fields(reading, "path_scope", "path_traversal") == ("workspace", True)


@pytest.mark.parametrize("path", ["*.log", "logs/*", "tmp_?.txt", "logs/[ab].log", "{a,b}.txt"])
def test_globs_are_flagged(world, path):
    assert classify({"tool": "delete_path", "args": {"path": path}}, world[0])["path_glob"] is True


@pytest.mark.parametrize("path", ["~", "~/x", "~/.ssh/config", "~root", "~root/x"])
def test_a_home_path_reads_as_outside(world, path, monkeypatch):
    """The first component `~` or `~user` is never expanded: outside, even when HOME is the workspace."""
    config, ws, _ = world
    monkeypatch.setenv("HOME", str(ws))
    for tool, args in (("read_file", {"path": path}), ("write_file", {"path": path, "content": ""}), ("list_dir", {"path": path})):
        reading = classify({"tool": tool, "args": args}, config)
        assert fields(reading, "path_scope", "path_glob") == ("outside", False), (tool, path)


@pytest.mark.parametrize("path", ["foo/~bar", "a~", "./~x"])
def test_a_tilde_that_is_not_the_first_component_is_a_name(world, path):
    reading = classify({"tool": "write_file", "args": {"path": path, "content": ""}}, world[0])
    assert fields(reading, "path_scope", "path_glob") == ("workspace", False)


def test_symlinks_are_flagged_and_resolved(world):
    config = world[0]
    through = classify({"tool": "write_file", "args": {"path": "link_out/new.txt", "content": ""}}, config)
    assert fields(through, "path_symlink", "path_scope") == (True, "outside")
    final = classify({"tool": "write_file", "args": {"path": "cfg", "content": ""}}, config)
    assert fields(final, "path_symlink", "path_scope") == (True, "outside")
    inner = classify({"tool": "delete_path", "args": {"path": "inner_link"}}, config)
    assert fields(inner, "path_symlink", "path_scope") == (True, "workspace")


def test_toolchain_paths(world):
    config = world[0]
    for path in (".toolchain/bin/python3", "/workspace/.toolchain/lib/new", "/usr/local/bin/x",
                 os.path.expanduser("~/.cargo/bin/x")):
        assert classify({"tool": "write_file", "args": {"path": path, "content": ""}}, config)["path_in_toolchain"], path
    assert not classify({"tool": "write_file", "args": {"path": "toolchain_notes.txt", "content": ""}},
                        config)["path_in_toolchain"]


@pytest.mark.parametrize("argv,klass", [
    (["ls", "-la"], "read_only"), (["cat", "notes.txt"], "read_only"), (["wc", "-l", "notes.txt"], "read_only"),
    (["grep", "-rn", "TODO", "."], "read_only"), (["/usr/bin/ls"], "read_only"), (["find", ".", "-name", "*.log"], "read_only"),
    (["find", ".", "-name", "*.log", "-delete"], "mutating"), (["find", ".", "-exec", "rm", "{}", ";"], "mutating"),
    (["sed", "-n", "1p", "notes.txt"], "read_only"), (["sed", "-i", "s/a/b/", "notes.txt"], "mutating"),
    (["rm", "notes.txt"], "mutating"), (["rm", "-rf", "logs"], "mutating"), (["mv", "a", "b"], "mutating"),
    (["python3", "x.py"], "mutating"), (["bash", "-c", "ls"], "mutating"), (["./run.sh"], "mutating"),
    (["/opt/tool/bin/x"], "mutating"), (["curl", "https://example.com"], "network"), (["wget", "x"], "network"),
    (["pip", "install", "requests"], "network"), (["python3", "-m", "pip", "install", "x"], "network"),
    (["npm", "install"], "network"), (["echo", "see https://example.com"], "network"), (["ssh", "host"], "network"),
    (["sudo", "ls"], "unknown"), (["frobnicate"], "unknown"), (["git", "status"], "git"),
])
def test_command_classes(world, argv, klass):
    assert classify({"tool": "run_command", "args": {"argv": argv}}, world[0])["command_class"] == klass


@pytest.mark.parametrize("argv", [[], [""], ["ls", 3], ["ls", "a\x00"], ["ls"] * 100])
def test_an_argv_it_cannot_read_is_unknown(world, argv):
    assert classify({"tool": "run_command", "args": {"argv": argv}}, world[0])["command_class"] == "unknown"


@pytest.mark.parametrize("argv,pattern", [
    (["pkill", "-f", "server"], True), (["killall", "python3"], True), (["kill", "%1"], True),
    (["kill", "-9", "-1"], True), (["kill", "-9", "1234"], False), (["kill", "1234", "99"], False),
    (["kill", "-s", "TERM", "42"], False), (["kill"], True), (["bash", "-c", "pkill sleep"], True),
    (["sh", "-c", "kill $(pgrep sleep)"], True), (["sh", "-c", "ls; kill 12"], False), (["xargs", "kill"], True),
    (["grep", "kill", "notes.txt"], False), (["echo", "pkill"], False), (["pgrep", "sleep"], False),
    # ASCII only (formal/Classifier): a signal, a process id and a word boundary are read in ASCII, so a
    # non ASCII digit is not a process id and a non ASCII letter beside pkill does not hide it
    (["kill", "-\u0669", "12"], True), (["kill", "\u0661\u0662"], True), (["kill", "\xb2"], True),
    (["kill", "-9\n", "12"], True), (["sh", "-c", "\xe9pkill x"], True), (["sh", "-c", "kill\xa012"], False),
])
def test_kill_by_pattern(world, argv, pattern):
    assert classify({"tool": "run_command", "args": {"argv": argv}}, world[0])["kill_by_pattern"] is pattern


GIT_LISTINGS = [
    ("tag", []), ("tag", ["-l"]), ("tag", ["--list"]), ("tag", ["-l", "v1.*"]), ("tag", ["-n"]), ("tag", ["-n3"]),
    ("tag", ["--sort=-creatordate"]), ("tag", ["--list", "--contains", "HEAD"]), ("tag", ["--list", "--format=%(refname)"]),
    ("branch", []), ("branch", ["-a"]), ("branch", ["--all"]), ("branch", ["-r"]), ("branch", ["--list"]),
    ("branch", ["-v"]), ("branch", ["-vv"]), ("branch", ["--list", "feat/*"]), ("branch", ["--show-current"]),
    ("branch", ["--merged", "main"]), ("branch", ["-a", "-v", "--list"]), ("branch", ["--sort=-committerdate"]),
]
GIT_BRANCH_TAG_WRITES = [
    ("tag", ["v1"]), ("tag", ["-a", "v1", "-m", "x"]), ("tag", ["-d", "v1"]), ("tag", ["--delete", "v1"]),
    ("tag", ["-f", "v1"]), ("tag", ["-s", "v1"]), ("tag", ["-l", "-d", "v1"]), ("tag", ["--list", "--force"]),
    ("tag", ["--contains"]), ("tag", ["--contains", "-d"]), ("tag", ["-n", "v1"]), ("tag", ["--frob"]),
    ("branch", ["feat"]), ("branch", ["-d", "feat"]), ("branch", ["-D", "feat"]), ("branch", ["-m", "a", "b"]),
    ("branch", ["-M", "a", "b"]), ("branch", ["--set-upstream-to=origin/main"]), ("branch", ["-u", "origin/main"]),
    ("branch", ["--unset-upstream"]), ("branch", ["-f", "feat", "HEAD"]), ("branch", ["-a", "feat"]),
    ("branch", ["-v", "feat"]), ("branch", ["--list", "-D", "feat"]), ("branch", ["-l"]), ("branch", ["--frob"]),
    ("branch", ["--edit-description"]), ("branch", ["--contains"]),
]


@pytest.mark.parametrize("sub,args", GIT_LISTINGS)
def test_git_listings_read_only(world, sub, args):
    for call in ({"tool": "git", "args": {"subcommand": sub, "args": args}},
                 {"tool": "run_command", "args": {"argv": ["git", sub, *args]}}):
        assert fields(classify(call, world[0]), "git_op", "remote_class") == ("local_read", "none"), call


@pytest.mark.parametrize("sub,args", GIT_BRANCH_TAG_WRITES)
def test_git_branch_tag_writes_stay_writes(world, sub, args):
    for call in ({"tool": "git", "args": {"subcommand": sub, "args": args}},
                 {"tool": "run_command", "args": {"argv": ["git", sub, *args]}}):
        assert classify(call, world[0])["git_op"] == "local_write", call


def test_git_branch_copy_is_not_read(world):
    # -c is on GIT_UNSAFE_OPTIONS, so it was already the unknown reading; it must never become a listing.
    assert classify({"tool": "git", "args": {"subcommand": "branch", "args": ["-c", "a", "b"]}}, world[0])["git_op"] != "local_read"


@pytest.mark.parametrize("sub,args,op,remote", [
    ("status", [], "local_read", "none"), ("log", ["--oneline"], "local_read", "none"), ("diff", [], "local_read", "none"),
    ("add", ["notes.txt"], "local_write", "none"), ("commit", ["-m", "a message with / and .."], "local_write", "none"),
    ("push", [], "push", "other"), ("push", ["origin", "main"], "push", "other"), ("push", ["--force"], "push", "other"),
    ("push", ["https://example.invalid/x.git"], "push", "other"), ("fetch", [], "network", "none"),
    ("pull", [], "network", "none"), ("clone", ["https://example.invalid/r"], "network", "none"),
    ("rm", ["notes.txt"], "mutating", "none"), ("clean", ["-fdx"], "mutating", "none"),
    ("reset", ["--hard"], "mutating", "none"), ("reset", ["HEAD~1"], "local_write", "none"),
    ("config", ["user.name", "x"], "unknown", "none"), ("status", ["-c", "core.pager=x"], "unknown", "none"),
    ("-C", ["/", "status"], "unknown", "none"), ("remote", ["-v"], "local_read", "none"),
    ("remote", ["add", "x", "y"], "unknown", "none"), ("frob", [], "unknown", "none"),
])
def test_git(world, sub, args, op, remote):
    for call in ({"tool": "git", "args": {"subcommand": sub, "args": args}},
                 {"tool": "run_command", "args": {"argv": ["git", sub, *args]}}):
        reading = classify(call, world[0])
        assert fields(reading, "git_op", "remote_class") == (op, remote), call


def test_an_allowed_remote_class(world):
    _config, ws, _ = world
    config = Config.for_workspace(ws, allowed_remotes=("backup",))
    assert classify({"tool": "git", "args": {"subcommand": "push", "args": ["backup"]}}, config)["remote_class"] == "allowed"
    assert classify({"tool": "git", "args": {"subcommand": "push"}}, config)["remote_class"] == "other"


def test_command_paths_count(world):
    config, _ws, decoy = world
    assert classify({"tool": "run_command", "args": {"argv": ["cat", "/etc/passwd"]}}, config)["path_scope"] == "outside"
    assert classify({"tool": "run_command", "args": {"argv": ["ls", "-la"]}}, config)["path_scope"] == "none"
    assert classify({"tool": "run_command", "args": {"argv": ["ls", f"--dir={decoy}"]}}, config)["path_scope"] == "outside"
    assert classify({"tool": "git", "args": {"subcommand": "add", "args": [str(decoy / "x")]}}, config)["path_scope"] == "outside"


def test_the_classifier_is_deterministic(world):
    config = world[0]
    calls = [{"tool": "delete_path", "args": {"path": "link_out/sentinel.txt"}},
             {"tool": "run_command", "args": {"argv": ["pkill", "-f", "x"]}}, {"tool": "git", "args": {"subcommand": "push"}}]
    assert [classify(call, config) for call in calls] == [classify(call, config) for call in calls]


def test_a_classifier_failure_fails_closed(world, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("boom")
    monkeypatch.setattr(classifier, "path_facts", boom)
    assert classify({"tool": "read_file", "args": {"path": "notes.txt"}}, world[0]) == classifier.unknown_reading()
