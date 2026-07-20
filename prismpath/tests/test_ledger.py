"""Flow-Ledger tests (Area 6, Slice 1) — real git, throwaway bare repos, project repo untouched.

Covers the Slice-1 DoD: done_set(commit_unit(...)) round-trips a known done-set; the git tree is a
cumulative snapshot; Output-Hash is a per-unit invalidation key; loops disambiguate on Seq; and —
the load-bearing safety property — ledger ops never touch an ambient project git repo.
"""
import os
import subprocess

import pytest

from prismpath import ledger
from prismpath.ledger import Ledger, sha256_files

HAS_GIT = subprocess.run(["git", "--version"], capture_output=True).returncode == 0
pytestmark = pytest.mark.skipif(not HAS_GIT, reason="git not available")


def _led(tmp_path, flow="demo", run="01HTEST"):
    return Ledger(flow=flow, run_id=run, state_dir=tmp_path / "ledger")


def _ls_tree(led):
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", led.ref],
                         env={**os.environ, "GIT_DIR": str(led.repo)}, capture_output=True, text=True)
    return sorted(l for l in out.stdout.splitlines() if l)


def test_wallclock_trailer_records_real_green_time(tmp_path):
    # the git dates are pinned (meaningless), so real "when did it go green" lives in a trailer
    led = _led(tmp_path)
    led.commit_unit("a", wallclock="2026-07-11T09:15:00Z")
    rec = led.log()[-1]
    assert rec["wallclock"] == "2026-07-11T09:15:00Z"
    # a default (no override) still records an ISO-8601 UTC stamp
    led.commit_unit("b")
    assert led.log()[-1]["wallclock"].endswith("Z")


def test_cas_retries_on_a_concurrent_ref_move(tmp_path, monkeypatch):
    led = _led(tmp_path)
    led.commit_unit("a")                       # ref now at some tip
    # force the first commit_unit attempt to read a STALE tip (None) so its CAS loses, then let it
    # re-read the real tip and succeed on retry — proving the proof isn't dropped on a race.
    real_tip = led.tip
    calls = {"n": 0}

    def flaky_tip():
        calls["n"] += 1
        return None if calls["n"] == 1 else real_tip()

    monkeypatch.setattr(led, "tip", flaky_tip)
    sha = led.commit_unit("b")                 # attempt 1 CAS-fails (stale parent), attempt 2 succeeds
    assert calls["n"] >= 2 and sha
    units = [r["unit"] for r in led.log()]
    assert units == ["a", "b"]                 # both proofs on the chain, none dropped


def test_commit_and_done_set_roundtrip(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("auth", files={"auth.luau": "-- auth"}, gate_name="browser")
    led.commit_unit("store", files={"store.luau": "-- store"}, depends=["auth"])
    led.commit_unit("ui", files={"ui.luau": "-- ui"}, depends=["auth", "store"])
    done = led.done_set()
    assert set(done) == {"auth", "store", "ui"}
    assert done["store"]["depends"] == ["auth"]
    assert done["ui"]["gate"] == "green"
    assert done["auth"]["output_hash"] == sha256_files({"auth.luau": "-- auth"})


def test_output_hash_is_a_per_unit_invalidation_key(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("auth", files={"auth.luau": "v1"})
    h1 = led.done_set()["auth"]["output_hash"]
    # a fresh run producing DIFFERENT bytes for the same unit -> different hash (re-open dependents)
    led2 = _led(tmp_path, run="01HOTHER")
    led2.commit_unit("auth", files={"auth.luau": "v2"})
    h2 = led2.done_set()["auth"]["output_hash"]
    assert h1 != h2
    # identical bytes -> identical hash (dedupe)
    led3 = _led(tmp_path, run="01HSAME")
    led3.commit_unit("auth", files={"auth.luau": "v1"})
    assert led3.done_set()["auth"]["output_hash"] == h1


def test_tree_is_cumulative_snapshot(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("auth", files={"auth.luau": "-- auth"})
    assert _ls_tree(led) == ["auth.luau"]
    led.commit_unit("store", files={"store.luau": "-- store"})
    assert _ls_tree(led) == ["auth.luau", "store.luau"]   # tip tree carries BOTH units' files


def test_loops_disambiguate_on_seq_newest_wins(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("fix", files={"a.luau": "attempt-1"}, seq=1)
    led.commit_unit("fix", files={"a.luau": "attempt-2"}, seq=2)
    done = led.done_set()
    assert done["fix"]["seq"] == 2                                   # newest wins
    assert done["fix"]["output_hash"] == sha256_files({"a.luau": "attempt-2"})
    assert len(led.log()) == 2                                       # append-only: both retained


def test_auto_seq_is_monotonic(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("a", files={"a": "1"})
    led.commit_unit("b", files={"b": "2"})
    led.commit_unit("c", files={"c": "3"})
    assert [r["seq"] for r in led.log()] == [1, 2, 3]


def test_commits_chain_on_one_orphan_ref(tmp_path):
    led = _led(tmp_path)
    a = led.commit_unit("a", files={"a": "1"})
    b = led.commit_unit("b", files={"b": "2"})
    env = {**os.environ, "GIT_DIR": str(led.repo)}
    parent = subprocess.run(["git", "rev-parse", f"{b}^"], env=env, capture_output=True, text=True).stdout.strip()
    assert parent == a                                              # linear chain
    # the ledger lives only under refs/prismpath/*, invisible to normal branch tooling
    heads = subprocess.run(["git", "for-each-ref", "refs/heads"], env=env, capture_output=True, text=True).stdout
    assert heads.strip() == ""


def test_separate_runs_use_separate_refs(tmp_path):
    a = _led(tmp_path, run="01HA")
    b = _led(tmp_path, run="01HB")
    a.commit_unit("x", files={"x": "1"})
    b.commit_unit("y", files={"y": "2"})
    assert set(a.done_set()) == {"x"}
    assert set(b.done_set()) == {"y"}                              # no cross-run collision


def test_repo_isolation_ambient_project_repo_untouched(tmp_path):
    # a real project repo the ledger must never disturb
    proj = tmp_path / "project"
    proj.mkdir()
    env = {**os.environ, "GIT_DIR": str(proj / ".git"), "GIT_WORK_TREE": str(proj)}
    subprocess.run(["git", "init", "-q", str(proj)], capture_output=True, check=True)
    (proj / "f.txt").write_text("hello")
    subprocess.run(["git", "-C", str(proj), "add", "f.txt"], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(proj), "-c", "user.name=t", "-c", "user.email=t@t",
                    "commit", "-qm", "init"], capture_output=True, check=True)

    def snapshot():
        refs = subprocess.run(["git", "-C", str(proj), "for-each-ref"], capture_output=True, text=True).stdout
        st = subprocess.run(["git", "-C", str(proj), "status", "--porcelain"], capture_output=True, text=True).stdout
        return refs, st

    before = snapshot()
    # run ledger ops from INSIDE the project dir (cwd), state repo elsewhere
    cwd = os.getcwd()
    os.chdir(proj)
    try:
        led = Ledger(flow="demo", run_id="01HISO", state_dir=tmp_path / "ledger")
        led.commit_unit("auth", files={"auth.luau": "-- auth"})
        led.commit_unit("store", files={"store.luau": "-- store"})
    finally:
        os.chdir(cwd)
    assert snapshot() == before                                    # project refs + working tree unchanged
    assert not (proj / "auth.luau").exists()                       # nothing written into the project tree


def test_ledger_repo_is_under_state_dir_not_project(tmp_path):
    led = _led(tmp_path)
    led.commit_unit("a", files={"a": "1"})
    assert led.repo == tmp_path / "ledger" / "demo.git"
    assert (led.repo / "HEAD").exists() and (led.repo / "objects").exists()   # a real bare repo


def test_sha256_files_is_order_independent():
    assert sha256_files({"a": "1", "b": "2"}) == sha256_files({"b": "2", "a": "1"})
    assert sha256_files({"a": "1"}) != sha256_files({"a": "2"})


def test_new_run_id_shape():
    rid = ledger.new_run_id()
    assert rid.endswith(tuple("0123456789abcdef")) and "-" in rid and "Z" in rid
