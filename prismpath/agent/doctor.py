# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent doctor`: checks a governed agent setup end to end and reports, for each check, ok, warn
or fail, with one plain line and the exact command that fixes it.

It only reports. Nothing under the configuration directory or the project is written, changed or repaired:
the hook dry run is a child process that decides one recorded harmless call without opening a run, and each
run is verified on a throwaway copy, so a run that is open stays open and a seal is never made here.

Checks, in the order they are reported:
  config-dir, key-files     the directory is mode 0700 and each key file 0600 (not applicable on Windows)
  authority-key, instance-key   the private key matches its public key (a nonce is signed and verified)
  policy                    the recorded policy's attestation verifies under the authority key, and its
                            hash is one of the shipped starters, strict, default or review (an older
                            shipped image of one, or an attested custom image, is a warning)
  policy-control            the recorded policy refuses every change to the agent's own control files (warn when
                            it does not: an older starter, or a custom image without the rule)
  hook-PreToolUse, hook-SessionEnd   the project's .claude/settings.json has our entry, the command ends in
                            `|| exit 2`, and the interpreter it names exists and can `import prismpath`
  hook-dry-run              a recorded Read of a file in the project answers allow within the budget
  runs                      an open run older than a day (warn), a run that fails verification (fail)
  disk                      free space under the runs directory (warn under 1 GiB)
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.agent import commands
from prismpath.agent import policy as policy_mod
from prismpath.agent.commands import (ATTESTATION_FILE, KEY_ROLES, POLICY_FILE, RUNS_DIR, _detail, _is_ours,
                                      _key_paths, _sha256_hex)

BUDGET_MS = 150
OPEN_RUN_DAYS = 1
LOW_DISK_BYTES = 1 << 30
OLDER_IMAGES = policy_mod.OLDER_STARTERS      # shipped starter images older than the current ones
EVENTS = ("PreToolUse", "SessionEnd")

_DRY_RUN = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from prismpath.agent import claude_code, commands\n"
    "policy, _ = commands.load_checked(Path(sys.argv[1]))\n"
    "result = claude_code.evaluate(json.loads(sys.stdin.read()), None, policy)\n"
    "print(result.answer['hookSpecificOutput']['permissionDecision'])\n")


def _check(name: str, status: str, detail: str, fix: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {"check": name, "status": status, "detail": detail, "fix": fix}
    row.update(extra)
    return row


def _q(path: Any) -> str:
    return shlex.quote(str(path))


def _init_fix(project: Path) -> str:
    return f"prismpath agent init --project {_q(project)} --yes"


# --------------------------------------------------------------------------------------- permissions
def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _check_permissions(home: Path) -> List[Dict[str, Any]]:
    if not home.is_dir():
        return [_check("config-dir", "fail", f"{home} does not exist", "prismpath agent init")]
    if os.name == "nt":                                                         # pragma: no cover
        return [_check("config-dir", "ok", f"{home} exists (file modes do not apply on Windows)")]
    rows = []
    mode = _mode(home)
    if mode & 0o077:
        rows.append(_check("config-dir", "fail", f"{home} is mode {mode:04o}, readable or writable by others",
                           f"chmod 700 {_q(home)}", mode=f"{mode:04o}"))
    else:
        rows.append(_check("config-dir", "ok", f"{home} is mode {mode:04o}", mode=f"{mode:04o}"))
    loose, missing = [], []
    for role in KEY_ROLES:
        for path in _key_paths(home, role):
            if not path.exists():
                missing.append(path)
            elif _mode(path) & 0o077:
                loose.append(path)
    if loose:
        rows.append(_check("key-files", "fail", "readable by others: " + ", ".join(f"{p.name} ({_mode(p):04o})" for p in loose),
                           "chmod 600 " + " ".join(_q(p) for p in loose), files=[str(p) for p in loose]))
    elif missing:
        rows.append(_check("key-files", "fail", "missing: " + ", ".join(p.name for p in missing), "prismpath agent init"))
    else:
        rows.append(_check("key-files", "ok", "all four key files are mode 0600"))
    return rows


# -------------------------------------------------------------------------------------------- keys
def _nonce() -> bytes:
    return os.urandom(32)


def _check_key_pair(home: Path, role: str) -> Dict[str, Any]:
    name = f"{role}-key"
    key, pub = _key_paths(home, role)
    if not key.is_file() or not pub.is_file():
        return _check(name, "fail", f"the {role} key pair is not complete in {home}", "prismpath agent init")
    try:
        from prismpath.hotswap import policy_pack
        verifier, key_id = policy_pack.load_public(str(pub))
        if role == "authority":
            signer = policy_pack._load_private(str(key))
        else:
            from prismpath.ledgers import root_statement
            signer = root_statement.InstanceKey.load(str(key))
        nonce = _nonce()
        verifier.verify(signer.sign(nonce), nonce)
    except Exception as exc:  # noqa: BLE001 - any failure to read, sign or verify is the finding
        return _check(name, "fail", f"{role}.key does not match {role}.pub, or one does not read ({_detail(exc)})",
                      f"move both {role} files aside and run `prismpath agent init`; a policy and runs signed "
                      f"under the old key must then be recorded again")
    return _check(name, "ok", f"{role}.key signs what {role}.pub verifies (key {key_id[:16]})", key_id=key_id)


# ------------------------------------------------------------------------------------------ policy
def _check_control(home: Path) -> Dict[str, Any]:
    """Whether the recorded policy refuses every change to the agent's own control files (cause 128)."""
    try:
        result = policy_mod.control_check((home / POLICY_FILE).read_bytes())
    except Exception as exc:  # noqa: BLE001
        return _check("policy-control", "fail", f"the recorded policy could not be checked for control files: {_detail(exc)}",
                      "prismpath agent init", refuses_control_changes=None)
    if result["refuses_control_changes"]:
        return _check("policy-control", "ok", "the recorded policy refuses every change to the agent's own control files",
                      refuses_control_changes=True)
    return _check("policy-control", "warn", result["message"], result["fix"], refuses_control_changes=False,
                  reason=result["reason"])


def _check_policy(home: Path) -> Dict[str, Any]:
    from prismpath.agent.policy import STARTERS, starter_of
    fix = "prismpath agent init"
    try:
        commands.load_checked(home)
    except Exception as exc:  # noqa: BLE001
        return _check("policy", "fail", f"the recorded policy is not usable: {_detail(exc)}", fix)
    image = (home / POLICY_FILE).read_bytes()
    recorded = _sha256_hex(image)
    starter = starter_of(image)
    if starter is not None:
        return _check("policy", "ok", f"the {starter} starter ({STARTERS[starter]}) {recorded[:16]} is attested by the "
                      f"authority key and is the shipped image", sha256=recorded, starter=starter)
    if recorded[:16] in OLDER_IMAGES:
        was, older = OLDER_IMAGES[recorded[:16]]
        return _check("policy", "warn", f"the recorded policy is an older shipped image, {older}; attested, but not the "
                      f"current {was} starter ({STARTERS[was]})", f"prismpath agent init --policy {was}",
                      sha256=recorded, starter=was)
    return _check("policy", "warn", f"the recorded policy {recorded[:16]} is custom: attested, but not one of the shipped "
                  f"starters (strict, default or review) nor a known older image of one", fix, sha256=recorded,
                  starter="custom")


# ------------------------------------------------------------------------------------------- hooks
def _entries(settings: Any, event: str) -> List[str]:
    hooks = settings.get("hooks", {}) if isinstance(settings, dict) else {}
    groups = hooks.get(event, []) if isinstance(hooks, dict) else []
    out = []
    for group in groups if isinstance(groups, list) else []:
        for hook in group.get("hooks", []) if isinstance(group, dict) and isinstance(group.get("hooks"), list) else []:
            if isinstance(hook, dict) and _is_ours(hook.get("command")):
                out.append(hook["command"])
    return out


def _interpreter(command: str) -> Optional[str]:
    try:
        words = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return None
    return words[0] if words else None


def _can_import(interpreter: str, project: Path) -> Optional[str]:
    """None when `interpreter` can import prismpath, otherwise why not."""
    try:
        done = subprocess.run([interpreter, "-c", "import prismpath"], capture_output=True, timeout=60,
                              cwd=str(project) if project.is_dir() else None)
    except Exception as exc:  # noqa: BLE001
        return _detail(exc)
    if done.returncode == 0:
        return None
    lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
    return lines[-1] if lines else f"exit {done.returncode}"


def _check_hooks(project: Path):
    """The rows for the two events and the first usable interpreter (None when there is none)."""
    path = project / ".claude" / "settings.json"
    fix = _init_fix(project)
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [_check(f"hook-{e}", "fail", f"{path} does not exist", fix) for e in EVENTS], None
    except Exception as exc:  # noqa: BLE001
        return [_check(f"hook-{e}", "fail", f"{path} does not read as JSON ({_detail(exc)})",
                       f"fix {_q(path)} by hand, then {fix}") for e in EVENTS], None
    rows, usable, imports = [], None, {}
    for event in EVENTS:
        name = f"hook-{event}"
        commands_found = _entries(settings, event)
        if not commands_found:
            rows.append(_check(name, "fail", f"{path} has no PrismPath {event} entry, so those calls are not governed", fix))
            continue
        problem = None
        for command in commands_found:
            tail = command.rstrip().endswith("|| exit 2")
            interpreter = _interpreter(command)
            if os.name != "nt" and not tail:
                problem = "the command does not end in `|| exit 2`, so a hook that cannot start lets the call run"
            elif not interpreter or not (os.path.isfile(interpreter) and os.access(interpreter, os.X_OK)):
                problem = f"the interpreter {interpreter!r} does not exist or cannot run"
            else:
                if interpreter not in imports:
                    imports[interpreter] = _can_import(interpreter, project)
                if imports[interpreter]:
                    problem = f"{interpreter} cannot import prismpath ({imports[interpreter]})"
                elif usable is None:
                    usable = interpreter
            if problem:
                break
        if problem:
            rows.append(_check(name, "fail", problem, fix))
        else:
            rows.append(_check(name, "ok", f"{event} runs {commands_found[0]}"))
    return rows, usable


def _check_dry_run(home: Path, project: Path, interpreter: Optional[str], budget_ms: float) -> Dict[str, Any]:
    name = "hook-dry-run"
    if interpreter is None:
        return _check(name, "fail", "not run: there is no hook interpreter that imports prismpath", _init_fix(project),
                      budget_ms=budget_ms)
    sample = {"session_id": "prismpath-doctor", "cwd": str(project), "hook_event_name": "PreToolUse", "tool_name": "Read",
              "tool_input": {"file_path": str(project / "README.md")}}
    start = time.perf_counter()
    try:
        done = subprocess.run([interpreter, "-c", _DRY_RUN, str(home)], input=json.dumps(sample).encode(),
                              capture_output=True, timeout=60, cwd=str(project) if project.is_dir() else None)
    except Exception as exc:  # noqa: BLE001
        return _check(name, "fail", f"the dry run did not finish ({_detail(exc)})", "prismpath agent status", budget_ms=budget_ms)
    elapsed = (time.perf_counter() - start) * 1000
    answer = done.stdout.decode("utf-8", "replace").strip()
    if done.returncode != 0 or answer != "allow":
        why = answer or (done.stderr.decode("utf-8", "replace").strip().splitlines() or ["no answer"])[-1]
        return _check(name, "fail", f"a Read of a file in the project did not answer allow ({_detail(Exception(why))})",
                      "prismpath agent init", budget_ms=budget_ms, elapsed_ms=round(elapsed, 1))
    if elapsed > budget_ms:
        return _check(name, "warn", f"a Read of a file in the project answered allow in {elapsed:.0f} ms, over the "
                      f"{budget_ms:g} ms budget; a slow hook slows every tool call",
                      "run it again when the machine is idle, and `prismpath agent status` to see what is installed",
                      budget_ms=budget_ms, elapsed_ms=round(elapsed, 1))
    return _check(name, "ok", f"a Read of a file in the project answered allow in {elapsed:.0f} ms (budget {budget_ms:g} ms)",
                  budget_ms=budget_ms, elapsed_ms=round(elapsed, 1))


# -------------------------------------------------------------------------------------------- runs
def _check_runs(home: Path, now: float) -> Dict[str, Any]:
    from prismpath.agent import run as runmod
    store = runmod.RunStore(home / RUNS_DIR)
    try:
        runs = store.runs()
    except Exception as exc:  # noqa: BLE001
        return _check("runs", "fail", f"the runs directory does not read ({_detail(exc)})", "prismpath agent verify")
    if not runs:
        return _check("runs", "ok", "no runs yet", runs=0)
    failed, stale, opened = [], [], 0
    scratch = Path(tempfile.mkdtemp(prefix="prismpath-doctor-"))
    try:
        for index, original in enumerate(runs):
            try:
                copy = scratch / str(index)
                shutil.copytree(original.dir, copy)
                run = runmod.Run(copy, original.session)
                summary = run.summary()
                if summary["receipts"]:
                    run.verify(home, seal=summary["seal"] != "diverged")
                if summary["open"]:
                    opened += 1
                    journal = original.dir / runmod.JOURNAL
                    age = now - (journal.stat().st_mtime if journal.exists() else original.dir.stat().st_mtime)
                    if age > OPEN_RUN_DAYS * 86400:
                        stale.append(f"{original.session} ({age / 86400:.0f} days)")
            except Exception as exc:  # noqa: BLE001 - the run that does not verify is the finding
                failed.append(f"{original.session}: {_detail(exc)}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if failed:
        return _check("runs", "fail", "a run fails verification: " + "; ".join(failed), "prismpath agent verify", runs=len(runs),
                      failed=len(failed))
    if stale:
        return _check("runs", "warn", "open for more than a day: " + ", ".join(stale), "prismpath agent verify",
                      runs=len(runs), stale=len(stale))
    return _check("runs", "ok", f"{len(runs)} runs verify ({opened} still open)", runs=len(runs))


def _check_disk(home: Path) -> Dict[str, Any]:
    target = home / RUNS_DIR
    while not target.exists() and target != target.parent:
        target = target.parent
    free = shutil.disk_usage(target).free
    gib = free / (1 << 30)
    if free < LOW_DISK_BYTES:
        return _check("disk", "warn", f"{gib:.2f} GiB free under {home / RUNS_DIR}, under 1 GiB; a run that cannot write "
                      f"its receipt is refused", f"free space on the disk that holds {_q(home / RUNS_DIR)}", free_bytes=free)
    return _check("disk", "ok", f"{gib:.1f} GiB free under {home / RUNS_DIR}", free_bytes=free)


# ----------------------------------------------------------------------------------------- report
def _control_rows(home: Path) -> List[Dict[str, Any]]:
    """The control-files row, only where a recorded policy is usable (the policy row already failed otherwise)."""
    try:
        commands.load_checked(home)
    except Exception:  # noqa: BLE001
        return []
    return [_check_control(home)]


def diagnose(project: Path, budget_ms: float = BUDGET_MS, now: Optional[float] = None) -> Dict[str, Any]:
    home = commands.config_dir()
    project = Path(project)
    checks = _check_permissions(home)
    if home.is_dir():
        checks += [_check_key_pair(home, role) for role in KEY_ROLES] + [_check_policy(home)] + _control_rows(home)
    state = commands.confinement_state()
    checks.append(_check("shell-confinement", "ok" if state["confined"] else "fail" if "refused" in state["detail"] else "warn",
                         state["detail"], None if state["confined"] else
                         ("install bubblewrap (bwrap) so allowed shell commands can run" if "refused" in state["detail"] else None)))
    hook_rows, interpreter = _check_hooks(project)
    checks += hook_rows
    checks.append(_check_dry_run(home, project, interpreter, budget_ms) if home.is_dir() else
                  _check("hook-dry-run", "fail", "not run: there is no configuration directory", "prismpath agent init",
                         budget_ms=budget_ms))
    if home.is_dir():
        checks += [_check_runs(home, time.time() if now is None else now), _check_disk(home)]
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("ok", "warn", "fail")}
    return {"config_dir": str(home), "project": str(project), "budget_ms": budget_ms, "ok": counts["fail"] == 0,
            "counts": counts, "checks": checks}


def doctor(project: Path, as_json: bool, budget_ms: float = BUDGET_MS, out=None, now: Optional[float] = None) -> int:
    out = out or sys.stdout
    report = diagnose(project, budget_ms, now)
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        for row in report["checks"]:
            print(f"{row['status'].upper():4}  {row['check']}: {row['detail']}", file=out)
            if row["fix"] and row["status"] != "ok":
                print(f"      fix: {row['fix']}", file=out)
        c = report["counts"]
        print(f"{c['ok']} ok, {c['warn']} warn, {c['fail']} fail", file=out)
    return 0 if report["ok"] else 1
