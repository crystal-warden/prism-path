# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent init | hook | verify | status`: a Claude Code session governed by the core, from one command.

Where things live. Everything the commands keep is in one directory of the user's configuration directory,
`<config>/prismpath/agent` (mode 0700), where `<config>` is XDG_CONFIG_HOME or ~/.config on Linux,
~/Library/Application Support on macOS and %APPDATA% on Windows:

  authority.key, authority.pub   the authority key, which says which policy may run (mode 0600)
  instance.key, instance.pub     the instance key, which signs the root statement over a run (mode 0600)
  policy.core.json               the policy image every hook call decides under: the starter `init --policy`
                                 chose (`strict`, `default` or `review`), `default` (agent_default) unless told
  policy.attestation.json        its `prismpath.core-image/1` attestation, signed with the authority key
  runs/<session>                 one run per Claude Code session (`prismpath.agent.run`)

`init` makes the keys (never replacing one), records the policy with its attestation, and writes the hook
entries into the project's `.claude/settings.json` only after showing the change and being told yes.

`hook` is what Claude Code runs. It FAILS CLOSED: whatever goes wrong (input that does not read, a missing or
broken key, a policy whose attestation does not verify, any exception at all) the answer is `deny` with the
registered cause 126 `agent:hook-error`, never an allow. Each hook call is a new process, so its import cost
is the hook's latency: this module and everything the hook path imports load no numpy and nothing the
decision does not need (tests/test_agent_cli.py checks it), and the heavier modules are imported inside the
functions that use them.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

AGENT_DIR = ("prismpath", "agent")
POLICY_FILE = "policy.core.json"
ATTESTATION_FILE = "policy.attestation.json"
RUNS_DIR = "runs"
POLICY_CASE = "agent_default"
HOOK_ERROR = "agent:hook-error"
SANDBOX_ERROR = "agent:sandbox-unavailable"
KEY_ROLES = ("authority", "instance")
# (event, matcher) of the entries init writes. PreToolUse decides. The two Post events only record what became of a call
# whose receipt is already written (Run.outcome_of_hook); they cannot block anything and decide nothing.
HOOK_EVENTS = (("PreToolUse", "*"), ("SessionEnd", None), ("PostToolUse", "*"), ("PostToolUseFailure", "*"))
OUTCOME_EVENTS = ("PostToolUse", "PostToolUseFailure")


class AgentError(Exception):
    """Something the person can fix; the message says what."""


# ----------------------------------------------------------------------------------------------- places
def config_dir(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> Path:
    """`<config>/prismpath/agent` for this platform."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform.startswith("win"):
        base = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
    elif platform == "darwin":
        base = home / "Library" / "Application Support"
    else:
        xdg = env.get("XDG_CONFIG_HOME", "")
        base = Path(xdg) if xdg and os.path.isabs(xdg) else home / ".config"
    return base.joinpath(*AGENT_DIR)


# Python 3.10's stand-in for -P: `python -c` puts '' (the current directory) first on sys.path; drop it, then run
# the module named by the first argument as `python -m` would.
LAUNCHER_310 = ("import sys, runpy; del sys.path[0]; "
                "runpy.run_module(sys.argv.pop(1), run_name='__main__', alter_sys=True)")


def hook_command() -> str:
    """The command Claude Code runs: this interpreter, so the hook runs the PrismPath that was installed."""
    # `python -m` puts the current directory, which Claude Code sets to the workspace, first on sys.path, so a
    # `prismpath/` package the agent planted there would run in place of the installed one, before any call is
    # classified. -P (3.11 and later) drops that entry. 3.10 has no -P, and -I would also drop the user's site and
    # PYTHONPATH, so a `pip install --user` PrismPath would not import and every call would be refused; there a short
    # -c launcher drops only that first entry and runs the module named by the next word.
    if sys.version_info >= (3, 11):
        argv = [sys.executable, "-P", "-m", "prismpath", "agent", "hook"]
    else:
        argv = [sys.executable, "-c", LAUNCHER_310, "prismpath", "agent", "hook"]
    if os.name == "nt":                                     # pragma: no cover
        import subprocess
        return subprocess.list2cmdline(argv)
    import shlex
    # Claude Code blocks a call only on exit 2; a hook that cannot even import prismpath exits 1, which it treats
    # as a non-blocking error and lets the call run. `|| exit 2` turns any such failure into a block, so the
    # hook fails closed before Python is reached as well as after.
    return " ".join(shlex.quote(word) for word in argv) + " || exit 2"


def _sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------- keys
def _key_paths(home: Path, role: str):
    return home / f"{role}.key", home / f"{role}.pub"


def _key_id(home: Path, role: str) -> Optional[str]:
    pub = _key_paths(home, role)[1]
    return _sha256_hex(pub.read_bytes()) if pub.is_file() else None


def _make_dir(path: Path) -> None:
    for directory in (path.parent, path):
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
    os.chmod(path, 0o700)


def _ensure_key(home: Path, role: str) -> str:
    """Make the key pair of `role` when neither file exists; keep a whole pair; refuse half of one."""
    key, pub = _key_paths(home, role)
    if key.exists() and pub.exists():
        os.chmod(key, 0o600)
        os.chmod(pub, 0o600)
        return "kept"
    if key.exists() or pub.exists():
        raise AgentError(f"{home} holds only half of the {role} key pair ({(key if key.exists() else pub).name}); "
                         f"it is never replaced, so move it aside or restore the other half")
    if role == "authority":
        from prismpath.hotswap import policy_pack
        policy_pack.keygen(str(home), "authority")
    else:
        from prismpath.ledgers import root_statement
        root_statement.keygen(str(home), "instance")
    os.chmod(key, 0o600)
    os.chmod(pub, 0o600)
    return "created"


def _attestation(home: Path, image: bytes, case: str = POLICY_CASE) -> bytes:
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    signer = policy_pack._load_private(str(_key_paths(home, "authority")[0]))
    return canon2.dumps({"format": core_evidence.IMAGE_FORMAT, "case": case,
                         "image_sha256": _sha256_hex(image), "key_id": _key_id(home, "authority"),
                         "sig": signer.sign(core_evidence.IMAGE_DOMAIN + image).hex()}) + b"\n"


def load_checked(home: Path):
    """The policy the hook decides under and the store of runs, after checking that both key pairs are
    present and read, the instance key is not the authority key, and the policy's attestation verifies under
    the authority key. Raises with the reason otherwise; the hook answers that reason with a deny."""
    from prismpath.agent.policy import Policy
    from prismpath.agent.run import RunStore
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence, root_statement
    for role in KEY_ROLES:
        for path in _key_paths(home, role):
            if not path.is_file():
                raise AgentError(f"no {role} key at {path}; run `prismpath agent init`")
    authority, authority_id = policy_pack.load_public(str(_key_paths(home, "authority")[1]))
    policy_pack._load_private(str(_key_paths(home, "authority")[0]))   # the private half must read too
    instance = root_statement.InstanceKey.load(str(_key_paths(home, "instance")[0]))
    if instance.key_id != _key_id(home, "instance"):
        raise AgentError("instance.key and instance.pub are not one key pair")
    root_statement.check_separation(instance, [authority_id])
    policy_path, attestation_path = home / POLICY_FILE, home / ATTESTATION_FILE
    if not policy_path.is_file() or not attestation_path.is_file():
        raise AgentError(f"no recorded policy in {home}; run `prismpath agent init`")
    image = policy_path.read_bytes()
    statement = canon2.loads(attestation_path.read_bytes().rstrip(b"\n"))
    if (not isinstance(statement, dict) or statement.get("format") != core_evidence.IMAGE_FORMAT
            or statement.get("key_id") != authority_id or statement.get("image_sha256") != _sha256_hex(image)):
        raise AgentError("the recorded policy's attestation does not name this policy and authority key")
    try:
        authority.verify(bytes.fromhex(statement["sig"]), core_evidence.IMAGE_DOMAIN + image)
    except Exception as exc:
        raise AgentError("the recorded policy's attestation signature does not verify") from exc
    return Policy(image), RunStore(home / RUNS_DIR)


# --------------------------------------------------------------------------------------------- settings
def _is_ours(command: Any) -> bool:
    if not isinstance(command, str):
        return False
    words = command.replace('"', " ").replace("'", " ").split()
    if words[-3:] == ["||", "exit", "2"]:
        words = words[:-3]
    return len(words) >= 3 and words[-2:] == ["agent", "hook"] and words[-3].endswith("prismpath")


def merged_settings(settings: Dict[str, Any], command: str) -> Dict[str, Any]:
    """`settings` with the PreToolUse, SessionEnd, PostToolUse and PostToolUseFailure hook entries running `command`, every other key kept.
    An entry that already runs a PrismPath hook is pointed at `command` in place, so running it twice adds
    nothing."""
    out = json.loads(json.dumps(settings))
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise AgentError("the settings' `hooks` is not an object; fix it by hand first")
    for event, matcher in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise AgentError(f"the settings' `hooks.{event}` is not a list; fix it by hand first")
        found = False
        for group in groups:
            for hook in (group.get("hooks") if isinstance(group, dict) and isinstance(group.get("hooks"), list) else []):
                if isinstance(hook, dict) and _is_ours(hook.get("command")):
                    hook["command"], hook["type"], found = command, "command", True
        if not found:
            entry: Dict[str, Any] = {"hooks": [{"type": "command", "command": command}]}
            if matcher is not None:
                entry = {"matcher": matcher, **entry}
            groups.append(entry)
    return out


def _settings_text(settings: Dict[str, Any]) -> str:
    return json.dumps(settings, indent=2) + "\n"


# ------------------------------------------------------------------------------------------------- init
def init(project: Path, yes: bool, as_json: bool, confirm=None, out=None, policy: Optional[str] = None) -> int:
    """Keys, policy and the project's hook entries. `confirm(prompt) -> bool` asks the person; None means
    ask on a terminal and otherwise take no for an answer. `policy` names the starter to record (`strict`,
    `default`, `review`); None keeps the starter already recorded, and records `default` where there is none."""
    import difflib
    out = out or sys.stdout
    home = config_dir()
    _make_dir(home)
    keys = {role: _ensure_key(home, role) for role in KEY_ROLES}
    from prismpath.agent.policy import DEFAULT_STARTER, STARTERS, Policy, older_starter_of, starter_of, starter_path
    from prismpath.ledgers import root_statement
    root_statement.check_separation(root_statement.InstanceKey.load(str(_key_paths(home, "instance")[0])),
                                    [_key_id(home, "authority")])
    if policy is not None and policy not in STARTERS:
        raise AgentError(f"no starter policy named {policy!r}; the starters are {', '.join(STARTERS)}")
    try:
        recorded: Optional[bytes] = load_checked(home)[0].image
    except Exception:  # noqa: BLE001 - absent or not verifying: record it again
        recorded = None
    kept = recorded is not None and (starter_of(recorded) or (older_starter_of(recorded) or (None,))[0])
    starter = policy or kept or DEFAULT_STARTER
    image = Policy.load(starter_path(starter)).image
    if recorded is None:
        policy_state = "recorded"
    else:
        policy_state = "kept" if recorded == image else "updated"
    if policy_state != "kept":
        for name, data in ((POLICY_FILE, image), (ATTESTATION_FILE, _attestation(home, image, STARTERS[starter]))):
            tmp = home / (name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, home / name)
    load_checked(home)
    from prismpath.agent import sandbox_hook
    sandbox_problem = None
    if sandbox_hook.supported():
        try:
            sandbox_hook.profile_for(home, image)      # compile once now, so the first Bash call does not
        except sandbox_hook.SandboxRefused as exc:      # the hook denies Bash with cause 129 until this is fixed
            sandbox_problem = str(exc) or type(exc).__name__

    path = Path(project) / ".claude" / "settings.json"
    before_text = path.read_text(encoding="utf-8") if path.exists() else ""
    try:
        before = json.loads(before_text) if before_text.strip() else {}
    except json.JSONDecodeError as exc:
        raise AgentError(f"{path} is not valid JSON ({exc}); it is left as it is") from exc
    if not isinstance(before, dict):
        raise AgentError(f"{path} does not hold a JSON object; it is left as it is")
    after = merged_settings(before, hook_command())
    after_text = _settings_text(after)
    diff = "" if after == before else "".join(difflib.unified_diff(
        before_text.splitlines(True) if before_text else [], after_text.splitlines(True),
        fromfile=str(path) if before_text else "/dev/null", tofile=str(path)))
    if not diff:
        settings_state = "unchanged"
    else:
        if not as_json:
            print(f"The hook entries for {path}:\n{diff}", file=out)
        if yes:
            agreed = True
        elif confirm is not None:
            agreed = confirm(f"Write this change to {path}? [y/N] ")
        elif not as_json and sys.stdin.isatty():
            agreed = input(f"Write this change to {path}? [y/N] ").strip().lower() in ("y", "yes")
        else:
            agreed = False
        if agreed:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(after_text, encoding="utf-8")
            os.replace(tmp, path)
            settings_state = "written"
        else:
            settings_state = "not written"
    report = {"config_dir": str(home),
              "keys": {role: {"id": _key_id(home, role), "state": keys[role]} for role in KEY_ROLES},
              "policy": {"name": starter, "image": STARTERS[starter], "sha256": _sha256_hex(image),
                         "state": policy_state},
              "settings": {"path": str(path), "state": settings_state, "diff": diff, "command": hook_command()},
              "sandbox": {"problem": sandbox_problem}}
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        for role in KEY_ROLES:
            print(f"{role} key {report['keys'][role]['id']} ({keys[role]}) in {home}", file=out)
        print(f"policy {starter} ({STARTERS[starter]}) sha256 {report['policy']['sha256']} ({policy_state}), "
              f"attested by the authority key", file=out)
        if settings_state == "not written":
            print(f"{path} was not changed; run again with --yes to write the hook entries", file=out)
        else:
            print(f"{path}: {settings_state}", file=out)
        if sandbox_problem:
            print(f"warning: the sandbox profile could not be prepared ({sandbox_problem}), so every allowed shell "
                  f"command will be refused with cause 129 until it is fixed; `prismpath agent doctor` says more",
                  file=out)
    return 0 if settings_state != "not written" else 1


# ------------------------------------------------------------------------------------------------- hook
def _cause_code(name: str = HOOK_ERROR) -> Optional[int]:
    try:
        from prismpath.kernel import causes
        return causes.code(name)
    except Exception:  # noqa: BLE001
        return None


def _detail(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= 240 else text[:237] + "..."


def deny_answer(detail: str, name: str = HOOK_ERROR) -> Dict[str, Any]:
    code = _cause_code(name)
    cause = f"{code} {name}" if code is not None else name
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": f"PrismPath refused this call: cause {cause} ({detail}). It was not run. "
                                    f"No receipt was written for it."}}


def receipt_id(session: str, index: int) -> str:
    return f"{index} of session {session}"


def observation_answer(data: Dict[str, Any], home: Path, store) -> Dict[str, Any]:
    """Record what a nested per call sandbox showed (`observe.send`), bound to the receipt of the call. The request
    comes from inside the agent sandbox, so it is a claim: it is read from at most the tail of the standard error, and
    `Run.observe` refuses a receipt or hashes that are not the call's."""
    from prismpath.agent import observe
    session = data.get("session_id")
    stderr = data.get("stderr")
    returncode, timed_out = int(data["returncode"]), bool(data.get("timed_out"))
    body = observe.observed(returncode, stderr.encode("utf-8", "replace")[-observe.MAX_STDERR:] if isinstance(stderr, str) else b"",
                            timed_out, str(data.get("backend") or "") or None)
    if not (store.root / _run_dir(session)).exists():
        raise AgentError(f"session {session} has no run to record an observation in")
    receipt, image, profile = data.get("receipt"), str(data.get("image_sha256")), str(data.get("profile_sha256"))
    run = store.get(session)
    if body is not None:
        run.observe(receipt, image, profile, body)
    # the runner finished the command, whatever it showed: that is an outcome of the receipt (like an observation, a claim)
    run.outcome_of_runner(receipt, image, profile, returncode, timed_out)
    return {"recorded": True}


def failure_class(data: Dict[str, Any]) -> str:
    """The class of a PostToolUseFailure, from fields the hooks reference documents (`is_interrupt`, and the
    `Exit code N` first line of `error` for a shell command). The error text itself is never kept."""
    import re
    if data.get("is_interrupt") is True:
        return "interrupt"
    error = data.get("error")
    return "exit-nonzero" if isinstance(error, str) and re.match(r"Exit code -?\d+", error) else "error"


def outcome_answer(data: Dict[str, Any], event: str, store) -> Dict[str, Any]:
    """Record a PostToolUse or PostToolUseFailure event as the outcome of the call whose receipt carries the same
    `tool_use_id`. An outcome is read only and decides nothing: the call already ran, the answer is always `{}`, and
    what cannot be bound (no run, no id, no receipt, a refusal, a repeat) is recorded as unbound or dropped, never
    raised. Nothing the tool returned (`tool_response`, `error`) is kept."""
    session = data["session_id"]
    if (store.root / _run_dir(session)).exists():
        store.get(session).outcome_of_hook(data.get("tool_use_id"), event, data.get("tool_name"),
                                           failure_class(data) if event == "PostToolUseFailure" else None)
    return {}


def hook(raw: bytes, env: Optional[Mapping[str, str]] = None, nested=None) -> Dict[str, Any]:
    """The answer to one hook input. Never raises; whatever fails is a deny with cause 126.

    `nested` (a `sandbox_hook.Nested`) is for the decider of `prismpath agent run`, where the hook client is inside
    the outer sandbox and the host interpreter and checkout that the per call rewrite names do not exist there. The
    rewrite then names the system interpreter and the runner the launcher bound, and the runner reports what the
    command showed over the decider's socket. Where the outer sandbox cannot host the per call one, a shell command
    is denied with cause 129; it is never run under the outer profile alone."""
    event = None
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise AgentError("the hook input is not a JSON object")
        event = data.get("hook_event_name")
        session = data.get("session_id")
        if not isinstance(session, str) or not session:
            raise AgentError("the hook input names no session_id")
        home = config_dir(env)
        policy, store = load_checked(home)
        if event == "SessionEnd":
            if (store.root / _run_dir(session)).exists():
                run = store.get(session)
                try:
                    run.infer_outcomes()    # allowed and asked receipts with no outcome, recorded as such; never blocks the seal
                except Exception:           # noqa: BLE001
                    pass
                run.seal(home)
            return {}
        if event in OUTCOME_EVENTS:
            return outcome_answer(data, event, store)
        if event == "PrismPathObservation" and nested is not None:
            try:
                return observation_answer(data, home, store)
            except Exception as exc:    # noqa: BLE001
                return {"recorded": False, "systemMessage": f"the observation was not recorded: {_detail(exc)}"}
        if event != "PreToolUse":
            raise AgentError(f"the hook was called for {event!r}; it answers PreToolUse and SessionEnd")
        from prismpath.agent import claude_code
        from prismpath.agent.policy import classifier_mismatch
        mismatch = classifier_mismatch(policy)
        if mismatch:
            raise AgentError(mismatch)          # a deny with the hook-error cause and the fix, not a bare cause 37
        from prismpath.agent import zones as zone_module
        result = claude_code.evaluate(data, env, policy, lambda ws: zone_module.information_point(
            home, policy.image, Path(ws), env))
        answer, profile = result.answer, None
        from prismpath.agent import sandbox_hook
        has_command = isinstance(data.get("tool_input"), dict) and isinstance(data["tool_input"].get("command"), str)
        if (result.decision.kind == "allow" or (result.decision.kind == "escalate" and has_command)) \
                and data.get("tool_name") == "Bash" and sandbox_hook.supported():
            # an allowed shell call, or a question the person approves, runs only inside the sandbox the same policy compiles to (sandbox_hook.py);
            # on a platform without the sandbox the call is decided and not confined, as before
            try:
                profile = sandbox_hook.sandbox_profile_for_call(data, home, policy.image, nested)
            except sandbox_hook.SandboxRefused as exc:
                return deny_answer(_detail(exc), SANDBOX_ERROR)
        run = store.open(session, policy.image)
        index = run.append(policy.reading_bytes(result.reading), result.decision.verdict,
                           sandbox_profile=profile.hash() if profile is not None else None,
                           sandbox_backend=(nested.backend if nested else "bwrap") if profile is not None else None,
                           tool_use_id=data.get("tool_use_id"))
        if profile is not None:
            # the receipt is written first so the runner can bind what the command shows to it (observe.py)
            from prismpath.ledgers import core_evidence
            observe = {"session": session, "receipt": index, "profile_sha256": profile.hash(),
                       "image_sha256": core_evidence.sha256_hex(policy.image)}
            if nested is None:
                observe["run_dir"] = str(run.dir)
            else:
                observe["socket"] = nested.socket
            updated = sandbox_hook.sandbox_input(data, result.workspace, profile, observe=observe,
                                                 python=nested.python if nested else None, runner=nested.runner if nested else None,
                                                 backend=nested.backend if nested else "bwrap")
            answer = claude_code.hook_answer(result.decision, updated)
        answer = claude_code.fill_receipt(answer, receipt_id(session, index))
        return answer
    except BaseException as exc:  # noqa: BLE001 - fail closed on everything, never allow
        if event == "SessionEnd":
            return {"systemMessage": f"PrismPath could not seal this session's run: cause {HOOK_ERROR} "
                                     f"({_detail(exc)}). `prismpath agent verify` seals it later."}
        if event in OUTCOME_EVENTS:     # the call already ran: there is nothing to deny, and nothing changes
            return {"systemMessage": f"PrismPath could not record this outcome ({_detail(exc)}). Nothing was changed."}
        return deny_answer(_detail(exc))


def hook_main() -> int:
    """Read stdin, answer on stdout, exit 0 (a nonzero exit would let Claude Code run the call)."""
    try:
        raw = sys.stdin.buffer.read()
    except BaseException as exc:  # noqa: BLE001
        answer = deny_answer(_detail(exc))
    else:
        answer = hook(raw)
    try:
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - nothing left to tell; Claude Code treats no answer as no decision
        pass
    return 0


def _run_dir(session: str) -> str:
    from prismpath.agent.run import run_dir_name
    return run_dir_name(session)


# ------------------------------------------------------------------------------------------ verify, status
def _require_keys(home: Path) -> None:
    for role in KEY_ROLES:
        for path in _key_paths(home, role):
            if not path.is_file():
                raise AgentError(f"no {role} key at {path}; run `prismpath agent init`")


def verify(as_json: bool, tamper_demo: bool = False, out=None) -> int:
    from prismpath.agent.run import RunError, RunStore
    out = out or sys.stdout
    home = config_dir()
    _require_keys(home)
    store = RunStore(home / RUNS_DIR)
    results: List[Dict[str, Any]] = []
    for run in store.runs():
        row: Dict[str, Any] = {"session": run.session, "dir": run.dir.name}
        try:
            summary = run.summary()
            row["was"] = "open" if summary["open"] else "sealed"
            if summary["receipts"] == 0:
                row.update(receipts=0, verified=True, note="no receipts yet")
            else:
                # an open run (never sealed, a first seal cut short, receipts appended since) is sealed first;
                # a sealed run whose receipts are not the journal's is verified as it stands, never resealed
                # over, so a changed seal file is refused rather than repaired
                if summary["seal"] == "diverged":
                    row["was"] = "sealed over other receipts than the journal's"
                result = run.verify(home, seal=summary["seal"] != "diverged")
                row.update(receipts=result["receipts"], replayed=result["replayed"], disagree=result["disagree"],
                           root_statement=result["root_statement"], observations=result.get("observations", 0),
                           outcomes=result.get("outcomes", 0),
                           verified=result["disagree"] == 0 and result["root_statement"] == "signed")
        except (RunError, Exception) as exc:  # noqa: BLE001 - one bad run does not stop the others
            row.update(verified=False, error=_detail(exc))
        results.append(row)
    report: Dict[str, Any] = {"config_dir": str(home), "runs": results,
                              "verified": all(r["verified"] for r in results)}
    if tamper_demo:
        report["tamper_demo"] = _tamper_demo(home, [r for r in results if r["verified"] and r.get("receipts")])
    ok = report["verified"] and (not tamper_demo or report["tamper_demo"].get("refused") is True)
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        if not results:
            print(f"no runs in {home / RUNS_DIR}", file=out)
        for row in results:
            if row.get("error"):
                print(f"{row['session']}: REFUSED ({row['error']})", file=out)
            elif row.get("note"):
                print(f"{row['session']}: {row['note']}", file=out)
            else:
                print(f"{row['session']}: {row['receipts']} receipts, {row['replayed']} replayed through the reference "
                      f"kernel, {row['disagree']} disagree, root statement {row['root_statement']} "
                      f"(was {row['was']}){'' if row['verified'] else ' REFUSED'}"
                      + (f"; {row['observations']} sandbox observations bound to their receipts, none of them a decision"
                         if row.get("observations") else "")
                      + (f"; {row['outcomes']} outcome entries chained and bound to their receipts (outside the signed root, none of them a decision)"
                         if row.get("outcomes") else ""), file=out)
        demo = report.get("tamper_demo")
        if demo is not None:
            if demo.get("refused") is True:
                print(f"tamper demo: a copy of {demo['session']} with byte {demo['offset']} of {demo['file']} "
                      f"flipped is refused: {demo['reason']}. The copy was deleted.", file=out)
            else:
                print(f"tamper demo: {demo.get('reason')}", file=out)
    return 0 if ok else 1


def _tamper_demo(home: Path, verified_rows) -> Dict[str, Any]:
    import shutil
    import tempfile
    from prismpath.ledgers import core_evidence
    if not verified_rows:
        return {"refused": None, "reason": "there is no verified run with receipts to copy"}
    row = verified_rows[-1]
    scratch = Path(tempfile.mkdtemp(prefix="prismpath-tamper-"))
    try:
        copy = scratch / "run"
        shutil.copytree(home / RUNS_DIR / row["dir"], copy)
        target = copy / "receipts.jsonl"
        data = bytearray(target.read_bytes())
        offset = len(data) // 2
        data[offset] ^= 0x01
        target.write_bytes(bytes(data))
        try:
            core_evidence.verify(copy, sample=None, pin_authority=home / "authority.pub",
                                 pin_instance=home / "instance.pub")
        except Exception as exc:  # noqa: BLE001 - the refusal is the point of the demo
            return {"session": row["session"], "file": "receipts.jsonl", "offset": offset, "refused": True,
                    "reason": _detail(exc)}
        return {"session": row["session"], "file": "receipts.jsonl", "offset": offset, "refused": False,
                "reason": "the tampered copy verified, which must never happen"}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run(program: List[str], workspace: Optional[str] = None, credential: Optional[str] = None,
        egress_log: Optional[str] = None, max_processes: Optional[int] = None,
        local_model: Optional[str] = None, extra_ro: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None) -> int:
    """`prismpath agent run -- PROGRAM [ARGS]`: the program as the agent, under the sandbox with only the hosts the
    recorded policy allows reachable (the model API, and `allowed_hosts` if the policy allows that class;
    prismpath/agent/launcher.py). Exits with the program's status. Raises AgentError, with
    nothing run, off Linux or without bwrap or socat."""
    import time
    from prismpath.agent import launcher
    if program[:1] == ["--"]:
        program = program[1:]
    # the decider decides every tool call with the recorded keys and policy; without them it would refuse each call
    # with cause 126, so say what is missing now and run nothing
    from prismpath.agent.policy import classifier_mismatch
    try:
        policy, _store = load_checked(config_dir())
    except AgentError as exc:
        raise AgentError(f"{exc}; `prismpath agent run` needs it before it starts the agent, so nothing was run") from exc
    mismatch = classifier_mismatch(policy)
    if mismatch:
        raise AgentError(f"{mismatch}; nothing was run")
    if egress_log is None:
        egress_log = str(config_dir() / "egress" / f"{time.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}.log")
    kwargs = {} if max_processes is None else {"max_processes": max_processes}
    if local_model:
        kwargs["local_model"] = local_model
    if extra_ro:
        kwargs["extra_ro"] = extra_ro
    if allowed_hosts:
        kwargs["allowed_hosts"] = [host.lower() for host in allowed_hosts]
    return launcher.launch(program, workspace or os.getcwd(), credential=credential, egress_log=egress_log, **kwargs)


def confinement_state() -> Dict[str, Any]:
    """Whether an allowed shell command is confined on this platform, and the sentence that says so."""
    from prismpath.agent import sandbox_exec, sandbox_hook
    if not sandbox_hook.supported():
        return {"confined": False, "platform": sys.platform,
                "detail": f"decided but not confined on this platform ({sys.platform}); the sandbox applies on Linux only"}
    if not sandbox_exec.available():
        return {"confined": False, "platform": sys.platform,
                "detail": f"not confined, and every allowed shell command is refused (cause 129): {sandbox_exec.BWRAP} is missing"}
    return {"confined": True, "platform": sys.platform, "detail": "decided and run inside the sandbox compiled from the policy"}


def zones_cmd(action: str, project: Path, protected: Optional[List[str]], protected_file: Optional[str],
              index: Optional[str], as_json: bool, out=None) -> int:
    """`prismpath agent zones set|status|warm` (prismpath/agent/zones.py)."""
    from prismpath.agent import zones
    out = out or sys.stdout
    home = config_dir()
    load_checked(home)                                     # keys and a recorded policy that verifies, or AgentError
    image = (home / POLICY_FILE).read_bytes()
    project = Path(os.path.realpath(project))
    try:
        if action == "set":
            names = [n for item in (protected or []) for n in item.split(",") if n]
            if protected_file:
                names += [line.strip() for line in Path(protected_file).read_text(encoding="utf-8").split("\n")
                          if line.strip() and not line.strip().startswith("#")]
            doc = zones.zone_document(names, project, Path(index) if index else None, image)
            zones.sign(home, doc)
            result = {"recorded": True, "project": doc["project"], "index": doc["index"],
                      "protected": doc["protected"], "policy_sha256": doc["policy_sha256"]}
        elif action == "status":
            result = zones.status(home, image, project)
        else:
            point = zones.information_point(home, image, project)
            if not isinstance(point, zones.ContextCloudZones):
                raise AgentError(f"there is nothing to warm: {zones.status(home, image, project)['detail']}")
            started = time.monotonic()
            facts = point.warm()
            result = {"files": len(facts), "seconds": round(time.monotonic() - started, 2),
                      "by_fact": {k: sum(1 for v in facts.values() if v == k) for k in zones.ANSWERS}}
    except zones.ZoneError as exc:
        raise AgentError(str(exc))
    if as_json:
        print(json.dumps(result, indent=1, sort_keys=True), file=out)
    else:
        for key, value in result.items():
            print(f"{key}: {value}", file=out)
    return 0


def outcome_line(c: Dict[str, int]) -> str:
    """One line of what became of the calls: `allowed 5 (4 ran, 1 no outcome); asked 2 (1 approved and ran, 1 no
    outcome); refused 3`. A call still waiting for its outcome shows as no outcome."""
    return (f"allowed {c['allowed']} ({c['allowed_ran']} ran, {c['allowed_no_outcome']} no outcome); "
            f"asked {c['asked']} ({c['asked_approved']} approved and ran, {c['asked_no_outcome']} no outcome); "
            f"refused {c['refused']}" + (f"; {c['unbound']} outcome events could not be bound" if c.get("unbound") else ""))


def status(project: Path, as_json: bool, out=None) -> int:
    from prismpath.agent.policy import STARTERS, control_check, older_date, older_starter_of, starter_of
    from prismpath.agent.run import RunStore
    out = out or sys.stdout
    home = config_dir()
    keys = {role: {"present": all(p.is_file() for p in _key_paths(home, role)), "id": _key_id(home, role)}
            for role in KEY_ROLES}
    policy: Dict[str, Any] = {"path": str(home / POLICY_FILE)}
    if (home / POLICY_FILE).is_file():
        policy["sha256"] = _sha256_hex((home / POLICY_FILE).read_bytes())
        image = (home / POLICY_FILE).read_bytes()
        older = older_starter_of(image)
        policy["name"] = starter_of(image) or (f"{older[0]} (before {older_date(image)})" if older else "custom")
        policy["image"] = STARTERS.get(policy["name"])
        try:
            policy["control"] = control_check(image)
        except Exception as exc:  # noqa: BLE001 - an image that does not load is reported by `attested` below
            policy["control"] = {"refuses_control_changes": None, "reason": _detail(exc)}
    try:
        load_checked(home)
        policy["attested"] = True
    except Exception as exc:  # noqa: BLE001
        policy["attested"], policy["problem"] = False, _detail(exc)
    runs = []
    for run in RunStore(home / RUNS_DIR).runs():
        try:
            summary = run.summary()
            runs.append({"session": run.session, "receipts": summary["receipts"],
                         "state": "open" if summary["open"] else "sealed", "outcomes": run.outcome_counts()})
        except Exception as exc:  # noqa: BLE001
            runs.append({"session": run.session, "receipts": None, "state": "corrupt", "problem": _detail(exc)})
    settings_path = Path(project) / ".claude" / "settings.json"
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {}) if isinstance(settings, dict) else {}
        installed = {event: any(_is_ours(h.get("command")) for g in hooks.get(event, []) if isinstance(g, dict)
                                for h in g.get("hooks", []) if isinstance(h, dict))
                     for event, _matcher in HOOK_EVENTS}
    except Exception:  # noqa: BLE001
        installed = {event: False for event, _matcher in HOOK_EVENTS}
    confinement = confinement_state()
    totals: Dict[str, int] = {}
    for r in runs:
        for key, value in (r.get("outcomes") or {}).items():
            totals[key] = totals.get(key, 0) + value
    report = {"config_dir": str(home), "keys": keys, "policy": policy, "runs": runs, "shell": confinement,
              "outcomes": totals, "project": {"settings": str(settings_path), "hooks": installed}}
    ready = all(k["present"] for k in keys.values()) and policy["attested"]
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        for role in KEY_ROLES:
            k = keys[role]
            print(f"{role} key: {k['id'] if k['present'] else 'missing'}", file=out)
        named = f"{policy['name']} {policy['sha256']}" if "sha256" in policy else "missing"
        print(f"policy: {named} ({'attested' if policy['attested'] else 'not usable: ' + policy['problem']})",
              file=out)
        if policy.get("control", {}).get("refuses_control_changes") is False:
            print(f"warning: {policy['control']['message']}", file=out)
        print(f"hooks in {settings_path}: " + ", ".join(f"{e} {'yes' if v else 'no'}" for e, v in installed.items()),
              file=out)
        print(f"shell commands: {confinement['detail']}", file=out)
        if not runs:
            print("runs: none", file=out)
        for r in runs:
            print(f"run {r['session']}: {r['receipts']} receipts, {r['state']}"
                  + (f"; {outcome_line(r['outcomes'])}" if r.get("outcomes") else ""), file=out)
        if totals:
            print(f"all runs: {outcome_line(totals)}", file=out)
            print("outcomes are records of what became of a call (PostToolUse, the sandbox runner, the end of the "
                  "session); outside the signed root, they decide nothing", file=out)
    return 0 if ready else 1
