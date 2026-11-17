# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent init | hook | verify | status`: a Claude Code session governed by the core, from one command.

Where things live. Everything the commands keep is in one directory of the user's configuration directory,
`<config>/prismpath/agent` (mode 0700), where `<config>` is XDG_CONFIG_HOME or ~/.config on Linux,
~/Library/Application Support on macOS and %APPDATA% on Windows:

  authority.key, authority.pub   the authority key, which says which policy may run (mode 0600)
  instance.key, instance.pub     the instance key, which signs the root statement over a run (mode 0600)
  policy.core.json               the policy image every hook call decides under: `agent_default`
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
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

AGENT_DIR = ("prismpath", "agent")
POLICY_FILE = "policy.core.json"
ATTESTATION_FILE = "policy.attestation.json"
RUNS_DIR = "runs"
POLICY_CASE = "agent_default"
HOOK_ERROR = "agent:hook-error"
KEY_ROLES = ("authority", "instance")


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


def hook_command() -> str:
    """The command Claude Code runs: this interpreter, so the hook runs the PrismPath that was installed."""
    argv = [sys.executable, "-m", "prismpath", "agent", "hook"]
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


def _attestation(home: Path, image: bytes) -> bytes:
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    signer = policy_pack._load_private(str(_key_paths(home, "authority")[0]))
    return canon2.dumps({"format": core_evidence.IMAGE_FORMAT, "case": POLICY_CASE,
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
    """`settings` with the PreToolUse and SessionEnd hook entries running `command`, every other key kept.
    An entry that already runs a PrismPath hook is pointed at `command` in place, so running it twice adds
    nothing."""
    out = json.loads(json.dumps(settings))
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise AgentError("the settings' `hooks` is not an object; fix it by hand first")
    for event, matcher in (("PreToolUse", "*"), ("SessionEnd", None)):
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
def init(project: Path, yes: bool, as_json: bool, confirm=None, out=None) -> int:
    """Keys, policy and the project's hook entries. `confirm(prompt) -> bool` asks the person; None means
    ask on a terminal and otherwise take no for an answer."""
    import difflib
    out = out or sys.stdout
    home = config_dir()
    _make_dir(home)
    keys = {role: _ensure_key(home, role) for role in KEY_ROLES}
    from prismpath.agent.policy import DEFAULT_POLICY_PATH, Policy
    from prismpath.ledgers import root_statement
    root_statement.check_separation(root_statement.InstanceKey.load(str(_key_paths(home, "instance")[0])),
                                    [_key_id(home, "authority")])
    image = Policy.load(DEFAULT_POLICY_PATH).image
    policy_state = "kept"
    try:
        load_checked(home)
        if (home / POLICY_FILE).read_bytes() != image:
            policy_state = "updated"
    except Exception:  # noqa: BLE001 - absent or not verifying: record it again
        policy_state = "recorded"
    if policy_state != "kept":
        for name, data in ((POLICY_FILE, image), (ATTESTATION_FILE, _attestation(home, image))):
            tmp = home / (name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, home / name)
    load_checked(home)

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
              "policy": {"name": POLICY_CASE, "sha256": _sha256_hex(image), "state": policy_state},
              "settings": {"path": str(path), "state": settings_state, "diff": diff, "command": hook_command()}}
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        for role in KEY_ROLES:
            print(f"{role} key {report['keys'][role]['id']} ({keys[role]}) in {home}", file=out)
        print(f"policy {POLICY_CASE} sha256 {report['policy']['sha256']} ({policy_state}), attested by the authority key",
              file=out)
        if settings_state == "not written":
            print(f"{path} was not changed; run again with --yes to write the hook entries", file=out)
        else:
            print(f"{path}: {settings_state}", file=out)
    return 0 if settings_state != "not written" else 1


# ------------------------------------------------------------------------------------------------- hook
def _cause_code() -> Optional[int]:
    try:
        from prismpath.kernel import causes
        return causes.code(HOOK_ERROR)
    except Exception:  # noqa: BLE001
        return None


def _detail(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= 240 else text[:237] + "..."


def deny_answer(detail: str) -> Dict[str, Any]:
    code = _cause_code()
    cause = f"{code} {HOOK_ERROR}" if code is not None else HOOK_ERROR
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": f"PrismPath refused this call: cause {cause} ({detail}). It was not run. "
                                    f"No receipt was written for it."}}


def receipt_id(session: str, index: int) -> str:
    return f"{index} of session {session}"


def hook(raw: bytes, env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """The answer to one hook input. Never raises; whatever fails is a deny with cause 126."""
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
                store.get(session).seal(home)
            return {}
        if event != "PreToolUse":
            raise AgentError(f"the hook was called for {event!r}; it answers PreToolUse and SessionEnd")
        from prismpath.agent import claude_code
        result = claude_code.evaluate(data, env, policy)
        index = store.open(session, policy.image).append(policy.reading_bytes(result.reading), result.decision.verdict)
        return claude_code.fill_receipt(result.answer, receipt_id(session, index))
    except BaseException as exc:  # noqa: BLE001 - fail closed on everything, never allow
        if event == "SessionEnd":
            return {"systemMessage": f"PrismPath could not seal this session's run: cause {HOOK_ERROR} "
                                     f"({_detail(exc)}). `prismpath agent verify` seals it later."}
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
                           root_statement=result["root_statement"],
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
                      f"(was {row['was']}){'' if row['verified'] else ' REFUSED'}", file=out)
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


def status(project: Path, as_json: bool, out=None) -> int:
    from prismpath.agent.run import RunStore
    out = out or sys.stdout
    home = config_dir()
    keys = {role: {"present": all(p.is_file() for p in _key_paths(home, role)), "id": _key_id(home, role)}
            for role in KEY_ROLES}
    policy: Dict[str, Any] = {"path": str(home / POLICY_FILE)}
    if (home / POLICY_FILE).is_file():
        policy["sha256"] = _sha256_hex((home / POLICY_FILE).read_bytes())
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
                         "state": "open" if summary["open"] else "sealed"})
        except Exception as exc:  # noqa: BLE001
            runs.append({"session": run.session, "receipts": None, "state": "corrupt", "problem": _detail(exc)})
    settings_path = Path(project) / ".claude" / "settings.json"
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {}) if isinstance(settings, dict) else {}
        installed = {event: any(_is_ours(h.get("command")) for g in hooks.get(event, []) if isinstance(g, dict)
                                for h in g.get("hooks", []) if isinstance(h, dict))
                     for event in ("PreToolUse", "SessionEnd")}
    except Exception:  # noqa: BLE001
        installed = {"PreToolUse": False, "SessionEnd": False}
    report = {"config_dir": str(home), "keys": keys, "policy": policy, "runs": runs,
              "project": {"settings": str(settings_path), "hooks": installed}}
    ready = all(k["present"] for k in keys.values()) and policy["attested"]
    if as_json:
        print(json.dumps(report, indent=2), file=out)
    else:
        for role in KEY_ROLES:
            k = keys[role]
            print(f"{role} key: {k['id'] if k['present'] else 'missing'}", file=out)
        print(f"policy: {policy.get('sha256', 'missing')} "
              f"({'attested' if policy['attested'] else 'not usable: ' + policy['problem']})", file=out)
        print(f"hooks in {settings_path}: " + ", ".join(f"{e} {'yes' if v else 'no'}" for e, v in installed.items()),
              file=out)
        if not runs:
            print("runs: none", file=out)
        for r in runs:
            print(f"run {r['session']}: {r['receipts']} receipts, {r['state']}", file=out)
    return 0 if ready else 1
