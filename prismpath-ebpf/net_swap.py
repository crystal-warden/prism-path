#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Trusted pre-loader for the eBPF policy hot-swap (spec-secure-hotswap §5, eBPF layer).

The kernel `loader … netupdate` will happily repopulate maps from any structurally-valid image.
This pre-loader puts the Authorized + Envelope-bounded + Audited gates in front of it, on the host,
where the crypto lives: it verifies the signed pack against its signed envelope and the monotonic
version floor, and only *then* execs the loader. Verification failures never reach the kernel.

The same gates stand in front of the FIRST attach (`--attach`, `loader … netattach`), and the loader itself
refuses `netattach` and `netupdate` unless it is handed the SHA-256 of the table the host verified
(`PPT_NET_VERIFIED_SHA256`, set here), so the table loaded is the table checked. `extra_checks` are further
host-side checks of what the table carries (net_from_policy's signed destination table); one that returns a
reason refuses the load.

The gate ends in `run_loader(table, verb, iface, ...)`, the one loader call. The `xdp` enforcement point of
policy distribution (`net_dist.py`) ends in the same call, so a table reaches the kernel one way and leaves one
audit event. The version floor is written before the loader runs (C4 of spec-policy-distribution.md), so a load
that fails part way never leaves the floor below a table the kernel may hold, and the audit log is signed by the
instance key when one is given.

Pure userspace and privilege-free up to the loader exec, so the whole gate is testable without root
(the loader call is injectable). Loud absence: no `cryptography` -> refuse (policy_pack raises).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Callable, List, Optional, Sequence

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from prismpath.distribution import devbuild               # noqa: E402
from prismpath.hotswap import policy_pack as pp          # noqa: E402
from prismpath.ledgers.audit_log import AuditLog          # noqa: E402


def _read_version(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip() or "0")
    except (FileNotFoundError, ValueError):
        return 0


def _write_version(path: str, v: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(v))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _hatch(asked: bool, audit) -> bool:
    """`--allow-unsigned` is an escape hatch: it works in a dev build, and in a production build it is refused
    with `dist:hatch-refused` and the signed checks run (docs/design/spec-policy-distribution.md, D1, D2)."""
    if not asked:
        return False
    try:
        devbuild.hatch("--allow-unsigned", audit)
    except devbuild.HatchRefused:
        return False
    return True


VERBS = {"swap": "netupdate", "attach": "netattach"}


def audit_log(state_dir: str, instance_key=None) -> AuditLog:
    """The gate's audit log, `net_swaps.log` in `state_dir`, each append signed by `instance_key` when given."""
    return AuditLog(os.path.join(state_dir, "net_swaps.log"), instance_key=instance_key,
                    sign_appends=instance_key is not None)


def run_loader(table: bytes, verb: str, iface: str, *, path: str, audit: AuditLog, action: str,
               loader: str = "./loader", run: Callable = subprocess.run, names_path: Optional[str] = None,
               record: Optional[dict] = None) -> dict:
    """The one loader call: `loader <path> <verb> <iface> [names]`, handed the SHA-256 of `table`
    (`PPT_NET_VERIFIED_SHA256`), so the loader refuses any other table. `path` is written with `table` first when
    it does not hold it already. One audit event either way: `action` with `record` when the loader succeeds, and
    `loader_failed` when it does not. The caller has run every gate and written its floor before this call."""
    if verb not in VERBS.values():
        raise ValueError(f"the loader verb is netupdate or netattach, not {verb!r}")
    to_hash = pp.sha256_hex(table)
    try:
        with open(path, "rb") as handle:
            held = handle.read()
    except OSError:
        held = None
    if held != table:
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            handle.write(table)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    argv = [loader, path, verb, iface] + ([names_path] if verb == "netattach" and names_path else [])
    r = run(argv, capture_output=True, text=True, env={**os.environ, "PPT_NET_VERIFIED_SHA256": to_hash})
    if r.returncode != 0:
        audit.append("net_swap", "loader_failed",
                     {"to_hash": to_hash, "iface": iface, "verb": verb, "stderr": (r.stderr or "")[-300:]})
        return {"ok": False, "reasons": ["loader:failed"],
                "loader_output": ((r.stdout or "") + (r.stderr or ""))[-400:]}
    audit.append("net_swap", action, {**(record or {}), "to_hash": to_hash, "iface": iface, "verb": verb,
                                      "result": "accepted"})
    return {"ok": True, "active": to_hash, "loader_output": (r.stdout or "")[-400:]}


def preload_swap(ppt_path: str, iface: str, pubkey_paths: List[str], envelope_base: Optional[str],
                 state_dir: str, *, allow_unsigned: bool = False, revoked_path: Optional[str] = None,
                 loader: str = "./loader", run: Callable = subprocess.run, dry_run: bool = False,
                 action: str = "swap", names_path: Optional[str] = None,
                 extra_checks: Sequence[Callable[[bytes], List[str]]] = (), instance_key=None) -> dict:
    """Verify (sig -> envelope -> version) on the host, then exec `loader <ppt> netupdate <iface>`, or with
    `action="attach"` the first attach, `loader <ppt> netattach <iface> [names]`. `extra_checks` each get the image
    bytes and return refusal reasons, run after the pack gates and before the loader.
    Returns {ok, ...}; the kernel loader is reached only on full verification success, through `run_loader`, and
    the version floor is written before it. Every outcome is one audit row, signed by `instance_key` when given.
    `dry_run` runs every gate and stops where the loader would be called: no loader, no kernel, no version floor
    written, and one `swap_dry_run` audit row."""
    if action not in VERBS:
        raise ValueError(f"action is swap or attach, not {action!r}")
    os.makedirs(state_dir, exist_ok=True)
    audit = audit_log(state_dir, instance_key)
    vpath = os.path.join(state_dir, "active_version")
    allow_unsigned = _hatch(allow_unsigned, audit)

    try:
        with open(ppt_path, "rb") as f:
            image = f.read()
    except OSError as e:
        return _reject(audit, None, [f"image:unreadable:{e.errno}"])
    to_hash = pp.sha256_hex(image)

    env = None
    if envelope_base:
        env, ereasons = pp.load_envelope(envelope_base, pubkey_paths)
        if env is None and not allow_unsigned:
            return _reject(audit, to_hash, ereasons)

    if allow_unsigned:
        ok, reasons = pp.validate_image(image, caps=(env or {}).get("caps"))
        if not ok:
            return _reject(audit, to_hash, reasons)
        version, key_id, unsigned = None, None, True
    else:
        ok, reasons, manifest = pp.verify_pack(ppt_path, pubkey_paths, pp.load_revoked(revoked_path))
        if not ok:
            return _reject(audit, to_hash, reasons)
        if pp.is_older(manifest):                   # L3: an older pack is read, and says so in the log
            from prismpath.distribution import legacy
            legacy.record(audit, legacy.PACK, reader="net_swap.preload_swap", sha256=to_hash,
                          key_id=manifest.get("key_id"))
        if env is None:
            return _reject(audit, to_hash, ["envelope:missing"])
        ok, reasons = pp.check_envelope(manifest, image, env)
        if not ok:
            return _reject(audit, to_hash, reasons)
        version, key_id, unsigned = manifest["version"], manifest.get("key_id"), False
        stored = _read_version(vpath)
        if version <= stored:
            return _reject(audit, to_hash, [f"version:not-monotonic:{version}<={stored}"])

    for check in extra_checks:
        reasons = check(image)
        if reasons:
            return _reject(audit, to_hash, list(reasons))

    if dry_run:
        audit.append("net_swap", "swap_dry_run", {"to_hash": to_hash, "version": version, "key_id": key_id,
                                                  "unsigned": unsigned, "iface": iface, "result": "verified"})
        return {"ok": True, "dry_run": True, "active": to_hash, "version": version, "unsigned": unsigned}

    # Verified. Now, and only now, touch the kernel: the floor first (C4), then the one loader call.
    if version is not None:
        _write_version(vpath, version)
    result = run_loader(image, VERBS[action], iface, path=ppt_path, audit=audit, action=action, loader=loader, run=run,
                        names_path=names_path if action == "attach" else None,
                        record={"version": version, "key_id": key_id, "unsigned": unsigned})
    if not result["ok"]:
        return result
    return {**result, "version": version, "unsigned": unsigned}


def _reject(audit: AuditLog, to_hash: Optional[str], reasons: List[str]) -> dict:
    audit.append("net_swap", "swap_rejected",
                 {"to_hash": to_hash, "reasons": reasons, "result": "rejected"})
    return {"ok": False, "reasons": reasons}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("ppt")
    ap.add_argument("iface")
    ap.add_argument("--pub", nargs="+", required=True, help="authority public key(s)")
    ap.add_argument("--envelope", help="envelope base path (without .json/.sig)")
    ap.add_argument("--state", default="./net_swap_state", help="state dir (audit log + version)")
    ap.add_argument("--key", help="the host's instance key (`prismpath ledger keygen`), which signs the audit log")
    ap.add_argument("--revoked", help="revocation list JSON")
    ap.add_argument("--loader", default="./loader", help="path to the kernel loader binary")
    ap.add_argument("--attach", action="store_true", help="the first attach (loader netattach), not a swap")
    ap.add_argument("--names", help="node names file the loader derives its drop mask from (attach)")
    ap.add_argument("--edge", help="an edge directory from net_from_policy.py: its signed destination table is "
                                   "checked before the load (the ppt and names are the directory's)")
    ap.add_argument("--allow-unsigned", dest="allow_unsigned", action="store_true")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help="run every gate, then stop before the loader (nothing is loaded or recorded as active)")
    args = ap.parse_args(argv)
    checks = []
    if args.edge:
        import net_from_policy
        checks.append(net_from_policy.edge_check(args.edge, args.pub, args.revoked, args.ppt))
    try:
        instance_key = None
        if args.key:
            from prismpath.ledgers.root_statement import InstanceKey
            instance_key = InstanceKey.load(args.key)
        res = preload_swap(args.ppt, args.iface, args.pub, args.envelope, args.state,
                           allow_unsigned=args.allow_unsigned, revoked_path=args.revoked,
                           loader=args.loader, dry_run=args.dry_run,
                           action="attach" if args.attach else "swap", names_path=args.names, extra_checks=checks,
                           instance_key=instance_key)
    except RuntimeError as e:                              # loud absence (no cryptography)
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps(res, indent=1))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
