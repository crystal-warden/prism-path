#!/usr/bin/env python3
"""Trusted pre-loader for the eBPF policy hot-swap (spec-secure-hotswap §5, eBPF layer).

The kernel `loader … netupdate` will happily repopulate maps from any structurally-valid image.
This pre-loader puts the Authorized + Envelope-bounded + Audited gates in front of it, on the host,
where the crypto lives: it verifies the signed pack against its signed envelope and the monotonic
version floor, and only *then* execs the loader. Verification failures never reach the kernel.

Pure userspace and privilege-free up to the loader exec, so the whole gate is testable without root
(the loader call is injectable). Loud absence: no `cryptography` -> refuse (policy_pack raises).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Callable, List, Optional

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from prismpath import policy_pack as pp          # noqa: E402
from prismpath.audit_log import AuditLog          # noqa: E402


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


def preload_swap(ppt_path: str, iface: str, pubkey_paths: List[str], envelope_base: Optional[str],
                 state_dir: str, *, allow_unsigned: bool = False, revoked_path: Optional[str] = None,
                 loader: str = "./loader", run: Callable = subprocess.run) -> dict:
    """Verify (sig -> envelope -> version) on the host, then exec `loader <ppt> netupdate <iface>`.
    Returns {ok, ...}; the kernel loader is reached only on full verification success. Every
    outcome is one audit row."""
    os.makedirs(state_dir, exist_ok=True)
    audit = AuditLog(os.path.join(state_dir, "net_swaps.log"))
    vpath = os.path.join(state_dir, "active_version")

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
        if env is None:
            return _reject(audit, to_hash, ["envelope:missing"])
        ok, reasons = pp.check_envelope(manifest, image, env)
        if not ok:
            return _reject(audit, to_hash, reasons)
        version, key_id, unsigned = manifest["version"], manifest.get("key_id"), False
        stored = _read_version(vpath)
        if version <= stored:
            return _reject(audit, to_hash, [f"version:not-monotonic:{version}<={stored}"])

    # Verified. Now, and only now, touch the kernel.
    r = run([loader, ppt_path, "netupdate", iface], capture_output=True, text=True)
    if r.returncode != 0:
        audit.append("net_swap", "loader_failed",
                     {"to_hash": to_hash, "iface": iface, "stderr": (r.stderr or "")[-300:]})
        return {"ok": False, "reasons": ["loader:failed"],
                "loader_output": ((r.stdout or "") + (r.stderr or ""))[-400:]}
    if version is not None:
        _write_version(vpath, version)
    audit.append("net_swap", "swap", {"to_hash": to_hash, "version": version, "key_id": key_id,
                                      "unsigned": unsigned, "iface": iface, "result": "accepted"})
    return {"ok": True, "active": to_hash, "version": version, "unsigned": unsigned,
            "loader_output": (r.stdout or "")[-400:]}


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
    ap.add_argument("--revoked", help="revocation list JSON")
    ap.add_argument("--loader", default="./loader", help="path to the kernel loader binary")
    ap.add_argument("--allow-unsigned", dest="allow_unsigned", action="store_true")
    args = ap.parse_args(argv)
    try:
        res = preload_swap(args.ppt, args.iface, args.pub, args.envelope, args.state,
                           allow_unsigned=args.allow_unsigned, revoked_path=args.revoked,
                           loader=args.loader)
    except RuntimeError as e:                              # loud absence (no cryptography)
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps(res, indent=1))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
