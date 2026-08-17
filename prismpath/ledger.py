# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ledger.py — the git Flow-Ledger: gate-green proof-commits (Area 6, Slice 1).

Where Slice 0 (checkpoint.py) makes a run *resumable*, the Flow-Ledger makes each completed unit
a durable, content-addressed PROOF. Every gate-green unit of work becomes exactly one commit on a
per-run orphan ref — its git tree is the content-hashed state the gate blessed, and its trailers
correlate it to the flow node. Progress is then a projection over `git log` (event sourcing), so a
tamper-evident audit trail and a resume-able done-set come for free from a tool already on the box.

Design (see docs/design/commit-as-state.md):
  * NEVER in-tree. The ledger is a SEPARATE bare repo under $XDG_STATE_HOME/prismpath/<flow>.git,
    written entirely via git plumbing (hash-object / write-tree / commit-tree / update-ref) with
    GIT_DIR pinned — so a project's own repo (its refs, index, working tree) is never touched, and
    SPRINT_FRESH's rmtree of the project can't delete the ledger.
  * One ref per run: refs/prismpath/runs/<run-id>, an orphan-then-linear chain. Concurrent/replayed
    runs never collide; deleting a ref GCs a run.
  * One commit per gate-green UNIT. Trailers (RFC-822, first-class in `git log --format`) carry the
    correlation + machine-parseable keys; the tree is the cumulative proof; PrismPath-Output-Hash is
    this unit's produced-artifact hash (the dedupe/invalidation key). Commits are append-only.
  * Reproducible & off the critical path: identity + dates are pinned (anchor on the tree/output
    hash, never the commit sha); every ref write is a compare-and-swap; the caller wraps ledger
    calls so a git failure degrades to the existing .lastgood/.kg.json path, never breaking a run.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

# Identity + git dates are pinned so the plumbing is deterministic and never a source of run-to-run
# nondeterminism from the git layer. Real green-time is recorded separately in the PrismPath-Wallclock
# trailer (see commit_unit), so the audit question "when did this go green?" is answerable while the
# git author/committer dates stay meaningless-but-stable. The proof is content-addressed via
# PrismPath-Output-Hash — anchor on that, NOT the commit sha (which is time-dependent once wall-clock is
# recorded). Tamper-evidence here is against ACCIDENT (a fold over an append-only log); it is NOT a
# defense against an adversary with filesystem access, who could rewrite the chain and the ref
# together — anchoring ref heads with OpenTimestamps periodically is the honest upgrade (future work).
_IDENTITY = {
    "GIT_AUTHOR_NAME": "prismpath", "GIT_AUTHOR_EMAIL": "prismpath@local",
    "GIT_COMMITTER_NAME": "prismpath", "GIT_COMMITTER_EMAIL": "prismpath@local",
    "GIT_AUTHOR_DATE": "2001-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2001-01-01T00:00:00 +0000",
}
_ZERO = "0" * 40      # update-ref old-value meaning "the ref must not already exist"
_CAS_RETRIES = 5      # on a concurrent ref move, re-read the tip and rebuild this many times


class LedgerError(Exception):
    pass


def default_state_dir() -> Path:
    """Where ledgers live. PRISMPATH_LEDGER_DIR overrides outright; else $XDG_STATE_HOME/prismpath (or
    ~/.local/state/prismpath). Never inside a project tree."""
    override = os.environ.get("PRISMPATH_LEDGER_DIR")
    if override:
        return Path(override)
    base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    return Path(base) / "prismpath"


def sha256_files(mapping: Dict[str, object]) -> str:
    """Content hash of a {path: content} mapping — order-independent, the per-unit output proof."""
    h = hashlib.sha256()
    for path in sorted(mapping):
        c = mapping[path]
        c = c if isinstance(c, (bytes, bytearray)) else str(c).encode()
        h.update(path.encode() + b"\0")
        h.update(c + b"\0")
    return "sha256:" + h.hexdigest()


def new_run_id() -> str:
    """A sortable, collision-resistant run id (UTC timestamp + random suffix)."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + os.urandom(4).hex()


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "flow"


class Ledger:
    def __init__(self, flow: str, run_id: str, state_dir=None):
        self.flow = flow
        self.run_id = run_id
        self.state_dir = Path(state_dir) if state_dir else default_state_dir()
        self.repo = self.state_dir / f"{_safe(flow)}.git"
        self.ref = f"refs/prismpath/runs/{run_id}"

    # --- git plumbing -----------------------------------------------------------------
    def _env(self, index: Optional[str] = None) -> dict:
        env = dict(os.environ)
        env["GIT_DIR"] = str(self.repo)
        env.pop("GIT_WORK_TREE", None)          # never a working tree — plumbing only
        env.update(_IDENTITY)
        if index:
            env["GIT_INDEX_FILE"] = index
        return env

    def _git(self, args: List[str], *, env: dict, input: Optional[bytes] = None,
             check: bool = True) -> str:
        p = subprocess.run(["git", *args], env=env, input=input, capture_output=True)
        if check and p.returncode != 0:
            raise LedgerError(f"git {' '.join(args[:2])} failed: {p.stderr.decode()[:200]}")
        return p.stdout.decode()

    def init(self) -> None:
        if not (self.repo / "HEAD").exists():
            self.repo.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["git", "init", "--bare", "-q", str(self.repo)],
                               capture_output=True)
            if r.returncode != 0:
                raise LedgerError(f"git init --bare failed: {r.stderr.decode()[:200]}")

    def tip(self) -> Optional[str]:
        env = self._env()
        out = self._git(["rev-parse", "--verify", "--quiet", self.ref], env=env, check=False)
        return out.strip() or None

    def _commit_tree(self, commit: str) -> str:
        return self._git(["rev-parse", f"{commit}^{{tree}}"], env=self._env()).strip()

    def _write_tree(self, files: Dict[str, bytes], parent_tree: Optional[str]) -> str:
        """Build a tree = parent_tree overlaid with `files` (a CUMULATIVE state snapshot), via a
        throwaway scratch index — no working tree, the project repo untouched."""
        fd, idx = tempfile.mkstemp(prefix="prismpath-idx-")
        os.close(fd)
        os.unlink(idx)   # git wants to create it fresh
        try:
            env = self._env(index=idx)
            if parent_tree:
                self._git(["read-tree", parent_tree], env=env)
            for path, content in files.items():
                blob = self._git(["hash-object", "-w", "--stdin"], env=env, input=content).strip()
                self._git(["update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"], env=env)
            return self._git(["write-tree"], env=env).strip()
        finally:
            if os.path.exists(idx):
                os.unlink(idx)

    def _cas_update(self, new: str, old: Optional[str]) -> bool:
        # compare-and-swap: fails (returns False) if another writer moved the ref since we read the
        # tip. The caller re-reads and rebuilds on the new tip rather than dropping the proof.
        p = subprocess.run(["git", "update-ref", self.ref, new, old or _ZERO],
                           env=self._env(), capture_output=True)
        return p.returncode == 0

    # --- the API ----------------------------------------------------------------------
    def commit_unit(self, unit: str, *, node: Optional[str] = None, gate: str = "green",
                    gate_name: Optional[str] = None, files: Optional[Dict[str, object]] = None,
                    output_hash: Optional[str] = None, seq: Optional[int] = None,
                    edge: Optional[str] = None, input_hash: Optional[str] = None,
                    depends: Optional[List[str]] = None, summary: Optional[str] = None,
                    wallclock: Optional[str] = None) -> str:
        """Record one gate-green unit as a proof-commit; returns the commit sha.

        Records real green-time in an `PrismPath-Wallclock` trailer (the git author/committer dates are
        pinned to keep plumbing deterministic, so they carry no time — the trailer is where "when did
        this go green?" lives). The proof is content-addressed via `PrismPath-Output-Hash`, NOT the
        commit sha (which is now time-dependent, by design). On a concurrent ref move the write is a
        compare-and-swap that RE-READS the tip and rebuilds on it, retrying rather than dropping the
        proof."""
        self.init()
        fb: Dict[str, bytes] = {
            p: (c if isinstance(c, (bytes, bytearray)) else str(c).encode())
            for p, c in (files or {}).items()}
        if output_hash is None:
            output_hash = sha256_files(fb)
        if wallclock is None:                       # real UTC green-time; the pinned git dates don't carry it
            wallclock = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        last_err = ""
        for _attempt in range(_CAS_RETRIES):
            parent = self.tip()                     # re-read the tip each attempt (CAS rebase)
            parent_tree = self._commit_tree(parent) if parent else None
            tree = self._write_tree(fb, parent_tree) if (fb or parent_tree) else self._empty_tree()
            this_seq = self._next_seq() if seq is None else seq

            trailers = [("PrismPath-Flow", self.flow), ("PrismPath-Run", self.run_id),
                        ("PrismPath-Unit", unit), ("PrismPath-Node", node or unit),
                        ("PrismPath-Seq", str(this_seq)), ("PrismPath-Gate", gate)]
            if gate_name:
                trailers.append(("PrismPath-Gate-Name", gate_name))
            trailers.append(("PrismPath-Output-Hash", output_hash))
            trailers.append(("PrismPath-Wallclock", wallclock))
            if input_hash:
                trailers.append(("PrismPath-Input-Hash", input_hash))
            if edge:
                trailers.append(("PrismPath-Edge", edge))
            if depends:
                trailers.append(("PrismPath-Depends", ",".join(depends)))

            subject = f"prismpath: {unit} {gate}  ({self.flow} run {self.run_id[:8]})"
            body = subject + "\n\n"
            if summary:
                body += summary.strip() + "\n\n"
            body += "\n".join(f"{k}: {v}" for k, v in trailers) + "\n"

            args = ["commit-tree", tree]
            if parent:
                args += ["-p", parent]
            sha = self._git(args, env=self._env(), input=body.encode()).strip()
            if self._cas_update(sha, parent):
                return sha
            last_err = f"ref {self.ref} moved under us (had {parent})"
        raise LedgerError(f"ledger CAS failed after {_CAS_RETRIES} retries: {last_err}")

    def _empty_tree(self) -> str:
        return self._write_tree({}, None)

    def _next_seq(self) -> int:
        seqs = [r["seq"] for r in self.log() if isinstance(r.get("seq"), int)]
        return (max(seqs) + 1) if seqs else 1

    def log(self) -> List[dict]:
        """Every unit-commit on the ref, oldest -> newest, with parsed PrismPath-* trailers."""
        if self.tip() is None:
            return []
        out = self._git(["log", self.ref, "--reverse", "-z", "--format=%H%n%B"], env=self._env())
        records: List[dict] = []
        for chunk in out.split("\0"):
            chunk = chunk.strip("\n")
            if not chunk.strip():
                continue
            sha, _, bodytext = chunk.partition("\n")
            rec: dict = {"commit": sha.strip()}
            for line in bodytext.splitlines():
                m = re.match(r"^PrismPath-([A-Za-z-]+):\s*(.*)$", line)
                if m:
                    rec[m.group(1).lower().replace("-", "_")] = m.group(2).strip()
            if "seq" in rec:
                try:
                    rec["seq"] = int(rec["seq"])
                except ValueError:
                    pass
            if "depends" in rec:
                rec["depends"] = [d for d in rec["depends"].split(",") if d]
            records.append(rec)
        return records

    def done_set(self) -> Dict[str, dict]:
        """The resume projection: {unit_id -> its latest green record}. Newest-wins per unit, so a
        re-run of a unit supersedes the old proof. This is the ledger's replacement for the mutable
        `.kg.json` status field — progress derived from the log, never a separate pointer."""
        done: Dict[str, dict] = {}
        for r in self.log():                    # oldest -> newest; later overwrites
            if r.get("gate") == "green" and r.get("unit"):
                done[r["unit"]] = r
        return done
