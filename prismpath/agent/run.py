# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A governed session's receipts across processes, as one signed core run.

Each hook call of an agent is a separate short-lived process, so the receipts of a session accumulate in
a run directory, one per session id under a root the caller names (`RunStore`). A run holds:

  * `image.bin`: the policy image of the session, written once; a later call with other bytes is refused;
  * `journal.jsonl`: the open part. One canon/2 line per decided reading, `{"i", "reading" (hex), "receipt"}`,
    where `receipt` is exactly the `prismpath.core-receipt/1` that `evidence.EpisodeRun.record` writes;
  * `lock`: the lock file every operation takes exclusively (`fcntl.flock`);
  * after a seal, the files `core_evidence.verify` reads, in the layout of `prismpath.agent.evidence`:
    `run.json`, `cases.jsonl`, `images.jsonl`, `receipts.jsonl`, `receipts.roots.jsonl`, `authority.pub`,
    `instance.pub`. No second format is defined: sealing builds them from the journal with the same
    leaves, Merkle root, image attestation and root statement as `EpisodeRun.close`.

`append` takes the lock, writes the one line with a single `write` on an append-mode descriptor, `fsync`s the
file (and the directory when the journal is new), and releases. It returns the receipt's index only after
the bytes are durable, so a receipt a caller was told about survives a crash, a kill and a power cut.

`seal` writes the signed root over every receipt so far. It is a function of the journal: when the sealed
files already hold exactly the journal's receipts it does nothing (sealing twice is idempotent and keeps
the earlier root statement and its time), and when more receipts were appended since (a session resumed
after its end hook), it replaces the seal with one over all of them. A run has one root statement and
one seal at a time, as the evidence layout has; the receipts themselves are never rewritten, only the
files derived from them. The seal files are written to temporary names and renamed into place, the root
statement last; a seal interrupted between renames leaves a run that `verify` rejects and the next
`seal`/`verify` call rebuilds from the journal.

Recovery. A run left open by a crashed or killed process is recovered by the next `seal` or `verify` call
(`verify` seals first when the run is open or stale). What is kept: every receipt whose `append` returned,
in order, with its reading. What is detected and not kept: a final line without its terminating newline or
that does not parse, which only a writer killed inside `append` leaves; its caller never got an index, so
no completed receipt is lost. The next operation under the lock truncates the journal to the last complete
line and appends the dropped bytes to `journal.torn` for the record, so the torn tail never sits in front
of later receipts. A damaged line anywhere else (a complete line that does not parse, wrong index, wrong
case or a receipt that is not its reading's) is not recovered from: `RunCorrupt` is raised and nothing is
dropped silently. Tampering with a sealed run is caught by `verify` (the root, the manifest and the cases
are bound to each other and to the pinned keys).

Platforms. The lock is `fcntl.flock` on Linux and macOS, which the kernel releases when the process dies,
so a killed holder never leaves the run locked. On Windows it is `msvcrt.locking` on the first byte of the
lock file (taken with a polling loop and released when the descriptor closes), which gives the same
exclusion between processes; it has not been exercised on Windows here. A platform with neither module
refuses with `RunError` rather than run unlocked.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence

try:                                    # Linux, macOS
    import fcntl as _fcntl
    _msvcrt = None
except ImportError:                     # Windows
    _fcntl = None
    try:
        import msvcrt as _msvcrt
    except ImportError:
        _msvcrt = None

DECIDER = "python"
JOURNAL = "journal.jsonl"
TORN = "journal.torn"
IMAGE = "image.bin"
LOCK = "lock"
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RunError(Exception):
    """The run store cannot do what was asked (no lock available, other image, no such run)."""


class RunCorrupt(RunError):
    """The journal is damaged somewhere a killed writer cannot have damaged it."""


def run_dir_name(session: str) -> str:
    """The directory of a session: the id itself when it is a safe file name, else a digest of it."""
    return session if _SAFE.match(session) and session not in (".", "..") else "x-" + hashlib.sha256(session.encode()).hexdigest()[:32]


@contextmanager
def _locked(path: Path):
    if _fcntl is None and _msvcrt is None:
        raise RunError("this platform has no file lock, so a run cannot be shared safely between processes")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX)
        else:                           # pragma: no cover (Windows)
            while True:
                try:
                    os.lseek(fd, 0, 0)
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.005)
        yield
    finally:
        try:
            if _fcntl is None:          # pragma: no cover (Windows)
                os.lseek(fd, 0, 0)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)                # releases a flock too


def _fsync_dir(path: Path) -> None:
    if os.name == "nt":                 # pragma: no cover
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_durable(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


class Run:
    """One session's run directory."""

    def __init__(self, directory: Path, session: str):
        self.dir, self.session = Path(directory), session

    # ------------------------------------------------------------------ open
    @classmethod
    def open(cls, root: Path, session: str, image: bytes) -> "Run":
        """The run of `session` under `root`, created with `image` when new. The image of an existing run
        must be the same bytes: one session is decided by one policy."""
        if not session:
            raise RunError("a run needs a session id")
        run = cls(Path(root) / run_dir_name(session), session)
        run.dir.mkdir(parents=True, exist_ok=True)
        with _locked(run.dir / LOCK):
            path = run.dir / IMAGE
            if path.exists():
                if path.read_bytes() != image:
                    raise RunError(f"session {session}: the run was begun with another policy image")
            else:
                _write_durable(path, image)
                _fsync_dir(run.dir)
        return run

    @classmethod
    def existing(cls, root: Path, session: str) -> "Run":
        run = cls(Path(root) / run_dir_name(session), session)
        if not (run.dir / IMAGE).exists():
            raise RunError(f"no run for session {session}")
        return run

    # ------------------------------------------------------------ the journal
    def _entries(self) -> List[Dict[str, Any]]:
        """The complete journal lines, parsed, after dropping a torn tail. Call with the lock held."""
        path = self.dir / JOURNAL
        if not path.exists():
            return []
        data = path.read_bytes()
        end = data.rfind(b"\n") + 1
        if end != len(data):            # a final line its writer never finished
            with open(self.dir / TORN, "ab") as torn:
                torn.write(data[end:] + b"\n")
                torn.flush()
                os.fsync(torn.fileno())
            with open(path, "r+b") as handle:
                handle.truncate(end)
                handle.flush()
                os.fsync(handle.fileno())
            data = data[:end]
        image = (self.dir / IMAGE).read_bytes()
        entries = []
        for n, line in enumerate(data.split(b"\n")[:-1]):
            try:
                entry = canon2.loads(line)
                reading = bytes.fromhex(entry["reading"])
                receipt = entry["receipt"]
                ok = (canon2.dumps(entry) == line and entry["i"] == n and receipt["idx"] == n
                      and receipt["case"] == self.session and receipt["reading"] == n
                      and receipt["reading_sha256"] == core_evidence.sha256_hex(reading)
                      and receipt["image_sha256"] == core_evidence.sha256_hex(image)
                      and set(entry) == {"i", "reading", "receipt"})
            except Exception:
                ok = False
            if not ok:
                raise RunCorrupt(f"session {self.session}: journal line {n} is damaged")
            entries.append(entry)
        return entries

    def append(self, reading: bytes, verdict: Dict[str, Any], decider: str = DECIDER) -> int:
        """Record one decided reading as the next receipt, durably, and return its index."""
        with _locked(self.dir / LOCK):
            n = len(self._entries())
            image = (self.dir / IMAGE).read_bytes()
            receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": n, "case": self.session, "reading": n,
                       "image_sha256": core_evidence.sha256_hex(image),
                       "reading_sha256": core_evidence.sha256_hex(reading), "decider": decider,
                       **core_evidence._decision(verdict)}
            line = canon2.dumps({"i": n, "reading": reading.hex(), "receipt": receipt}) + b"\n"
            path = self.dir / JOURNAL
            new = not path.exists()
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            if new:
                _fsync_dir(self.dir)
            return n

    # ------------------------------------------------------------------ seal
    def is_open(self) -> bool:
        """True when the sealed files do not hold exactly the journal's receipts (never sealed, a crash
        before the seal, or receipts appended since)."""
        with _locked(self.dir / LOCK):
            return not self._sealed_matches(self._entries())

    def _receipt_bytes(self, entries) -> bytes:
        return b"".join(canon2.dumps(e["receipt"]) + b"\n" for e in entries)

    def _sealed_matches(self, entries) -> bool:
        files = [self.dir / name for name in core_evidence.FILES]
        if not all(f.exists() for f in files):
            return False
        return (self.dir / "receipts.jsonl").read_bytes() == self._receipt_bytes(entries)

    def seal(self, keys: Path, time_us: Optional[int] = None, decider: str = DECIDER) -> Dict[str, Any]:
        """Seal every receipt so far with the root statement signed by the instance key; the manifest.
        Does nothing when the run is already sealed over exactly these receipts."""
        from prismpath.hotswap import policy_pack
        from prismpath.ledgers import root_statement
        with _locked(self.dir / LOCK):
            entries = self._entries()
            if self._sealed_matches(entries):
                return canon2.loads((self.dir / "run.json").read_bytes().rstrip(b"\n"))
            image = (self.dir / IMAGE).read_bytes()
            authority_key, authority_pub, instance_key, instance_pub = core_evidence.ensure_keys(Path(keys))
            instance = root_statement.InstanceKey.load(str(instance_key))
            authority_id = core_evidence.sha256_hex(authority_pub.read_bytes())
            root_statement.check_separation(instance, [authority_id])
            receipts = self._receipt_bytes(entries)
            case = {"id": self.session, "image": image, "readings": [bytes.fromhex(e["reading"]) for e in entries]}
            out: Dict[str, bytes] = {}
            tmp_cases = self.dir / "cases.jsonl.tmp"
            core_evidence.write_cases([case], tmp_cases)
            out["cases.jsonl"] = tmp_cases.read_bytes()
            tmp_cases.unlink()
            signer = policy_pack._load_private(str(authority_key))
            out["images.jsonl"] = canon2.dumps({
                "format": core_evidence.IMAGE_FORMAT, "case": self.session,
                "image_sha256": core_evidence.sha256_hex(image), "key_id": authority_id,
                "sig": signer.sign(core_evidence.IMAGE_DOMAIN + image).hex()}) + b"\n"
            leaves = [core_evidence.sha256_hex(e) for e in receipts.split(b"\n")[:-1]]
            manifest = {"format": core_evidence.RUN_FORMAT, "decider": decider, "cases": 1, "receipts": len(leaves),
                        "excluded": [], "cases_sha256": core_evidence.sha256_hex(out["cases.jsonl"]),
                        "images_sha256": core_evidence.sha256_hex(out["images.jsonl"]),
                        "authority_key_id": authority_id, "instance_key_id": instance.key_id}
            manifest_bytes = canon2.dumps(manifest)
            out["run.json"] = manifest_bytes + b"\n"
            out["receipts.jsonl"] = receipts
            out["authority.pub"] = authority_pub.read_bytes()
            out["instance.pub"] = instance_pub.read_bytes()
            statement = core_evidence.make_root_statement(
                instance, root_statement.merkle_root(leaves), len(leaves), manifest_bytes, time_us=time_us)
            out["receipts.roots.jsonl"] = canon2.dumps(statement) + b"\n"
            for name in core_evidence.FILES:         # the root statement is last in FILES' order of writing below
                if name != "receipts.roots.jsonl":
                    _write_durable(self.dir / name, out[name])
            _write_durable(self.dir / "receipts.roots.jsonl", out["receipts.roots.jsonl"])
            _fsync_dir(self.dir)
            return manifest

    def verify(self, keys: Path, oracle=None, replay=None) -> Dict[str, Any]:
        """Seal if the run is open or stale (recovery), then verify it with `core_evidence.verify`: every
        receipt replayed, both keys pinned."""
        self.seal(keys)
        with _locked(self.dir / LOCK):
            return core_evidence.verify(self.dir, sample=None, pin_authority=Path(keys) / "authority.pub",
                                        pin_instance=Path(keys) / "instance.pub", replay=replay)


class RunStore:
    """The runs of a root directory, by session id."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def open(self, session: str, image: bytes) -> Run:
        return Run.open(self.root, session, image)

    def get(self, session: str) -> Run:
        return Run.existing(self.root, session)

    def sessions(self) -> List[str]:
        return sorted(p.name for p in self.root.iterdir() if (p / IMAGE).exists()) if self.root.exists() else []
