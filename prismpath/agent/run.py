# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A governed session's receipts across processes, as one signed core run.

Each hook call of an agent is a separate short-lived process, so the receipts of a session accumulate in
a run directory, one per session id under a root the caller names (`RunStore`). A run holds:

  * `image.bin`: the policy image of the session, written once; a later call with other bytes is refused;
  * `journal.jsonl`: the open part. One canon/2 line per decided reading, `{"i", "reading" (hex), "receipt"}`
    where `receipt` is exactly the `prismpath.core-receipt/1` that `evidence.EpisodeRun.record` writes. A line may
    carry extras beside them: `sandbox` (the profile hash and backend of an allowed shell call), `tool_use_id` (the
    id Claude Code gave the call), `grant` (the grant a gateway request presented), `routes_sha256` (the digest of
    the gateway's route table) and `hosts_sha256` (the digest of the egress proxy's allowed host list). The journal check binds the
    extras to their line (`_extras_ok` and the line's own canon/2 bytes), and the sealed root does not: it covers
    only the receipts, so an extra is evidence of the journal and not of the signed root;
  * `lock`: the lock file every operation takes exclusively (`fcntl.flock`);
  * `journal.prefix`: the validated-prefix record that keeps an append's cost independent of the run's length;
  * after a seal, the files `core_evidence.verify` reads, in the layout of `prismpath.agent.evidence`:
    `run.json`, `cases.jsonl`, `images.jsonl`, `receipts.jsonl`, `receipts.roots.jsonl`, `authority.pub`,
    `instance.pub`. No second format is defined: sealing builds them from the journal with the same
    leaves, Merkle root, image attestation and root statement as `EpisodeRun.close`.

`append` takes the lock, writes the one line with a single `write` on an append-mode descriptor, `fsync`s the
file (and the directory when the journal is new), and releases. It returns the receipt's index only after
the bytes are durable, so a receipt a caller was told about survives a crash, a kill and a power cut.

An append does not re-read the journal. `journal.prefix` records how many bytes and lines of the journal
were already validated and the digest of the last of those lines; an append under the lock checks that the
journal is at least that long and still holds that last line there, validates only the bytes after it, and
rewrites the record after its own line. So an append costs the same at the thousandth receipt as at the
first. The record is a shortcut and never evidence: it is not fsynced, and when it is absent, does not
read, or does not match the file (a shorter journal, another last line), the whole journal is validated as
before. `seal`, `is_open` and `verify` always validate every line, so a change to the trusted prefix that
an append did not look at is still refused (`RunCorrupt`) at the seal.

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

from prismpath.agent import session_state
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
PREFIX = "journal.prefix"
IMAGE = "image.bin"
OBSERVATIONS = "observations.jsonl"
OUTCOMES = "outcomes.jsonl"
OUTCOME_FORMAT = "prismpath.outcome/1"
MAX_UNBOUND_OUTCOMES = 256
MAX_TOOL_NAME = 128
HOOK_EVENTS = ("PostToolUse", "PostToolUseFailure")
OUTCOME_SOURCES = ("hook", "runner", "session-end")
NO_OUTCOME = {"allow": "no outcome", "escalate": "no outcome (declined or not run)"}
OUTCOME_CLASSES = ("ran", "failed", *NO_OUTCOME.values())
UNBOUND_REASONS = ("no-tool-use-id", "no-receipt", "receipt-was-a-refusal", "duplicate")
_BOUND_KEYS = {"format", "i", "source", "event", "tool", "outcome", "decision", "receipt", "receipt_sha256", "prev", "sha256"}
_UNBOUND_KEYS = {"format", "i", "source", "event", "tool", "outcome", "reason", "prev", "sha256"}
_OPTIONAL_OUTCOME_KEYS = {"tool_use_id", "failure"}
_TOOL_USE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
LOCK = "lock"
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")



_HEX64 = re.compile(r"[0-9a-f]{64}")
# Digests of a launcher or server argument that is not part of the signed policy: the gateway's route table
# (`routes_sha256`) and the egress proxy's allowed host list (`hosts_sha256`).
BOUND_DIGESTS = ("routes_sha256", "hosts_sha256")
_GRANT_ID = re.compile(r"[0-9a-f]{32}")


def _counts_ok(state: Any) -> bool:
    """A validated-prefix record's session counts are shaped like `session_state.ZERO`."""
    return (isinstance(state, dict) and set(state) == set(session_state.ZERO)
            and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in state.values())
            and state["changes"] in (0, 1))


def _extras_ok(entry: Dict[str, Any]) -> bool:
    """A journal line holds `i`, `reading` and `receipt`, and at most a sandbox record, a tool_use_id, a grant, and the
    digest of the gateway's route table or of the egress proxy's allowed host list the line was decided under."""
    if not {"i", "reading", "receipt"} <= set(entry) <= {"i", "reading", "receipt", "sandbox", "tool_use_id", "grant", *BOUND_DIGESTS}:
        return False
    if any(key in entry and not _HEX64.fullmatch(str(entry[key])) for key in BOUND_DIGESTS):
        return False
    sandbox, grant = entry.get("sandbox"), entry.get("grant")
    if "sandbox" in entry and not (isinstance(sandbox, dict)
                                   and set(sandbox) in ({"profile_sha256"}, {"profile_sha256", "backend"})
                                   and _HEX64.fullmatch(str(sandbox["profile_sha256"]))
                                   and sandbox.get("backend", "bwrap") in ("bwrap", "landlock")):
        return False
    if "tool_use_id" in entry and not valid_tool_use_id(entry["tool_use_id"]):
        return False
    if "grant" in entry and not (isinstance(grant, dict) and set(grant) == {"grant_id", "grant_sha256"}
                                 and _GRANT_ID.fullmatch(str(grant["grant_id"]))
                                 and _HEX64.fullmatch(str(grant["grant_sha256"]))):
        return False
    return True


class RunError(Exception):
    """The run store cannot do what was asked (no lock available, other image, no such run)."""


class RunCorrupt(RunError):
    """The journal is damaged somewhere a killed writer cannot have damaged it."""


class RunStale(RunError):
    """An append that named how many receipts the run held when its decision was made found another count: a receipt
    was appended since (a parallel tool call), so the decision may rest on state that is no longer true."""


def observe_format() -> str:
    from prismpath.agent import observe
    return observe.FORMAT


def valid_tool_use_id(value: Any) -> bool:
    """Whether `value` is shaped like a Claude Code tool_use_id (`toolu_01ABC...`): 1 to 128 of letters, digits, `_`, `-`."""
    return isinstance(value, str) and _TOOL_USE_ID.match(value) is not None


def receipt_kind(receipt: Dict[str, Any]) -> str:
    """`allow`, `escalate` or `refuse`, which is what the receipt's decision says the hook answered
    (`allow`, `ask` or `deny`)."""
    if receipt.get("decision") != "route":
        return "refuse"
    target = receipt.get("target")
    return "allow" if target == "allow" else "escalate" if isinstance(target, str) and target.startswith("escalate_") else "refuse"


def _clean_tool(tool: Any) -> str:
    """A tool name as it may be kept: printable, no spaces, at most MAX_TOOL_NAME characters; anything else is empty."""
    return tool if isinstance(tool, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,%d}" % MAX_TOOL_NAME, tool) else ""


def real_outcomes(lines: List[Dict[str, Any]]) -> Dict[int, str]:
    """Receipt index to `ran` or `failed` from the bound outcome lines a hook or the runner wrote (the hook's wins)."""
    out: Dict[int, str] = {}
    for line in sorted(lines, key=lambda l: l["source"] != "runner"):      # the runner first, then the hook over it
        if line["outcome"] in ("ran", "failed"):
            out[line["receipt"]] = line["outcome"]
    return out


def outcome_counts(entries: List[Dict[str, Any]], lines: List[Dict[str, Any]]) -> Dict[str, int]:
    done = real_outcomes(lines)
    counts = {"allowed": 0, "allowed_ran": 0, "allowed_no_outcome": 0, "asked": 0, "asked_approved": 0,
              "asked_failed": 0, "asked_no_outcome": 0, "refused": 0, "failed": 0,
              "unbound": sum(1 for l in lines if l["outcome"] == "unbound")}
    for entry in entries:
        kind = receipt_kind(entry["receipt"])
        if kind == "refuse":
            counts["refused"] += 1
            continue
        key, ran = ("allowed", "allowed_ran") if kind == "allow" else ("asked", "asked_approved")
        counts[key] += 1
        if entry["i"] in done:
            if done[entry["i"]] == "failed" and key == "asked":
                counts["asked_failed"] += 1         # a call the person approved that did not run to the end is not an approval that ran
            else:
                counts[ran] += 1
            counts["failed"] += done[entry["i"]] == "failed"
        else:
            counts[key + "_no_outcome"] += 1
    return counts


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
    def _prefix(self) -> Optional[Dict[str, Any]]:
        """The validated-prefix record, or None when it is absent or does not read."""
        try:
            record = canon2.loads((self.dir / PREFIX).read_bytes())
            if (set(record) - {"state"} == {"bytes", "count", "last", "last_len"} and all(
                    isinstance(record[k], int) and not isinstance(record[k], bool) for k in ("bytes", "count", "last_len"))
                    and isinstance(record["last"], str) and 0 < record["last_len"] <= record["bytes"]
                    and record["count"] > 0 and ("state" not in record or _counts_ok(record["state"]))):
                return record
        except Exception:   # noqa: BLE001 - a record that does not read is only a missed shortcut
            pass
        return None

    def _write_prefix(self, length: int, count: int, last: bytes, state: Optional[Dict[str, int]] = None) -> None:
        """Record that the first `length` bytes of the journal, `count` lines ending with `last`, were
        validated, and, when known, the session counts of those lines (`session_state.step`). Not fsynced: the record
        is a shortcut, and a lost or stale one only means more is validated, and a record with no counts only means
        `session_counts` reads the whole journal once."""
        record = {"bytes": length, "count": count, "last": core_evidence.sha256_hex(last), "last_len": len(last)}
        if state is not None:
            record["state"] = state
        tmp = self.dir / (PREFIX + ".tmp")
        tmp.write_bytes(canon2.dumps(record))
        os.replace(tmp, self.dir / PREFIX)

    def _scan(self, full: bool, with_state: bool = False):
        """(count, entries) of the journal after dropping a torn tail, and with `with_state` the session counts of
        every line as a third item (None when they are not known). Call with the lock held.

        With `full`, every line is validated and `entries` holds them all. Without it, the lines the
        validated-prefix record covers are trusted when the record still matches the file (the journal is
        at least that long and its last recorded line is the same bytes, on a line boundary), only the bytes
        after it are validated, and `entries` holds only those. Any mismatch validates the whole journal.

        The counts are carried the same way: from zero when the scan starts at the first line, from the record's
        `state` when it starts after the record, and unknown when the record has none (one written before the counts
        were kept) or a line's reading does not read, in which case the record is written without them."""
        path = self.dir / JOURNAL
        if not path.exists():
            return (0, [], dict(session_state.ZERO)) if with_state else (0, [])
        image_sha = core_evidence.sha256_hex((self.dir / IMAGE).read_bytes())
        start, count, last = 0, 0, b""
        state: Optional[Dict[str, int]] = dict(session_state.ZERO)
        with open(path, "rb") as handle:
            record = None if full else self._prefix()
            if record is not None and record["bytes"] <= os.fstat(handle.fileno()).st_size:
                at = record["bytes"] - record["last_len"]
                handle.seek(at - 1 if at else 0)
                chunk = handle.read(record["last_len"] + (1 if at else 0))
                line = chunk[1:] if at else chunk
                if ((not at or chunk[:1] == b"\n") and line.endswith(b"\n")
                        and core_evidence.sha256_hex(line) == record["last"]):
                    start, count, last = record["bytes"], record["count"], line
                    state = dict(record["state"]) if "state" in record else None
            handle.seek(start)
            data = handle.read()
        end = data.rfind(b"\n") + 1
        if end != len(data):            # a final line its writer never finished
            with open(self.dir / TORN, "ab") as torn:
                torn.write(data[end:] + b"\n")
                torn.flush()
                os.fsync(torn.fileno())
            with open(path, "r+b") as handle:
                handle.truncate(start + end)
                handle.flush()
                os.fsync(handle.fileno())
            data = data[:end]
        entries = []
        lines = data.split(b"\n")[:-1]
        for k, line in enumerate(lines):
            n = count + k
            try:
                entry = canon2.loads(line)
                reading = bytes.fromhex(entry["reading"])
                receipt = entry["receipt"]
                ok = (canon2.dumps(entry) == line and entry["i"] == n and receipt["idx"] == n
                      and receipt["case"] == self.session and receipt["reading"] == n
                      and receipt["reading_sha256"] == core_evidence.sha256_hex(reading)
                      and receipt["image_sha256"] == image_sha
                      and _extras_ok(entry))
            except Exception:
                ok = False
            if not ok:
                raise RunCorrupt(f"session {self.session}: journal line {n} is damaged")
            entries.append(entry)
            if state is not None:
                try:
                    state = session_state.step(state, entry)
                except Exception:   # noqa: BLE001 - counts that cannot be kept are unknown, and read as restrictive
                    state = None
        total = count + len(lines)
        if lines:
            last = lines[-1] + b"\n"
        if total and (lines or full):
            self._write_prefix(start + end, total, last, state)
        return (total, entries, state) if with_state else (total, entries)

    def _entries(self) -> List[Dict[str, Any]]:
        """Every complete journal line, parsed and validated, after dropping a torn tail. Call with the lock held."""
        return self._scan(full=True)[1]

    #: files a run holds only once it has a journal: a run that has one of them and no journal has lost it
    _JOURNAL_FILES = (PREFIX, TORN, OBSERVATIONS, OUTCOMES, "receipts.jsonl", "run.json")

    def snapshot(self) -> "tuple[int, List[Dict[str, Any]]]":
        """`(count, entries)`: how many receipts the run holds and every journal line, each validated against its
        reading and the image, read under the lock. A run with no journal and none of the files only a journal leaves
        has none; one that has such a file and no journal is `RunCorrupt`. What a decision that depends on the session's
        history reads (prismpath/agent/session_state.py)."""
        with _locked(self.dir / LOCK):
            if not (self.dir / IMAGE).exists():
                raise RunError(f"no run for session {self.session}")
            if not (self.dir / JOURNAL).exists():
                if any((self.dir / name).exists() for name in self._JOURNAL_FILES):
                    raise RunCorrupt(f"session {self.session}: the journal is missing")
                return 0, []
            return self._scan(full=True)

    def session_counts(self) -> "tuple[int, Dict[str, int]]":
        """`(count, counts)`: how many receipts the run holds and the session counts of all of them
        (`session_state.step`), read under the lock like `snapshot` and with the same missing-journal rule, but
        validating only the lines appended since the validated-prefix record, which keeps the counts of the lines it
        covers. `session_state.derive` over `snapshot()` is the same answer (prismpath/tests/test_session_state.py).
        The record is trusted as it is on append, and is in the run directory with the journal it describes, so
        whoever could change it could change the journal; `seal` and `verify` still validate every line."""
        with _locked(self.dir / LOCK):
            if not (self.dir / IMAGE).exists():
                raise RunError(f"no run for session {self.session}")
            if not (self.dir / JOURNAL).exists():
                if any((self.dir / name).exists() for name in self._JOURNAL_FILES):
                    raise RunCorrupt(f"session {self.session}: the journal is missing")
                return 0, dict(session_state.ZERO)
            count, _entries, state = self._scan(full=False, with_state=True)
            if state is None:
                count, _entries, state = self._scan(full=True, with_state=True)
            if state is None:
                raise RunCorrupt(f"session {self.session}: a journal reading does not read as a reading")
            return count, state

    def _last_entry_with_tool_use_id(self, tool_use_id: str) -> Optional[Dict[str, Any]]:
        """The latest journal line that carries `tool_use_id`, or None. Call with the lock held.

        The cost does not grow with the run: `_scan(full=False)` validates only what was appended since the
        prefix record, and the journal is then read backwards in blocks, a line at a time, parsing only a line that
        holds the id (Claude Code answers a call a moment after it was decided, so the line is near the end). Lines
        the prefix record covers are trusted here as they are on append; `seal` and `verify` still validate them all."""
        self._scan(full=False)
        path = self.dir / JOURNAL
        if not path.exists():
            return None
        needle = b'"tool_use_id":' + canon2.dumps(tool_use_id)
        with open(path, "rb") as handle:
            position = handle.seek(0, os.SEEK_END)
            tail = b""
            while position > 0:
                step = min(65536, position)
                position -= step
                handle.seek(position)
                tail = handle.read(step) + tail
                parts = tail.split(b"\n")
                tail = parts[0] if position > 0 else b""        # a partial first line waits for the next block
                for line in reversed(parts[1:] if position > 0 else parts):
                    if needle in line:
                        entry = canon2.loads(line)
                        if entry.get("tool_use_id") == tool_use_id and _extras_ok(entry):
                            return entry
        return None

    def append(self, reading: bytes, verdict: Dict[str, Any], decider: str = DECIDER,
               sandbox_profile: Optional[str] = None, sandbox_backend: Optional[str] = None,
               tool_use_id: Optional[str] = None, grant: Optional[Dict[str, str]] = None,
               routes_sha256: Optional[str] = None, hosts_sha256: Optional[str] = None,
               expect: Optional[int] = None) -> int:
        """Record one decided reading as the next receipt, durably, and return its index. `sandbox_profile` is the
        SHA-256 of the sandbox profile the allowed call was rewritten to run under; it is kept on the journal
        line beside the receipt (the receipt is exactly `prismpath.core-receipt/1`, which has no such field),
        so it is bound to the line by the journal's own check and is not part of the sealed root. `sandbox_backend`
        (`bwrap` or `landlock`) is the per call sandbox the hook had the call rewritten to run in; a line that has
        none was written before the backend was recorded and means bwrap. `tool_use_id`, the id Claude Code gave the
        call, is kept the same way (an optional key of the line, never in the receipt), so the PostToolUse outcome of
        that call can be bound to this receipt (`Run.outcome_of_hook`). A value that is not shaped like an id is left
        off. `grant` is the `{"grant_id", "grant_sha256"}` of the grant a gateway request presented, kept the same way.
        `routes_sha256` and `hosts_sha256` are the digests of the gateway's route table and of the egress proxy's allowed
        host list, kept the same way, so that `verify` reports which table or list the receipts were decided under.
        `expect`, when given, is the number of receipts the caller's decision was made against (`snapshot`): the append
        is refused with `RunStale`, writing nothing, when the run holds another number."""
        with _locked(self.dir / LOCK):
            n, _tail, counts = self._scan(full=False, with_state=True)
            if expect is not None and n != expect:
                raise RunStale(f"session {self.session}: the run holds {n} receipts, not the {expect} this decision was made against")
            image = (self.dir / IMAGE).read_bytes()
            receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": n, "case": self.session, "reading": n,
                       "image_sha256": core_evidence.sha256_hex(image),
                       "reading_sha256": core_evidence.sha256_hex(reading), "decider": decider,
                       **core_evidence._decision(verdict)}
            entry = {"i": n, "reading": reading.hex(), "receipt": receipt}
            if sandbox_profile is not None:
                entry["sandbox"] = {"profile_sha256": sandbox_profile}
                if sandbox_backend is not None:
                    entry["sandbox"]["backend"] = sandbox_backend
            if valid_tool_use_id(tool_use_id):
                entry["tool_use_id"] = tool_use_id
            if grant is not None:
                entry["grant"] = {"grant_id": grant["grant_id"], "grant_sha256": grant["grant_sha256"]}
            for key, value in (("routes_sha256", routes_sha256), ("hosts_sha256", hosts_sha256)):
                if value is not None:
                    entry[key] = value
            if not _extras_ok(entry):
                raise RunError(f"session {self.session}: a journal line's sandbox or grant record is malformed")
            line = canon2.dumps(entry) + b"\n"
            path = self.dir / JOURNAL
            new = not path.exists()
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
                length = os.fstat(fd).st_size
            finally:
                os.close(fd)
            if new:
                _fsync_dir(self.dir)
            if counts is not None:
                try:
                    counts = session_state.step(counts, entry)
                except Exception:   # noqa: BLE001 - counts that cannot be kept are unknown, and read as restrictive
                    counts = None
            self._write_prefix(length, n + 1, line, counts)
            return n

    # ------------------------------------------------------------------ observations
    def observe(self, receipt: int, image_sha256: str, profile_sha256: str, observed: Dict[str, Any]) -> int:
        """Append one observation, bound to the receipt of the allowed call it is about, and return its sequence
        number. An observation is a record of what a sandboxed command showed. It never changes a decision, a
        policy or a profile, and it is not read by anything that decides (prismpath/agent/observe.py). It is kept
        in its own file with its own hashes, not in the journal and not in the signed root, so `core-receipt/1`
        and the root statement are unchanged. Refused when the receipt does not exist, or the image or profile hash
        is not the one that receipt and its journal line record."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
            if not isinstance(receipt, int) or isinstance(receipt, bool) or not 0 <= receipt < len(entries):
                raise RunError(f"session {self.session}: there is no receipt {receipt} to bind an observation to")
            self._check_binding(entries[receipt], image_sha256, profile_sha256, observed)
            lines = self._observation_lines()
            prev = lines[-1]["sha256"] if lines else ""
            entry = {"format": observe_format(), "i": len(lines), "receipt": receipt,
                     "receipt_sha256": core_evidence.sha256_hex(canon2.dumps(entries[receipt]["receipt"])),
                     "image_sha256": image_sha256, "profile_sha256": profile_sha256, "observed": observed, "prev": prev}
            entry["sha256"] = core_evidence.sha256_hex(canon2.dumps(entry))
            data = canon2.dumps(entry) + b"\n"
            path = self.dir / OBSERVATIONS
            new = not path.exists()
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            if new:
                _fsync_dir(self.dir)
            return entry["i"]

    @staticmethod
    def _check_binding(journal_entry: Dict[str, Any], image_sha256: str, profile_sha256: str,
                       observed: Optional[Dict[str, Any]] = None) -> None:
        if journal_entry["receipt"]["image_sha256"] != image_sha256:
            raise RunError("the observation's image hash is not the receipt's")
        if journal_entry.get("sandbox", {}).get("profile_sha256") != profile_sha256:
            raise RunError("the observation's profile hash is not the one the receipt's call was sandboxed under")
        claimed = (observed or {}).get("backend")
        if claimed is not None and claimed != journal_entry["sandbox"].get("backend", "bwrap"):
            raise RunError("the observation names a per call sandbox other than the one the receipt's call was rewritten to use")

    def _observation_lines(self) -> List[Dict[str, Any]]:
        """The observation lines, each checked for its own hash, its place in the chain and its format. Call with
        the lock held. Raises RunCorrupt."""
        path = self.dir / OBSERVATIONS
        if not path.exists():
            return []
        data = path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise RunCorrupt(f"session {self.session}: the observations file ends in a line that was not finished")
        out: List[Dict[str, Any]] = []
        prev = ""
        for n, line in enumerate(data.split(b"\n")[:-1]):
            try:
                entry = canon2.loads(line)
                body = {k: v for k, v in entry.items() if k != "sha256"}
                ok = (canon2.dumps(entry) == line and entry["format"] == observe_format() and entry["i"] == n
                      and entry["prev"] == prev and entry["sha256"] == core_evidence.sha256_hex(canon2.dumps(body))
                      and set(entry) == {"format", "i", "receipt", "receipt_sha256", "image_sha256", "profile_sha256",
                                         "observed", "prev", "sha256"})
            except Exception:
                ok = False
            if not ok:
                raise RunCorrupt(f"session {self.session}: observation {n} is damaged")
            prev = entry["sha256"]
            out.append(entry)
        return out

    def observations(self) -> List[Dict[str, Any]]:
        """Every observation of the run, as written."""
        with _locked(self.dir / LOCK):
            return self._observation_lines()

    def verify_observations(self) -> int:
        """Check every observation against the journal and return how many there are: each hashes to itself, the
        chain holds, and each names a receipt that exists, whose canonical bytes hash to the recorded value, whose
        image hash it carries and whose journal line holds its profile hash. Raises RunCorrupt otherwise. An
        observation file that was cut short cannot be told from one that never had more lines (it is not under
        the signed root)."""
        with _locked(self.dir / LOCK):
            lines = self._observation_lines()
            if not lines:
                return 0
            entries = self._entries()
            for line in lines:
                n = line["receipt"]
                if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n < len(entries):
                    raise RunCorrupt(f"session {self.session}: observation {line['i']} names receipt {n}, which does not exist")
                try:
                    self._check_binding(entries[n], line["image_sha256"], line["profile_sha256"], line.get("observed"))
                except RunError as exc:
                    raise RunCorrupt(f"session {self.session}: observation {line['i']}: {exc}") from exc
                if line["receipt_sha256"] != core_evidence.sha256_hex(canon2.dumps(entries[n]["receipt"])):
                    raise RunCorrupt(f"session {self.session}: observation {line['i']} is not about the receipt it names")
            return len(lines)

    # ------------------------------------------------------------------ outcomes
    def _outcome_lines(self) -> List[Dict[str, Any]]:
        """The outcome lines, each checked for its own hash, its place in the chain, its format and its shape. Call
        with the lock held. Raises RunCorrupt. (Whether each is bound to the journal is `verify_outcomes`.)"""
        path = self.dir / OUTCOMES
        if not path.exists():
            return []
        data = path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise RunCorrupt(f"session {self.session}: the outcomes file ends in a line that was not finished")
        out: List[Dict[str, Any]] = []
        prev = ""
        for n, line in enumerate(data.split(b"\n")[:-1]):
            try:
                entry = canon2.loads(line)
                body = {k: v for k, v in entry.items() if k != "sha256"}
                keys = set(entry)
                bound = entry["outcome"] != "unbound"
                required = _BOUND_KEYS if bound else _UNBOUND_KEYS
                ok = (canon2.dumps(entry) == line and entry["format"] == OUTCOME_FORMAT and entry["i"] == n
                      and entry["prev"] == prev and entry["sha256"] == core_evidence.sha256_hex(canon2.dumps(body))
                      and required <= keys <= required | _OPTIONAL_OUTCOME_KEYS
                      and entry["source"] in OUTCOME_SOURCES and entry["outcome"] in OUTCOME_CLASSES + ("unbound",)
                      and isinstance(entry["tool"], str) and len(entry["tool"]) <= MAX_TOOL_NAME
                      and ("tool_use_id" not in entry or valid_tool_use_id(entry["tool_use_id"]))
                      and (bound or entry["reason"] in UNBOUND_REASONS))
            except Exception:
                ok = False
            if not ok:
                raise RunCorrupt(f"session {self.session}: outcome {n} is damaged")
            prev = entry["sha256"]
            out.append(entry)
        return out

    def _add_outcome(self, lines: List[Dict[str, Any]], fields: Dict[str, Any]) -> Dict[str, Any]:
        """Append one outcome line after `lines` (the lines already there). Call with the lock held."""
        entry = {"format": OUTCOME_FORMAT, "i": len(lines), **fields, "prev": lines[-1]["sha256"] if lines else ""}
        entry["sha256"] = core_evidence.sha256_hex(canon2.dumps(entry))
        data = canon2.dumps(entry) + b"\n"
        path = self.dir / OUTCOMES
        new = not path.exists()
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        if new:
            _fsync_dir(self.dir)
        lines.append(entry)
        return entry

    @staticmethod
    def _bound_fields(journal_entry: Dict[str, Any], source: str, event: str, tool: str, outcome: str,
                      failure: Optional[str] = None) -> Dict[str, Any]:
        receipt = journal_entry["receipt"]
        fields: Dict[str, Any] = {"source": source, "event": event, "tool": _clean_tool(tool), "outcome": outcome,
                                  "decision": receipt_kind(receipt), "receipt": journal_entry["i"],
                                  "receipt_sha256": core_evidence.sha256_hex(canon2.dumps(receipt))}
        if "tool_use_id" in journal_entry:
            fields["tool_use_id"] = journal_entry["tool_use_id"]
        if failure:
            fields["failure"] = failure
        return fields

    def outcome_of_hook(self, tool_use_id: Any, event: str, tool: Any, failure: Optional[str] = None) -> Dict[str, Any]:
        """Record what a PostToolUse (`ran`) or PostToolUseFailure (`failed`, with `failure`, a class and never the
        error text) event says about the call whose receipt carries `tool_use_id`. Returns the line written, or
        None when an unbound one would pass the cap.

        An outcome is a record that an allowed call, or a call the person was asked about, did or did not run. It
        is never a decision and nothing that decides reads it. It is kept in its own hash-chained file, not in the
        journal and not under the signed root, so `core-receipt/1` and the root statement are unchanged. It fails
        open: an event that cannot be bound (no id, no receipt with that id, a receipt that was a refusal, a
        second outcome for one receipt) is recorded as `unbound` with the reason and changes nothing. What the
        tool returned is not kept, only the class of the outcome, the tool's name and the receipt's index."""
        if event not in HOOK_EVENTS:
            raise RunError(f"{event!r} is not an outcome event")
        with _locked(self.dir / LOCK):
            lines = self._outcome_lines()
            unbound: Optional[str] = None
            target = None
            if not valid_tool_use_id(tool_use_id):
                unbound = "no-tool-use-id"
            else:
                target = self._last_entry_with_tool_use_id(tool_use_id)
                if target is None:
                    unbound = "no-receipt"
                else:
                    if receipt_kind(target["receipt"]) == "refuse":
                        unbound = "receipt-was-a-refusal"
                    elif any(l.get("receipt") == target["i"] and l["source"] == "hook" for l in lines):
                        unbound = "duplicate"
            if unbound is not None:
                if sum(1 for l in lines if l["outcome"] == "unbound") >= MAX_UNBOUND_OUTCOMES:
                    return None
                fields: Dict[str, Any] = {"source": "hook", "event": event, "tool": _clean_tool(tool),
                                          "outcome": "unbound", "reason": unbound}
                if valid_tool_use_id(tool_use_id):
                    fields["tool_use_id"] = tool_use_id
                return self._add_outcome(lines, fields)
            return self._add_outcome(lines, self._bound_fields(
                target, "hook", event, tool, "ran" if event == "PostToolUse" else "failed", failure))

    def outcome_of_runner(self, receipt: int, image_sha256: str, profile_sha256: str, returncode: int,
                          timed_out: bool = False) -> Optional[Dict[str, Any]]:
        """Record that the per call sandbox's runner finished the allowed (or approved) shell command of `receipt`:
        `ran` for exit status 0, `failed` otherwise or at the time limit. Bound the way an observation is (the
        receipt exists, the image and profile hashes are its), and refused the same way. A second report for one
        receipt is dropped. Like every outcome it is a claim of the process that sent it, read by nothing that decides."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
            if not isinstance(receipt, int) or isinstance(receipt, bool) or not 0 <= receipt < len(entries):
                raise RunError(f"session {self.session}: there is no receipt {receipt} to bind an outcome to")
            self._check_binding(entries[receipt], image_sha256, profile_sha256)
            if receipt_kind(entries[receipt]["receipt"]) == "refuse":
                raise RunError(f"session {self.session}: receipt {receipt} is a refusal, which does not run")
            lines = self._outcome_lines()
            if any(l.get("receipt") == receipt and l["source"] == "runner" for l in lines):
                return None
            failed = bool(timed_out) or returncode != 0
            failure = "timed-out" if timed_out else "exit-nonzero" if failed else None
            return self._add_outcome(lines, self._bound_fields(
                entries[receipt], "runner", "runner", "Bash", "failed" if failed else "ran", failure))

    def infer_outcomes(self) -> int:
        """At the end of a session, record every allowed receipt that has no outcome as `no outcome` and every
        escalated one as `no outcome (declined or not run)`: a question the person declined and one that was
        approved and never ran look the same from here. Returns how many were recorded. A receipt that already has
        an outcome line of any kind is left alone, so a second end hook adds only the receipts since."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
            lines = self._outcome_lines()
            have = {l["receipt"] for l in lines if l["outcome"] != "unbound"}
            added = 0
            for entry in entries:
                kind = receipt_kind(entry["receipt"])
                if kind != "refuse" and entry["i"] not in have:
                    self._add_outcome(lines, self._bound_fields(
                        entry, "session-end", "SessionEnd", "", NO_OUTCOME[kind]))
                    added += 1
            return added

    def outcomes(self) -> List[Dict[str, Any]]:
        """Every outcome line of the run, as written."""
        with _locked(self.dir / LOCK):
            return self._outcome_lines()

    def outcome_map(self) -> Dict[int, str]:
        """Receipt index to `ran` or `failed`, for each receipt with an outcome a hook or the runner reported. The
        `no outcome` lines the end of a session writes are not outcomes and are not in it."""
        with _locked(self.dir / LOCK):
            return real_outcomes(self._outcome_lines())

    def outcome_counts(self) -> Dict[str, int]:
        """Totals over the receipts of this run: allowed, how many of them ran (an outcome was reported) and how many
        have no outcome, asked, how many were approved (ran) and how many have no outcome, refused, how many outcomes
        failed, and how many events could not be bound. A call still waiting for its outcome counts as having none."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
            lines = self._outcome_lines()
        return outcome_counts(entries, lines)

    def verify_outcomes(self) -> int:
        """Check every outcome line against the journal and return how many there are: each hashes to itself, the
        chain holds, and each bound one names a receipt that exists, hashes to the recorded value, was an allow or
        an ask (the recorded decision), carries the journal line's tool_use_id (or none where the line has none),
        and is the only one of its source for that receipt; an outcome class fits its source. Raises RunCorrupt
        otherwise. The file is not under the signed root, so a cut tail cannot be told from a file that never had
        more lines."""
        with _locked(self.dir / LOCK):
            lines = self._outcome_lines()
            if not lines:
                return 0
            entries = self._entries()
            seen = set()
            unbound = 0
            for line in lines:
                where = f"session {self.session}: outcome {line['i']}"
                if line["outcome"] == "unbound":
                    unbound += 1
                    if unbound > MAX_UNBOUND_OUTCOMES:
                        raise RunCorrupt(f"{where} is past the cap on unbound events")
                    continue
                n = line["receipt"]
                if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n < len(entries):
                    raise RunCorrupt(f"{where} names receipt {n}, which does not exist")
                journal, receipt = entries[n], entries[n]["receipt"]
                if line["receipt_sha256"] != core_evidence.sha256_hex(canon2.dumps(receipt)):
                    raise RunCorrupt(f"{where} is not about the receipt it names")
                kind = receipt_kind(receipt)
                if kind == "refuse" or line["decision"] != kind:
                    raise RunCorrupt(f"{where} does not match the decision of the receipt it names")
                if line.get("tool_use_id") != journal.get("tool_use_id"):
                    raise RunCorrupt(f"{where} carries a tool_use_id that is not the receipt's")
                if (line["source"] == "session-end") != (line["outcome"] in NO_OUTCOME.values()):
                    raise RunCorrupt(f"{where} has an outcome that does not fit its source")
                if line["source"] == "session-end" and line["outcome"] != NO_OUTCOME[kind]:
                    raise RunCorrupt(f"{where} has a no outcome line that does not fit the decision")
                if (line["source"], n) in seen:
                    raise RunCorrupt(f"{where} is a second {line['source']} outcome for receipt {n}")
                seen.add((line["source"], n))
            return len(lines)

    # ------------------------------------------------------------------ seal
    def bound_digests(self) -> Dict[str, List[str]]:
        """The distinct route table and allowed host list digests the journal's lines carry, each sorted. One value
        is a run decided under one table or list, none is a run that recorded none (an agent run has no route table),
        and more than one is a run that was resumed under another."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
        return {key: sorted({e[key] for e in entries if key in e}) for key in BOUND_DIGESTS}

    def summary(self) -> Dict[str, Any]:
        """The receipt count, whether the run is open, and how its seal stands against the journal, every
        journal line validated: `unsealed` (no seal file yet), `partial` (some seal files and not all, a first
        seal interrupted), `sealed` (the sealed receipts are the journal's), `behind` (they are a prefix of the
        journal's: receipts were appended after the seal) or `diverged` (they are not: a sealed file was changed,
        or a reseal was interrupted)."""
        with _locked(self.dir / LOCK):
            entries = self._entries()
            present = [(self.dir / name).exists() for name in core_evidence.FILES]
            if not any(present):
                seal = "unsealed"
            elif not all(present):
                seal = "partial"
            else:
                sealed, journal = (self.dir / "receipts.jsonl").read_bytes(), self._receipt_bytes(entries)
                seal = "sealed" if sealed == journal else "behind" if journal.startswith(sealed) else "diverged"
            return {"receipts": len(entries), "open": seal != "sealed", "seal": seal}

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

    def verify(self, keys: Path, oracle=None, replay=None, seal: bool = True) -> Dict[str, Any]:
        """Seal if the run is open or stale (recovery), then verify it with `core_evidence.verify`: every
        receipt replayed, both keys pinned. With `seal=False` the run is verified as it stands."""
        if seal:
            self.seal(keys)
        with _locked(self.dir / LOCK):
            result = core_evidence.verify(self.dir, sample=None, pin_authority=Path(keys) / "authority.pub",
                                          pin_instance=Path(keys) / "instance.pub", replay=replay)
        result["observations"] = self.verify_observations()      # raises RunCorrupt on a damaged or unbound one
        result["outcomes"] = self.verify_outcomes()               # the same for the outcomes file
        result["bound"] = self.bound_digests()                    # the route table and host list digests, outside the root
        return result


class RunStore:
    """The runs of a root directory, by session id."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def open(self, session: str, image: bytes) -> Run:
        return Run.open(self.root, session, image)

    def get(self, session: str) -> Run:
        return Run.existing(self.root, session)

    def runs(self) -> List[Run]:
        """Every run under the root, each with its session id: the directory's name, or for a session id that
        is not a safe file name the `case` its receipts name (a digest-named run without receipts keeps the
        directory name, and has nothing to verify)."""
        out = []
        for name in self.sessions():
            session = name
            if name.startswith("x-"):
                try:
                    with open(self.root / name / JOURNAL, "rb") as handle:
                        session = canon2.loads(handle.readline().rstrip(b"\n"))["receipt"]["case"]
                except Exception:   # noqa: BLE001 - no journal yet, or one the full validation will refuse
                    session = name
                if run_dir_name(session) != name:
                    session = name
            out.append(Run(self.root / name, session))
        return out

    def sessions(self) -> List[str]:
        return sorted(p.name for p in self.root.iterdir() if (p / IMAGE).exists()) if self.root.exists() else []
