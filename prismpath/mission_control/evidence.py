# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The evidence readers: everything the auditing interface shows, read from files under the evidence roots.

Each reader is a function over paths, with no transport in it, so the auditing routes (U1 to U6), the
operating cause monitor (O6) and the authoring change status (A5) call the same code and the same verifier
the command line calls. Every verdict is the console's (`verdict_of: "console"`), computed by the
repository's own verifiers, never by code of this module: `prismpath.trail.run` for a trail,
`root_statement.verify_receipt_bundle` for one receipt, `core_evidence.verify` for an evidence run (the
governed harness, intent and population runs use its layout and are read the same way), and
`flow_authority.verify_flow` for a flow manifest. Each report carries the command that is the check of
record, and the raw bytes a page needs to check the verdict itself.

Evidence is untrusted input, so every reader holds to the same rules.

* Confinement. A path is resolved against the roots the launch named (`MC_EVIDENCE`, or the `roots` a
  caller passes, such as the followed project for A5) and refused unless it is inside one once every
  symlink is resolved, so a traversal or a link out of a root is `outside-roots`. No root means nothing is
  readable.
* Bounded reads. A file is opened without following a final symlink, must be a regular file, and is read
  whole only up to `SETTINGS.max_evidence_bytes` (`MC_MAX_EVIDENCE_BYTES`); a larger one is `too-large`. An
  audit log and its statements are read once into memory and parsed from those bytes, so a report is about
  one snapshot and nothing reopens the file. An evidence run is read by `core_evidence.verify` itself, so its
  files are measured before and stat'ed again after, and a run that changed while it was read is refused.
* Canonical bytes. The verifiers read canon/2 strictly: a line in any spelling but its canonical one is
  refused and reported as a finding (`bad_format`, `document:not-canonical`), never respelled or skipped
  quietly. Bytes that are not UTF-8 are a finding too, not a crash.
* No writes. No reader opens a file for writing, creates a directory or appends to a log.

A refusal is `EvidenceRefused`, a ValueError with a `reason`: `outside-roots`, `not-found`, `not-a-file`,
`too-large`, `changed-while-read`, `bad-pin` or `bad-request`. A transport maps the first to a 403, the
second to a 404, `too-large` to a 413 and the rest to a 400. Evidence that reads and does not verify is not
a refusal: it is a report whose status is `invalid` with the findings named.
"""
from __future__ import annotations

import errno
import os
import shlex
import stat as _stat
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from prismpath import trail
from prismpath.extras import MissingExtra
from prismpath.ledgers import audit_log, core_evidence, root_statement

from . import causes_view
from .config import SETTINGS
from .files import is_contained

VERDICT_OF = "console"
MAX_RAW_LINES = 1000            # lines one raw read returns at most
MAX_BUCKETS = 10_000            # buckets one cause series spans at most
KEY_BYTES = 32                  # a raw Ed25519 public key
# Files that are audit logs by name; any other file with a statements file beside it is one too.
LOG_NAMES = ("swaps.log", "mission_audit.log", "audit.jsonl")
LOG_SUFFIXES = (".audit.jsonl",)
SKIPPED_DIRS = (".git", "__pycache__")
# The console's own audit log writes an action as an intent and, after the effect, `<action>.result`
# naming the intent (`audit.RESULT_SUFFIX`); a refusal is one event, complete in itself.
RESULT_SUFFIX = ".result"
REFUSAL_SUFFIX = ".refused"
CONSOLE_ACTOR = "console/"
MAX_LISTED = 100                # unrecorded intents and orphan results a report names at most
ANCHOR_LABEL = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"


class EvidenceRefused(ValueError):
    """The reader would not read what it was asked to: `reason` says why, the message says what."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


# ----------------------------------------------------------------- confinement and bounded reads
def _roots(roots: Optional[Iterable[str]]) -> List[str]:
    """The roots as real paths, in the order given: the launch's evidence roots unless a caller names its own."""
    named = SETTINGS.evidence_roots if roots is None else roots
    out: List[str] = []
    for root in named:
        if isinstance(root, str) and root:
            real = os.path.realpath(os.path.abspath(os.path.expanduser(root)))
            if real not in out:
                out.append(real)
    return out


def _confine(path: Any, roots: Optional[Iterable[str]]) -> Tuple[str, str]:
    """(real path, the root holding it) for `path`, or EvidenceRefused. A relative path is taken against each
    root in turn, the first under which it exists; an absolute one must already be inside a root."""
    if not isinstance(path, (str, os.PathLike)) or not str(path) or "\x00" in str(path):
        raise EvidenceRefused("bad-request", "name a path under an evidence root")
    path = os.fspath(path)
    real_roots = _roots(roots)
    if not real_roots:
        raise EvidenceRefused("outside-roots", "refused: no evidence root was named (MC_EVIDENCE)")
    if os.path.isabs(path):
        candidates = [os.path.abspath(path)]
    else:
        joined = [os.path.abspath(os.path.join(root, path)) for root in real_roots]
        candidates = [candidate for candidate in joined if os.path.lexists(candidate)] or joined[:1]
    for candidate in candidates:
        for root in real_roots:
            if is_contained(candidate, root):
                return os.path.realpath(candidate), root
    raise EvidenceRefused("outside-roots", "refused: the path is not under an evidence root")


def _read_bounded(real: str, limit: int, what: str = "the file") -> bytes:
    """The bytes of the regular file at `real`, at most `limit` of them, or EvidenceRefused. The final
    component is opened without following a symlink, so a link swapped in after confinement is refused."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(real, flags)
    except FileNotFoundError:
        raise EvidenceRefused("not-found", f"{what} does not exist") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise EvidenceRefused("outside-roots", f"{what} became a symlink after it was confined") from None
        if error.errno in (errno.EISDIR, errno.ENXIO):
            raise EvidenceRefused("not-a-file", f"{what} is not a regular file") from None
        raise EvidenceRefused("not-found", f"{what} cannot be opened: {error.strerror}") from None
    try:
        info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            raise EvidenceRefused("not-a-file", f"{what} is not a regular file")
        if info.st_size > limit:
            raise EvidenceRefused("too-large", f"{what} is {info.st_size} bytes, over the {limit} byte bound "
                                               f"(MC_MAX_EVIDENCE_BYTES)")
        chunks, held = [], 0
        while True:
            chunk = os.read(fd, min(1 << 20, limit + 1 - held))
            if not chunk:
                break
            chunks.append(chunk)
            held += len(chunk)
            if held > limit:                      # it grew after the size was read
                raise EvidenceRefused("too-large", f"{what} is over the {limit} byte bound (MC_MAX_EVIDENCE_BYTES)")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _regular_size(real: str, what: str) -> os.stat_result:
    """The stat of a regular file that is not a symlink, or EvidenceRefused."""
    try:
        info = os.lstat(real)
    except FileNotFoundError:
        raise EvidenceRefused("not-found", f"{what} does not exist") from None
    if not _stat.S_ISREG(info.st_mode):
        raise EvidenceRefused("not-a-file", f"{what} is not a regular file")
    return info


def _pins(pinned: Optional[Iterable[Any]]) -> Optional[List[bytes]]:
    """Pinned public keys as raw 32 byte strings (bytes, or hex as a page holds them), or EvidenceRefused."""
    if pinned is None:
        return None
    if isinstance(pinned, (bytes, str)):
        pinned = [pinned]
    out = []
    for key in pinned:
        if isinstance(key, str):
            try:
                key = bytes.fromhex(key)
            except ValueError:
                raise EvidenceRefused("bad-pin", "a pinned key is the hex of a raw 32 byte Ed25519 public key") from None
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
            raise EvidenceRefused("bad-pin", "a pinned key is a raw 32 byte Ed25519 public key")
        out.append(bytes(key))
    return out or None


def _pin_file(path: Any, roots: Optional[Iterable[str]], what: str) -> str:
    """The real path of a public key file under the roots, holding a raw 32 byte key, or EvidenceRefused."""
    real, _root = _confine(path, roots)
    if len(_read_bounded(real, KEY_BYTES + 1, what)) != KEY_BYTES:
        raise EvidenceRefused("bad-pin", f"{what} is not a raw 32 byte Ed25519 public key")
    return real


def read_pins(paths: Optional[Iterable[Any]], roots: Optional[Iterable[str]] = None) -> Optional[List[bytes]]:
    """The raw keys held by public key files under the roots, for a transport that takes key FILES only and
    never key material from a request: each must be a raw 32 byte Ed25519 public key. None for no file. A
    name that is itself the hex of a key is refused as `bad-pin`, so a page cannot post the key it pinned."""
    if not paths:
        return None
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    out = []
    for path in paths:
        if isinstance(path, str) and len(path) == 2 * KEY_BYTES and all(c in "0123456789abcdefABCDEF" for c in path):
            raise EvidenceRefused("bad-pin", "name a public key file under an evidence root, not the key itself")
        real = _pin_file(path, roots, "a pinned key")
        out.append(_read_bounded(real, KEY_BYTES + 1, "a pinned key"))
    return out


def _positive(value: Any, name: str, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        raise EvidenceRefused("bad-request", f"{name} is a {'nonnegative' if allow_zero else 'positive'} integer")
    return value


def _since(since: Optional[str]) -> None:
    if since is None:
        return
    try:
        trail._parse_since(since)
    except (TypeError, ValueError, AttributeError):
        raise EvidenceRefused("bad-request", "since is an ISO 8601 time") from None


class _Snapshot:
    """An audit log and its statements, read once under the bounds and parsed from those bytes."""

    def __init__(self, path: Any, roots: Optional[Iterable[str]]):
        limit = SETTINGS.max_evidence_bytes
        self.path, self.root = _confine(path, roots)
        self.data = _read_bounded(self.path, limit, "the audit log")
        statements = root_statement.statements_path_for(self.path)
        self.statements_path: Optional[str] = None
        self.statements_data = b""
        if os.path.lexists(statements):
            self.statements_path, _root = _confine(statements, roots)
            self.statements_data = _read_bounded(self.statements_path, limit, "the statements file")
        self.log = audit_log.AuditLog(self.path, statements_path=statements, source=self.data,
                                      statements_source=self.statements_data)

    def event_lines(self) -> List[bytes]:
        """The raw bytes of each event's line, in event order: the lines the log read, as it split them."""
        skipped = set(self.log.skipped)
        out = []
        text = self.data.decode("utf-8", errors="surrogateescape")
        for line_num, line in enumerate(text.split("\n"), 1):
            if line.strip() and line_num not in skipped:
                out.append(line.encode("utf-8", errors="surrogateescape"))
        return out

    def skipped(self) -> List[Dict[str, Any]]:
        return [{"line": line, "why": self.log.skipped_causes.get(line, "")} for line in self.log.skipped]


def _cause_of(event: Any) -> Any:
    data = event.get("data") if isinstance(event, dict) else None
    return data.get("cause") if isinstance(data, dict) else None


def _cause_key(rendered: Dict[str, Any]) -> str:
    return str(rendered["code"]) if rendered["code"] is not None else rendered["label"]


def action_pairs(log: "audit_log.AuditLog") -> Optional[Dict[str, Any]]:
    """The console's own actions in a log, each intent paired with its `<action>.result`: per action how many
    intents there are, how many were done, how many failed, and how many have no result, which is an effect
    whose outcome the console did not record. A result that names no intent of its action, or names it by a
    leaf that is not the intent's, is an orphan. Refusals (`*.refused`) are counted apart. None for a log no
    console actor wrote, such as a run's or a deployment's."""
    events = [(pos, event) for pos, event in enumerate(log.events)
              if isinstance(event, dict) and isinstance(event.get("actor"), str)
              and event["actor"].startswith(CONSOLE_ACTOR) and isinstance(event.get("action"), str)]
    if not events:
        return None
    by_idx = {event.get("idx"): (pos, event) for pos, event in events}
    results: Dict[int, Dict[str, Any]] = {}
    orphans: List[Dict[str, Any]] = []
    for pos, event in events:
        action = event["action"]
        if not action.endswith(RESULT_SUFFIX):
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        named = by_idx.get(data.get("intent")) if isinstance(data.get("intent"), int) else None
        if named is None or named[1]["action"] != action[:-len(RESULT_SUFFIX)]:
            why = "names no intent of its action"
        elif data.get("intent_leaf") != log.leaves[named[0]]:
            why = "names its intent by another leaf"
        elif named[0] in results:
            why = "a second result for one intent"
        else:
            results[named[0]] = data
            continue
        orphans.append({"index": pos, "action": action, "why": why})
    by_action: Dict[str, Dict[str, int]] = {}
    refusals: Dict[str, int] = {}
    unrecorded: List[Dict[str, Any]] = []
    for pos, event in events:
        action = event["action"]
        if action.endswith(RESULT_SUFFIX):
            continue
        if action.endswith(REFUSAL_SUFFIX):
            refusals[action] = refusals.get(action, 0) + 1
            continue
        counts = by_action.setdefault(action, {"intents": 0, "done": 0, "failed": 0, "unrecorded": 0})
        counts["intents"] += 1
        result = results.get(pos)
        if result is None:
            counts["unrecorded"] += 1
            unrecorded.append({"index": pos, "action": action})
        elif result.get("ok") is True:
            counts["done"] += 1
        else:
            counts["failed"] += 1
    return {"by_action": by_action, "refusals": refusals, "unrecorded": unrecorded[:MAX_LISTED],
            "unrecorded_total": len(unrecorded), "orphans": orphans[:MAX_LISTED], "orphans_total": len(orphans)}


def _quote(path: str) -> str:
    return shlex.quote(path)


# ----------------------------------------------------------------- discovery
def _is_run(dirpath: str, filenames: Iterable[str]) -> bool:
    names = set(filenames)
    return "run.json" in names and "receipts.jsonl" in names


def _is_log(full: str, name: str) -> bool:
    if name.endswith(".roots.jsonl"):
        return False
    if name in LOG_NAMES or name.endswith(LOG_SUFFIXES):
        return True
    return os.path.lexists(root_statement.statements_path_for(full))


def discover_logs(roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Every audit log and evidence run under the roots: {roots, logs, runs, truncated}. A log is named by
    its file name (`*.audit.jsonl`, `swaps.log`, `mission_audit.log`) or by a statements file beside it; a
    run is a directory holding `run.json` and `receipts.jsonl`, whose files are not listed as logs.
    Symlinked directories are not walked and a file whose real path leaves its root is not listed. The
    listing stops at `SETTINGS.max_tree_entries` entries, and `truncated` says so."""
    real_roots = _roots(roots)
    logs: List[Dict[str, Any]] = []
    runs: List[Dict[str, Any]] = []
    cap = SETTINGS.max_tree_entries
    visited, truncated = 0, False
    for root in real_roots:
        if truncated or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames if name not in SKIPPED_DIRS)
            visited += len(filenames) + 1
            if visited > cap * 20 or len(logs) + len(runs) >= cap:
                truncated = True
                break
            if _is_run(dirpath, filenames):
                if is_contained(dirpath, root):
                    runs.append({"path": os.path.realpath(dirpath), "evidence_root": root,
                                 "rel": os.path.relpath(dirpath, root),
                                 "files": sorted(name for name in core_evidence.FILES if name in filenames),
                                 "complete": all(name in filenames for name in core_evidence.FILES)})
                continue
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if name.startswith(".") or not _is_log(full, name) or not is_contained(full, root):
                    continue
                if len(logs) + len(runs) >= cap:
                    truncated = True
                    break
                try:
                    info = _regular_size(os.path.realpath(full), "the log")
                except EvidenceRefused:
                    continue
                statements = root_statement.statements_path_for(full)
                has_statements = os.path.lexists(statements) and is_contained(statements, root)
                logs.append({"path": os.path.realpath(full), "evidence_root": root, "rel": os.path.relpath(full, root),
                             "size": info.st_size, "mtime": info.st_mtime,
                             "statements": os.path.realpath(statements) if has_statements else None,
                             "statements_size": os.path.getsize(statements) if has_statements else None})
            if truncated:
                break
    logs.sort(key=lambda entry: entry["path"])
    runs.sort(key=lambda entry: entry["path"])
    return {"roots": real_roots, "logs": logs, "runs": runs, "truncated": truncated}


# ----------------------------------------------------------------- the trail
def trail_report(path: Any, since: Optional[str] = None, last: Optional[int] = None,
                 pinned: Optional[Iterable[Any]] = None, roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """`prismpath trail` over one audit log: by action, outcome and cause over the window, whether the Merkle
    root verifies, and the root statement chain's status (`signed`, `signed-unpinned`, `unsigned` or
    `invalid`) with every finding. `pinned` is the reader's own public keys; none are read from the log.
    Adds the file's sha256 and size, the lines that did not read and why, and every cause decoded."""
    pins = _pins(pinned)
    _since(since)
    if last is not None:
        _positive(last, "last")
    snapshot = _Snapshot(path, roots)
    report = trail.run(snapshot.path, since=since, last=last, pinned=pins, statements_path=snapshot.log.statements_path,
                       log=snapshot.log)
    seen = {}
    for event in snapshot.log.events:
        if isinstance(event, dict) and event.get("action") == "decision":
            rendered = causes_view.render(_cause_of(event))
            seen.setdefault(_cause_key(rendered), rendered)
    pub = " --pub instance.pub" if pins else ""
    report.update({
        "verdict_of": VERDICT_OF, "evidence_root": snapshot.root, "size": len(snapshot.data),
        "sha256": core_evidence.sha256_hex(snapshot.data),
        "statements_sha256": core_evidence.sha256_hex(snapshot.statements_data) if snapshot.statements_path else None,
        "skipped": snapshot.skipped(),
        "causes_decoded": sorted(seen.values(), key=lambda entry: (entry["code"] is None, entry["code"] or 0)),
        "console_actions": action_pairs(snapshot.log),
        "command": f"prismpath trail {_quote(snapshot.path)}{pub}",
    })
    return report


# ----------------------------------------------------------------- one receipt
def receipt_view(path: Any, index: Any, pinned: Optional[Iterable[Any]] = None,
                 roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """One receipt of an audit log: the event, its raw line, its cause decoded, its leaf, its inclusion path
    and the root it reaches, the first root statement that covers it and the receipt bundle, with the
    console's verdict on the bundle and the commands that export and check it. A receipt no statement covers
    yet has no bundle (`uncovered` says why), and its path is in the tree over the whole log."""
    pins = _pins(pinned)
    snapshot = _Snapshot(path, roots)
    log = snapshot.log
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(log.events):
        raise EvidenceRefused("bad-request", f"the receipt index is an integer from 0 to {len(log.events) - 1}")
    event = log.events[index]
    try:
        bundle = log.receipt_bundle(index)
    except LookupError as uncovered:
        bundle, why = None, str(uncovered)
    else:
        why = None
    if bundle is not None:
        inclusion, root, tree_leaves = bundle["path"], bundle["statement"].get("root", ""), bundle["statement"]["leaves"]
        verdict = {**root_statement.verify_receipt_bundle(bundle, pins), "verdict_of": VERDICT_OF}
    else:
        inclusion, root, tree_leaves = log.prove(index)["path"], log.current_root(), len(log.leaves)
        verdict = None
    quoted = _quote(snapshot.path)
    pub = " --pub instance.pub" if pins else " --pub <instance.pub>"
    return {"log": snapshot.path, "evidence_root": snapshot.root, "index": index, "event": event,
            "raw": snapshot.event_lines()[index], "cause": causes_view.render(_cause_of(event)),
            "leaf": log.leaves[index], "path_steps": len(inclusion), "path": inclusion, "root": root,
            "tree_leaves": tree_leaves, "statement": bundle["statement"] if bundle else None,
            "bundle": bundle, "uncovered": why, "verdict": verdict,
            "export": f"prismpath trail {quoted} --receipt {index} --bundle-out bundle.json",
            "command": f"prismpath trail --verify-bundle bundle.json{pub}"}


# ----------------------------------------------------------------- raw bytes
def raw_lines(path: Any, start: Any = 0, count: Any = 100, roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Lines `start` to `start + count` of any file under the roots, as the bytes written (no line feed),
    at most MAX_RAW_LINES of them, with the file's line count, size and sha256: what a page recomputes a
    leaf, a root or a signature from without trusting the console."""
    start = _positive(start, "start", allow_zero=True)
    count = min(_positive(count, "count"), MAX_RAW_LINES)
    real, root = _confine(path, roots)
    data = _read_bounded(real, SETTINGS.max_evidence_bytes)
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    chosen = lines[start:start + count]
    return {"path": real, "evidence_root": root, "start": start, "count": len(chosen), "total": len(lines),
            "size": len(data), "sha256": core_evidence.sha256_hex(data), "lines": chosen}


# ----------------------------------------------------------------- the cause series
def cause_series(path: Any, bucket_s: Any, since: Optional[str] = None, last: Optional[int] = None,
                 roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Counts by cause (decisions) and by action (every event) per `bucket_s` second bucket of event time,
    for the buckets that hold any event, oldest first; every cause seen decoded under `causes`, keyed as the
    buckets key it (its code, or its label when it has none). An event with no time counts under
    `untimed`. A window spanning more than MAX_BUCKETS buckets is refused: ask for wider buckets."""
    bucket_s = _positive(bucket_s, "bucket_s")
    _since(since)
    if last is not None:
        _positive(last, "last")
    snapshot = _Snapshot(path, roots)
    events = [event for event in snapshot.log.events if isinstance(event, dict)]
    if since is not None:
        floor = trail._parse_since(since)
        events = [event for event in events if audit_log.event_seconds(event) >= floor]
    if last:
        events = events[-last:]
    timed = [event for event in events if isinstance(event.get("ts_us"), int) and not isinstance(event.get("ts_us"), bool)]
    starts = [event["ts_us"] // 1_000_000 // bucket_s * bucket_s for event in timed]
    if starts and (max(starts) - min(starts)) // bucket_s + 1 > MAX_BUCKETS:
        raise EvidenceRefused("bad-request", f"the window spans more than {MAX_BUCKETS} buckets of {bucket_s} s")
    buckets: Dict[int, Dict[str, Any]] = {}
    decoded: Dict[str, Dict[str, Any]] = {}
    for event, start in zip(timed, starts):
        bucket = buckets.setdefault(start, {"start": start, "by_cause": {}, "by_action": {}})
        action = event.get("action") if isinstance(event.get("action"), str) else "?"
        bucket["by_action"][action] = bucket["by_action"].get(action, 0) + 1
        if action == "decision":
            rendered = causes_view.render(_cause_of(event))
            key = _cause_key(rendered)
            decoded.setdefault(key, rendered)
            bucket["by_cause"][key] = bucket["by_cause"].get(key, 0) + 1
    return {"path": snapshot.path, "evidence_root": snapshot.root, "bucket_s": bucket_s, "events": len(events),
            "untimed": len(events) - len(timed), "buckets": [buckets[start] for start in sorted(buckets)],
            "causes": decoded, "verdict_of": VERDICT_OF}


# ----------------------------------------------------------------- evidence runs
def _run_files(real: str, roots: Optional[Iterable[str]]) -> Dict[str, Tuple[int, int, int]]:
    """Each file of the run that exists, confined, regular and within the bound in total: name -> (inode,
    size, mtime_ns), to compare after the verifier has read them."""
    seen, total = {}, 0
    for name in core_evidence.FILES:
        full = os.path.join(real, name)
        if not os.path.lexists(full):
            continue                                      # the verifier names a missing file itself
        confined, _root = _confine(full, roots)
        info = _regular_size(confined, f"the run's {name}")
        total += info.st_size
        if total > SETTINGS.max_evidence_bytes:
            raise EvidenceRefused("too-large", f"the run's files are over the {SETTINGS.max_evidence_bytes} byte "
                                               f"bound (MC_MAX_EVIDENCE_BYTES)")
        seen[name] = (info.st_ino, info.st_size, info.st_mtime_ns)
    return seen


def run_report(run_dir: Any, pins: Optional[Dict[str, Any]] = None, sample: Optional[int] = None, seed: int = 0,
               roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """`core_evidence.verify` over an evidence run directory (a differential run, or a governed harness,
    intent or population run, which share its layout): keys, root statement, Merkle root, image signatures,
    every receipt's binding, and a replay of `sample` receipts through the reference kernel, never more than
    `SETTINGS.evidence_sample` (`MC_EVIDENCE_SAMPLE`). `pins` names the reader's own copies of the public
    keys, {"authority": path, "instance": path}, under the roots; with both the root statement is `signed`,
    otherwise `signed-unpinned`. A run that does not verify is a report with `ok` false, status `invalid`
    and the verifier's `problem`, not a refusal."""
    pins = pins or {}
    if not isinstance(pins, dict) or set(pins) - {"authority", "instance"}:
        raise EvidenceRefused("bad-request", "pins names an authority and an instance public key file")
    pin_paths = {role: _pin_file(path, roots, f"the pinned {role} key") for role, path in pins.items() if path}
    cap = max(1, int(SETTINGS.evidence_sample))
    replay = cap if sample is None else min(_positive(sample, "sample"), cap)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise EvidenceRefused("bad-request", "seed is an integer")
    real, root = _confine(run_dir, roots)
    if not os.path.isdir(real):
        raise EvidenceRefused("not-a-file", "an evidence run is a directory")
    before = _run_files(real, roots)
    command = (f"prismpath evidence verify {_quote(real)} --sample all"
               f" --pin-authority {_quote(pin_paths.get('authority', '<authority.pub>'))}"
               f" --pin-instance {_quote(pin_paths.get('instance', '<instance.pub>'))}")
    base = {"run": real, "evidence_root": root, "verdict_of": VERDICT_OF, "sample_cap": cap, "command": command}
    try:
        summary = core_evidence.verify(Path(real), sample=replay, seed=seed,
                                       pin_authority=pin_paths.get("authority"), pin_instance=pin_paths.get("instance"))
    except core_evidence.Bad as refused:
        result = {**base, "ok": False, "status": root_statement.INVALID, "problem": str(refused)}
    except MissingExtra as missing:
        result = {**base, "ok": False, "status": "unavailable", "problem": str(missing)}
    except UnicodeDecodeError:
        result = {**base, "ok": False, "status": root_statement.INVALID,
                  "problem": "a file of the run is not UTF-8 where the verifier reads text"}
    else:
        result = {**summary, **base, "ok": True, "status": summary["root_statement"]}
    if _run_files(real, roots) != before:
        raise EvidenceRefused("changed-while-read", "the run changed while it was verified; verify it again")
    return result


# ----------------------------------------------------------------- flow manifests
def manifest_status(flow_path: Any, pins: Optional[Iterable[Any]] = None,
                    roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Whether a flow document is authorized, for A5 and U6: `flow_authority.verify_flow` against the pinned
    authority public key files (under the roots). Status `signed` (a pinned key signed a manifest naming
    this text), `stale` (a manifest signed for another text, `flow:sha256-mismatch`), `invalid` (any other
    cause), `unsigned` (no manifest), or `unchecked` (a manifest and no key to check it with). The flow, the
    manifest and its signature must all be under the roots: a manifest linked in from elsewhere is refused.
    `roots` defaults to the evidence roots; authoring passes the followed project."""
    from prismpath.hotswap import flow_authority
    real, root = _confine(flow_path, roots)
    _read_bounded(real, SETTINGS.max_file_bytes, "the flow")
    for side in flow_authority.manifest_paths(real):
        if os.path.lexists(side):
            confined, _root = _confine(side, roots)
            _read_bounded(confined, SETTINGS.max_file_bytes, "the flow manifest")
    pin_paths = [_pin_file(path, roots, "a pinned authority key") for path in (pins or [])]
    try:
        flow_sha = flow_authority.flow_sha256(real)
    except UnicodeDecodeError:
        raise EvidenceRefused("bad-request", "the flow is not UTF-8 text") from None
    present = any(os.path.lexists(side) for side in flow_authority.manifest_paths(real))
    if not pin_paths:
        manifest = flow_authority.read_manifest(real)
        status = "unchecked" if present else "unsigned"
        found: List[str] = [] if present else ["sig:missing"]
    else:
        try:
            ok, found, manifest = flow_authority.verify_flow(real, pin_paths)
        except UnicodeDecodeError:
            ok, found, manifest = False, ["manifest:bad-format"], None
        if ok:
            status = "signed"
        elif found == ["sig:missing"]:
            status = "unsigned"
        elif found == ["flow:sha256-mismatch"]:
            status = "stale"
        else:
            status = "invalid"
    manifest = manifest if isinstance(manifest, dict) else None
    key_id = manifest.get("key_id") if manifest else None
    pub = " ".join(f"--pub {_quote(path)}" for path in pin_paths) or "--pub <authority.pub>"
    return {"flow": real, "evidence_root": root, "status": status, "causes": [causes_view.render(name) for name in found],
            "flow_sha256": flow_sha, "manifest_flow_sha256": manifest.get("flow_sha256") if manifest else None,
            "version": manifest.get("version") if manifest else None,
            "key": root_statement.fingerprint(key_id) if isinstance(key_id, str) else None,
            "manifest": manifest, "pinned": bool(pin_paths), "verdict_of": VERDICT_OF,
            "command": f"prismpath authorize verify {_quote(real)} {pub}"}


# ----------------------------------------------------------------- policy packs
def pack_report(ppt_path: Any, pins: Optional[Iterable[Any]] = None,
                roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """`policy_pack.verify_pack` over a signed policy image under the roots, against the pinned authority
    public key files (under the roots too): status `signed`, `unsigned` (no manifest), `invalid` (any other
    cause) or `unchecked` (no key to check it with). The image, its manifest and its signature must be under
    the roots and within the bound."""
    from prismpath.hotswap import policy_pack
    real, root = _confine(ppt_path, roots)
    _read_bounded(real, SETTINGS.max_evidence_bytes, "the policy image")
    sides = (real + ".manifest.json", real + ".manifest.sig")
    for side in sides:
        if os.path.lexists(side):
            confined, _root = _confine(side, roots)
            _read_bounded(confined, SETTINGS.max_file_bytes, "the pack manifest")
    pin_paths = [_pin_file(path, roots, "a pinned authority key") for path in (pins or [])]
    present = all(os.path.lexists(side) for side in sides)
    if not pin_paths:
        ok, found, manifest = None, ([] if present else ["sig:missing"]), None
        status = "unchecked" if present else "unsigned"
    else:
        ok, found, manifest = policy_pack.verify_pack(real, pin_paths)
        status = "signed" if ok else ("unsigned" if found == ["sig:missing"] else "invalid")
    manifest = manifest if isinstance(manifest, dict) else None
    key_id = manifest.get("key_id") if manifest else None
    pub = " ".join(f"--pub {_quote(path)}" for path in pin_paths) or "--pub <authority.pub>"
    return {"ppt": real, "evidence_root": root, "status": status, "ok": ok,
            "causes": [causes_view.render(name) for name in found], "manifest": manifest,
            "key": root_statement.fingerprint(key_id) if isinstance(key_id, str) else None,
            "pinned": bool(pin_paths), "verdict_of": VERDICT_OF,
            "command": f"prismpath swap verify --ppt {_quote(real)} {pub}"}


# ----------------------------------------------------------------- anchors
def anchor_report(leaf: Optional[str] = None, anchor_dir: Any = None, label: str = "v1", root_file: Any = None,
                  tsr: Any = None, cafile: Any = None, roots: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Verify an anchored record under the roots, reading only. With `leaf`, the OpenTimestamps unit verify
    (`ledger_ots.verify_unit`): the leaf's Merkle path to the root the anchor in `anchor_dir` names, then
    `ots verify` of that root's proof, which needs the `ots` program and Bitcoin block data. With
    `root_file`, `tsr` and `cafile`, the RFC 3161 verify (`ledger_airgap.rfc3161_verify`, offline, by
    `openssl ts`). Nothing anchors, upgrades or stamps a calendar here."""
    import re
    from prismpath.ledgers import ledger_airgap, ledger_ots
    if root_file is not None or tsr is not None or cafile is not None:
        if not (root_file and tsr and cafile) or leaf:
            raise EvidenceRefused("bad-request", "an RFC 3161 verify names the root file, the response and the CA file")
        paths = {}
        for name, path in (("root", root_file), ("tsr", tsr), ("cafile", cafile)):
            real, _root = _confine(path, roots)
            _read_bounded(real, SETTINGS.max_file_bytes, f"the {name} file")
            paths[name] = real
        try:
            result = ledger_airgap.rfc3161_verify(paths["root"], paths["tsr"], paths["cafile"])
        except FileNotFoundError:
            result = {"verified": None, "status": "unavailable", "detail": "openssl is not installed"}
        return {"mode": "rfc3161", **result, **{key: paths[key] for key in paths}, "verdict_of": VERDICT_OF,
                "command": f"prismpath ledger rfc3161 --root {_quote(paths['root'])} --tsr {_quote(paths['tsr'])} "
                           f"--cafile {_quote(paths['cafile'])}"}
    if not isinstance(leaf, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", leaf):
        raise EvidenceRefused("bad-request", "name the leaf hash (64 hex characters) and the anchor directory, "
                                             "or a root file with its RFC 3161 response and CA file")
    if not isinstance(label, str) or not re.fullmatch(ANCHOR_LABEL, label):
        raise EvidenceRefused("bad-request", "an anchor label is letters, digits, dot, dash or underscore")
    real, root = _confine(anchor_dir, roots)
    if not os.path.isdir(real):
        raise EvidenceRefused("not-a-file", "an anchor directory is a directory")
    for name in (f"manifest_{label}.json", f"root_{label}.txt.ots"):
        side = os.path.join(real, name)
        if os.path.lexists(side):
            confined, _root = _confine(side, roots)
            _read_bounded(confined, SETTINGS.max_evidence_bytes, f"the anchor's {name}")
        elif name.startswith("manifest_"):
            raise EvidenceRefused("not-found", f"no anchor manifest for label {label!r} in that directory")
    try:
        result = ledger_ots.verify_unit(leaf.lower(), real, label)
    except FileNotFoundError:
        result = {"merkle_ok": None, "ots_ok": None, "status": "unavailable",
                  "reason": "the ots program or an anchor file is missing"}
    except (ValueError, KeyError, TypeError, AttributeError):
        result = {"merkle_ok": False, "reason": "the anchor manifest does not read"}
    return {"mode": "ots", "dir": real, "evidence_root": root, "label": label, **result, "verdict_of": VERDICT_OF,
            "command": f"prismpath ledger verify --out {_quote(real)} --leaf {leaf.lower()} --label {_quote(label)}"}
