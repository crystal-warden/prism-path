# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy manifest: the one signed file that says what a release of a policy is (SPEC.md section 10).

A manifest is `<name>.policy.md`, one per stream. Its front matter is a list of `policy.<key>: <value>` lines that
name the rules source, the image it compiles to, the side files the image is read with (egress hosts, zones,
routes and so on) each by path and sha256, and the terms of the release (stream, seq, targets, validity). Its body
is prose and one fixed rule, `-> refuse_135: always`, so the file parses as a flow and `prismpath authorize sign`
can sign it. The rules reach no image unless this file is signed.

    ---
    policy.id: agent-default-1
    policy.stream: agent-default
    policy.seq: 1
    policy.targets: agent
    policy.rules: agent_default.rules.md
    policy.rules_sha256: <sha256 of the rules source file>
    policy.image: agent_default.core.json
    policy.image_sha256: <sha256 of the image's canonical bytes, without the final line feed>
    policy.widens: yes
    policy.valid_days: 90
    ---
    ## manifest
    Notes for the reader.
    -> refuse_135: always

`parse` reads the front matter into a `Manifest`. It refuses an unknown key, a missing required key, a key written
twice and a value of the wrong form, and names the line of each (`ManifestError`). `check` is the release check
that comes before anything is sealed or installed from a manifest: the signature held, the rules source compiles
to the image byte for byte, both hashes hold, and every side input named is the one its hash says. This module
reads no file and holds no key. The caller reads the files and verifies the signature (the flow authority, in
the onion) and hands the bytes and the answer in, so the kernel stays pure. Standard library and the kernel only.
"""
from __future__ import annotations

import calendar
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Collection, Dict, List, Mapping, Optional, Tuple

from prismpath.kernel import policy_source

PREFIX = "policy."
FIXED_RULE = "-> refuse_135: always"        # `dist:bad-format`, in the canonical rendering a flow parser reads as an edge
FLOW_KEYS = ("name", "description", "start")   # the keys of a flow that are not `policy.` keys; the flow signed takes its name from `name`
MAX_SEQ = 2 ** 53 - 1                        # the same bound as a sealed envelope's integers (E1)
MAX_LIST = 256
MAX_INT = 2 ** 31 - 1

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}")
_STREAM = re.compile(r"[a-z0-9._/-]{1,64}")
_TARGET = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_PATHPART = re.compile(r"[A-Za-z0-9_.@+=,-][A-Za-z0-9_.@+=, -]*")
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")
_RULE_LINE = re.compile(r"^\s*-?\s*->")
_HEAD = re.compile(r"^\s*##\s+\S")

# The keys, in the order of the proposal: (type, required). A type is the form of the value:
#   token, name       one word of the form `_TOKEN` or `_NAME`
#   stream, target    a stream name (`[a-z0-9._/-]{1,64}`), a target kind name (`[a-z][a-z0-9_-]*`)
#   int:LO:HI         a decimal integer in LO..HI
#   sha256            64 lowercase hex digits
#   path              a relative path under the manifest's directory, no `..`, no drive, no backslash
#   time              Unix seconds, or `YYYY-MM-DDTHH:MM:SSZ`, read as Unix seconds
#   yesno             `yes` or `no`
#   list:T            items of type T joined by `|`, an empty value is an empty list, no item twice
#   enum:A|B          one of the words
#   domain            `field=value|value; field=LO..HI`, the floor and ceiling of each field
KEYS: Dict[str, Tuple[str, bool]] = {
    # identity
    "id": ("name", True),
    "stream": ("stream", True),
    "seq": (f"int:1:{MAX_SEQ}", True),
    "targets": ("list:target", True),
    # rules and image
    "rules": ("path", True),
    "rules_sha256": ("sha256", True),
    "image": ("path", True),
    "image_sha256": ("sha256", True),
    # validity (exactly one of expires and valid_days)
    "not_before": ("time", False),
    "expires": ("time", False),
    "valid_days": ("int:1:3650", False),
    "widens": ("yesno", True),
    "replaces": ("sha256", False),
    # side inputs: a file and its hash
    "egress_hosts": ("path", False), "egress_hosts_sha256": ("sha256", False),
    "zones": ("path", False), "zones_sha256": ("sha256", False),
    "routes": ("path", False), "routes_sha256": ("sha256", False),
    "identity_bundle": ("path", False), "identity_bundle_sha256": ("sha256", False),
    "identity_map": ("path", False), "identity_map_sha256": ("sha256", False),
    "net_dests": ("path", False), "net_dests_sha256": ("sha256", False),
    # side inputs: values
    "allowed_remotes": ("list:token", False),
    "max_processes": (f"int:1:{MAX_INT}", False),
    "timeout_s": (f"int:1:{MAX_INT}", False),
    "shell_many": (f"int:1:{MAX_INT}", False),
    "toolchain_dirs": ("list:path", False),
    "ro_mounts": ("list:path", False),
    "local_model": ("token", False),
    "grant_classes": ("list:token", False),
    # Context Cloud
    "cc_protected": ("list:token", False),
    "cc_index": ("path", False), "cc_index_sha256": ("sha256", False),
    "cc_freshness_s": (f"int:1:{MAX_INT}", False),
    "cc_required_certainty": ("enum:certain|likely", False),
    "cc_engine_agreement": ("int:1:64", False),
    # domain
    "domain": ("domain", False),
}
# The side files: each is a path with its hash, both or neither. The value is the kind of file in the receipt.
FILES = ("egress_hosts", "zones", "routes", "identity_bundle", "identity_map", "net_dests", "cc_index")
FILE_SHA = {name: f"{name}_sha256" for name in FILES}


class ManifestError(ValueError):
    """The manifest does not read. `problems` is a list of (line, message), line 0 for the whole file."""

    def __init__(self, problems: List[Tuple[int, str]], path: str = "<manifest>"):
        self.problems, self.path = problems, path
        super().__init__("\n".join(self.lines()))

    def lines(self) -> List[str]:
        return [f"{self.path}:{line}: {message}" if line else f"{self.path}: {message}" for line, message in self.problems]


@dataclass(frozen=True)
class FileRef:
    """A side file the manifest names: its path (relative to the manifest), its sha256 and the line of each."""
    key: str
    path: str
    sha256: str
    line: int


@dataclass(frozen=True)
class Manifest:
    """The terms of one release, as the front matter wrote them. `values` holds every key that was written
    (without the prefix) as its parsed value, `lines` the line of each. An absent optional key is `None` here
    and is not in `values`; no default is applied, a default belongs to the target that reads the key."""
    id: str
    stream: str
    seq: int
    targets: Tuple[str, ...]                  # sorted, as a sealed envelope carries them
    rules: str
    rules_sha256: str
    image: str
    image_sha256: str
    widens: bool
    not_before: Optional[int]                 # Unix seconds, or None: the time of sealing
    expires: Optional[int]                    # Unix seconds, or None when `valid_days` is given
    valid_days: Optional[int]                 # days from not_before, or None when `expires` is given
    replaces: str                             # a policy hash, or "" for a release that replaces nothing
    files: Mapping[str, FileRef]              # by key: egress_hosts, zones, routes, identity_bundle, identity_map, net_dests, cc_index
    values: Mapping[str, Any]
    lines: Mapping[str, int]
    flow_name: str = ""                       # the front matter's `name`, which the signed flow carries; "" when absent
    sha256: str = ""                          # of the manifest file's bytes, for the caller to record

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


# ----------------------------------------------------------------------------------------------- values
def _int(text: str, low: int, high: int) -> int:
    if not re.fullmatch(r"[0-9]+", text) or (len(text) > 1 and text[0] == "0"):
        raise ValueError(f"`{text}` is not a whole number written without a sign or a leading zero")
    value = int(text)
    if not low <= value <= high:
        raise ValueError(f"{value} is outside {low}..{high}")
    return value


def _path(text: str) -> str:
    if not text:
        raise ValueError("an empty path")
    if text.startswith("/") or "\\" in text or re.match(r"^[A-Za-z]:", text):
        raise ValueError(f"`{text}` is not a relative path under the manifest's directory")
    parts = text.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise ValueError(f"`{text}` has an empty, `.` or `..` part, so it could leave the manifest's directory")
        if not _PATHPART.fullmatch(part) or part != part.strip():
            raise ValueError(f"`{text}` has a character a path of a manifest does not carry")
    return text


def _time(text: str) -> int:
    if re.fullmatch(r"[0-9]+", text):
        return _int(text, 0, MAX_SEQ)
    match = _TIME.fullmatch(text)
    if not match:
        raise ValueError(f"`{text}` is not Unix seconds or a UTC time written `YYYY-MM-DDTHH:MM:SSZ`")
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    if not (1970 <= year <= 9999 and 1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1]
            and hour < 24 and minute < 60 and second < 60):
        raise ValueError(f"`{text}` is not a time")
    return calendar.timegm((year, month, day, hour, minute, second))


def _scalar(kind: str, text: str) -> Any:
    if kind == "token":
        if not _TOKEN.fullmatch(text):
            raise ValueError(f"`{text}` is not a word of letters, digits and `_ . : @ / -`")
        return text
    if kind == "name":
        if not _NAME.fullmatch(text):
            raise ValueError(f"`{text}` is not a name of letters, digits, `_`, `.` and `-`, 1 to 64 long")
        return text
    if kind == "stream":
        if not _STREAM.fullmatch(text):
            raise ValueError(f"`{text}` is not a stream name (lowercase letters, digits and `. _ / -`, 1 to 64 long)")
        return text
    if kind == "target":
        if not _TARGET.fullmatch(text):
            raise ValueError(f"`{text}` is not a target kind name (lowercase, starting with a letter)")
        return text
    if kind == "sha256":
        if not _HEX64.fullmatch(text):
            raise ValueError(f"`{text}` is not 64 lowercase hex digits")
        return text
    if kind == "path":
        return _path(text)
    if kind == "time":
        return _time(text)
    if kind == "yesno":
        if text not in ("yes", "no"):
            raise ValueError(f"`{text}` is not yes or no")
        return text == "yes"
    if kind.startswith("int:"):
        _, low, high = kind.split(":")
        return _int(text, int(low), int(high))
    if kind.startswith("enum:"):
        words = kind[len("enum:"):].split("|")
        if text not in words:
            raise ValueError(f"`{text}` is not one of {' | '.join(words)}")
        return text
    raise AssertionError(kind)


def _domain(text: str) -> Tuple[Tuple[str, str], ...]:
    """`field=a|b|c; other=0..10` as ((field, "a|b|c"), (other, "0..10")): the ceiling of each field, written as
    a list of the values it may take or an integer range, each field once. Seal copies the lists a rules source
    types into this key, and the key bounds what a later release may widen to."""
    entries = []
    seen = set()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"`{part}` is not `field=value|value` or `field=LO..HI`")
        name, _, spec = part.partition("=")
        name, spec = name.strip(), spec.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"`{name}` is not a field name")
        if name in seen:
            raise ValueError(f"the field {name} is written twice")
        seen.add(name)
        if re.fullmatch(r"-?[0-9]+\.\.-?[0-9]+", spec):
            low, high = (int(side) for side in spec.split(".."))
            if low > high:
                raise ValueError(f"the range of {name} is empty ({spec})")
        else:
            if ".." in spec:
                raise ValueError(f"`{spec}` is not a range LO..HI of whole numbers")
            values = [value.strip() for value in spec.split("|")]
            if not all(re.fullmatch(r"[A-Za-z0-9_.:-]+", value) for value in values) or len(set(values)) != len(values):
                raise ValueError(f"the values of {name} are words of `[A-Za-z0-9_.:-]`, none twice (or a range LO..HI)")
            spec = "|".join(values)
        entries.append((name, spec))
    return tuple(entries)


def _value(kind: str, text: str) -> Any:
    """The value a key's text reads as, or ValueError naming what is wrong with it."""
    if kind == "domain":
        return _domain(text)
    if kind.startswith("list:"):
        item = kind[len("list:"):]
        parts = [part.strip() for part in text.split("|")] if text.strip() else []
        if len(parts) > MAX_LIST:
            raise ValueError(f"more than {MAX_LIST} items")
        items = [_scalar(item, part) for part in parts]
        if item == "target" and not items:
            raise ValueError("at least one target kind")
        if len(set(items)) != len(items):
            raise ValueError("an item is written twice")
        return tuple(sorted(items)) if item == "target" else tuple(items)
    return _scalar(kind, text)


# ----------------------------------------------------------------------------------------------- parse
def _front(lines: List[str], problems: List[Tuple[int, str]]) -> Tuple[Dict[str, Tuple[str, int]], Dict[str, Tuple[str, int]], int]:
    """(`policy.` keys, flow keys, index of the first body line), each value with its line."""
    if not lines or lines[0].strip() != "---":
        problems.append((1, "a manifest starts with a front matter block between two `---` lines"))
        return {}, {}, len(lines)
    keys: Dict[str, Tuple[str, int]] = {}
    flow: Dict[str, Tuple[str, int]] = {}
    for at in range(1, len(lines)):
        text, line = lines[at], at + 1
        if text.strip() == "---":
            return keys, flow, at + 1
        if not text.strip():
            continue
        if ":" not in text:
            problems.append((line, "a front matter line is `policy.<key>: <value>`"))
            continue
        key, value = text.split(":", 1)
        key, value = key.strip(), value.strip()
        if key.startswith(PREFIX):
            name, bucket = key[len(PREFIX):], keys
            if name not in KEYS:
                problems.append((line, f"`{key}` is not a key of a policy manifest; the keys are "
                                       f"{', '.join(PREFIX + k for k in KEYS)}"))
                continue
        elif key in FLOW_KEYS:
            name, bucket = key, flow
        else:
            problems.append((line, f"`{key}` is not a front matter key of a policy manifest: every key starts with "
                                   f"`{PREFIX}` (or is `name`, `description` or `start`, which belong to the flow)"))
            continue
        if name in bucket:
            problems.append((line, f"`{key}` is written twice (first on line {bucket[name][1]})"))
            continue
        bucket[name] = (value, line)
    problems.append((1, "the front matter has no closing `---` line"))
    return keys, flow, len(lines)


def _body(lines: List[str], start: int, problems: List[Tuple[int, str]]) -> None:
    """The body holds the one fixed rule under a `##` heading, so the file is a flow with one node and one edge."""
    heading_seen = False
    rules = []
    for at in range(start, len(lines)):
        text, line = lines[at], at + 1
        if _HEAD.match(text):
            heading_seen = True
        if _RULE_LINE.match(text):
            rules.append((line, text.strip(), heading_seen))
    if not rules:
        problems.append((0, f"the body has no rule; it holds the one rule `{FIXED_RULE}` under a `##` heading, so the "
                            f"file parses as a flow and can be signed"))
        return
    for line, text, under in rules:
        if text != FIXED_RULE:
            problems.append((line, f"a manifest's body holds no rule but `{FIXED_RULE}`; the rules are in "
                                   f"`policy.rules`" + (" (a rules source line with a space in its target would "
                                                        "also make the file refused as a flow)"
                                                        if re.match(r"^\s*-?\s*->\s*(refuse|escalate)\s", text) else "")))
        elif not under:
            problems.append((line, "the fixed rule is under a `##` heading"))
    if len(rules) > 1 and all(text == FIXED_RULE for _l, text, _u in rules):
        problems.append((rules[1][0], f"the rule `{FIXED_RULE}` is written once"))


def parse(text: str, path: str = "<manifest>") -> Manifest:
    """The manifest a text writes. `ManifestError` names every line it cannot read."""
    problems: List[Tuple[int, str]] = []
    raw = text
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    keys, flow, body_at = _front(lines, problems)
    values: Dict[str, Any] = {}
    at: Dict[str, int] = {}
    for name, (written, line) in keys.items():
        kind = KEYS[name][0]
        try:
            values[name] = _value(kind, written)
            at[name] = line
        except ValueError as error:
            problems.append((line, f"{PREFIX}{name}: {error}"))
    if all(line != 1 for line, _m in problems):
        _body(lines, body_at, problems)
    for name, (_kind, required) in KEYS.items():
        if required and name not in keys:
            problems.append((0, f"the required key `{PREFIX}{name}` is missing"))
    if "expires" in keys and "valid_days" in keys:
        problems.append((at.get("valid_days", 0), f"`{PREFIX}expires` and `{PREFIX}valid_days` are both written; write one"))
    elif "expires" not in keys and "valid_days" not in keys:
        problems.append((0, f"one of `{PREFIX}expires` and `{PREFIX}valid_days` is required"))
    for name in FILES:
        have_path, have_sha = name in keys, FILE_SHA[name] in keys
        if have_path != have_sha:
            present = name if have_path else FILE_SHA[name]
            missing = FILE_SHA[name] if have_path else name
            problems.append((at.get(present, 0), f"`{PREFIX}{present}` is written without `{PREFIX}{missing}`; a side "
                                                 f"input is a path and its sha256"))
    if "not_before" in values and "expires" in values and values["expires"] <= values["not_before"]:
        problems.append((at["expires"], f"`{PREFIX}expires` is not after `{PREFIX}not_before`"))
    if values.get("widens") is False and not values.get("replaces"):
        problems.append((at.get("widens", 0), f"`{PREFIX}widens: no` needs `{PREFIX}replaces`: a release that replaces "
                                              f"nothing widens (W7)"))
    seen_paths: Dict[str, str] = {}
    for name in ("rules", "image", *FILES):
        if name in values:
            if values[name] in seen_paths:
                problems.append((at[name], f"`{PREFIX}{name}` names the same file as `{PREFIX}{seen_paths[values[name]]}`"))
            seen_paths[values[name]] = name
    if problems:
        raise ManifestError(sorted(problems, key=lambda item: item[0]), path)
    files = {name: FileRef(name, values[name], values[FILE_SHA[name]], at[name]) for name in FILES if name in values}
    return Manifest(
        id=values["id"], stream=values["stream"], seq=values["seq"], targets=values["targets"], rules=values["rules"],
        rules_sha256=values["rules_sha256"], image=values["image"], image_sha256=values["image_sha256"],
        widens=values["widens"], not_before=values.get("not_before"), expires=values.get("expires"),
        valid_days=values.get("valid_days"), replaces=values.get("replaces", ""), files=files, values=values, lines=at,
        flow_name=flow.get("name", ("", 0))[0], sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest())


# ----------------------------------------------------------------------------------------------- check
@dataclass(frozen=True)
class Signature:
    """What the caller found when it verified the manifest's signature (`prismpath authorize verify`): whether it
    holds, and the causes (`sig:missing`, `sig:invalid`, `flow:sha256-mismatch` and so on) when it does not."""
    ok: bool
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """One thing the check found wrong. `code` is a short stable word, `line` the manifest's line, 0 for the file."""
    code: str
    line: int
    message: str

    def render(self, path: str) -> str:
        return f"{path}:{self.line}: {self.code}: {self.message}" if self.line else f"{path}: {self.code}: {self.message}"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(manifest: Manifest, signature: Signature, read: Callable[[str], Optional[bytes]], *,
          known_targets: Optional[Collection[str]] = None) -> List[Finding]:
    """What is wrong with a release, in the order the proposal gives: the signature, then the rules and the
    image, then each side input. An empty list means the manifest holds. `read(path)` returns the bytes of a
    path the manifest names (relative to the manifest), or None when there is no such file; it is the caller's
    to confine to the manifest's directory. A failed signature is the only finding returned, since nothing a
    manifest says counts without it. `known_targets` is the set of target kinds the caller can seal for; a
    target outside it is a finding."""
    if not signature.ok:
        reasons = ", ".join(signature.reasons) or "it does not verify"
        return [Finding("signature", 0, f"the signature does not hold ({reasons}), so nothing in the manifest counts")]
    found: List[Finding] = []
    lines = manifest.lines
    if known_targets is not None:
        for target in manifest.targets:
            if target not in known_targets:
                found.append(Finding("target", lines["targets"], f"`{target}` is not a target kind this tool seals for"))
    rules = read(manifest.rules)
    held = read(manifest.image)
    if rules is None:
        found.append(Finding("missing", lines["rules"], f"{manifest.rules} is not there"))
    if held is None:
        found.append(Finding("missing", lines["image"], f"{manifest.image} is not there"))
    if rules is not None:
        if _sha(rules) != manifest.rules_sha256:
            found.append(Finding("rules-sha256", lines["rules_sha256"],
                                 f"{manifest.rules} is sha256 {_sha(rules)}, and the manifest says {manifest.rules_sha256}"))
        try:
            compiled = policy_source.compile_full(rules.decode("utf-8"), manifest.rules)
        except UnicodeDecodeError:
            found.append(Finding("rules-compile", lines["rules"], f"{manifest.rules} is not UTF-8 text"))
        except policy_source.SourceError as error:
            for line, message in error.problems:
                found.append(Finding("rules-compile", lines["rules"],
                                     f"{manifest.rules}:{line}: {message}" if line else f"{manifest.rules}: {message}"))
        else:
            image_sha = _sha(compiled.image)
            if image_sha != manifest.image_sha256:
                found.append(Finding("image-sha256", lines["image_sha256"],
                                     f"{manifest.rules} compiles to image sha256 {image_sha}, and the manifest says "
                                     f"{manifest.image_sha256}"))
            if held is not None and held not in (compiled.image, compiled.image + b"\n"):
                held_sha = _sha(policy_source.read_image_bytes(held))
                found.append(Finding("image-stale", lines["image"],
                                     f"{manifest.rules} compiles to image sha256 {image_sha}, but {manifest.image} is "
                                     f"sha256 {held_sha}; compile it again with `prismpath policy compile`"))
    elif held is not None and _sha(policy_source.read_image_bytes(held)) != manifest.image_sha256:
        found.append(Finding("image-sha256", lines["image_sha256"],
                             f"{manifest.image} is sha256 {_sha(policy_source.read_image_bytes(held))}, and the manifest "
                             f"says {manifest.image_sha256}"))
    for ref in manifest.files.values():
        data = read(ref.path)
        if data is None:
            found.append(Finding("missing", ref.line, f"{ref.path} is not there"))
        elif _sha(data) != ref.sha256:
            found.append(Finding(f"{ref.key}-sha256", manifest.lines[FILE_SHA[ref.key]],
                                 f"{ref.path} is sha256 {_sha(data)}, and the manifest says {ref.sha256}"))
    return found

