# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy manifest: the one signed file that says what a release of a policy is (SPEC.md section 10).

A manifest is `<name>.policy.md`, one per stream. Its front matter is a list of `policy.<key>: <value>` lines that
name the rules source, the image it compiles to, the side files the image is read with (egress hosts, zones,
routes and so on) each by path and sha256, and the terms of the release (stream, seq, targets, validity). Its body
is prose and one fixed rule, `-> refuse_135: always`, so the file parses as a flow and `prismpath authorize sign`
can sign it. The rules reach no image unless this file is signed.

    ---
    name: agent-default
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
twice and a value of the wrong form, and names the line of each (`ManifestError`). The flow key `name` is required and
is the stream, so the flow authority's version floor, which is kept per flow name, is one per stream, and the signed
version must be `policy.seq`. `check` is the release check that comes before anything is sealed or installed from a
manifest: the signature held, the rules source compiles to the image byte for byte, both hashes hold, each target's
own compile checks hold, and every side input named is the one its hash says. `verify` is the same check, and it
returns the bytes it checked and the signed facts as a `Release`, which is all the sealing tool reads: it never
opens a file the check did not hash (`distribution/seal.py`, `seal_manifest`). This module
reads no file and holds no key. The caller reads the files and verifies the signature (the flow authority, in
the onion) and hands the bytes and the answer in, so the kernel stays pure. Standard library and the kernel only.
"""
from __future__ import annotations

import calendar
import hashlib
import unicodedata
import re
from dataclasses import dataclass
from typing import Any, Callable, Collection, Dict, List, Mapping, Optional, Tuple

from prismpath.kernel import policy_source

PREFIX = "policy."
FIXED_RULE = "-> refuse_135: always"        # `dist:bad-format`, in the canonical rendering a flow parser reads as an edge
FLOW_KEYS = ("name", "description", "start")   # the keys of a flow that are not `policy.` keys; the flow signed takes its name from `name`
MAX_SEQ = 2 ** 53 - 1                        # the same bound as a sealed envelope's integers (E1)
MAX_LIST = 256
SECONDS_PER_DAY = 86400
MAX_INT = 2 ** 31 - 1

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}")
_STREAM = re.compile(r"[a-z0-9._/-]{1,64}")
_TARGET = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_PATHPART = re.compile(r"[A-Za-z0-9_.@+=,-][A-Za-z0-9_.@+=, -]*")
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
_RULE_LINE = re.compile(r"^\s*-?\s*->")
_POLICY_KEY = re.compile(r"^\s*policy\.[A-Za-z0-9_]+\s*:")
_FRONT_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.]*")
_GRANT_CLASS = re.compile(r"[a-z][a-z0-9_]{0,31}")             # kinds._GRANT_CLASS
ZONE_NAME_MAX, ZONES_MAX = 512, 10000                          # kinds.ZONE_NAME_MAX, kinds.ZONES_MAX: agent.zones names
MAX_DESCRIPTION = 200
MAX_NAME = 64
_HEAD = re.compile(r"^\s*##\s+\S")

# The keys, in the order of the proposal: (type, required). A type is the form of the value:
#   token, name       one word of the form `_TOKEN` or `_NAME`
#   stream, target    a stream name (`[a-z0-9._/-]{1,64}`), a target kind name (`[a-z][a-z0-9_-]*`)
#   int:LO:HI         a decimal integer in LO..HI
#   sha256            64 lowercase hex digits
#   path              a relative path under the manifest's directory, no `..`, no drive, no backslash
#   hostpath          a path on the host that runs the policy: absolute (`/usr`), under the home (`~/.cargo`) or under the
#                     workspace (`workspace:.toolchain`); no `..`, `.` or empty part, no backslash
#   grantclass        `[a-z][a-z0-9_]{0,31}`, as a grant's classes are
#   zonename          1 to 512 characters of a word, no `/`, as the names of agent.zones are
#   time              Unix seconds, or `YYYY-MM-DDTHH:MM:SSZ`, read as Unix seconds
#   yesno             `yes` or `no`
#   list:T            items of type T joined by `|`, an empty value is an empty list, no item twice
#   enum:A|B          one of the words
#   reserved          a key of the proposal no reader defines yet: written, it is refused (see `RESERVED`)
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
    "toolchain_dirs": ("list:hostpath", False),
    "ro_mounts": ("list:hostpath", False),
    "local_model": ("token", False),
    "grant_classes": ("list:grantclass", False),
    # Context Cloud
    "cc_protected": ("list:zonename", False),
    "cc_index": ("path", False), "cc_index_sha256": ("sha256", False),
    "cc_freshness_s": (f"int:1:{MAX_INT}", False),
    "cc_required_certainty": ("enum:certain|likely", False),
    "cc_engine_agreement": ("int:1:64", False),
    # domain
    "domain": ("reserved", False),
}
# Keys the grammar knows and refuses. `policy.domain` was to name the floor and ceiling of each field. The rules
# source's own `field.<name>:` lines are the domain, and `policy.rules_sha256` already signs them, so a second
# statement could only repeat them or contradict them, and the bound on a later release it was meant to be has no
# reader. A signed file must not carry a syntax whose meaning is not fixed, so the key is refused until one is.
RESERVED = {"domain": "the domain is the rules source's typed `field.` lines, which `policy.rules_sha256` signs; "
                      "the key is reserved until a reader of a floor and ceiling of each field is specified"}
# The side files: each is a path with its hash, both or neither. The value is the kind of file in the receipt.
FILES = ("egress_hosts", "zones", "routes", "identity_bundle", "identity_map", "net_dests", "cc_index")
FILE_SHA = {name: f"{name}_sha256" for name in FILES}
# The keys of the release itself; every other key but a side file, its hash and a reserved key is a value key, which a
# target kind carries at the value it registered (`TargetKind.manifest_values`) or the sealing tool refuses.
RELEASE_KEYS = ("id", "stream", "seq", "targets", "rules", "rules_sha256", "image", "image_sha256", "not_before",
                "expires", "valid_days", "widens", "replaces")
VALUE_KEYS = tuple(name for name in KEYS if name not in RELEASE_KEYS and name not in FILES
                   and name not in FILE_SHA.values() and name not in RESERVED)


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
    sha256: str = ""                          # the `flow_sha256` a signature covers: sha256 of the text with CR LF read as LF

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


def _hostpath(text: str) -> str:
    """A path on the host that runs the policy: `/usr`, `~/.cargo` or `workspace:.toolchain` (under the workspace)."""
    if text.startswith("workspace:"):
        rest = text[len("workspace:"):]
    elif text.startswith("~/"):
        rest = text[2:]
    elif text.startswith("/") and text != "/":
        rest = text[1:]
    else:
        raise ValueError(f"`{text}` is not an absolute path, `~/` under the home or `workspace:` under the workspace")
    if "\\" in text:
        raise ValueError(f"`{text}` has a backslash")
    for part in rest.split("/"):
        if part in ("", ".", "..") or not _PATHPART.fullmatch(part) or part != part.strip():
            raise ValueError(f"`{text}` has an empty, `.` or `..` part or a character a path of a manifest does not carry")
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
    if kind == "hostpath":
        return _hostpath(text)
    if kind == "grantclass":
        if not _GRANT_CLASS.fullmatch(text):
            raise ValueError(f"`{text}` is not a class name (`[a-z][a-z0-9_]{{0,31}}`)")
        return text
    if kind == "zonename":
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,%d}" % ZONE_NAME_MAX, text) or text in (".", ".."):
            raise ValueError(f"`{text}` is not a name of letters, digits and `_ . : @ -`, 1 to {ZONE_NAME_MAX} long, no `/`")
        return text
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


def _value(kind: str, text: str, name: str = "") -> Any:
    """The value a key's text reads as, or ValueError naming what is wrong with it."""
    if kind == "reserved":
        raise ValueError(f"is reserved and not written: {RESERVED[name]}")
    if kind.startswith("list:"):
        item = kind[len("list:"):]
        parts = [part.strip() for part in text.split("|")] if text.strip() else []
        limit = ZONES_MAX if item == "zonename" else MAX_LIST
        if len(parts) > limit:
            raise ValueError(f"more than {limit} items")
        items = [_scalar(item, part) for part in parts]
        if item == "target" and not items:
            raise ValueError("at least one target kind")
        if len(set(items)) != len(items):
            raise ValueError("an item is written twice")
        return tuple(sorted(items)) if item == "target" else tuple(items)
    return _scalar(kind, text)


# ----------------------------------------------------------------------------------------------- parse
def _control_problems(text: str) -> List[Tuple[int, str]]:
    """Every character that makes two readers split a line differently or hides text: any control character but the
    line feed (a carriage return only as the first half of CR LF), a line or paragraph separator, a byte order mark.
    The flow authority hashes the file with universal newlines, so a lone CR must never reach the parser as a
    character: it would be a line end to the signature and not to this reader (SPEC.md section 10)."""
    found: List[Tuple[int, str]] = []
    line = 1
    for at, char in enumerate(text):
        if char == "\n":
            line += 1
        elif char == "\r" and text[at + 1:at + 2] == "\n":
            continue
        elif unicodedata.category(char) in ("Cc", "Zl", "Zp") or char == "\ufeff":
            found.append((line, f"the character U+{ord(char):04X} is not allowed: a line ends with a line feed "
                                f"(or CR LF) and no other control character is written"))
            if len(found) >= 8:
                break
    return found


def _free_text(kind: str, value: str) -> str:
    if kind == "description":
        if not value.isprintable() or len(value) > MAX_DESCRIPTION:
            raise ValueError(f"a description is printable text of at most {MAX_DESCRIPTION} characters")
        return value
    if not _STREAM.fullmatch(value):
        raise ValueError(f"`{value}` is not a stream name (lowercase letters, digits and `. _ / -`, 1 to {MAX_NAME} "
                         f"long); `name` is the manifest's `policy.stream`")
    return value


def _front(lines: List[str], problems: List[Tuple[int, str]]) -> Tuple[Dict[str, Tuple[str, int]], Dict[str, Tuple[str, int]], int]:
    """(`policy.` keys, flow keys, index of the first body line), each value with its line. The two fences are
    exactly `---`, as the flow parser needs them, and a key starts in column 0."""
    if not lines or lines[0] != "---":
        problems.append((1, "a manifest starts with a front matter block between two lines that are exactly `---`"))
        return {}, {}, len(lines)
    keys: Dict[str, Tuple[str, int]] = {}
    flow: Dict[str, Tuple[str, int]] = {}
    for at in range(1, len(lines)):
        text, line = lines[at], at + 1
        if text == "---":
            return keys, flow, at + 1
        if text.strip() == "---":
            problems.append((line, "a fence is exactly `---`, with nothing before or after it"))
            continue
        if not text.strip(" "):
            continue
        if ":" not in text or text[0] in " \t":
            problems.append((line, "a front matter line is `policy.<key>: <value>`, starting in the first column"))
            continue
        key, value = text.split(":", 1)
        value = value.strip(" ")
        if not _FRONT_KEY.fullmatch(key):
            problems.append((line, f"`{key}` is not a front matter key of a policy manifest: every key starts with "
                                   f"`{PREFIX}` (or is `name`, `description` or `start`, which belong to the flow)"))
            continue
        if key.startswith(PREFIX):
            name, bucket = key[len(PREFIX):], keys
            if name not in KEYS:
                problems.append((line, f"`{key}` is not a key of a policy manifest; the keys are "
                                       f"{', '.join(PREFIX + k for k in KEYS)}"))
                continue
        elif key in FLOW_KEYS:
            name, bucket = key, flow
            try:
                _free_text(key, value)
            except ValueError as error:
                problems.append((line, f"{key}: {error}"))
                continue
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
    """The body holds the one fixed rule under a `##` heading, so the file is a flow with one node and one edge. A
    `policy.` key or a fence below the front matter is refused: it would be read as prose and look signed."""
    heading_seen = False
    rules = []
    for at in range(start, len(lines)):
        text, line = lines[at], at + 1
        if _POLICY_KEY.match(text):
            problems.append((line, "a `policy.` key is written in the front matter, above the closing `---`; here it "
                                   "would be read as a note and the release would not have it"))
        elif text.strip() == "---":
            problems.append((line, "the body holds no `---` line; the front matter ended above"))
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
    """The manifest a text writes. `ManifestError` names every line it cannot read. The text is read as the flow
    authority hashes it: CR LF is a line feed, and a carriage return anywhere else is refused, so the text parsed
    is the text signed (`Manifest.sha256` is the hash a signature covers)."""
    problems: List[Tuple[int, str]] = _control_problems(text)
    if problems:
        raise ManifestError(problems, path)
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    keys, flow, body_at = _front(lines, problems)
    values: Dict[str, Any] = {}
    at: Dict[str, int] = {}
    for name, (written, line) in keys.items():
        kind = KEYS[name][0]
        try:
            values[name] = _value(kind, written, name)
            at[name] = line
        except ValueError as error:
            problems.append((line, f"{PREFIX}{name}: {error}"))
    if all(line != 1 for line, _m in problems):
        _body(lines, body_at, problems)
    for name, (_kind, required) in KEYS.items():
        if required and name not in keys:
            problems.append((0, f"the required key `{PREFIX}{name}` is missing"))
    if "name" not in flow:
        problems.append((0, f"the flow key `name` is missing; it is the stream (`{PREFIX}stream`), so the version "
                            f"floor the signature is held to is one per stream"))
    elif "stream" in values and flow["name"][0] != values["stream"]:
        problems.append((flow["name"][1], f"`name: {flow['name'][0]}` is not the stream `{values['stream']}`; a "
                                          f"manifest's flow name is its `{PREFIX}stream`, so the version floor the "
                                          f"signature is held to is one per stream"))
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
                                              f"nothing widens (W2 reads a release as not larger only with `widens: false` and the policy it replaces, W6 makes a first install larger)"))
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
        flow_name=flow.get("name", ("", 0))[0], sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())


# ----------------------------------------------------------------------------------------------- check
@dataclass(frozen=True)
class Signature:
    """What the caller found when it verified the manifest's signature (`prismpath authorize verify`): whether it
    holds, and the causes (`sig:missing`, `sig:invalid`, `flow:sha256-mismatch` and so on) when it does not. When it
    holds, `flow_sha256` is the one the signature covers and `check` requires the text it parsed to have it, so a
    caller that read the file twice cannot check one text and sign another. `created`, `version` and `key_id` are the
    verified flow manifest's own: the signing time, the signed version, which must be `policy.seq`, and the id of the
    authority key that signed."""
    ok: bool
    reasons: Tuple[str, ...] = ()
    flow_sha256: str = ""            # the `flow_sha256` of the verified flow manifest: what the signature covers
    created: Optional[int] = None    # the verified flow manifest's `created`, Unix seconds: the start of `valid_days`
    version: Optional[int] = None    # the verified flow manifest's `version`, which is `policy.seq`
    key_id: str = ""                 # the verified flow manifest's `key_id`, the authority key that signed


@dataclass(frozen=True)
class Finding:
    """One thing the check found wrong. `code` is a short stable word, `line` the manifest's line, 0 for the file."""
    code: str
    line: int
    message: str

    def render(self, path: str) -> str:
        return f"{path}:{self.line}: {self.code}: {self.message}" if self.line else f"{path}: {self.code}: {self.message}"


@dataclass(frozen=True)
class Release:
    """A manifest that `verify` found holds, with the bytes it checked and the facts the signature gives. The sealing
    tool reads only this: `image` is the compiled image (the `policy.core` body, canonical bytes with no final line
    feed), never the image file's bytes, `rules` the rules source, `files` each side file by key, and `values` the
    values each category of the rules source lists. `manifest_sha256` is the signed `flow_sha256`. `not_before` is
    `policy.not_before`, else the signing time, and `expires` the end `expiry` gives, so the same manifest always seals
    to the same envelopes."""
    manifest: Manifest
    image: bytes
    rules: bytes
    files: Mapping[str, bytes]
    values: Mapping[str, Tuple[str, ...]]
    manifest_sha256: str
    created: int
    version: int
    key_id: str
    not_before: int
    expires: int


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_signature_only(signature: Signature) -> Finding:
    """The finding for a signature that does not hold, for a caller whose manifest does not read either."""
    reasons = ", ".join(signature.reasons) or "it does not verify"
    return Finding("signature", 0, f"the signature does not hold ({reasons}), so nothing in the manifest counts")


def expiry(manifest: Manifest, created: Optional[int]) -> Optional[int]:
    """The Unix second a release ends, or None when it cannot be told. `expires` is written. `valid_days` counts from
    `not_before` when it is written and otherwise from the `created` of the verified flow manifest, the signing
    time, as the delegate envelope counts its grant; never from the time of sealing."""
    if manifest.expires is not None:
        return manifest.expires
    start = manifest.not_before if manifest.not_before is not None else created
    return None if start is None else start + manifest.valid_days * SECONDS_PER_DAY


def check(manifest: Manifest, signature: Signature, read: Callable[[str], Optional[bytes]], *,
          known_targets: Collection[str], now: Optional[int] = None) -> List[Finding]:
    """What is wrong with a release, in the order the proposal gives: the signature, then the rules and the
    image, each target's compile checks, then each side input. An empty list means the manifest holds. `read(path)`
    returns the bytes of a path the manifest names (relative to the manifest), or None when there is no such file; it
    is the caller's to confine to the manifest's directory. A failed signature is the only finding returned, since
    nothing a manifest says counts without it. `known_targets` is the set of target kinds the caller can seal for, and
    it is required, so no caller skips it; a target outside it is a finding. With `now` (Unix seconds, the caller's
    clock) a manifest before `not_before` or past its end (`expiry`) is a finding, and so is one with `valid_days`
    whose start the signature does not give."""
    return _examine(manifest, signature, read, known_targets, now)[0]


def verify(manifest: Manifest, signature: Signature, read: Callable[[str], Optional[bytes]], *,
           known_targets: Collection[str], now: int) -> Tuple[List[Finding], Optional[Release]]:
    """`check`, and when it finds nothing the `Release` that holds the bytes it checked and the signed facts, else
    None. `now` is required: a release is never made from a manifest whose time was not checked. A signature that
    gives no signing time, version or key id makes no release."""
    found, rules, compiled, files = _examine(manifest, signature, read, known_targets, now)
    if found:
        return found, None
    if signature.created is None or signature.version is None or not signature.key_id:
        return [Finding("signature", 0, "the signature gives no signing time, version or key id, so no release is "
                                        "made from it")], None
    end = expiry(manifest, signature.created)
    assert rules is not None and compiled is not None and end is not None
    return [], Release(manifest, compiled.image, rules, files, dict(compiled.values), signature.flow_sha256,
                       signature.created, signature.version, signature.key_id,
                       manifest.not_before if manifest.not_before is not None else signature.created, end)


def _examine(manifest: Manifest, signature: Signature, read: Callable[[str], Optional[bytes]],
             known_targets: Collection[str], now: Optional[int]):
    """(findings, the rules bytes, the `Compiled` rules, {side key: bytes}) of `check`."""
    if not signature.ok:
        return [check_signature_only(signature)], None, None, {}
    if signature.flow_sha256 and signature.flow_sha256 != manifest.sha256:
        return [Finding("signature", 0, f"the text read is sha256 {manifest.sha256}, and the signature covers "
                                        f"{signature.flow_sha256}, so the file was not the one signed")], None, None, {}
    if not signature.flow_sha256:
        return [Finding("signature", 0, "the signature names no flow_sha256, so it is not bound to the text read")], \
            None, None, {}
    found: List[Finding] = []
    lines = manifest.lines
    if signature.version is not None and signature.version != manifest.seq:
        found.append(Finding("version", lines["seq"], f"the manifest is signed at version {signature.version} and its "
                                                      f"seq is {manifest.seq}; sign it with `--version {manifest.seq}`, "
                                                      f"so the version floor and the stream's seq are one counter"))
    if now is not None:
        if manifest.not_before is not None and now < manifest.not_before:
            found.append(Finding("not-yet-valid", lines["not_before"], f"the manifest is valid from {manifest.not_before} "
                                                                       f"and it is {now}"))
        end = expiry(manifest, signature.created)
        if end is None:
            found.append(Finding("expiry", lines["valid_days"], "valid_days counts from the signing time and the "
                                                                 "signature gives none"))
        elif now >= end:
            found.append(Finding("expired", lines.get("expires", lines.get("valid_days", 0)),
                                 f"the manifest ended at {end} and it is {now}"))
    for target in manifest.targets:
        if target not in known_targets:
            found.append(Finding("target", lines["targets"], f"`{target}` is not a target kind this tool seals for"))

    def read_file(path: str) -> Optional[bytes]:
        try:
            return read(path)
        except (OSError, ValueError) as error:
            failed.add(path)
            found.append(Finding("unreadable", lines.get(path_keys.get(path, ""), 0), f"{path}: {error}"))
            return None

    failed = set()
    path_keys = {manifest.rules: "rules", manifest.image: "image", **{ref.path: ref.key for ref in manifest.files.values()}}
    rules = read_file(manifest.rules)
    held = read_file(manifest.image)
    compiled = None
    if rules is None and manifest.rules not in failed:
        found.append(Finding("missing", lines["rules"], f"{manifest.rules} is not there"))
    if held is None and manifest.image not in failed:
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
            for target in manifest.targets:
                found += _target_checks(manifest, target, compiled)
    elif held is not None and _sha(policy_source.read_image_bytes(held)) != manifest.image_sha256:
        found.append(Finding("image-sha256", lines["image_sha256"],
                             f"{manifest.image} is sha256 {_sha(policy_source.read_image_bytes(held))}, and the manifest "
                             f"says {manifest.image_sha256}"))
    files: Dict[str, bytes] = {}
    for ref in manifest.files.values():
        data = read_file(ref.path)
        if data is None:
            if ref.path not in failed:
                found.append(Finding("missing", ref.line, f"{ref.path} is not there"))
        elif _sha(data) != ref.sha256:
            found.append(Finding(f"{ref.key}-sha256", manifest.lines[FILE_SHA[ref.key]],
                                 f"{ref.path} is sha256 {_sha(data)}, and the manifest says {ref.sha256}"))
        else:
            files[ref.key] = data
    return found, rules, compiled, files


def _target_checks(manifest: Manifest, target: str, compiled) -> List[Finding]:
    """`prismpath policy compile --target <target>` on the rules (the proposal's step 4): the checks the target kind
    registered (`policy_source.COMPILE_CHECKS`), each finding named with its line in the rules source. A kind that
    registered none has none to run, and its PEP still holds the image to its own check (V11) when it is sealed."""
    checks = policy_source.COMPILE_CHECKS.get(target)
    if checks is None:
        return []
    return [Finding("target-check", manifest.lines["targets"],
                    f"{target}: {manifest.rules}:{policy_source.line_of(where, compiled.field_lines, compiled.rule_lines)}: "
                    f"{message}")
            for where, message in checks(compiled.image, compiled.values)]
