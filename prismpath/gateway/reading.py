# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The reading of one HTTP request: a finite record the core decides, in the canonical form the agent classifier's
readings use (canon2 bytes, `Policy.reading_bytes`).

    http_reading_version  int, 1
    method_class   read (GET, HEAD) | write (POST, PUT, PATCH) | delete | other | unknown
    path_class     a class the owner's route table names | other (no route matches) | unknown
    body_class     none (no body) | small | large | oversize (declared too large, never read) | unknown
    content_class none (no Content-Type) | json | form | text | other | unknown
    query          none | present | unknown
    grant          none | valid | invalid | expired

Nothing about the sender is read. The reading is what the request says it wants of the resource, so two clients
that send the same request get the same reading and the same decision.

Unreadable is `unknown`. A field is `unknown` when the request is malformed in it or ambiguous in a way two
servers could read differently: a method that is not a token, a target that is not an origin form path of plain
characters (no percent escapes, no `.` or `..` segments, no empty segments, no `;`), a query with a control
character or a space, a length that is not one plain decimal, a body sent with Transfer-Encoding, a repeated
Content-Type, Content-Length or grant header. The policy decides what an `unknown` is worth; the shipped demo
refuses every one. The proxy forwards only a request whose whole reading it could take, and sends the target it
read, never a rewrite of it.

The route table is the owner's. `{"routes": [{"match": "/admin/*", "class": "admin"}, ...]}`: the first entry
that matches wins; `/x/*` matches `/x` and everything below it, and an entry without `*` matches that path only.
Matching ignores case, since many servers do. A path no entry matches is `other`.

The grant is read by grants.py against the gateway's authority key, policy and revocation list, and covers a
path class and a method class. Without a verifier (a reading taken outside a gateway) a request with the grant
header reads `invalid`, since nothing can verify it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

READING_VERSION = 1
GRANT_HEADER = "X-PrismPath-Grant"
SMALL_BODY = 64 * 1024
MAX_BODY = 1024 * 1024
MAX_TARGET = 2048

METHOD_CLASSES = ("read", "write", "delete", "other", "unknown")
BODY_CLASSES = ("none", "small", "large", "oversize", "unknown")
CONTENT_CLASSES = ("none", "json", "form", "text", "other", "unknown")
QUERY_CLASSES = ("none", "present", "unknown")
GRANT_STATES = ("none", "valid", "invalid", "expired")
FIELDS = ("http_reading_version", "method_class", "path_class", "body_class", "content_class", "query", "grant")

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,16}$")
_PATH = re.compile(r"^/[A-Za-z0-9._~+=@:,/-]*$")
_QUERY = re.compile(r"^[\x21-\x7e]*$")
_DIGITS = re.compile(r"^[0-9]{1,12}$")
_CLASS = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_MEDIA = re.compile(r"^([A-Za-z0-9!#$&^_.+-]+)/([A-Za-z0-9!#$&^_.+-]+)\s*(;.*)?$")
_READ, _WRITE = ("GET", "HEAD"), ("POST", "PUT", "PATCH")


class RouteError(ValueError):
    pass


@dataclass(frozen=True)
class Routes:
    """The owner's route table, in order."""
    entries: Tuple[Tuple[str, bool, str], ...] = ()    # (lower case path, prefix, class)

    @classmethod
    def from_doc(cls, doc) -> "Routes":
        rows = doc.get("routes") if isinstance(doc, dict) and set(doc) == {"routes"} else None
        if not isinstance(rows, list):
            raise RouteError('the route table is {"routes": [{"match": "/admin/*", "class": "admin"}, ...]}')
        entries: List[Tuple[str, bool, str]] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"match", "class"}:
                raise RouteError(f"a route is {{\"match\": PATH, \"class\": NAME}}, not {row!r}")
            match, name = row["match"], row["class"]
            if not isinstance(match, str) or not isinstance(name, str):
                raise RouteError(f"a route's match and class are text, not {row!r}")
            prefix = match.endswith("/*")
            base = match[:-2] if prefix else match
            plain = (base == "" and prefix) or (base != "" and _PATH.match(base) and "//" not in base and (base == "/" or not base.endswith("/")))
            if not plain:
                raise RouteError(f"route {match!r} is not a path of plain characters, with `*` only as a closing `/*`")
            if not _CLASS.match(name) or name in ("unknown", "other"):
                raise RouteError(f"route class {name!r} must be lower case letters, digits and `_`, and not `other` or `unknown`")
            entries.append((base.lower(), prefix, name))
        return cls(tuple(entries))

    @classmethod
    def load(cls, path: Path) -> "Routes":
        return cls.from_doc(json.loads(Path(path).read_text(encoding="utf-8")))

    def canonical(self) -> bytes:
        """The table as canon/2 bytes, in order, with each path lower case, so the same table is the same bytes
        whatever its file's spacing or key order."""
        from prismpath.kernel import canon2
        return canon2.dumps({"routes": [{"match": base + ("/*" if prefix else ""), "class": name}
                                        for base, prefix, name in self.entries]})

    def digest(self) -> str:
        import hashlib
        return hashlib.sha256(self.canonical()).hexdigest()

    def classes(self) -> List[str]:
        return sorted({name for _p, _x, name in self.entries} | {"other", "unknown"})

    def classify(self, path: str) -> str:
        low = path.lower()
        for base, prefix, name in self.entries:
            if low == base or (prefix and (low.startswith(base + "/") or base == "")):
                return name
        return "other"


def method_class(method: Optional[str]) -> str:
    if not isinstance(method, str) or not _TOKEN.match(method):
        return "unknown"
    if method in _READ:
        return "read"
    if method in _WRITE:
        return "write"
    return "delete" if method == "DELETE" else "other"


def split_target(target: Optional[str]) -> Tuple[Optional[str], str]:
    """(path or None when it cannot be read, query class) of a request target."""
    if not isinstance(target, str) or len(target) > MAX_TARGET or not target.startswith("/"):
        return None, "unknown"
    path, mark, query = target.partition("?")
    if not mark:
        query_class = "none"
    elif query and _QUERY.match(query) and "#" not in query:
        query_class = "present"
    elif query == "":
        query_class = "none"
    else:
        query_class = "unknown"
    if not _PATH.match(path) or any(seg in (".", "..") for seg in path.split("/")) or "//" in path:
        return None, query_class
    return path, query_class


def content_class(values: Sequence[str]) -> str:
    if not values:
        return "none"
    if len(values) != 1:
        return "unknown"
    found = _MEDIA.match(values[0].strip())
    if not found:
        return "unknown"
    kind, sub = found.group(1).lower(), found.group(2).lower()
    if kind == "application" and (sub == "json" or sub.endswith("+json")):
        return "json"
    if kind == "application" and sub == "x-www-form-urlencoded":
        return "form"
    return "text" if kind == "text" else "other"


def declared_length(lengths: Sequence[str], transfer_encoding: Sequence[str]) -> Optional[int]:
    """The body length a request declares, 0 when it declares none, None when it cannot be read."""
    if transfer_encoding or len(lengths) > 1:
        return None
    if not lengths:
        return 0
    return int(lengths[0]) if _DIGITS.match(lengths[0]) else None


def body_class(length: Optional[int]) -> str:
    if length is None:
        return "unknown"
    if length == 0:
        return "none"
    return "small" if length <= SMALL_BODY else "large" if length <= MAX_BODY else "oversize"


def grant_state(values: Sequence[str]) -> str:
    """The grant of a request read without a verifier: none without the header, invalid with it."""
    return "none" if not values else "invalid"


UNREADABLE: Dict[str, object] = {
    "http_reading_version": READING_VERSION, "method_class": "unknown", "path_class": "unknown",
    "body_class": "unknown", "content_class": "unknown", "query": "unknown", "grant": "invalid"}


def read_request(method: Optional[str], target: Optional[str], headers: Mapping[str, Sequence[str]],
                 routes: Routes, body_length: Optional[int], grants=None) -> Dict[str, object]:
    """The reading of a request. `headers` maps a lower case name to every value sent under it; `body_length` is
    the length of the body the proxy actually holds (None when it could not take it); `grants` is the gateway's
    grants.Verifier, or None."""
    return read(method, target, headers, routes, body_length, grants)[0]


def read(method: Optional[str], target: Optional[str], headers: Mapping[str, Sequence[str]],
         routes: Routes, body_length: Optional[int], grants=None) -> Tuple[Dict[str, object], Optional[Dict[str, str]]]:
    """(reading, grant record) of a request; the record is what the receipt's journal line keeps of the grant."""
    path, query = split_target(target)
    methods = method_class(method)
    paths = "unknown" if path is None else routes.classify(path)
    values = headers.get(GRANT_HEADER.lower(), ())
    if grants is None:
        grant, record = grant_state(values), None
    else:
        grant, record = grants.read(values, paths, methods)
    return ({"http_reading_version": READING_VERSION, "method_class": methods, "path_class": paths,
             "body_class": body_class(body_length), "content_class": content_class(headers.get("content-type", ())),
             "query": query, "grant": grant}, record)
