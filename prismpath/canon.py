# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canon: the shared byte level helpers every persisted or signed artifact is built from.

Every document PrismPath hashes or signs is canon/2, the integer only JCS profile of
`prismpath.kernel.canon2`, and names it: the document carries `"encoding": "canon/2"` (`ENCODING_KEY`,
`CANON2`), its hash is sha256 over its canon/2 bytes, and a signature over it is computed over
`CANON2_DOMAIN` followed by those bytes, unless its own format names a domain of its own (a root
statement, a core run's records). canon/1, the earlier Python `json` encodings, is retired: nothing
writes it and nothing reads it, so a document with no tag, or any tag but canon/2, is refused with
`EncodingError` and never read under another encoding (docs/design/spec-verified-core.md, section 3.1).
`document_bytes` and `signed_message` are that rule; `canon2_bytes` and `tagged` are the writer's side;
`content_bytes` hashes content PrismPath did not write.

JSON that is not hashed and not signed (a durable run checkpoint, the connector's JSONL sink lines, the
flow authority's version floor file) is read and written with `plain_loads`, `plain_load` and
`plain_dumps`. The document `plain_loads` reads is marked (`PlainDict`), and every hashing helper in this
module refuses a value that holds the mark (`PlainJSONRefused`), so such a document never reaches a hash or
a signature; what is taken out of it is content, and is hashed as content (`content_bytes`).

Truncations, the `sha256:` prefix, and hex versus raw byte concatenation are properties of specific
artifacts and stay at the call sites that own them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Optional


class CanonicalError(ValueError):
    """A value that has no canonical JSON form: NaN, Infinity, -Infinity, or a string holding a lone
    surrogate. Canonical bytes are what signatures, Merkle leaves and content hashes are computed over,
    so a value that cannot be written the same way by every implementation is refused, never converted."""


class CanonicalReadError(CanonicalError, json.JSONDecodeError):
    """The reading side of `CanonicalError`: a document holds a NaN or Infinity token, a number beyond
    the double range (`1e400`), or a lone surrogate. It is also a `json.JSONDecodeError`, so every
    caller that already refuses an unparseable document refuses this one the same way."""

    def __init__(self, message: str):
        json.JSONDecodeError.__init__(self, message, "", 0)
        self.args = (message,)

    def __str__(self) -> str:
        return self.msg


def _surrogate_free(obj: Any) -> None:
    """Raise CanonicalError when any string or key inside `obj` holds a lone surrogate. Only called
    after `json.dumps` has accepted the object, so it cannot be circular."""
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _LONE_SURROGATE.search(item):
                raise CanonicalError("string holds a lone surrogate, which has no UTF-8 or canonical JSON form")
        elif isinstance(item, dict):
            for key, value in item.items():
                if isinstance(key, str) and _LONE_SURROGATE.search(key):
                    raise CanonicalError("object key holds a lone surrogate, which has no UTF-8 or canonical JSON form")
                stack.append(value)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


CANON2 = "canon/2"
ENCODING_KEY = "encoding"
CANON2_DOMAIN = b"prismpath.canon/2\x00"


class EncodingError(CanonicalError):
    """A document names an encoding PrismPath does not read (anything but `canon/2`, a tag that is not a
    string, or no tag at all: canon/1 is retired), or a canon/2 document that canon/2 does not read (a
    float, a duplicate key, an integer beyond plus or minus 2^53 minus 1). It is refused, never read
    under another encoding."""


class PlainJSONRefused(CanonicalError):
    """A value read by `plain_loads` (JSON that is not hashed and not signed) reached a hashing helper."""


class PlainDict(dict):
    """The JSON object `plain_loads` reads (the document itself, not the values inside it). Every hashing
    helper in this module refuses a value that holds one, so a checkpoint, a sink line or a version floor
    file can never be hashed or signed by mistake."""


def _refuse_plain(obj: Any) -> None:
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, PlainDict):
            raise PlainJSONRefused("a value read as plain JSON (a checkpoint, a sink line, a version floor file) "
                                   "is never hashed or signed; build the document that is hashed from its fields")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


class FloatRefused(EncodingError):
    """A float in content that is hashed or signed. canon/2 has no float, and PrismPath never writes one
    as a decimal string of its own making: the caller supplies an integer of a stated unit or a decimal
    string it chose."""


_FLOAT_MESSAGE = ("a float is refused in hashed content: supply an integer of a stated unit "
                  "(microseconds, basis points, bytes) or a decimal string")


def canon2_bytes(obj: Any) -> bytes:
    """The canon/2 bytes of `obj`: what every writer hashes and signs. A float, an integer beyond plus or
    minus 2^53 minus 1, a lone surrogate or nesting deeper than 128 raise EncodingError (a
    CanonicalError), never a conversion."""
    from prismpath.kernel import canon2
    _refuse_plain(obj)
    try:
        return canon2.dumps(obj)
    except canon2.Canon2Error as error:
        if error.rule == "float":
            raise FloatRefused(_FLOAT_MESSAGE) from error
        raise EncodingError(f"no canon/2 form: {error}") from error


def tagged(doc: dict) -> dict:
    """`doc` with `"encoding": "canon/2"`, the member that tells every reader which encoding hashes it. A
    document read as plain JSON is refused (`PlainJSONRefused`): it is built again from its fields."""
    _refuse_plain(doc)
    return {**doc, ENCODING_KEY: CANON2}


def encoding_of(doc: Any) -> str:
    """`canon/2` for an object that names it. Raises EncodingError for any other tag, for a document with
    no tag (canon/1, retired) and for a value that is not an object."""
    if not isinstance(doc, dict) or ENCODING_KEY not in doc:
        raise EncodingError('a document without "encoding": "canon/2" is refused: canon/1 is retired and is '
                            'not read, hashed or verified')
    if doc[ENCODING_KEY] == CANON2:
        return CANON2
    raise EncodingError(f"unknown encoding {str(doc[ENCODING_KEY])[:40]!r}: only canon/2 is read")


def document_bytes(doc: Any) -> bytes:
    """The bytes a document is hashed over: its canon/2 bytes. Raises EncodingError for a document that
    does not name canon/2 and PlainJSONRefused for one read as plain JSON."""
    _refuse_plain(doc)
    encoding_of(doc)
    return canon2_bytes(doc)


def signed_message(doc: Any) -> bytes:
    """What a signature over `doc` covers when its format has no domain of its own: `CANON2_DOMAIN` and
    the canon/2 bytes. Raises EncodingError for a document that does not name canon/2 and PlainJSONRefused for
    one read as plain JSON."""
    _refuse_plain(doc)
    encoding_of(doc)
    return CANON2_DOMAIN + canon2_bytes(doc)


def document_hash(doc: Any) -> str:
    """sha256 hex over `document_bytes(doc)`."""
    return sha256_hex(document_bytes(doc))


def _content_value(value: Any, default: Optional[Any], depth: int = 0) -> Any:
    if depth > 128:
        raise EncodingError("no canon/2 form: nesting deeper than 128")
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        raise FloatRefused(_FLOAT_MESSAGE)
    if isinstance(value, (list, tuple)):
        return [_content_value(item, default, depth + 1) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                # json.dumps's own spelling of the key types it accepts; any other key is a TypeError
                if key is None or isinstance(key, bool):
                    key = {None: "null", True: "true", False: "false"}[key]
                elif isinstance(key, float):
                    raise FloatRefused(_FLOAT_MESSAGE)
                elif isinstance(key, int):
                    key = str(key)
                else:
                    raise TypeError(f"keys must be str, int, float, bool or None, not {type(key).__name__}")
            out[key] = _content_value(item, default, depth + 1)
        return out
    if default is None:
        raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
    return _content_value(default(value), default, depth + 1)


def content_bytes(value: Any, default: Optional[Any] = None) -> bytes:
    """The canon/2 bytes of content PrismPath hashes but did not write: an item a worker returned, a
    proof value, a connector's data. canon/2 has no float and PrismPath does not invent a spelling for
    one, so a float anywhere in the content (a value or an object key, NaN and the infinities included)
    raises `FloatRefused`, an `EncodingError`; the caller supplies an integer of a stated unit or a
    decimal string. `default` stringifies a value that is not JSON (a path, an object), and its product is held to the
    same rule."""
    _refuse_plain(value)
    return canon2_bytes(_content_value(value, default))


def loads_document(text: Any) -> Any:
    """Read a document that is hashed or signed: an object that names canon/2, read by the strict canon/2
    reader (a float, a duplicate key, an out of range integer or a lone surrogate is refused). Anything
    else, an untagged object, another tag, or a value that is not an object, raises CanonicalReadError, a
    json.JSONDecodeError."""
    from prismpath.kernel import canon2
    try:
        probe = json.loads(text)             # only to name the tag; the value read is canon/2's own
    except ValueError:
        probe = None
    if isinstance(probe, dict):
        try:
            encoding_of(probe)
        except EncodingError as error:
            raise CanonicalReadError(str(error)) from error
    try:
        value = canon2.loads(text)
    except canon2.Canon2Error as error:
        raise CanonicalReadError(f"a document that is read as canon/2 does not read under it: {error}") from error
    if not isinstance(value, dict):
        raise CanonicalReadError("a document that is hashed or signed is a JSON object")
    return value


def plain_dumps(obj: Any, **kwargs: Any) -> str:
    """`json.dumps` for JSON that is written to disk and is not hashed or signed (a durable run checkpoint,
    a sink line): the same keyword arguments, but NaN, Infinity and lone surrogates raise CanonicalError."""
    kwargs["allow_nan"] = False
    try:
        text = json.dumps(obj, **kwargs)
    except ValueError as error:
        if "Out of range float" in str(error):
            raise CanonicalError("NaN, Infinity and -Infinity have no JSON form") from error
        raise
    _surrogate_free(obj)
    return text


def _refuse_constant(token: str) -> Any:
    raise CanonicalReadError(f"{token} is not allowed: JSON has no non finite numbers")


def _finite_float(text: str) -> float:
    number = float(text)
    if number in (float("inf"), float("-inf")):
        raise CanonicalReadError(f"number {text[:24]} is beyond the double range and is refused, not read as infinity")
    return number


def plain_loads(text: Any, *, mark: bool = True, **kwargs: Any) -> Any:
    """`json.loads` for JSON that is neither hashed nor signed: a NaN, Infinity or -Infinity token, a number
    beyond the double range and a lone surrogate raise CanonicalReadError (a json.JSONDecodeError). A document
    that is an object is returned as a `PlainDict`, which no hashing helper accepts (`mark=False` returns an
    ordinary dict, for content: `loads_content`)."""
    kwargs.setdefault("parse_constant", _refuse_constant)
    kwargs.setdefault("parse_float", _finite_float)
    value = json.loads(text, **kwargs)
    try:
        _surrogate_free(value)
    except CanonicalError as error:
        raise CanonicalReadError(str(error)) from error
    return PlainDict(value) if mark and type(value) is dict else value


def loads_content(text: Any, **kwargs: Any) -> Any:
    """Read JSON that PrismPath did not write and may hash afterwards as content (`content_bytes`): a model's
    reply, data a connector fetched. The same refusals as `plain_loads`, and no `PlainDict` mark, because
    this is content, not a checkpoint or a sink line."""
    return plain_loads(text, mark=False, **kwargs)


def plain_load(handle: Any, **kwargs: Any) -> Any:
    """`plain_loads` over an open file."""
    return plain_loads(handle.read(), **kwargs)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    """`sha256:<hex>`, the string form checkpoints, locks, and the connector persist."""
    return "sha256:" + sha256_hex(data)


def file_sha256_prefixed(path) -> str:
    """Content hash of a file as `sha256:<hex>`; raises OSError like open() does."""
    with open(path, "rb") as f:
        return sha256_prefixed(f.read())


def manifest_hash(m: dict) -> str:
    """The content address of an attestation manifest: sha256 over the canon/2 bytes of every field except
    `manifest_hash` itself (ledger_airgap and the fixture generators share this). A manifest that does not
    name canon/2 is refused."""
    _refuse_plain(m)
    encoding_of(m)
    return sha256_hex(canon2_bytes({k: m[k] for k in m if k != "manifest_hash"}))


def atomic_write(path, data: str, encoding: str = "utf-8") -> None:
    """Write text so a reader sees the old file or the new one, never a torn one: parent directory
    created, temp file beside the target, flushed and fsynced, then os.replace."""
    path = os.fspath(path)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding=encoding) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def atomic_write_bytes(path, data: bytes) -> None:
    """`atomic_write` for bytes: the old file or the new one, never a torn one."""
    path = os.fspath(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def safe_name(name: str) -> str:
    """Filesystem safe and deliberately NOT injective (composer disambiguates with a hash when it
    matters): every character outside [A-Za-z0-9_.-] becomes `_`; empty becomes `flow`."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "flow"
