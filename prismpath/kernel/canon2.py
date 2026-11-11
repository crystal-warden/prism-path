# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canon2: the canon/2 document reader and writer, the one encoding of the verified core's documents.

canon/2 is the integer only profile of RFC 8785 (JCS) that docs/design/spec-verified-core.md section 3
specifies and the Lean reader `Core.readBytes` (formal/Core/Json.lean) defines. A policy image and a
reading of the core are canon/2 documents, and this module is the reference reader and writer for them;
`prismpath-rs/src/canon2.rs` is its Rust twin, held to the same frozen vectors
(`prismpath/portable/conformance/canon2.json`).

`loads` is the strict reader (the Lean `Core.readCanonical`): it accepts exactly the canonical bytes of a
canon/2 value and nothing else. A text is first read as canon/2: JSON (RFC 8259) whose numbers are
integers within plus or minus 2^53 minus 1 written without a fraction, an exponent or a negative zero,
whose objects hold no key twice, whose strings hold no lone surrogate escape, and whose arrays and objects
nest at most 128 deep. A text that breaks one of these raises `Canon2Error` with `rule` set to the first
rule broken reading left to right, the same rule the Lean reader names: `utf8`, `syntax`, `float`,
`integer-range`, `negative-zero`, `duplicate-key`, `lone-surrogate` or `depth`. A text that reads but is
not the canonical spelling of its value (whitespace, members out of key order, a needless escape) raises
`Canon2Error` with `rule` `not-canonical`: it is refused, never re-canonicalized.

`dumps` writes the canonical bytes: no whitespace, object members sorted by the UTF-16 code units of
their keys, strings raw UTF-8 with only `"`, `\\` and the control characters escaped (`\\b \\t \\n \\f \\r`,
otherwise lowercase `\\u00xx`), integers in decimal. It refuses every value `loads` could not read back,
so `loads(dumps(v)) == v` for every value it writes.

`canonicalize` is the one path for text a person wrote: it reads the text by the rules above but for
the spelling (whitespace, member order and escapes are allowed) and returns the canonical bytes of its
value, which `loads` then accepts. It is a writer's step, taken before a document is hashed, signed or
handed to a reader; no reader calls it (the Lean `Core.canonicalize`).

canon/1 (Python's own `json` with the compact and spaced forms) is retired: this is the one encoding of
everything PrismPath hashes or signs, and `prismpath.canon` applies it to every document (section 3.1 of
the spec).
"""
from __future__ import annotations

from typing import Any, List, Tuple

EXACT_LIMIT = 2 ** 53 - 1
MAX_DEPTH = 128

RULES = ("utf8", "syntax", "float", "integer-range", "negative-zero", "duplicate-key", "lone-surrogate",
         "depth", "not-canonical")

_WS = " \t\n\r"
_DIGITS = "0123456789"
_HEX = "0123456789abcdefABCDEF"
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class Canon2Error(ValueError):
    """A text that is not a canon/2 document, or a value that has no canon/2 form. `rule` is one of
    RULES, the first rule broken reading left to right."""

    def __init__(self, rule: str, detail: str = ""):
        assert rule in RULES, rule
        super().__init__(f"canon/2 {rule}" + (f": {detail}" if detail else ""))
        self.rule = rule


# ----------------------------------------------------------------- reading
class _Reader:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def skip_ws(self) -> None:
        text, pos = self.text, self.pos
        while pos < len(text) and text[pos] in _WS:
            pos += 1
        self.pos = pos

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def value(self, depth: int) -> Any:
        self.skip_ws()
        text, pos = self.text, self.pos
        char = self.peek()
        if text.startswith("null", pos):
            self.pos += 4
            return None
        if text.startswith("true", pos):
            self.pos += 4
            return True
        if text.startswith("false", pos):
            self.pos += 5
            return False
        if char == '"':
            self.pos += 1
            return self.string()
        if char == "-":
            self.pos += 1
            return self.number(True)
        if char == "[":
            if depth + 1 > MAX_DEPTH:
                raise Canon2Error("depth")
            self.pos += 1
            self.skip_ws()
            if self.peek() == "]":
                self.pos += 1
                return []
            items = [self.value(depth + 1)]
            while True:
                self.skip_ws()
                char = self.peek()
                if char == "]":
                    self.pos += 1
                    return items
                if char != ",":
                    raise Canon2Error("syntax", f"expected , or ] at {self.pos}")
                self.pos += 1
                items.append(self.value(depth + 1))
        if char == "{":
            if depth + 1 > MAX_DEPTH:
                raise Canon2Error("depth")
            self.pos += 1
            self.skip_ws()
            if self.peek() == "}":
                self.pos += 1
                return {}
            members: dict = {}
            while True:
                self.skip_ws()
                if self.peek() != '"':
                    raise Canon2Error("syntax", f"expected a key at {self.pos}")
                self.pos += 1
                key = self.string()
                if key in members:
                    raise Canon2Error("duplicate-key", repr(key)[:40])
                self.skip_ws()
                if self.peek() != ":":
                    raise Canon2Error("syntax", f"expected : at {self.pos}")
                self.pos += 1
                members[key] = self.value(depth + 1)
                self.skip_ws()
                char = self.peek()
                if char == "}":
                    self.pos += 1
                    return members
                if char != ",":
                    raise Canon2Error("syntax", f"expected , or }} at {self.pos}")
                self.pos += 1
        if char and char in _DIGITS:
            return self.number(False)
        raise Canon2Error("syntax", f"unexpected {char!r} at {pos}" if char else "unexpected end")

    def _hex4(self, at: int):
        """The value of four characters at `at` as hex, None when they are not hex, or the string 'short'
        when fewer than four characters remain."""
        chunk = self.text[at:at + 4]
        if len(chunk) < 4:
            return "short"
        if all(c in _HEX for c in chunk):
            return int(chunk, 16)
        return None

    def string(self) -> str:
        text = self.text
        out: List[str] = []
        while True:
            if self.pos >= len(text):
                raise Canon2Error("syntax", "unterminated string")
            char = text[self.pos]
            if char == '"':
                self.pos += 1
                return "".join(out)
            if char == "\\" and self.pos + 1 < len(text):
                escape = text[self.pos + 1]
                if escape == "u" and self.pos + 6 <= len(text):
                    high = self._hex4(self.pos + 2)
                    if high is None:
                        raise Canon2Error("syntax", "bad \\u escape")
                    if 0xD800 <= high <= 0xDBFF:
                        after = self.pos + 6
                        if text.startswith("\\u", after) and after + 6 <= len(text):
                            low = self._hex4(after + 2)
                            if low is None:
                                raise Canon2Error("syntax", "bad \\u escape")
                            if 0xDC00 <= low <= 0xDFFF:
                                out.append(chr(0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00)))
                                self.pos = after + 6
                                continue
                        raise Canon2Error("lone-surrogate")
                    if 0xDC00 <= high <= 0xDFFF:
                        raise Canon2Error("lone-surrogate")
                    out.append(chr(high))
                    self.pos += 6
                    continue
                if escape in _ESCAPES and escape != "u":
                    out.append(_ESCAPES[escape])
                    self.pos += 2
                    continue
                raise Canon2Error("syntax", "bad escape")
            if ord(char) < 0x20:
                raise Canon2Error("syntax", "control character in a string")
            out.append(char)
            self.pos += 1

    def _digits(self) -> str:
        text, start = self.text, self.pos
        pos = start
        while pos < len(text) and text[pos] in _DIGITS:
            pos += 1
        self.pos = pos
        return text[start:pos]

    def number(self, negative: bool) -> int:
        char = self.peek()
        if char == "0":
            self.pos += 1
            digits = "0"
        elif char and char in _DIGITS:
            digits = self._digits()
        else:
            raise Canon2Error("syntax", "a number needs a digit")
        fraction = exponent = False
        if self.peek() == ".":
            self.pos += 1
            if not self._digits():
                raise Canon2Error("syntax", "a fraction needs a digit")
            fraction = True
        if self.peek() in ("e", "E") and self.peek():
            self.pos += 1
            if self.peek() in ("+", "-") and self.peek():
                self.pos += 1
            if not self._digits():
                raise Canon2Error("syntax", "an exponent needs a digit")
            exponent = True
        if fraction or exponent:
            raise Canon2Error("float", "a number with a fraction or an exponent")
        if negative and digits == "0":
            raise Canon2Error("negative-zero")
        if len(digits) > 16:                   # past 2^53 whatever the digits, and int() is never asked
            raise Canon2Error("integer-range", digits[:24])
        value = int(digits)
        if negative:
            value = -value
        if not -EXACT_LIMIT <= value <= EXACT_LIMIT:
            raise Canon2Error("integer-range", digits[:24])
        return value


def _read(data: Any, caller: str) -> Tuple[Any, bytes]:
    """The value of `data` read by every canon/2 rule but the spelling, and the bytes it was read from."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise Canon2Error("utf8", str(error)[:80]) from None
    elif isinstance(data, str):
        text = data
        if any(0xD800 <= ord(c) <= 0xDFFF for c in text):
            raise Canon2Error("utf8", "the text holds a surrogate code point, which has no UTF-8 form")
        raw = text.encode("utf-8")
    else:
        raise TypeError(f"canon2.{caller} takes bytes or str, not {type(data).__name__}")
    reader = _Reader(text)
    value = reader.value(0)
    reader.skip_ws()
    if reader.pos != len(text):
        raise Canon2Error("syntax", f"trailing text at {reader.pos}")
    return value, raw


def loads(data: Any) -> Any:
    """The canon/2 document in `data` (bytes, which are decoded as strict UTF-8 first, or an already
    decoded str) as dict, list, str, int, bool or None, when `data` is exactly the canonical spelling of
    that value. Raises Canon2Error: the first rule broken, or `not-canonical` for a document spelled any
    other way."""
    value, raw = _read(data, "loads")
    if dumps(value) != raw:
        raise Canon2Error("not-canonical", "the document reads as canon/2 but is not its canonical spelling; "
                          "write it through canonicalize first")
    return value


# ----------------------------------------------------------------- writing
def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _write_string(text: str, out: List[str]) -> None:
    out.append('"')
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append({0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}.get(code, f"\\u{code:04x}"))
        elif 0xD800 <= code <= 0xDFFF:
            raise Canon2Error("lone-surrogate", "a string holds a lone surrogate")
        else:
            out.append(char)
    out.append('"')


def _write(value: Any, depth: int, out: List[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not -EXACT_LIMIT <= value <= EXACT_LIMIT:
            raise Canon2Error("integer-range", "an integer beyond plus or minus 2^53 minus 1; write it as a decimal string")
        out.append(str(int(value)))
    elif isinstance(value, float):
        raise Canon2Error("float", "canon/2 has no float; write a decimal string or an integer of a stated unit")
    elif isinstance(value, str):
        _write_string(value, out)
    elif isinstance(value, (list, tuple)):
        if depth + 1 > MAX_DEPTH:
            raise Canon2Error("depth")
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, depth + 1, out)
        out.append("]")
    elif isinstance(value, dict):
        if depth + 1 > MAX_DEPTH:
            raise Canon2Error("depth")
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"canon/2 object keys are strings, not {type(key).__name__}")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                out.append(",")
            _write_string(key, out)
            out.append(":")
            _write(value[key], depth + 1, out)
        out.append("}")
    else:
        raise TypeError(f"{type(value).__name__} has no canon/2 form")


def dumps(value: Any) -> bytes:
    """The canonical canon/2 bytes of `value`. Raises Canon2Error for a float, an integer beyond plus or
    minus 2^53 minus 1, a lone surrogate or nesting deeper than 128, and TypeError for anything that is
    not JSON."""
    out: List[str] = []
    _write(value, 0, out)
    return "".join(out).encode("utf-8")


def canonicalize(data: Any) -> bytes:
    """The canonical bytes of the canon/2 value a person wrote in `data`, in any legal spelling
    (whitespace, member order, escapes). Every other rule holds as in `loads` (a float, a duplicate key,
    an integer out of range, a lone surrogate, nesting past 128 and bad UTF-8 raise Canon2Error); the
    result is what `loads` accepts. A writer's step, never a reader's."""
    value, _raw = _read(data, "canonicalize")
    return dumps(value)


def rule_of(data: Any) -> Tuple[bool, str]:
    """(True, '') when the strict reader accepts `data`, else (False, rule). A convenience for vectors and
    the harness."""
    try:
        loads(data)
    except Canon2Error as error:
        return False, error.rule
    return True, ""
