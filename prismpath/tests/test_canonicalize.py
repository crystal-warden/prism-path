# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The canonicalize path (docs/design/spec-verified-core.md, section 3.2): every reader of a hashed or signed
document refuses any spelling but the exact canonical canon/2 bytes, and a document a person wrote reaches a
reader through `canon.canonicalize_document` or `prismpath canonicalize`, which keep every other canon/2 rule."""
import json

import pytest

from prismpath import canon, cli
from prismpath.kernel import canon2

HUMAN = b'{\n  "encoding": "canon/2",\n  "name": "\\u0041pple",\n  "a": [1, 2,  3]\n}\n'
CANONICAL = b'{"a":[1,2,3],"encoding":"canon/2","name":"Apple"}'


def test_a_human_document_is_refused_until_canonicalized():
    with pytest.raises(canon.NotCanonical) as raised:
        canon.loads_document(HUMAN)
    assert canon.NotCanonical.CAUSE == "document:not-canonical"
    assert "document:not-canonical" in str(raised.value)
    written = canon.canonicalize_document(HUMAN)
    assert written == CANONICAL
    assert canon.loads_document(written) == json.loads(HUMAN)
    assert canon.loads_document(written + b"\n") == json.loads(HUMAN)       # the one terminator a file ends with
    assert canon.canonicalize_document(written) == written


@pytest.mark.parametrize("text", [CANONICAL + b"\r\n", CANONICAL + b"\n\n", b" " + CANONICAL, CANONICAL + b" "])
def test_only_one_line_feed_is_taken_off(text):
    with pytest.raises(canon.NotCanonical):
        canon.loads_document(text)


@pytest.mark.parametrize("text,error", [(b'{"encoding":"canon/2","x": 1.5}', canon.FloatRefused),
                                        (b'{"a":1,"a":2}', canon.EncodingError),
                                        (b'{"x": 9007199254740992}', canon.EncodingError),
                                        (b"\xff", canon.EncodingError)])
def test_canonicalize_keeps_every_other_rule(text, error):
    with pytest.raises(error):
        canon.canonicalize_document(text)


def test_the_cli_writes_checks_and_rewrites(tmp_path, capsysbinary):
    path = tmp_path / "doc.json"
    path.write_bytes(HUMAN)
    assert cli.main(["canonicalize", str(path)]) == 0
    assert capsysbinary.readouterr().out == CANONICAL + b"\n"
    assert cli.main(["canonicalize", "--check", str(path)]) == 1
    out = tmp_path / "out.json"
    assert cli.main(["canonicalize", str(path), "--out", str(out)]) == 0
    assert out.read_bytes() == CANONICAL + b"\n"
    assert path.read_bytes() == HUMAN
    assert cli.main(["canonicalize", "--in-place", str(path)]) == 0
    assert path.read_bytes() == CANONICAL + b"\n"
    assert cli.main(["canonicalize", "--check", str(path)]) == 0
    assert canon.loads_document(path.read_bytes()) == json.loads(HUMAN)


def test_the_cli_refuses_a_document_with_no_canon2_form(tmp_path, capsys):
    path = tmp_path / "doc.json"
    path.write_bytes(b'{"x": 0.5}')
    assert cli.main(["canonicalize", str(path)]) == 2
    assert "float" in capsys.readouterr().err
    assert path.read_bytes() == b'{"x": 0.5}'


def test_canonicalize_and_the_strict_reader_agree_with_the_kernel():
    assert canon2.canonicalize(HUMAN) == CANONICAL
    with pytest.raises(canon2.Canon2Error) as raised:
        canon2.loads(HUMAN)
    assert raised.value.rule == "not-canonical"
