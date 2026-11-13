# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The protocol's encoder and its strict reader."""
import pytest

from integrations.governed_net import protocol as p


def enc(**kw):
    base = dict(cmd=p.READ, request_id=5, hclass=p.H_WS_FILE, handle=9, arg0=0, arg1=100)
    base.update(kw)
    return p.encode(p.Request(**base))


def bad(raw, reason):
    with pytest.raises(p.Malformed) as caught:
        p.decode(raw)
    assert caught.value.reason == reason


def test_round_trip_every_command():
    cases = [p.Request(cmd=p.LIST, request_id=1, hclass=p.H_WS_DIR, handle=1),
             p.Request(cmd=p.READ, request_id=2, hclass=p.H_WS_FILE, handle=3, arg0=10, arg1=4096),
             p.Request(cmd=p.WRITE, request_id=3, hclass=p.H_WS_FILE, handle=3, data=b"hello"),
             p.Request(cmd=p.CREATE, request_id=4, hclass=p.H_WS_DIR, handle=1, name=b"new.txt", data=b"x"),
             p.Request(cmd=p.DELETE, request_id=5, hclass=p.H_WS_FILE, handle=3),
             p.Request(cmd=p.RUN, request_id=6, hclass=p.H_WS_FILE, handle=3, arg0=1),
             p.Request(cmd=p.GIT_STATUS, request_id=7), p.Request(cmd=p.GIT_LOG, request_id=8, arg0=3),
             p.Request(cmd=p.GIT_COMMIT, request_id=9, data=b"msg"), p.Request(cmd=p.GIT_PUSH, request_id=10, arg0=1),
             p.Request(cmd=p.GIT_FETCH, request_id=2 ** 64 - 1, arg0=1)]
    for req in cases:
        raw = p.encode(req)
        assert len(raw) == p.HEADER_LEN + len(req.name) + len(req.data)
        assert p.decode(raw) == req


def test_short_trailing_and_truncated():
    raw = enc()
    bad(raw[:31], "short")
    bad(b"", "short")
    bad(raw + b"\x00", "length")
    bad(enc(cmd=p.WRITE, arg1=0, data=b"abc")[:-1], "length")


def test_header_fields():
    bad(enc(magic=0x474E4555), "magic")
    bad(enc(version=0), "version")
    bad(enc(version=2), "version")
    bad(enc(cmd=0), "command")
    bad(enc(cmd=12), "command")
    bad(enc(cmd=255), "command")
    bad(enc(flags=1), "reserved")
    bad(enc(reserved=1), "reserved")
    bad(enc(request_id=0), "request-id")
    bad(enc(arg1=2 ** 31), "arg-range")
    bad(enc(arg0=2 ** 32 - 1), "arg-range")
    assert p.decode(enc(arg1=2 ** 31 - 1)).arg1 == 2 ** 31 - 1


def test_lengths():
    bad(p.encode(p.Request(cmd=p.CREATE, request_id=1, hclass=2, handle=1, name=b"a" * 65)), "name-length")
    bad(p.encode(p.Request(cmd=p.WRITE, request_id=1, hclass=1, handle=1, data=b"a" * 1025)), "data-length")
    assert p.decode(p.encode(p.Request(cmd=p.WRITE, request_id=1, hclass=1, handle=1, data=b"a" * 1024)))


def test_unused_fields_must_be_zero():
    bad(enc(cmd=p.GIT_STATUS, hclass=0, handle=1, arg1=0), "unused-field")
    bad(enc(cmd=p.GIT_STATUS, hclass=1, handle=0, arg1=0), "unused-field")
    bad(enc(cmd=p.LIST, hclass=2, handle=1, arg0=1, arg1=0), "unused-field")
    bad(enc(cmd=p.RUN, arg0=1, arg1=1), "unused-field")
    bad(p.encode(p.Request(cmd=p.WRITE, request_id=1, hclass=1, handle=1, name=b"x")), "unused-field")
    bad(p.encode(p.Request(cmd=p.DELETE, request_id=1, hclass=1, handle=1, data=b"x")), "unused-field")


@pytest.mark.parametrize("name", [b".", b"..", b".hidden", b"a/b", b"/etc", b"-rf", b"a b", b"a*", b"~x", b"\xc3\xa9", b"a\x00"])
def test_names_that_are_not_one_plain_component(name):
    bad(p.encode(p.Request(cmd=p.CREATE, request_id=1, hclass=2, handle=1, name=name)), "name-char")


@pytest.mark.parametrize("name", [b"a", b"notes.txt", b"_x-1.2", b"A" * 64, b"0"])
def test_good_names(name):
    assert p.decode(p.encode(p.Request(cmd=p.CREATE, request_id=1, hclass=2, handle=1, name=name))).name == name


def test_reading_holds_only_integers_and_every_field():
    req = p.decode(enc())
    reading = req.reading()
    assert tuple(sorted(reading)) == tuple(sorted(p.SCHEMA))
    assert all(type(value) is int for value in reading.values())
    assert req.reading(hclass=3)["hclass"] == 3


def test_replies_and_listings():
    rep = p.Reply(p.REFUSED, 77, 107, 4, b"why")
    assert p.decode_reply(p.encode_reply(rep)) == rep
    with pytest.raises(p.Malformed):
        p.decode_reply(p.encode_reply(rep) + b"x")
    entries = [(p.H_WS_FILE, 0x10, "a.txt"), (p.H_TC_DIR, 0x11, ".toolchain")]
    assert p.decode_listing(p.encode_listing(entries)) == entries


def test_reasons_match_the_xdp_numbers():
    from pathlib import Path
    text = (Path(p.__file__).resolve().parents[2] / "prismpath-ebpf" / "gnet" / "gn_common.h").read_text()
    for code, name in p.REASONS.items():
        macro = "GN_BAD_" + name.upper().replace("-", "_")
        if name == "unused-field":
            macro = "GN_BAD_UNUSED"
        assert f"#define {macro} {code}u" in text, macro
    assert f"#define GN_PORT        {p.PORT}u" in text
