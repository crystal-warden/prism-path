"""R9a: the sealing tool is a function from inputs to sealed envelopes, and `dist seal` is a thin caller of it."""

import io
import json
from contextlib import redirect_stdout

import pytest

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import seal
from prismpath.distribution.kinds import Refused
from prismpath.tests import _dist
from prismpath.tests._dist import GEN, STREAM

BODY = _dist.image(5)
NOT_BEFORE = _dist.NOT_BEFORE


def _call(**more):
    inputs = dict(stream=STREAM, seq=1, targets=["host"], signers=[GEN.test_key("A")], not_before=NOT_BEFORE,
                  expires=NOT_BEFORE + 3600, meta=GEN.image_meta(BODY))
    inputs.update(more)
    return seal.seal_release("policy.ppt", BODY, **inputs)


def test_a_fixed_input_seals_to_the_same_bytes_and_a_first_release_widens():
    first, second = _call(), _call()
    assert first.sealed == second.sealed
    assert first.widens and first.replaces == "" and first.change is None
    release = env.read(env.unseal(first.sealed)[0])
    assert release.body_sha256 == canon.sha256_hex(BODY) and release.stream == STREAM and release.seq == 1


def test_the_command_writes_the_bytes_the_function_returns(tmp_path):
    from cryptography.hazmat.primitives import serialization as ser
    from prismpath import cli
    pem = tmp_path / "A.pem"
    pem.write_bytes(GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    body, out, meta = tmp_path / "p.ppt", tmp_path / "p.sealed", tmp_path / "meta.json"
    body.write_bytes(BODY)
    meta.write_text(json.dumps(GEN.image_meta(BODY)))
    args = cli.build_parser().parse_args([
        "dist", "seal", "--artifact", "policy.ppt", "--body", str(body), "--stream", STREAM, "--seq", "1",
        "--target", "host", "--not-before", str(NOT_BEFORE), "--expires", str(NOT_BEFORE + 3600), "--key", str(pem),
        "--meta", str(meta), "--out", str(out)])
    printed = io.StringIO()
    with redirect_stdout(printed):
        assert args.func(args) == 0
    assert out.read_bytes() == _call().sealed
    assert json.loads(printed.getvalue())["widens"] is True


def test_a_release_with_nothing_held_asks_no_one_for_a_change_statement():
    # nothing is held, so nothing is compared and `confirm` is never asked
    assert _call(confirm=lambda comparison, replaces: pytest.fail("asked")).change is None


def test_a_release_above_the_ceiling_is_refused_before_it_is_sealed(tmp_path):
    with pytest.raises(Refused):
        _call(ceiling=str(tmp_path))                     # a directory with no install set holds no ceiling
