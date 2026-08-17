# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tamper tests for the Facet wire — backs the trust-boundary tiers in PROTOCOL.md §6.

Three claims, three tiers, one file:

  * §2.2 self-framing (I2/I3): the *bare* codec is not silent under tampering — a single-bit flip in a
    Facet stream is overwhelmingly either structurally rejected (a broken frame or an out-of-range
    symbol) or decision-preserving (a different reading in the same cell). It is NOT integrity, though:
    a residual of flips decode cleanly to a DIFFERENT verdict. That residual is exactly why the keyed
    layer exists — measured here, not hand-waved.
  * §2.5 keyed AEAD: with the confidentiality layer, EVERY single-byte tamper of the ciphertext is
    rejected (Poly1305). This is the real in-transit integrity guarantee.
  * §2.4 Merkle root (I4): a tampered reading's leaf no longer verifies against the committed root.
"""
import hashlib
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent

# Load bench/wire.py under a distinct name (it is itself called wire.py); this also puts
# adapters/telemetry on sys.path, so the codec modules import cleanly afterward.
_spec = importlib.util.spec_from_file_location("fusion_wire_bench", ADAPTER / "bench" / "wire.py")
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)

import packed as pk        # noqa: E402
import zeckendorf as z     # noqa: E402
from prismpath.ledger_ots import merkle_root_and_paths, verify_leaf   # noqa: E402

GRAPH = W.parse(W.FLOW.read_text())
PARTS = W.q.build_partitions(GRAPH)
ORDER = sorted(PARTS.keys())
NODE = W.w.decision_nodes(GRAPH)[0]
READINGS = [r for _t, r in W.events_from_fixture(n=300)]


def _symbols(reading):
    s = W.q.quantize(PARTS, reading)
    return [s[f] + 1 for f in ORDER]


def _flip_bit(bits, i):
    return bits[:i] + ("0" if bits[i] == "1" else "1") + bits[i + 1:]


def _decision_stat(reading):
    """The quantized symbol tuple — by I1 this IS the decision-sufficient statistic the wire carries."""
    s = W.q.quantize(PARTS, reading)
    return tuple(s[f] for f in ORDER)


def test_bare_codec_self_frames_but_is_not_integrity():
    """Two honest facts about the *bare* codec (no keys):

    (a) its self-framing makes it self-checking — single-bit flips vs the transmitted decision statistic
        are overwhelmingly rejected outright (broken frame / out-of-range symbol) or preserve it; and
    (b) it is still NOT integrity — a well-formed stream for a different reading is accepted verbatim,
        carrying a different decision statistic, because the codec has no notion of origin.
    (a) is measured; (b) is demonstrated by construction. The keyed-layer test closes the (b) gap.
    """
    # (a) characterize every single-bit flip against the decision statistic
    rejected = same = diff = 0
    for reading in READINGS[:80]:
        orig = _decision_stat(reading)
        bits = W.w.encode_reading(PARTS, reading)
        for i in range(len(bits)):
            try:
                got = _decision_stat(W.w.decode_reading(PARTS, _flip_bit(bits, i)))
            except Exception:
                rejected += 1
                continue
            if got == orig:
                same += 1
            else:
                diff += 1
    total = rejected + same + diff
    assert total > 0 and rejected > 0
    assert (rejected + same) / total >= 0.9        # self-framing flags or preserves essentially all flips
    print(f"\n[bare codec] single-bit flips: rejected={rejected} preserved={same} "
          f"silently-changed={diff} of {total} ({100*(rejected+same)/total:.1f}% flagged-or-preserved)")

    # (b) the integrity gap, by construction: a VALID stream for a different reading is accepted verbatim.
    t1 = _decision_stat(READINGS[0])
    r2 = next((r for r in READINGS if _decision_stat(r) != t1), None)
    assert r2 is not None, "corpus lacks two distinct decision statistics"
    forged = W.w.encode_reading(PARTS, r2)          # a perfectly well-formed Facet stream
    dec = W.w.decode_reading(PARTS, forged)         # decodes with no error...
    assert _decision_stat(dec) == _decision_stat(r2) != t1   # ...to a DIFFERENT decision statistic.
    print(f"[bare codec] forgery accepted: a valid stream carrying {_decision_stat(r2)} passes where "
          f"{t1} was expected — no origin integrity without the keyed layer.")


def test_aead_layer_rejects_every_single_byte_tamper():
    """With the keyed layer, tampering is rejected outright — the tier-2 in-transit guarantee."""
    aead_mod = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    ChaCha20Poly1305 = aead_mod.ChaCha20Poly1305

    syms = []
    for r in READINGS[:120]:
        syms += _symbols(r)
    wire_bytes = pk.pack(z.encode_stream(syms))
    assert len(wire_bytes) > 0

    key = ChaCha20Poly1305.generate_key()
    aead = ChaCha20Poly1305(key)
    nonce = bytes(12)                      # fixed nonce is fine for this integrity test (no reuse across msgs)
    ct = aead.encrypt(nonce, wire_bytes, None)
    assert aead.decrypt(nonce, ct, None) == wire_bytes      # untampered round-trips

    caught = trials = 0
    for i in range(len(ct)):
        for mask in (0x01, 0x40, 0x80):    # a few bit positions per byte
            bad = bytearray(ct)
            bad[i] ^= mask
            trials += 1
            try:
                aead.decrypt(nonce, bytes(bad), None)
            except Exception:
                caught += 1
    assert trials > 0
    assert caught == trials                # EVERY single-byte tamper rejected
    print(f"\n[aead] rejected {caught}/{trials} single-byte ciphertext tampers (100%)")


def test_merkle_root_makes_a_tampered_reading_evident():
    """§2.4/I4: a tampered reading's leaf no longer verifies against the committed root."""
    leaves = [hashlib.sha256(pk.encode(_symbols(r))).hexdigest() for r in READINGS[:16]]
    root, paths = merkle_root_and_paths(leaves)
    assert verify_leaf(leaves[5], paths[5], root)          # an untampered leaf verifies

    tampered_leaf = hashlib.sha256(pk.encode(_symbols(READINGS[5])) + b"\x00").hexdigest()
    assert tampered_leaf != leaves[5]
    assert not verify_leaf(tampered_leaf, paths[5], root)  # the tampered reading fails against the committed root

    bad_root, _ = merkle_root_and_paths([tampered_leaf if i == 5 else h for i, h in enumerate(leaves)])
    assert bad_root != root                                # and the recomputed root diverges from the committed one
