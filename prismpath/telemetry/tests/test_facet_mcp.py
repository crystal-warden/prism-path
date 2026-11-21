# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet MCP server: cell indices in describe and decode, the compact and summary forms, signed policies
only, a wrong hash, a root mismatch, `unchecked` said in words, and the protocol over stdio."""
import io
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.hotswap import flow_authority as fa  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.telemetry import facet_mcp as fm  # noqa: E402
from prismpath.telemetry import packed, selfheal  # noqa: E402

from prismpath.tests._repo import REPO_ROOT as ROOT  # noqa: E402

FUSION = ROOT / "adapters/fusion/flows/fusion_triage.md"
INPUT = ROOT / "prismpath-hw/demo/flows/demo_input.md"
INTENT = ROOT / "integrations/governed_intent/policy/intent_calls.core.json"
if not all(path.exists() for path in (FUSION, INPUT, INTENT)):   # skipped here so the acceptance skip budget can name this file
    pytest.skip("the three policies the server is tested with are only in a repo checkout", allow_module_level=True)
BLOCK_BITS = 64


@pytest.fixture()
def env(tmp_path):
    keys = pp.keygen(str(tmp_path / "keys"))
    reg = tmp_path / "reg"
    reg.mkdir()
    for src in (FUSION, INPUT):
        shutil.copy(src, reg / src.name)
        fa.sign_flow(str(reg / src.name), 1, keys["private"], keys["public"])
    shutil.copy(INTENT, reg / INTENT.name)
    fm.sign_image(str(reg / INTENT.name), keys["private"], keys["public"])
    server = fm.build(str(reg), [keys["public"]])
    return {"tmp": tmp_path, "keys": keys, "reg": reg, "server": server,
            "fusion": fm.Policy(str(reg / FUSION.name)), "intent": fm.Policy(str(reg / INTENT.name))}


def _readings(policy, n, seed=3):
    rng = random.Random(seed)
    syms = [{f: rng.randrange(policy.parts[f].n) for f in policy.order} for _ in range(n)]
    reps = [{f: policy.parts[f].cells[s[f]]["rep"] for f in policy.order} for s in syms]
    return syms, reps


def _root(data, block_bits=BLOCK_BITS):
    return selfheal.commit(selfheal.chunk(packed.unpack(data), block_bits))[0]


def _call(server, name, **args):
    return json.loads(server.call(name, args))


def _flip(policy, data, silent=True):
    for bit in range(len(data) * 8):
        x = bytearray(data)
        x[bit // 8] ^= 0x80 >> (bit % 8)
        try:
            policy.symbols(bytes(x))
            ok = True
        except fm.Refused:
            ok = False
        if ok == silent:
            return bytes(x)
    raise AssertionError("no flip of that kind")


# ------------------------------------------------------------------ indices
def test_describe_numbers_every_cell_in_canonical_field_order(env):
    p = env["fusion"]
    out = _call(env["server"], "facet_describe", policy_hash=p.sha256)
    assert out["field_order"] == sorted(p.parts) == [f["field"] for f in out["fields"]]
    for f in out["fields"]:
        assert [c["index"] for c in f["cells"]] == list(range(p.parts[f["field"]].n))
    assert out["signed"] is True and out["decision_node"] == p.node


def test_decode_carries_each_cell_index_next_to_its_label(env):
    p = env["fusion"]
    syms, reps = _readings(p, 8)
    out = _call(env["server"], "facet_decode", stream_hex=p.encode(reps).hex(), policy_hash=p.sha256)
    assert out["field_order"] == p.order and out["reading_count"] == 8
    for r, s, rep in zip(out["readings"], syms, reps):
        assert [c["field"] for c in r["cells"]] == p.order
        assert [c["index"] for c in r["cells"]] == [s[f] for f in p.order]
        assert all(c["meaning"] for c in r["cells"])
        assert r["decision"] == p.decision(rep)


def test_core_image_decodes_with_indices(env):
    p = env["intent"]
    syms, reps = _readings(p, 5)
    out = _call(env["server"], "facet_decode", stream_hex=p.encode(reps).hex(), policy_hash=p.sha256)
    assert [[c["index"] for c in r["cells"]] for r in out["readings"]] == [[s[f] for f in p.order] for s in syms]


# ------------------------------------------------------------------ compact and summary
def test_compact_is_the_index_tuple_and_decision_per_reading(env):
    p = env["fusion"]
    syms, reps = _readings(p, 16)
    hexs = p.encode(reps).hex()
    full = _call(env["server"], "facet_decode", stream_hex=hexs, policy_hash=p.sha256)
    compact = _call(env["server"], "facet_decode", stream_hex=hexs, policy_hash=p.sha256, format="compact")
    assert compact["readings"] == [{"cells": [s[f] for f in p.order], "decision": p.decision(r)}
                                   for s, r in zip(syms, reps)]
    assert compact["readings"] == [{"cells": [c["index"] for c in r["cells"]], "decision": r["decision"]}
                                   for r in full["readings"]]
    assert len(json.dumps(compact)) < len(json.dumps(full)) / 2
    assert _call(env["server"], "facet_decode", stream_hex=hexs, policy_hash=p.sha256, format="x")["error"] == "refused"


def test_summary_counts_decisions_cells_and_exceptions(env):
    p = env["fusion"]
    syms, reps = _readings(p, 64)
    hexs = p.encode(reps).hex()
    decisions = [p.decision(r) for r in reps]
    out = _call(env["server"], "facet_summary", stream_hex=hexs, policy_hash=p.sha256)
    assert out["decision_distribution"] == {d: decisions.count(d) for d in sorted(set(decisions))}
    assert out["reading_count"] == 64
    for f in p.order:
        want = {}
        for s in syms:
            want[str(s[f])] = want.get(str(s[f]), 0) + 1
        assert out["cells_present"][f] == {k: want[k] for k in sorted(want, key=int)}
    odd = [i for i, d in enumerate(decisions) if d != p.default]
    assert p.default == "all_quiet" and [e["reading"] for e in out["exceptions"]] == odd
    assert out["exceptions_total"] == len(odd)
    named = _call(env["server"], "facet_summary", stream_hex=hexs, policy_hash=p.sha256, decision="all_quiet")
    assert [e["reading"] for e in named["exceptions"]] == [i for i, d in enumerate(decisions) if d == "all_quiet"]
    capped = _call(env["server"], "facet_summary", stream_hex=hexs, policy_hash=p.sha256, limit=2)
    assert capped["exceptions_listed"] == 2 and capped["exceptions_total"] == len(odd)
    bad = _call(env["server"], "facet_summary", stream_hex=hexs, policy_hash=p.sha256, decision="nonsense")
    assert bad["error"] == "refused"


def test_summary_without_a_default_edge_uses_the_most_frequent_decision(env):
    p = env["intent"]
    assert p.default is None
    _syms, reps = _readings(p, 32)
    out = _call(env["server"], "facet_summary", stream_hex=p.encode(reps).hex(), policy_hash=p.sha256)
    top = max(sorted(out["decision_distribution"]), key=out["decision_distribution"].get)
    assert repr(top) in out["exception_rule"]
    assert out["exceptions_total"] == 32 - out["decision_distribution"][top]


# ------------------------------------------------------------------ signed policies only
def test_unknown_policy_hash_is_refused(env):
    out = _call(env["server"], "facet_describe", policy_hash="0" * 64)
    assert out["error"] == "refused" and "unknown policy" in out["reason"]


def test_unsigned_policy_is_refused_and_named(env):
    shutil.copy(FUSION, env["reg"] / "extra.md")
    (env["reg"] / "extra.md").write_text(FUSION.read_text() + "\n")
    h = fm.Policy(str(env["reg"] / "extra.md")).sha256
    assert h != env["fusion"].sha256
    out = _call(env["server"], "facet_describe", policy_hash=h)
    assert out["error"] == "refused" and "sig:missing" in out["reason"]
    unsigned_image = env["reg"] / "unsigned.core.json"
    unsigned_image.write_bytes(INTENT.read_bytes().replace(b"\n", b"") + b"\n\n")
    # the unsigned image is not served either way
    good, refused = env["server"].registry.scan()
    assert str(unsigned_image) in refused and refused[str(unsigned_image)] == ["sig:missing"]


def test_policy_edited_after_signing_stops_being_served(env):
    p = env["fusion"]
    _call(env["server"], "facet_describe", policy_hash=p.sha256)["signed"]
    path = env["reg"] / FUSION.name
    path.write_text(path.read_text() + "\n")
    out = _call(env["server"], "facet_describe", policy_hash=p.sha256)
    assert out["error"] == "refused" and "unknown policy" in out["reason"]
    assert env["server"].registry.scan()[1][str(path)] == ["flow:sha256-mismatch"]


def test_image_edited_after_attestation_wrong_key_and_revoked_key_are_refused(env):
    image = env["reg"] / INTENT.name
    other = pp.keygen(str(env["tmp"] / "other"), name="other")
    ok, causes, _ = fm.verify_image(str(image), [other["public"]])
    assert (ok, causes) == (False, ["sig:invalid"])
    ok, causes, _ = fm.verify_image(str(image), [env["keys"]["public"]], frozenset([env["keys"]["key_id"]]))
    assert (ok, causes) == (False, ["sig:revoked-key"])
    ok, causes, _ = fm.verify_image(str(image), [env["keys"]["public"]])
    assert ok
    image.write_bytes(image.read_bytes().replace(b"refuse_106", b"refuse_999", 1))
    ok, causes, _ = fm.verify_image(str(image), [env["keys"]["public"]])
    assert (ok, causes) == (False, ["sig:invalid"])


def test_a_policy_signed_by_an_untrusted_key_is_not_served(env):
    other = pp.keygen(str(env["tmp"] / "other"), name="other")
    server = fm.build(str(env["reg"]), [other["public"]])
    out = json.loads(server.call("facet_describe", {"policy_hash": env["fusion"].sha256}))
    assert out["error"] == "refused" and "sig:invalid" in out["reason"]


def test_a_registry_with_no_authority_key_cannot_start(env):
    with pytest.raises(ValueError):
        fm.Registry(str(env["reg"]), [])


# ------------------------------------------------------------------ wrong hash
def test_a_pinned_session_refuses_another_signed_policys_hash(env):
    pinned = fm.FacetServer(env["server"].registry, env["fusion"].sha256)
    syms, reps = _readings(env["fusion"], 4)
    other = fm.Policy(str(env["reg"] / INPUT.name)).sha256
    for name, args in (("facet_decode", {"stream_hex": env["fusion"].encode(reps).hex()}),
                       ("facet_describe", {}), ("facet_summary", {"stream_hex": env["fusion"].encode(reps).hex()})):
        out = json.loads(pinned.call(name, {**args, "policy_hash": other}))
        assert out["error"] == "refused" and "mismatch" in out["reason"]


# ------------------------------------------------------------------ integrity
def test_no_root_says_unchecked_in_words(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 4)
    hexs = p.encode(reps).hex()
    for name in ("facet_decode", "facet_summary"):
        out = _call(env["server"], name, stream_hex=hexs, policy_hash=p.sha256)
        assert out["integrity"] == "unchecked"
        assert "no epoch Merkle root was given" in out["integrity_note"] and "bit flip" in out["integrity_note"]


def test_a_matching_root_is_checked_and_decodes(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    for name in ("facet_decode", "facet_summary"):
        out = _call(env["server"], name, stream_hex=data.hex(), policy_hash=p.sha256, epoch_root=_root(data),
                    block_bits=BLOCK_BITS)
        assert out["integrity"] == "checked" and out["epoch_root"] == _root(data)
        assert "integrity_note" not in out


def test_blocks_form_checks_against_the_root_and_the_stream(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    blocks = selfheal.chunk(packed.unpack(data), 40)
    root = selfheal.commit(blocks)[0]
    out = _call(env["server"], "facet_decode", stream_hex=data.hex(), policy_hash=p.sha256, epoch_root=root,
                epoch_blocks=blocks)
    assert out["integrity"] == "checked"
    forged = [blocks[0][:-1] + ("1" if blocks[0][-1] == "0" else "0")] + blocks[1:]
    bad = _call(env["server"], "facet_decode", stream_hex=data.hex(), policy_hash=p.sha256, epoch_root=root,
                epoch_blocks=forged)
    assert bad["error"] == "refused" and "integrity failure" in bad["reason"]
    other = selfheal.chunk("1" * 80, 40)
    swapped = _call(env["server"], "facet_decode", stream_hex=data.hex(), policy_hash=p.sha256,
                    epoch_root=selfheal.commit(other)[0], epoch_blocks=other)
    assert swapped["error"] == "refused" and "not the bits of the epoch" in swapped["reason"]


def test_a_root_mismatch_is_refused_by_both_tools(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    for name in ("facet_decode", "facet_summary"):
        out = _call(env["server"], name, stream_hex=data.hex(), policy_hash=p.sha256, epoch_root="ab" * 32,
                    block_bits=BLOCK_BITS)
        assert out["error"] == "refused" and "integrity failure" in out["reason"] and "readings" not in out


def test_a_silent_bit_flip_decodes_without_a_root_and_is_refused_with_one(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    flipped = _flip(p, data, silent=True)
    assert flipped != data
    loose = _call(env["server"], "facet_decode", stream_hex=flipped.hex(), policy_hash=p.sha256)
    assert loose["integrity"] == "unchecked" and loose["reading_count"] == 8      # the flaw the root closes
    strict = _call(env["server"], "facet_decode", stream_hex=flipped.hex(), policy_hash=p.sha256,
                   epoch_root=_root(data), block_bits=BLOCK_BITS)
    assert strict["error"] == "refused" and "integrity failure" in strict["reason"]


def test_integrity_arguments_that_cannot_be_checked_are_refused(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 2)
    hexs = p.encode(reps).hex()
    for extra in ({"epoch_root": "ab" * 32}, {"block_bits": 64}, {"epoch_root": "xyz", "block_bits": 64},
                  {"epoch_root": "ab" * 32, "block_bits": 0}, {"epoch_root": "ab" * 32, "block_bits": 8,
                                                              "epoch_blocks": ["0"]}):
        out = _call(env["server"], "facet_decode", stream_hex=hexs, policy_hash=p.sha256, **extra)
        assert out["error"] == "refused"


def test_a_stream_that_does_not_fit_the_codebook_is_refused(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    refused = sum(_call(env["server"], "facet_decode", stream_hex=_flip_at(data, b).hex(),
                        policy_hash=p.sha256).get("error") == "refused" for b in range(len(data) * 8))
    assert refused > len(data) * 8 * 0.9
    assert _call(env["server"], "facet_decode", stream_hex="zz", policy_hash=p.sha256)["error"] == "refused"


def _flip_at(data, bit):
    x = bytearray(data)
    x[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(x)


# ------------------------------------------------------------------ the protocol over stdio
def _rpc(proc, message):
    proc.stdin.write((json.dumps(message) + "\n").encode())
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_mcp_session_over_stdio(env):
    p = env["fusion"]
    _syms, reps = _readings(p, 8)
    data = p.encode(reps)
    cmd = [sys.executable, "-m", "prismpath.telemetry.facet_mcp", "--registry", str(env["reg"]),
           "--authority-pub", env["keys"]["public"]]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
    try:
        init = _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "1"}}})
        assert init["id"] == 1 and init["result"]["serverInfo"]["name"] == "prismpath-facet"
        assert "tools" in init["result"]["capabilities"] and "resultType" not in init["result"]
        proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')   # no answer to a notification
        listed = _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert [t["name"] for t in listed["result"]["tools"]] == ["facet_describe", "facet_decode", "facet_summary"]
        assert all(t["inputSchema"]["type"] == "object" for t in listed["result"]["tools"])
        call = _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "facet_decode", "arguments": {
                               "stream_hex": data.hex(), "policy_hash": p.sha256, "format": "compact",
                               "epoch_root": _root(data), "block_bits": BLOCK_BITS}}})
        assert call["id"] == 3 and call["result"]["isError"] is False
        body = json.loads(call["result"]["content"][0]["text"])
        assert body["integrity"] == "checked" and len(body["readings"]) == 8
        refused = _rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                              "params": {"name": "facet_summary", "arguments": {
                                  "stream_hex": data.hex(), "policy_hash": p.sha256, "epoch_root": "cd" * 32,
                                  "block_bits": BLOCK_BITS}}})
        assert refused["result"]["isError"] is True
        assert json.loads(refused["result"]["content"][0]["text"])["error"] == "refused"
        discover = _rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "server/discover",
                               "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}})
        assert discover["result"]["resultType"] == "complete" and "2026-07-28" in discover["result"]["supportedVersions"]
        assert _rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "nope"})["error"]["code"] == -32601
        assert _rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                           "params": {"name": "nope", "arguments": {}}})["error"]["code"] == -32602
        proc.stdin.write(b"not json\n")
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["error"]["code"] == -32700
        proc.stdin.write(b'{"jsonrpc":"2.0","id":8,"id":9,"method":"ping"}\n')
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["error"]["code"] == -32600
        proc.stdin.write(b'[{"jsonrpc":"2.0","id":10,"method":"ping"},{"jsonrpc":"2.0","id":11,"method":"tools/list"}]\n')
        proc.stdin.flush()
        batch = json.loads(proc.stdout.readline())
        assert [m["id"] for m in batch] == [10, 11]
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
        proc.stdout.close()
        proc.stderr.close()
    assert proc.returncode == 0


def test_serve_ends_at_end_of_input_and_reports_refused_policies_on_stderr(env):
    (env["reg"] / "loose.md").write_text("# loose\n\n## start\n-> end: else\n\n## end\n")
    out = io.BytesIO()
    fm.serve(env["server"], io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'), out)
    assert json.loads(out.getvalue())["id"] == 1
    good, refused = env["server"].registry.scan()
    assert len(good) == 3 and refused[str(env["reg"] / "loose.md")] == ["sig:missing"]
