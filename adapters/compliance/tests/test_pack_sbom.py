# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The pack SBOM: a CycloneDX description of a signed policy pack, valid against the cached CycloneDX 1.6
schema, written only when the pack verifies, and the same bytes every time for the same pack."""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("jsonschema")

from adapters.compliance import emit  # noqa: E402
from prismpath.hotswap import policy_pack  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.tests._repo import repo_file

sys.path.insert(0, str(repo_file("prismpath-hw")))    # the compiler lives beside the hardware targets
import ppt_compile  # noqa: E402

FLOW = """---
name: sbom_fixture
start: start
field.temp: int min=0 max=200
---
## start
-> hot: when temp >= 100
-> cold: else

## hot
-> end

## cold
-> end

## end
"""


@pytest.fixture()
def pack(tmp_path):
    keys = policy_pack.keygen(str(tmp_path / "keys"))
    image_path = tmp_path / "thermal.ppt"
    image_path.write_bytes(ppt_compile.compile_flow(parse(FLOW)).serialize())
    manifest = policy_pack.build_pack(str(image_path), {}, version=3, envelope_id="env1",
                                      priv_path=keys["private"], pub_path=keys["public"], flow_text=FLOW)
    return {"ppt": str(image_path), "keys": keys, "manifest": manifest}


def _sbom(pack, **kwargs):
    return emit.pack_sbom(pack["ppt"], [pack["keys"]["public"]], **kwargs)


def test_a_verified_pack_is_described_by_its_signed_manifest_and_the_schema_accepts_it(pack):
    result = _sbom(pack, supplier="Example Supplier")
    assert result["ok"], result
    sbom = result["sbom"]
    assert emit.validate(sbom, "cyclonedx") == (True, [])
    component = sbom["metadata"]["component"]
    assert component["type"] == "data" and component["name"] == "thermal" and component["version"] == "3"
    assert component["hashes"] == [{"alg": "SHA-256", "content": pack["manifest"]["image_sha256"]}]
    assert component["supplier"] == {"name": "Example Supplier"}
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["prismpath:key_id"] == pack["keys"]["key_id"]
    assert properties["prismpath:envelope_id"] == "env1"
    assert properties["prismpath:wcet_cycles"] == str(pack["manifest"]["wcet_cycles"])
    assert properties["prismpath:field:temp"] == pack["manifest"]["fields"]["temp"]
    # The authored flow is bound by hash in the signed manifest, and the SBOM names it as a part.
    assert properties["prismpath:flow_sha256"] == pack["manifest"]["flow_sha256"]
    assert component["components"][0]["hashes"][0]["content"] == pack["manifest"]["flow_sha256"]
    assert sbom["metadata"]["timestamp"] == pack["manifest"]["created"]


def test_the_same_pack_always_yields_the_same_document(pack):
    assert json.dumps(_sbom(pack)["sbom"], sort_keys=True) == json.dumps(_sbom(pack)["sbom"], sort_keys=True)


def test_a_tampered_image_gets_the_refusal_not_an_sbom(pack):
    raw = bytearray(Path(pack["ppt"]).read_bytes())
    raw[-1] ^= 0x01
    Path(pack["ppt"]).write_bytes(bytes(raw))
    result = _sbom(pack)
    assert not result["ok"] and "sbom" not in result
    assert any("sha256" in reason for reason in result["reasons"])


def test_another_key_gets_the_refusal(pack, tmp_path):
    stranger = policy_pack.keygen(str(tmp_path / "stranger"), "stranger")
    result = emit.pack_sbom(pack["ppt"], [stranger["public"]])
    assert not result["ok"] and "sbom" not in result


def test_a_revoked_key_gets_the_refusal(pack):
    result = _sbom(pack, revoked=frozenset({pack["keys"]["key_id"]}))
    assert not result["ok"] and "sbom" not in result
