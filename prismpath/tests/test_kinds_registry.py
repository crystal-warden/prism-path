# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Target kinds register themselves (prismpath/ports/target.py, prismpath/distribution/kinds.py), and the registry
fails closed: in a process that never imported a kind, no enforcement point of it can be built, its artifacts do not
read, its policy is checked against no guessed domain and `prismpath policy compile --target` checks nothing for it.
The trust path imports no kind, so that process is one that imported only the trust path."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.agent import dist_kind as agent_kind, profile
from prismpath.distribution import install, kinds, widening
from prismpath.gateway import dist_kind as gateway_kind
from prismpath.kernel import policy_source
from prismpath.ports.target import TargetKind

PACKAGE_ROOT = Path(__file__).resolve().parents[2]

_BARE = r"""
import argparse, io, json, sys, tempfile
from pathlib import Path
from prismpath.distribution import install, kinds, pep, verify, widening
from prismpath.distribution.adapters import Adapter
from prismpath.kernel import policy_source

out = {"loaded": sorted(name for name in sys.modules if name.startswith(("prismpath.agent", "prismpath.gateway")))}
out["targets"] = sorted(kinds.TARGETS)

class Point(Adapter):
    def activate(self, release): pass
    def deactivate(self, cause): pass

def refusal(make):
    try:
        make()
    except Exception as error:
        return type(error).__name__ + ": " + str(error)
    return None

state = tempfile.mkdtemp()
for kind in ("agent", "gateway"):
    point = type("Point", (Point,), {"kind": kind})()
    out["pep_" + kind] = refusal(lambda: pep.Pep(state, point, object(), lambda: 0))
    out["view_" + kind] = refusal(lambda: verify.PepView(kind=kind, stream="s"))
out["checks"] = {name: kinds.ARTIFACTS[name].check(None, b"[]", None)
                 for name in ("egress.hosts", "gateway.routes", "identity.bundle", "identity.map", "net.dests")}
out["read"] = refusal(lambda: kinds.read("egress.hosts", b"[]"))
out["domain"] = refusal(lambda: kinds.reading_domain("agent"))
core = Path(sys.argv[1]).read_bytes().rstrip(b"\n")
other = Path(sys.argv[2]).read_bytes().rstrip(b"\n")

class Envelope:
    policy_sha256 = "0" * 64
out["policy_core"] = kinds.check_policy_core(Envelope(), core, verify.PepView(kind="host", stream="s"))
out["compare_policies"] = widening.compare_policies(core, other)
out["compare_zones"] = widening.compare_artifact("agent.zones", b"{}", None)
out["categories"] = refusal(lambda: install.built_categories("xdp"))
parser = argparse.ArgumentParser()
policy_source.add_parser(parser.add_subparsers(dest="command"))
image = Path(state) / "out.core.json"
args = parser.parse_args(["policy", "compile", sys.argv[3], "--target", "agent", "-o", str(image)])
err, sys.stderr = sys.stderr, io.StringIO()
out["compile"] = policy_source.policy_cmd(args)
out["compile_error"], sys.stderr = sys.stderr.getvalue(), err
out["compile_wrote"] = image.exists()

from prismpath import kinds_builtin
kinds_builtin.load()
out["targets_after"] = sorted(kinds.TARGETS)
point = type("Point", (Point,), {"kind": "agent"})()
out["pep_agent_after"] = refusal(lambda: pep.Pep(state, point, None, lambda: 0))
out["policy_core_after"] = kinds.check_policy_core(Envelope(), core, verify.PepView(kind="host", stream="s"))
print(json.dumps(out))
"""


def _starter(name: str) -> Path:
    return PACKAGE_ROOT / "prismpath" / "agent" / "policy" / name


@pytest.fixture(scope="module")
def bare():
    """What a process that imported only the trust path sees, then the same process after `kinds_builtin.load`."""
    done = subprocess.run([sys.executable, "-c", _BARE, str(_starter("agent_default.core.json")),
                           str(_starter("agent_review.core.json")), str(_starter("agent_default.rules.md"))],
                          cwd=str(PACKAGE_ROOT), capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_the_trust_path_imports_no_kind(bare):
    assert bare["loaded"] == []
    assert bare["targets"] == ["host", "mesh", "xdp"]


def test_a_pep_of_a_kind_whose_module_was_not_imported_is_refused(bare):
    for kind in ("agent", "gateway"):
        assert bare[f"pep_{kind}"] == f"PepRefused: no enforcement point of kind {kind!r} is built"
        assert bare[f"view_{kind}"] == f"ValueError: no enforcement point of kind {kind!r} is built"


def test_an_artifact_whose_reader_was_not_registered_does_not_read(bare):
    assert bare["checks"] == dict.fromkeys(("egress.hosts", "gateway.routes", "identity.bundle", "identity.map",
                                            "net.dests"), kinds.BAD_FORMAT)
    assert bare["read"].startswith("Refused: dist:bad-format")


def test_no_policy_is_checked_against_a_guessed_domain(bare):
    assert bare["domain"].startswith("Refused: dist:bad-format")
    assert bare["policy_core"] == kinds.BAD_FORMAT                # refused, never passed
    assert bare["compare_policies"] == widening.CANNOT_DECIDE     # which counts as larger
    assert bare["compare_zones"] == widening.CANNOT_DECIDE
    assert bare["categories"].startswith("Refused: dist:bad-format")


def test_a_compile_for_a_target_with_no_checks_writes_nothing(bare):
    assert bare["compile"] == 2 and not bare["compile_wrote"]
    assert "no checks of the agent target are loaded" in bare["compile_error"]


def test_loading_the_built_in_kinds_registers_them(bare):
    assert bare["targets_after"] == ["agent", "gateway", "host", "mesh", "xdp"]
    assert bare["pep_agent_after"] == "PepRefused: a PEP needs its own instance key (K2)"
    assert bare["policy_core_after"] == "image:sha256-mismatch"   # past the domain check, to the envelope's hash


def test_a_kind_registers_once_with_one_row():
    kinds.register(agent_kind.KIND)                               # the same registration again changes nothing
    assert kinds.KINDS["agent"] is agent_kind.KIND and kinds.TARGETS["agent"] is agent_kind.ROW
    other = kinds.Target(needs=frozenset({"policy.core"}), decides=True)
    with pytest.raises(ValueError, match="registered with another row"):
        kinds.register(TargetKind(name="agent", row=other))
    with pytest.raises(ValueError, match="registered with another row"):
        kinds.register_target("gateway", other)
    with pytest.raises(ValueError, match="not a target kind of this format"):
        kinds.register(TargetKind(name="toaster", row=agent_kind.ROW))
    with pytest.raises(ValueError, match="already has a reader"):
        kinds.register_reader("egress.hosts", gateway_kind.read_routes)
    with pytest.raises(ValueError, match="not an artifact a release carries"):
        kinds.register_reader("trust.revocation", gateway_kind.read_routes)


def test_every_kind_is_checked_against_the_agent_domain_q4():
    for kind in ("agent", "gateway", "xdp", "cfs", "host", "mesh"):
        assert kinds.reading_domain(kind) is profile.AGENT_DOMAIN
    assert install.built_categories("xdp") == frozenset(profile.KNOWN_CATEGORIES) | {profile.ZONE_NAME}
    assert install.built_categories("agent") == frozenset(profile.KNOWN_CATEGORIES) | {profile.ZONE_NAME}
    from prismpath.gateway import reading
    assert install.built_categories("gateway") == frozenset(reading.FIELDS)


def test_the_registered_readers_and_comparators_are_the_kinds_own():
    assert kinds.READERS["egress.hosts"] is agent_kind.read_hosts
    assert kinds.READERS["gateway.routes"] is gateway_kind.read_routes
    assert widening.COMPARATORS["agent.zones"] is agent_kind.compare_zones
    assert widening.COMPARATORS["identity.map"] is gateway_kind.compare_maps
    assert policy_source.COMPILE_CHECKS["agent"] is agent_kind.compile_checks
