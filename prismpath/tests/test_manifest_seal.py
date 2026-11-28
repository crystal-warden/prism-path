# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath dist seal --manifest`: a release sealed from a signed policy manifest (SPEC.md section 10).

Pinned here: the check hands the sealing tool the bytes it verified and the signed facts (`policy_manifest.verify`),
the name and version bindings, the reserved `policy.domain`, one release per target made by each kind's `derive`, the
envelope meta members `manifest_sha256`, `source_sha256` and `rules_sha256`, the tool's own widening decision (W7)
against the controller state, an absent side key, a value key no artifact carries, mixed targets, the command end to
end with the version floor, and an agent PEP that stages and commits what it sealed."""
import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon, kinds_builtin  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import kinds, manifest_cli, seal, widening  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.hotswap import flow_authority, policy_pack  # noqa: E402
from prismpath.kernel import policy_manifest as pm, policy_source  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

kinds_builtin.load()

POLICY = Path(__file__).resolve().parents[1] / "agent" / "policy"
RULES = (POLICY / "agent_default.rules.md").read_bytes()
IMAGE = (POLICY / "agent_default.core.json").read_bytes()
STRICT_RULES = (POLICY / "agent_rules.rules.md").read_bytes()
STRICT_IMAGE = (POLICY / "agent_rules.core.json").read_bytes()
SHA = lambda data: hashlib.sha256(data).hexdigest()   # noqa: E731
HOSTS = canon.canon2_bytes(["api.example.com"])
MORE_HOSTS = canon.canon2_bytes(["api.example.com", "b.example.com"])
STREAM = "agent/demo"
SIGNERS = [_dist.GEN.test_key("A")]


def zones(*names) -> bytes:
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-zones/1",
                               "protected": sorted(names)})


class Owner:
    """A directory of manifests, sources and side files, and the authority key that signs manifests."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        keys = policy_pack.keygen(str(directory / "keys"))
        self.priv, self.pub = keys.get("private", keys.get("priv")), keys.get("public", keys.get("pub"))

    def write(self, seq=1, *, rules=RULES, image=IMAGE, side=None, sign=True, version=None, **front) -> Path:
        """Write and sign `m<seq>.policy.md` for the sources and the side files `side` (key -> bytes)."""
        (self.dir / f"r{seq}.rules.md").write_bytes(rules)
        (self.dir / f"i{seq}.core.json").write_bytes(image)
        keys = {"id": f"demo-{seq}", "stream": STREAM, "seq": str(seq), "targets": "agent", "rules": f"r{seq}.rules.md",
                "rules_sha256": SHA(rules), "image": f"i{seq}.core.json",
                "image_sha256": SHA(policy_source.read_image_bytes(image)), "widens": "yes", "valid_days": "30"}
        for key, data in (side or {}).items():
            (self.dir / f"{key}{seq}.dat").write_bytes(data)
            keys[key], keys[f"{key}_sha256"] = f"{key}{seq}.dat", SHA(data)
        keys.update({key: value for key, value in front.items()})
        lines = "\n".join(f"policy.{key}: {value}" for key, value in keys.items() if value is not None)
        path = self.dir / f"m{seq}.policy.md"
        path.write_text(f"---\nname: {keys['stream']}\n{lines}\n---\n## manifest\nA release.\n{pm.FIXED_RULE}\n",
                        encoding="utf-8")
        if sign:
            flow_authority.sign_flow(str(path), int(keys["seq"]) if version is None else version, self.priv, self.pub)
        return path

    def release(self, seq=1, **kwargs) -> pm.Release:
        done = manifest_cli.examine(str(self.write(seq, **kwargs)), [self.pub])
        assert done.findings == [] and done.release is not None, done.findings
        return done.release


@pytest.fixture
def owner(tmp_path):
    return Owner(tmp_path / "owner")


def read(sealed: bytes):
    return env.read(env.unseal(sealed)[0])


def by_artifact(result, target="agent"):
    return {one.artifact: one for one in result.envelopes if one.target == target}


# ----------------------------------------------------------------------------------------------- F10: what the check hands on
def test_verify_hands_on_the_bytes_it_checked_and_the_signed_facts(owner):
    release = owner.release(side={"egress_hosts": HOSTS})
    signed = flow_authority.read_manifest(str(owner.dir / "m1.policy.md"))
    assert release.image == policy_source.read_image_bytes(IMAGE) and release.rules == RULES
    assert release.files == {"egress_hosts": HOSTS}
    assert release.manifest_sha256 == signed["flow_sha256"] == release.manifest.sha256
    assert (release.version, release.key_id) == (1, signed["key_id"])
    assert release.not_before == release.created and release.expires == release.created + 30 * 86400


def test_known_targets_is_required():
    with pytest.raises(TypeError):
        pm.check(None, pm.Signature(False), lambda path: None)          # noqa: the keyword is required


def test_the_signed_version_must_be_the_seq(owner):
    path = owner.write(2, version=1)
    done = manifest_cli.examine(str(path), [owner.pub])
    assert [f.code for f in done.findings] == ["version"] and done.release is None


def test_the_flow_name_must_be_the_stream(owner):
    path = owner.write(sign=False)
    path.write_text(path.read_text(encoding="utf-8").replace(f"name: {STREAM}", "name: other"), encoding="utf-8")
    flow_authority.sign_flow(str(path), 1, owner.priv, owner.pub)
    with pytest.raises(manifest_cli.Unreadable) as raised:
        manifest_cli.examine(str(path), [owner.pub])
    assert any("is not the stream" in line for line in raised.value.lines)
    path.write_text(path.read_text(encoding="utf-8").replace("name: other\n", ""), encoding="utf-8")
    flow_authority.sign_flow(str(path), 1, owner.priv, owner.pub)
    with pytest.raises(manifest_cli.Unreadable) as raised:
        manifest_cli.examine(str(path), [owner.pub])
    assert any("`name` is missing" in line for line in raised.value.lines)


def test_policy_domain_is_reserved(owner):
    with pytest.raises(pm.ManifestError) as raised:
        pm.parse(owner.write(sign=False, domain="tool=read").read_text(encoding="utf-8"))
    assert any("reserved" in message for _line, message in raised.value.problems)


def test_a_target_no_kind_can_seal_from_a_manifest_does_not_hold(owner):
    done = manifest_cli.examine(str(owner.write(targets="host")), [owner.pub])
    assert [f.code for f in done.findings] == ["target"] and kinds.sealable() >= {"agent", "gateway"}
    assert "host" not in kinds.sealable() and "mesh" not in kinds.sealable() and "xdp" not in kinds.sealable()


def test_the_sealing_tool_reads_no_file_again(owner):
    release = owner.release(side={"egress_hosts": HOSTS})
    for path in owner.dir.glob("*.dat"):
        path.write_bytes(b"changed after the check")
    (owner.dir / "i1.core.json").write_bytes(b"{}")
    result = seal.seal_manifest(release, SIGNERS)
    assert by_artifact(result)["egress.hosts"].body == HOSTS


# ----------------------------------------------------------------------------------------------- one release per target
def test_an_agent_release_is_its_policy_core_and_its_hosts_with_the_manifest_meta(owner):
    release = owner.release(side={"egress_hosts": HOSTS})
    result = seal.seal_manifest(release, SIGNERS)
    sealed = by_artifact(result)
    assert sorted(sealed) == ["egress.hosts", "policy.core"]
    core, hosts = read(sealed["policy.core"].sealed), read(sealed["egress.hosts"].sealed)
    assert sealed["policy.core"].body == release.image and core.policy_sha256 == SHA(release.image)
    assert core.meta == {"manifest_sha256": release.manifest_sha256, "source_sha256": SHA(RULES)}
    assert hosts.meta == {"manifest_sha256": release.manifest_sha256, "rules_sha256": SHA(RULES)}
    for one in (core, hosts):                                   # E7: one release
        assert (one.stream, one.seq, one.targets, one.not_before, one.expires) == (
            STREAM, 1, ("agent",), release.not_before, release.expires)
        assert (one.policy_sha256, one.replaces, one.widens) == (SHA(release.image), "", True)
        assert one.release == env.release_id([("egress.hosts", SHA(HOSTS)), ("policy.core", SHA(release.image))])
    assert result.larger and result.widens and result.replaces == ""


def test_the_same_manifest_seals_to_the_same_bytes(owner):
    release = owner.release(side={"egress_hosts": HOSTS})
    assert seal.seal_manifest(release, SIGNERS) == seal.seal_manifest(release, SIGNERS)


def test_an_absent_side_key_is_the_target_default_that_allows_least(owner):
    result = seal.seal_manifest(owner.release(), SIGNERS)
    sealed = by_artifact(result)
    assert sorted(sealed) == ["egress.hosts", "policy.core"] and sealed["egress.hosts"].body == canon.canon2_bytes([])
    with_zones = by_artifact(seal.seal_manifest(owner.release(2, side={"zones": zones("payroll")}), SIGNERS))
    assert sorted(with_zones) == ["agent.zones", "egress.hosts", "policy.core"]


def test_a_side_file_that_does_not_read_as_its_artifact_is_refused(owner):
    with pytest.raises(Refused) as raised:
        seal.seal_manifest(owner.release(side={"egress_hosts": b"api.example.com\n"}), SIGNERS)
    assert raised.value.cause == kinds.BAD_FORMAT


def test_a_side_file_no_target_reads_is_refused(owner):
    with pytest.raises(Refused) as raised:
        seal.seal_manifest(owner.release(side={"routes": b"[]"}), SIGNERS)
    assert "read by no target" in str(raised.value)


def test_a_value_key_is_carried_only_at_the_value_the_kind_carries(owner):
    from prismpath.agent import dist_kind
    defaults = owner.release(max_processes="64", timeout_s="30", shell_many="20", allowed_remotes="", ro_mounts="",
                             toolchain_dirs=" | ".join(reversed(dist_kind.TOOLCHAIN_DIRS)))
    assert seal.seal_manifest(defaults, SIGNERS).envelopes
    for key, value in (("max_processes", "8"), ("toolchain_dirs", "/usr"), ("local_model", "m"),
                       ("cc_freshness_s", "60"), ("grant_classes", "read")):
        with pytest.raises(Refused) as raised:
            seal.seal_manifest(owner.release(2, **{key: value}), SIGNERS)
        assert f"policy.{key}" in str(raised.value), key


def test_the_carried_values_are_the_agents_built_in_defaults():
    from prismpath.agent import classifier, dist_kind, profile, session_state
    assert dist_kind.MANIFEST_VALUES["max_processes"] == profile.MAX_PROCESSES
    assert dist_kind.MANIFEST_VALUES["timeout_s"] == profile.TIMEOUT_S
    assert dist_kind.MANIFEST_VALUES["shell_many"] == session_state.SHELL_MANY
    workspace = Path("/w")
    home = Path("~").expanduser()
    spelled = []
    for path in classifier.Config.for_workspace(workspace).toolchain_dirs:
        path = Path(path)
        if path.is_relative_to(Path(classifier.os.path.realpath(workspace))):
            spelled.append("workspace:" + str(path.relative_to(Path(classifier.os.path.realpath(workspace)))))
        elif path.is_relative_to(home):
            spelled.append("~/" + str(path.relative_to(home)))
        else:
            spelled.append(str(path))
    assert sorted(spelled) == sorted(dist_kind.TOOLCHAIN_DIRS)
    shipped = pm.parse((POLICY / "agent_default.policy.md").read_text(encoding="utf-8"))
    assert all(seal._same_value(shipped.get(key), value) for key, value in dist_kind.MANIFEST_VALUES.items())


def test_a_gateway_release_needs_its_routes(owner):
    from prismpath.gateway.reading import Routes
    with pytest.raises(Refused) as raised:
        seal.seal_manifest(owner.release(targets="gateway"), SIGNERS)
    assert "route table" in str(raised.value)
    routes = Routes.from_doc({"routes": [{"match": "/api/*", "class": "api"}]}).canonical()
    release = owner.release(2, targets="gateway | agent", side={"routes": routes, "egress_hosts": HOSTS})
    result = seal.seal_manifest(release, SIGNERS)
    assert sorted(by_artifact(result, "gateway")) == ["gateway.routes", "policy.core"]
    assert sorted(by_artifact(result, "agent")) == ["egress.hosts", "policy.core"]
    assert set(result.releases) == {"agent", "gateway"} and result.releases["agent"] != result.releases["gateway"]
    for one in result.envelopes:
        envelope = read(one.sealed)
        assert envelope.targets == (one.target,) and envelope.policy_sha256 == SHA(release.image)


# ----------------------------------------------------------------------------------------------- F13: W7 at the tool
def test_widens_no_without_a_held_release_is_refused(owner):
    first = owner.release(side={"egress_hosts": HOSTS})
    with pytest.raises(Refused) as raised:
        seal.seal_manifest(owner.release(2, widens="no", replaces=SHA(first.image), side={"egress_hosts": HOSTS}),
                           SIGNERS)
    assert raised.value.cause == widening.UNSIGNED and "holds no release" in str(raised.value)


def test_widens_no_is_sealed_only_when_the_tool_finds_it_not_larger(owner, tmp_path, monkeypatch):
    first = owner.release(side={"egress_hosts": MORE_HOSTS})
    held = _held(tmp_path, first)
    renewal = seal.seal_manifest(owner.release(2, widens="no", replaces=SHA(first.image),
                                               side={"egress_hosts": HOSTS}), SIGNERS, held=held)
    assert (renewal.widens, renewal.larger, renewal.replaces) == (False, False, SHA(first.image))
    assert all(read(one.sealed).widens is False and read(one.sealed).replaces == SHA(first.image)
               for one in renewal.envelopes)
    with pytest.raises(Refused) as raised:          # a host added: the manifest's no is not the tool's
        seal.seal_manifest(owner.release(3, widens="no", replaces=SHA(first.image),
                                         side={"egress_hosts": canon.canon2_bytes(["c.example.com"])}),
                           SIGNERS, held=held)
    assert raised.value.cause == widening.UNSIGNED and "found the release larger" in str(raised.value)
    larger = seal.seal_manifest(owner.release(4, side={"egress_hosts": canon.canon2_bytes(["c.example.com"])}),
                                SIGNERS, held=held)
    assert (larger.widens, larger.larger, larger.replaces) == (True, True, SHA(first.image))


def test_widens_yes_never_signs_a_widening_statement(owner):
    result = seal.seal_manifest(owner.release(), SIGNERS)
    assert all(one.artifact not in kinds.TRUST_ARTIFACTS for one in result.envelopes)


def _held(tmp_path, release):
    """A controller directory that serves the agent stream and holds the release sealed from `release`."""
    from prismpath.distribution import trust
    from prismpath.distribution.controller import Controller
    directory = tmp_path / "controller"
    control = Controller(str(directory), _dist.instance_key("C"), clock=lambda: release.created + 60)
    control.add_anchor(trust.anchor_bytes([_dist.public("A")], target="agent", stream=STREAM))
    result = seal.seal_manifest(release, SIGNERS)
    statement, body = seal.widening_sealed(by_artifact(result)["policy.core"].sealed, [], SIGNERS)
    control.put(statement, body)
    for one in result.envelopes:
        control.put(one.sealed, one.body)
    control.save()
    return str(directory)


def test_mixed_targets_that_replace_different_policies_are_refused(owner, tmp_path):
    first = owner.release(side={"egress_hosts": HOSTS})
    held = _held(tmp_path, first)
    from prismpath.gateway.reading import Routes
    routes = Routes.from_doc({"routes": [{"match": "/api/*", "class": "api"}]}).canonical()
    mixed = owner.release(2, targets="agent | gateway", side={"egress_hosts": HOSTS, "routes": routes})
    with pytest.raises(Refused) as raised:          # the agent replaces the held release and the gateway nothing
        seal.seal_manifest(mixed, SIGNERS, held=held)
    assert "replace different policies" in str(raised.value)


# ----------------------------------------------------------------------------------------------- a PEP takes it
def test_an_agent_pep_stages_and_commits_a_release_sealed_from_a_manifest(owner, tmp_path):
    release = owner.release(side={"egress_hosts": HOSTS})
    result = seal.seal_manifest(release, SIGNERS)
    point = _dist.AgentPep(tmp_path / "pep", clock=_dist.Clock(release.created + 60), stream=STREAM)
    core = by_artifact(result)["policy.core"]
    statement, body = seal.widening_sealed(core.sealed, [], SIGNERS)
    acks = [point.pep.stage(statement, body)] + [point.pep.stage(one.sealed, one.body) for one in result.envelopes]
    assert all(_dist.state_record.read(ack, point.key.public_raw).cause in (None, "") for ack in acks)
    point.pep.commit(STREAM, 1, SHA(release.image))
    assert point.pep.active.policy_sha256 == SHA(release.image)
    assert point.pep.active.bodies["egress.hosts"] == HOSTS


def test_an_envelope_with_a_manifest_member_of_the_wrong_form_does_not_read(owner):
    release = owner.release()
    core = by_artifact(seal.seal_manifest(release, SIGNERS))["policy.core"]
    from prismpath.kernel import canon2
    doc = canon2.loads(env.unseal(core.sealed)[0])
    for meta in ({"manifest_sha256": "x"}, {"rules_sha256": SHA(RULES)}, {"source_sha256": 1}):
        with pytest.raises(Refused):
            env.read(canon2.dumps({**doc, "meta": meta}))
    hosts = canon2.loads(env.unseal(by_artifact(seal.seal_manifest(release, SIGNERS))["egress.hosts"].sealed)[0])
    with pytest.raises(Refused):
        env.read(canon2.dumps({**hosts, "meta": {"source_sha256": SHA(RULES)}}))


# ----------------------------------------------------------------------------------------------- the command
def run(*argv):
    from prismpath import cli
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


def _signer_pem(directory: Path) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    path = directory / "dist-authority.pem"
    path.write_bytes(_dist.GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                            ser.NoEncryption()))
    return str(path)


def test_the_command_seals_a_manifest_into_a_directory_and_raises_the_floor(owner, tmp_path):
    path = owner.write(side={"egress_hosts": HOSTS})
    out, state = tmp_path / "out", tmp_path / "state"
    key = _signer_pem(tmp_path)
    code, printed, err = run("dist", "seal", "--manifest", str(path), "--pub", owner.pub, "--key", key, "--out",
                             str(out), "--state-dir", str(state))
    assert code == 0, err
    doc = json.loads(printed)
    assert sorted(one["artifact"] for one in doc["envelopes"]) == ["egress.hosts", "policy.core"] and doc["widens"]
    assert (out / "agent.policy.core.sealed").is_file() and (out / "agent.egress.hosts.body").read_bytes() == HOSTS
    floor = json.loads((state / flow_authority.FLOOR_FILE).read_text(encoding="utf-8"))
    assert floor[STREAM]["version"] == 1
    again = run("dist", "seal", "--manifest", str(path), "--pub", owner.pub, "--key", key, "--out", str(out),
                "--state-dir", str(state))
    assert again[0] == 0                                       # the same version and text: a repeat
    older = owner.write(1, side={"egress_hosts": MORE_HOSTS})  # another text at the version sealed
    code, _printed, err = run("dist", "seal", "--manifest", str(older), "--pub", owner.pub, "--key", key, "--out",
                              str(tmp_path / "out2"), "--state-dir", str(state))
    assert code == 1 and "flow:version-replay" in err and not (tmp_path / "out2").exists()


def test_the_command_refuses_a_manifest_that_does_not_hold_and_writes_nothing(owner, tmp_path):
    path = owner.write(side={"egress_hosts": HOSTS})
    (owner.dir / "egress_hosts1.dat").write_bytes(MORE_HOSTS)
    code, _printed, err = run("dist", "seal", "--manifest", str(path), "--pub", owner.pub, "--key",
                              _signer_pem(tmp_path), "--out", str(tmp_path / "out"))
    assert code == 1 and "egress_hosts-sha256" in err and not (tmp_path / "out").exists()


def test_the_command_takes_no_release_flag_with_a_manifest(owner, tmp_path):
    path = owner.write()
    code, _printed, err = run("dist", "seal", "--manifest", str(path), "--pub", owner.pub, "--key",
                              _signer_pem(tmp_path), "--out", str(tmp_path / "out"), "--seq", "3", "--widens")
    assert code == 2 and "--seq" in err and "--widens" in err
    code, _printed, err = run("dist", "seal", "--manifest", str(path), "--key", _signer_pem(tmp_path), "--out",
                              str(tmp_path / "out"))
    assert code == 2 and "--pub" in err


def test_the_flag_form_still_seals_and_says_it_is_deprecated(tmp_path):
    body = tmp_path / "hosts.body"
    body.write_bytes(HOSTS)
    key = _signer_pem(tmp_path)
    code, printed, err = run("dist", "seal", "--artifact", "egress.hosts", "--body", str(body), "--stream", STREAM,
                             "--seq", "1", "--target", "agent", "--not-before", "1800000000", "--expires",
                             "1800086400", "--key", key, "--out", str(tmp_path / "a.sealed"))
    assert code == 0 and "deprecated" in err and "--manifest" in err and json.loads(printed)["widens"]
    code, _printed, err = run("dist", "seal", "--artifact", "egress.hosts", "--key", key, "--out", str(tmp_path / "b"))
    assert code == 2 and "--body" in err and "--seq" in err


def test_a_controller_stores_both_releases_of_a_mixed_manifest_at_one_seq(owner, tmp_path):
    from prismpath.distribution import trust
    from prismpath.distribution.controller import Controller
    from prismpath.gateway.reading import Routes
    routes = Routes.from_doc({"routes": [{"match": "/api/*", "class": "api"}]}).canonical()
    release = owner.release(targets="agent | gateway", side={"egress_hosts": HOSTS, "routes": routes})
    result = seal.seal_manifest(release, SIGNERS)
    control = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=lambda: release.created + 60)
    for target in ("agent", "gateway"):
        control.add_anchor(trust.anchor_bytes([_dist.public("A")], target=target, stream=STREAM))
        statement, body = seal.widening_sealed(by_artifact(result, target)["policy.core"].sealed, [], SIGNERS)
        control.put(statement, body)
    stored = [control.put(one.sealed, one.body) for one in result.envelopes]
    assert sorted((one.targets[0], one.artifact) for one in stored) == [
        ("agent", "egress.hosts"), ("agent", "policy.core"), ("gateway", "gateway.routes"), ("gateway", "policy.core")]
    assert {one.seq for one in stored} == {1} and len({one.release for one in stored}) == 2
