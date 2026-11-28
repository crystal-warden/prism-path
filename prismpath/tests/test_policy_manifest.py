# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy manifest grammar and `prismpath policy manifest check` (SPEC.md section 10).

Pinned here: every key's form, the line each refusal names, the pairs and the one of expires and valid_days, the body's
one fixed rule and that the file parses as a flow, the check's findings in the order the proposal gives (signature,
rules and image, side inputs) and that the check reads no file itself, the shipped starter manifest, and the command
end to end with a real signature (exit 0 holds, exit 1 a finding, exit 2 a manifest that does not read)."""
import hashlib
import io
import json
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from prismpath.kernel import policy_manifest as pm, policy_source
from prismpath.kernel.parser import parse as parse_flow

POLICY = Path(__file__).resolve().parents[1] / "agent" / "policy"
RULES = (POLICY / "agent_default.rules.md").read_bytes()
IMAGE = (POLICY / "agent_default.core.json").read_bytes()
SHA = lambda data: hashlib.sha256(data).hexdigest()   # noqa: E731
ZEROS, ONES = "0" * 64, "1" * 64


def SIG(manifest, created=None, version=None):    # noqa: N802
    """A signature that holds for exactly the text `manifest` was parsed from, signed at its seq."""
    return pm.Signature(True, (), manifest.sha256, created, manifest.seq if version is None else version, ONES)


def check(*args, known_targets=frozenset({"agent"}), **kwargs):
    return pm.check(*args, known_targets=known_targets, **kwargs)

BASE = {
    "id": "starter-1", "stream": "starter", "seq": "1", "targets": "agent", "rules": "a.rules.md",
    "rules_sha256": ZEROS, "image": "a.core.json", "image_sha256": ZEROS, "widens": "yes", "valid_days": "30",
}


def text(name=None, **changes):
    """A manifest's text. Its flow name, the stream, is the last line of the front matter, so the key lines are 2 on."""
    keys = {**BASE, **changes}
    front = "\n".join(f"policy.{key}: {value}" for key, value in keys.items() if value is not None)
    name = name or keys.get("stream") or "starter"
    return f"---\n{front}\nname: {name}\n---\n## manifest\nNotes.\n{pm.FIXED_RULE}\n"


def problems(source):
    with pytest.raises(pm.ManifestError) as raised:
        pm.parse(source, "m.policy.md")
    return raised.value.problems


# ----------------------------------------------------------------------------------------------- grammar
def test_the_shipped_starter_manifest_reads_and_writes_no_value_key_a_pep_does_not_hold():
    manifest = pm.parse((POLICY / "agent_default.policy.md").read_text(encoding="utf-8"))
    assert (manifest.stream, manifest.seq, manifest.targets, manifest.valid_days) == ("agent-default", 1, ("agent",), 90)
    assert manifest.files == {}                                                   # hosts empty, zones absent
    assert not set(manifest.values) & set(pm.VALUE_KEYS)       # no artifact of a release holds a value key yet
    assert manifest.widens is True and manifest.replaces == ""


def test_the_shipped_starter_manifest_parses_as_a_flow_so_it_can_be_signed():
    graph = parse_flow((POLICY / "agent_default.policy.md").read_text(encoding="utf-8"))
    assert graph.name == "agent-default" and graph.nodes["manifest"].edges == [("refuse_135", "always")]


def test_the_shipped_starter_manifest_names_the_shipped_sources_by_hash():
    manifest = pm.parse((POLICY / "agent_default.policy.md").read_text(encoding="utf-8"))
    assert manifest.rules_sha256 == SHA(RULES)
    assert manifest.image_sha256 == SHA(policy_source.read_image_bytes(IMAGE))
    assert check(manifest, SIG(manifest), lambda path: (POLICY / path).read_bytes()) == []


def test_every_key_of_the_proposal_is_accepted_with_its_form():
    every = text(
        not_before="2026-12-01T00:00:00Z", expires="1800000000", valid_days=None, replaces=ONES, widens="no",
        targets="gateway | agent", egress_hosts="h.txt", egress_hosts_sha256=ONES, allowed_remotes="10.0.0.1 | host.example",
        zones="z.json", zones_sha256=ONES, routes="r.json", routes_sha256=ONES, identity_bundle="b.json",
        identity_bundle_sha256=ONES, identity_map="m.json", identity_map_sha256=ONES, net_dests="n.json",
        net_dests_sha256=ONES, max_processes="64", timeout_s="30", shell_many="20", toolchain_dirs="/usr | ~/.cargo | workspace:.toolchain",
        ro_mounts="/data/models", local_model="http://127.0.0.1:8000", grant_classes="read | write", cc_protected="auth | billing",
        cc_index="idx.json", cc_index_sha256=ONES, cc_freshness_s="3600", cc_required_certainty="likely",
        cc_engine_agreement="2", points="tests | parse")
    manifest = pm.parse(every)
    assert manifest.targets == ("agent", "gateway") and manifest.not_before == 1796083200 and manifest.expires == 1800000000
    assert manifest.widens is False and set(manifest.files) == set(pm.FILES)
    assert manifest.get("cc_required_certainty") == "likely" and manifest.get("toolchain_dirs") == ("/usr", "~/.cargo", "workspace:.toolchain")
    assert set(manifest.values) == {name for name in pm.KEYS if name not in ("valid_days", "domain")}


def test_the_accepted_keys_are_exactly_the_proposals():
    proposal = {"id", "stream", "seq", "targets", "rules", "rules_sha256", "image", "image_sha256", "not_before", "expires",
                "valid_days", "widens", "replaces", "egress_hosts", "egress_hosts_sha256", "allowed_remotes", "zones",
                "zones_sha256", "routes", "routes_sha256", "identity_bundle", "identity_bundle_sha256", "identity_map",
                "identity_map_sha256", "net_dests", "net_dests_sha256", "max_processes", "timeout_s", "shell_many",
                "toolchain_dirs", "ro_mounts", "local_model", "grant_classes", "cc_protected", "cc_index",
                "cc_index_sha256", "cc_freshness_s", "cc_required_certainty", "cc_engine_agreement", "domain",
                "points"}
    assert set(pm.KEYS) == proposal


def test_an_unknown_key_is_refused_with_its_line():
    source = text().replace("policy.seq: 1", "policy.seq: 1\npolicy.colour: red")
    found = problems(source)
    assert [(line, "policy.colour" in message) for line, message in found] == [(5, True)]


def test_a_key_without_the_prefix_is_refused_but_the_flow_keys_are_allowed():
    assert any("not a front matter key" in m for _l, m in problems(text().replace("policy.seq: 1", "seq: 1\npolicy.seq: 1")))
    manifest = pm.parse(text().replace("---\n", "---\ndescription: x\nstart: manifest\n", 1))
    assert manifest.flow_name == "starter"


def test_a_missing_required_key_is_named():
    for key in ("id", "stream", "seq", "targets", "rules", "rules_sha256", "image", "image_sha256", "widens"):
        found = problems(text(**{key: None}))
        assert any(f"`policy.{key}` is missing" in message for _l, message in found), key


def test_a_key_written_twice_names_the_first_line():
    found = problems(text().replace("policy.seq: 1", "policy.seq: 1\npolicy.seq: 2"))
    assert found == [(5, "`policy.seq` is written twice (first on line 4)")]


@pytest.mark.parametrize("key,value", [
    ("seq", "0"), ("seq", "01"), ("seq", "x"), ("seq", "-1"), ("stream", "Upper"), ("targets", ""), ("targets", "Agent"),
    ("targets", "agent | agent"), ("rules", "/abs/a.rules.md"), ("rules", "../a.rules.md"), ("rules", "a/../b.md"),
    ("rules", "a\\b.md"), ("rules", "C:x.md"), ("rules_sha256", "ABC"), ("image_sha256", "0" * 63), ("widens", "true"),
    ("valid_days", "0"), ("valid_days", "99999"), ("not_before", "2026-13-01T00:00:00Z"), ("not_before", "yesterday"),
    ("replaces", "nope"), ("max_processes", "0"), ("timeout_s", "1.5"), ("shell_many", "-3"),
    ("cc_required_certainty", "unknown"), ("cc_engine_agreement", "0"), ("domain", "tool"), ("domain", "a=1..x"),
    ("domain", "a=b|b"), ("allowed_remotes", "a | a"), ("id", "bad id"), ("local_model", "a b"),
])
def test_a_value_of_the_wrong_form_is_refused_with_its_line(key, value):
    found = problems(text(**{key: value}))
    line = 2 + list(BASE).index(key) if key in BASE else 2 + len(BASE)
    assert any(l == line and f"policy.{key}" in m for l, m in found), found


def test_a_value_with_a_unix_time_and_an_rfc_3339_time_is_the_same_instant():
    assert pm.parse(text(not_before="1796083200")).not_before == pm.parse(text(not_before="2026-12-01T00:00:00Z")).not_before


def test_one_of_expires_and_valid_days_is_required():
    assert any("one of" in m for _l, m in problems(text(valid_days=None)))
    assert any("both written" in m for _l, m in problems(text(expires="1800000000")))
    assert pm.parse(text(valid_days=None, expires="1800000000")).expires == 1800000000


def test_expires_must_follow_not_before():
    assert any("not after" in m for _l, m in problems(text(valid_days=None, expires="100", not_before="200")))


def test_a_side_file_and_its_hash_come_together():
    assert any("without `policy.egress_hosts_sha256`" in m for _l, m in problems(text(egress_hosts="h.txt")))
    assert any("without `policy.zones`" in m for _l, m in problems(text(zones_sha256=ONES)))
    assert any("same file" in m for _l, m in problems(text(egress_hosts="a.rules.md", egress_hosts_sha256=ONES)))


def test_a_release_that_does_not_widen_names_what_it_replaces():
    assert any("replaces nothing widens" in m for _l, m in problems(text(widens="no")))
    assert pm.parse(text(widens="no", replaces=ONES)).replaces == ONES


def test_the_body_holds_the_one_fixed_rule_under_a_heading():
    base = text()
    assert any("no rule" in m for _l, m in problems(base.replace(pm.FIXED_RULE, "")))
    bad = base.replace(pm.FIXED_RULE, "-> refuse dist:bad-format: always")
    assert any("rules source line" in m for _l, m in problems(bad))
    assert any("no rule but" in m for _l, m in problems(base.replace(pm.FIXED_RULE, "-> allow: always")))
    assert any("under a `##` heading" in m for _l, m in problems(base.replace("## manifest\n", "")))
    assert any("written once" in m for _l, m in problems(base + pm.FIXED_RULE + "\n"))


def test_the_front_matter_must_open_and_close():
    assert (1, "a manifest starts with a front matter block between two lines that are exactly `---`") in problems("policy.id: x\n")
    assert any("no closing" in m for _l, m in problems("---\npolicy.id: x\n"))
    assert any("`policy.<key>: <value>`" in m for _l, m in problems(text().replace("policy.seq: 1", "seq 1")))


def test_every_problem_is_reported_not_only_the_first():
    found = problems(text(seq="0", stream="UP", colour=None).replace("policy.id", "policy.nope"))
    assert len(found) >= 4 and [line for line, _m in found] == sorted(line for line, _m in found)


def test_crlf_line_ends_read_as_lf():
    assert pm.parse(text().replace("\n", "\r\n")).seq == 1


def test_the_manifest_hash_is_of_the_file_bytes():
    source = text()
    assert pm.parse(source).sha256 == SHA(source.encode("utf-8"))


# ----------------------------------------------------------------------------------------------- check
def release(tmp_path, **extra):
    """A directory holding the default starter's sources and a manifest for them (and the side files named)."""
    (tmp_path / "a.rules.md").write_bytes(RULES)
    (tmp_path / "a.core.json").write_bytes(IMAGE)
    side = {}
    for key, data in (extra.pop("side", None) or {}).items():
        (tmp_path / f"{key}.dat").write_bytes(data)
        side[key] = f"{key}.dat"
        side[f"{key}_sha256"] = SHA(data)
    source = text(rules_sha256=SHA(RULES), image_sha256=SHA(policy_source.read_image_bytes(IMAGE)), **side, **extra)
    path = tmp_path / "a.policy.md"
    path.write_text(source, encoding="utf-8")
    return path, pm.parse(source, str(path))


def reader(directory):
    def read(path):
        target = Path(directory) / path
        return target.read_bytes() if target.is_file() else None
    return read


def codes(findings):
    return [f.code for f in findings]


def test_a_manifest_that_holds_has_no_findings(tmp_path):
    _path, manifest = release(tmp_path, side={"zones": b"{}", "egress_hosts": b"a.example\n"})
    assert check(manifest, SIG(manifest), reader(tmp_path), known_targets={"agent"}) == []


def test_a_signature_that_fails_is_the_only_finding(tmp_path):
    (tmp_path / "a.core.json").write_bytes(b"{}")
    _path, manifest = release(tmp_path)
    (tmp_path / "a.core.json").write_bytes(b"{}")
    found = check(manifest, pm.Signature(False, ("sig:invalid",)), reader(tmp_path))
    assert codes(found) == ["signature"] and "sig:invalid" in found[0].message


def test_an_edited_rules_source_is_found_by_its_hash_and_its_image(tmp_path):
    _path, manifest = release(tmp_path)
    (tmp_path / "a.rules.md").write_bytes(RULES.replace(b"-> allow", b"-> allow", 1) + b"\nAn added note.\n")
    found = check(manifest, SIG(manifest), reader(tmp_path))
    assert codes(found) == ["rules-sha256"] and found[0].line == manifest.lines["rules_sha256"]
    (tmp_path / "a.rules.md").write_bytes(RULES.replace(b'-> refuse agent:unclassifiable: when git_op == "unknown" or path_scope == "unknown"',
                                                         b'-> allow: when git_op == "unknown"'))
    assert set(codes(check(manifest, SIG(manifest), reader(tmp_path)))) == {"rules-sha256", "image-sha256", "image-stale", "target-check"}


def test_a_rules_source_that_does_not_compile_names_its_line(tmp_path):
    _path, manifest = release(tmp_path)
    (tmp_path / "a.rules.md").write_bytes(b"---\nname: x\n---\n## core_decision\n-> refuse no:such-cause: always\n")
    found = check(manifest, SIG(manifest), reader(tmp_path))
    assert "rules-compile" in codes(found) and any(":5:" in f.message for f in found if f.code == "rules-compile")


def test_a_stale_image_file_is_found_even_when_the_hash_names_the_compile(tmp_path):
    _path, manifest = release(tmp_path)
    (tmp_path / "a.core.json").write_bytes(IMAGE.replace(b"allow", b"allux", 1))
    assert codes(check(manifest, SIG(manifest), reader(tmp_path))) == ["image-stale"]


def test_an_image_without_its_final_line_feed_still_holds(tmp_path):
    _path, manifest = release(tmp_path)
    (tmp_path / "a.core.json").write_bytes(policy_source.read_image_bytes(IMAGE))
    assert check(manifest, SIG(manifest), reader(tmp_path)) == []


def test_a_missing_file_is_a_finding_on_its_key_line(tmp_path):
    _path, manifest = release(tmp_path, side={"zones": b"{}"})
    (tmp_path / "zones.dat").unlink()
    (tmp_path / "a.core.json").unlink()
    found = check(manifest, SIG(manifest), reader(tmp_path))
    assert sorted((f.code, f.line) for f in found) == sorted([("missing", manifest.lines["image"]),
                                                              ("missing", manifest.lines["zones"])])


def test_a_side_input_whose_hash_differs_is_found(tmp_path):
    _path, manifest = release(tmp_path, side={"routes": b"[]", "net_dests": b"x"})
    (tmp_path / "routes.dat").write_bytes(b"[1]")
    found = check(manifest, SIG(manifest), reader(tmp_path))
    assert [(f.code, f.line) for f in found] == [("routes-sha256", manifest.lines["routes_sha256"])]


def test_a_target_outside_the_known_set_is_found(tmp_path):
    _path, manifest = release(tmp_path)
    found = check(manifest, SIG(manifest), reader(tmp_path), known_targets={"gateway"})
    assert codes(found) == ["target"]


def test_the_check_reads_only_through_the_reader_it_is_given(tmp_path):
    _path, manifest = release(tmp_path, side={"zones": b"{}"})
    asked = []

    def read(path):
        asked.append(path)
        return (tmp_path / path).read_bytes()
    check(manifest, SIG(manifest), read)
    assert sorted(asked) == ["a.core.json", "a.rules.md", "zones.dat"]


# ----------------------------------------------------------------------------------------------- the command
@pytest.fixture
def signed(tmp_path):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import flow_authority, policy_pack
    path, manifest = release(tmp_path, side={"egress_hosts": b"a.example\n"})
    keys = policy_pack.keygen(str(tmp_path / "keys"))
    flow_authority.sign_flow(str(path), 1, keys["private"] if "private" in keys else keys["priv"],
                             keys["public"] if "public" in keys else keys["pub"])
    pub = keys["public"] if "public" in keys else keys["pub"]
    return tmp_path, path, pub


def run(*argv):
    from prismpath import cli
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


def test_the_command_passes_a_signed_manifest_that_holds(signed):
    _dir, path, pub = signed
    code, out, err = run("policy", "manifest", "check", str(path), "--pub", pub)
    assert (code, err) == (0, "") and "holds" in out and "1 side input" in out
    code, out, _err = run("policy", "manifest", "check", str(path), "--pub", pub, "--json")
    assert code == 0 and json.loads(out)["ok"] is True


def test_the_command_exits_1_for_an_edited_side_input(signed):
    directory, path, pub = signed
    (directory / "egress_hosts.dat").write_bytes(b"evil.example\n")
    code, _out, err = run("policy", "manifest", "check", str(path), "--pub", pub)
    assert code == 1 and "egress_hosts-sha256" in err


def test_the_command_exits_1_for_an_edited_manifest(signed):
    _dir, path, pub = signed
    path.write_text(path.read_text(encoding="utf-8").replace("policy.seq: 1", "policy.seq: 2"), encoding="utf-8")
    code, _out, err = run("policy", "manifest", "check", str(path), "--pub", pub)
    assert code == 1 and "flow:sha256-mismatch" in err


def test_the_command_exits_1_for_an_unsigned_manifest(signed):
    directory, path, pub = signed
    copy = directory / "b.policy.md"
    shutil.copy(path, copy)
    code, _out, err = run("policy", "manifest", "check", str(copy), "--pub", pub)
    assert code == 1 and "sig:missing" in err


def test_the_command_exits_2_for_a_manifest_that_does_not_read(signed):
    directory, path, pub = signed
    bad = directory / "c.policy.md"
    bad.write_text(text(colour="x"), encoding="utf-8")
    from prismpath.hotswap import flow_authority
    flow_authority.sign_flow(str(bad), 1, str(directory / "keys" / "authority.key"), pub)
    code, _out, err = run("policy", "manifest", "check", str(bad), "--pub", pub)
    assert code == 2 and "c.policy.md:" in err
    assert run("policy", "manifest", "check", str(directory / "none.policy.md"), "--pub", pub)[0] == 2


def test_a_file_that_is_a_link_out_of_the_directory_reads_as_absent(signed, tmp_path_factory):
    directory, path, pub = signed
    outside = tmp_path_factory.mktemp("outside") / "h.txt"
    outside.write_bytes(b"a.example\n")
    (directory / "egress_hosts.dat").unlink()
    (directory / "egress_hosts.dat").symlink_to(outside)
    code, _out, err = run("policy", "manifest", "check", str(path), "--pub", pub)
    assert code == 1 and "egress_hosts.dat is not there" in err


def test_the_policy_command_still_has_its_other_actions():
    code, out, _err = run("policy", "causes", "--json")
    assert code == 0 and json.loads(out)


# ----------------------------------------------------------------------------------------------- review fixes
def front(extra="", flow="description: the release\n"):
    return text().replace("---\n", "---\n" + flow + extra, 1)


def test_a_lone_carriage_return_or_any_control_character_is_refused():
    for char in ("\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029", "\x00", "\ufeff", "\t"):
        found = problems(front().replace("the release", f"the{char}release"))
        assert any("is not allowed" in m for _l, m in found), repr(char)


def test_the_swallowed_key_attack_fails():
    """The proof of the review: a line feed after `description` turned into a carriage return used to drop the
    signed key after it while the signature, which reads CR as a line end, still verified."""
    signed = front("policy.cc_protected: secrets|payroll\n")
    assert pm.parse(signed).get("cc_protected") == ("secrets", "payroll")
    attacked = signed.replace("the release\npolicy.cc_protected", "the release\rpolicy.cc_protected")
    assert any("U+000D" in m for _l, m in problems(attacked))


def test_crlf_text_hashes_as_the_signature_covers_it():
    source = text()
    assert pm.parse(source.replace("\n", "\r\n")).sha256 == SHA(source.encode("utf-8"))


def test_flow_keys_have_a_form():
    assert any("name:" in m for _l, m in problems(front(flow="name: has space\n")))
    assert any("description:" in m for _l, m in problems(front(flow="description: " + "x" * 201 + "\n")))
    assert any("start:" in m for _l, m in problems(front(flow="start: a b\n")))


@pytest.mark.parametrize("value", ["usr/lib", "/", "/a/../b", "/a//b", "~/a/..", "~x", "workspace:../x", "/a\\b", "workspace:"])
def test_a_host_path_is_refused_when_it_leaves_its_root(value):
    assert any("policy.toolchain_dirs" in m for _l, m in problems(text(toolchain_dirs=value)))


def test_a_host_path_accepts_the_defaults_it_replaces():
    manifest = pm.parse(text(toolchain_dirs="/usr | /opt | ~/.cargo | workspace:.toolchain", ro_mounts="/data/x y"))
    assert manifest.get("ro_mounts") == ("/data/x y",)


def test_valid_days_counts_from_the_signing_time_and_the_clock_is_checked(tmp_path):
    _path, manifest = release(tmp_path)                                     # valid_days 30, no not_before
    day = 86400
    assert pm.expiry(manifest, 1000) == 1000 + 30 * day
    assert check(manifest, SIG(manifest, 1000), reader(tmp_path), now=1000 + 29 * day) == []
    assert codes(check(manifest, SIG(manifest, 1000), reader(tmp_path), now=1000 + 30 * day)) == ["expired"]
    assert codes(check(manifest, SIG(manifest, None), reader(tmp_path), now=5)) == ["expiry"]
    _path, written = release(tmp_path, not_before="5000")
    assert pm.expiry(written, 1000) == 5000 + 30 * day
    assert codes(check(written, SIG(written, 1000), reader(tmp_path), now=4000)) == ["not-yet-valid"]


def test_an_expires_time_in_the_past_is_found(tmp_path):
    _path, manifest = release(tmp_path, valid_days=None, expires="1000")
    assert codes(check(manifest, SIG(manifest), reader(tmp_path), now=2000)) == ["expired"]


def test_a_signature_for_other_text_is_refused(tmp_path):
    _path, manifest = release(tmp_path)
    found = check(manifest, pm.Signature(True, (), ONES, 1), reader(tmp_path))
    assert codes(found) == ["signature"] and "not the one signed" in found[0].message
    assert codes(check(manifest, pm.Signature(True), reader(tmp_path))) == ["signature"]


def test_a_policy_key_or_fence_in_the_body_is_refused():
    base = text()
    assert any("above the closing" in m for _l, m in problems(base + "policy.cc_protected: secrets\n"))
    assert any("no `---` line" in m for _l, m in problems(base + "---\n"))


def test_the_fences_are_exactly_three_hyphens_and_keys_start_in_column_one():
    assert problems(text().replace("\n---\n", "\n --- \n", 1))
    assert any("first column" in m for _l, m in problems(text().replace("policy.seq: 1", " policy.seq: 1")))
    assert problems(text().replace("---\n", "--- \n", 1))


def test_unicode_digits_spaces_and_an_empty_domain_are_refused():
    assert any("policy.not_before" in m for _l, m in problems(text(not_before="\uff12\uff10\uff12\uff16-11-28T00:00:00Z")))
    assert problems(text(shell_many="\u00a020"))
    assert any("reserved" in m for _l, m in problems(text(domain="")))
    assert problems(text(grant_classes="Read"))
    assert problems(text(grant_classes="read | ../x"))


def test_cc_protected_follows_the_zone_names():
    assert pm.parse(text(cc_protected=" | ".join(f"n{i}" for i in range(300)))).get("cc_protected")[299] == "n299"
    assert problems(text(cc_protected="a/b"))
    assert problems(text(cc_protected="x" * 513))
    assert pm.parse(text(cc_protected="x" * 512)).get("cc_protected")


def test_a_file_that_cannot_be_read_is_a_finding_on_its_line(tmp_path):
    _path, manifest = release(tmp_path, side={"zones": b"{}"})

    def read(path):
        if path == "zones.dat":
            raise ValueError("is too big")
        return (tmp_path / path).read_bytes()
    found = check(manifest, SIG(manifest), read)
    assert [(f.code, f.line) for f in found] == [("unreadable", manifest.lines["zones"])]


def test_the_widens_message_cites_w2_and_w6():
    assert any("W2" in m and "W6" in m for _l, m in problems(text(widens="no")))


def test_the_proof_script_attack_on_a_signed_manifest_exits_1_or_2(signed):
    directory, path, pub = signed
    body = path.read_text(encoding="utf-8")
    with_key = body.replace("policy.id:", "description: the release\npolicy.cc_protected: secrets\npolicy.id:", 1)
    path.write_text(with_key, encoding="utf-8")
    from prismpath.hotswap import flow_authority, policy_pack
    keys = policy_pack.keygen(str(directory / "k2"))
    pub2 = keys["public"] if "public" in keys else keys["pub"]
    priv2 = keys["private"] if "private" in keys else keys["priv"]
    flow_authority.sign_flow(str(path), 1, priv2, pub2)
    assert run("policy", "manifest", "check", str(path), "--pub", pub2)[0] == 0
    path.write_bytes(with_key.replace("the release\npolicy.cc", "the release\rpolicy.cc").encode("utf-8"))
    code, _out, _err = run("policy", "manifest", "check", str(path), "--pub", pub2)
    assert code in (1, 2)


def test_a_missing_revocation_list_is_refused_like_a_missing_key(signed):
    _dir, path, pub = signed
    code, _out, err = run("policy", "manifest", "check", str(path), "--pub", pub, "--revoked", str(path) + ".nope")
    assert code == 2 and "no such file" in err


def test_pub_can_be_repeated_and_the_file_can_follow_it(signed):
    _dir, path, pub = signed
    assert run("policy", "manifest", "check", "--pub", pub, "--pub", pub, str(path))[0] == 0


def test_an_unsigned_manifest_that_does_not_read_reports_the_signature(signed):
    directory, _path, pub = signed
    bad = directory / "d.policy.md"
    bad.write_text(text(colour="x"), encoding="utf-8")
    code, _out, err = run("policy", "manifest", "check", str(bad), "--pub", pub)
    assert code == 1 and "signature" in err


def test_a_side_file_over_the_bound_is_a_finding(signed, monkeypatch):
    directory, path, pub = signed
    from prismpath.distribution import manifest_cli
    monkeypatch.setattr(manifest_cli, "MAX_FILE", 3)
    code, _out, err = run("policy", "manifest", "check", str(path), "--pub", pub)
    assert code == 1 and "unreadable" in err
