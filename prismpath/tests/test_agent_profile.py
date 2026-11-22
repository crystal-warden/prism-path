# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""compile_profile: the sandbox profile a signed image needs, from its whole allow set (prismpath/agent/profile.py)."""
import hashlib

import pytest

from prismpath.agent.policy import STARTERS, Policy, starter_path
from prismpath.agent.profile import FORMAT, STRICTEST, Profile, ProfileError, allow_set, compile_profile
from prismpath.kernel import canon2


def image(name):
    return starter_path(name).read_bytes()


def variant(starter="default", rules=(), fields=None):
    """A starter's image with rules put first and fields added, as canonical bytes."""
    doc = canon2.loads(image(starter).rstrip(b"\n"))
    doc["rules"] = list(rules) + doc["rules"]
    doc["fields"].update(fields or {})
    return canon2.dumps(doc)


NETWORK = {"target": "allow", "when": ["and", ["cmp", "command_class", "==", ["str", "network"]],
                                       ["cmp", "path_scope", "==", ["str", "workspace"]]]}
NO_COMMAND = [["cmp", "command_class", "==", ["str", "none"]], ["cmp", "git_op", "==", ["str", "none"]]]
OUTSIDE_READ = {"target": "allow", "when": ["and", ["cmp", "tool", "==", ["str", "read_file"]],
                                            ["cmp", "path_scope", "==", ["str", "outside"]], *NO_COMMAND]}
OUTSIDE_WRITE = {"target": "allow", "when": ["and", ["cmp", "tool", "==", ["str", "write_file"]],
                                             ["cmp", "path_scope", "==", ["str", "outside"]], *NO_COMMAND]}


@pytest.mark.parametrize("starter", sorted(STARTERS))
def test_starters_get_the_workspace_and_no_network(starter):
    profile = compile_profile(image(starter))
    assert profile == STRICTEST
    assert profile.ro_mounts == ("/usr",) and profile.rw_path == "workspace"
    assert not profile.network and not profile.host_write and not profile.host_visible


def test_the_allow_set_holds_what_the_reference_allows():
    # an image that allows only a read of the workspace has exactly the readings of that rule
    rule = {"target": "allow", "when": ["and", ["cmp", "tool", "==", ["str", "read_file"]],
                                        ["cmp", "path_scope", "==", ["str", "workspace"]]]}
    doc = canon2.loads(image("default").rstrip(b"\n"))
    doc["rules"] = [rule]
    allowed = list(allow_set(Policy(canon2.dumps(doc))))
    assert allowed and all(r["tool"] == "read_file" and r["path_scope"] == "workspace" for r in allowed)


def test_an_image_that_allows_network_gets_network_and_nothing_else():
    profile = compile_profile(variant(rules=[NETWORK]))
    assert profile.network
    assert profile.ro_mounts == ("/usr",) and not profile.host_write


def test_an_image_that_allows_a_network_git_op_gets_network():
    rule = {"target": "allow", "when": ["cmp", "git_op", "==", ["str", "network"]]}
    assert compile_profile(variant(rules=[rule])).network


def test_a_push_to_an_allowed_remote_is_allowed_but_gives_no_network():
    # the starters allow it, and the sandbox is stricter than the oracle there: the push fails for want of a network
    policy = Policy(image("default"))
    reading = {"classifier_version": 3, "net_dest": "none", "proc_class": "none", "command_class": "none", "git_op": "push", "kill_by_pattern": False,
               "path_control": False, "path_glob": False, "path_in_toolchain": False, "path_scope": "none", "path_symlink": False,
               "path_traversal": False, "remote_class": "allowed", "tool": "git", "zone_reach": "none"}
    assert policy.decide(policy.reading_bytes(reading)).runs
    assert not compile_profile(image("default")).network


def test_outside_reads_mount_the_host_read_only_and_writes_make_it_writable():
    read = compile_profile(variant(rules=[OUTSIDE_READ]))
    assert read.ro_mounts == ("/",) and read.host_visible and not read.host_write and not read.network
    write = compile_profile(variant(rules=[OUTSIDE_WRITE]))
    assert write.ro_mounts == ("/",) and write.host_write


def test_a_refusal_ahead_of_an_allow_keeps_the_capability_off():
    # first rule that holds decides: a network refusal ahead of a network allow leaves nothing allowed
    refuse = {"target": "refuse_106", "when": ["cmp", "command_class", "==", ["str", "network"]]}
    assert not compile_profile(variant(rules=[refuse, NETWORK])).network


@pytest.mark.fresh_needs
def test_the_same_image_twice_is_byte_identical_with_the_same_hash():
    for rules in ([], [NETWORK], [OUTSIDE_WRITE]):
        a, b = compile_profile(variant(rules=rules)), compile_profile(variant(rules=rules))
        assert a.canonical() == b.canonical() and a.hash() == b.hash()
        assert a.hash() == hashlib.sha256(a.canonical()).hexdigest()


def test_the_canonical_bytes_are_canon2_and_differ_when_a_capability_differs():
    base, net = compile_profile(image("default")), compile_profile(variant(rules=[NETWORK]))
    obj = canon2.loads(base.canonical())
    assert obj["format"] == FORMAT and obj["network"] is False and obj["rw_path"] == "workspace"
    assert canon2.dumps(obj) == base.canonical()
    assert base.hash() != net.hash()


def test_a_trailing_line_feed_and_a_loaded_policy_give_the_same_profile():
    raw = starter_path("default").read_bytes()
    assert raw.endswith(b"\n")
    assert compile_profile(raw) == compile_profile(Policy(raw)) == compile_profile(raw[:-1])


def test_a_category_the_classifier_does_not_produce_fails_closed():
    open_rule = {"target": "allow", "when": ["cmp", "zone", "==", ["str", "dmz"]]}
    with pytest.raises(ProfileError, match="zone.*no finite domain"):
        compile_profile(variant(rules=[open_rule], fields={"zone": "category"}))


def test_a_wide_int_and_a_fixed_point_field_fail_closed():
    with pytest.raises(ProfileError, match="wide.*past the 64"):
        compile_profile(variant(fields={"wide": "int min=0 max=1000"}))
    with pytest.raises(ProfileError, match="amount"):
        compile_profile(variant(fields={"amount": "fixed scale=2 min=0 max=10"}))


def test_a_field_no_rule_reads_still_has_to_have_a_domain():
    with pytest.raises(ProfileError, match="idle"):
        compile_profile(variant(fields={"idle": "category"}))


def test_an_image_without_the_projected_fields_fails_closed():
    doc = canon2.loads(image("default").rstrip(b"\n"))
    doc["fields"]["spare"] = "bool"
    doc["rules"] = [{"target": "allow", "when": ["truthy", "spare"]}]
    doc["fields"] = {"spare": "bool"}
    with pytest.raises(ProfileError, match="does not define 'path_scope'"):
        compile_profile(canon2.dumps(doc))


def test_bytes_that_are_not_an_image_fail_closed():
    with pytest.raises(ProfileError, match="does not load"):
        compile_profile(b"{}")


def test_the_strictest_profile_is_what_a_default_profile_is():
    assert Profile() == STRICTEST
