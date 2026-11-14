# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The client (and what it imports) runs on Apple's Python 3.9 with the standard library only.

The owner's Mac has /usr/bin/python3 3.9 and nothing installed, so the client side must parse under a 3.9
target (no 3.10+ grammar) and import nothing but the standard library and `protocol`. This checks both
without installing vermin, by parsing with `ast.parse(..., feature_version=(3, 9))` and walking the import
nodes. It also checks the client's own reply parser agrees with the harness's, and the interface helpers.
"""
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
# the modules that must run on the Mac (client + what it imports), and the standalone host loader
CLIENT_SIDE = [PKG / "client.py", PKG / "protocol.py"]
STANDALONE = [PKG.parents[1] / "prismpath-ebpf" / "gnet" / "gn_loader.py"]

STDLIB = set(getattr(sys, "stdlib_module_names", set())) | {"urllib"}


@pytest.mark.parametrize("path", CLIENT_SIDE + STANDALONE, ids=lambda p: p.name)
def test_parses_under_python39(path):
    """3.10+ syntax (match statements, parenthesised context managers, etc.) raises here."""
    ast.parse(path.read_text(), filename=str(path), feature_version=(3, 9))


@pytest.mark.parametrize("path", CLIENT_SIDE, ids=lambda p: p.name)
def test_client_imports_only_stdlib_and_protocol(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root in STDLIB, "%s imports non-stdlib %s" % (path.name, alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:                              # a relative import: only `protocol` is allowed
                assert node.module in (None, "protocol"), "%s relative-imports %s" % (path.name, node.module)
                if node.module is None:
                    assert all(a.name == "protocol" for a in node.names)
            else:
                root = (node.module or "").split(".")[0]
                assert root in STDLIB, "%s imports non-stdlib %s" % (path.name, node.module)


def test_client_parse_reply_matches_harness():
    from integrations.governed_harness import harness
    from integrations.governed_net import client
    samples = [
        '{"tool": "list", "args": {"handle": 1}}',
        '  {"final": "done"}  ',
        'call:run_command{"argv": ["sh", "-c", "x"]}',
        'thinking... {"tool":"write","args":{"handle":3,"content":"x"}} tail',
        'no json here',
        '{"not a tool": 1} then {"tool":"delete","args":{"handle":9}}',
        'call:bad{not json}',
    ]
    for text in samples:
        assert client.parse_reply(text) == harness.parse_reply(text), text


def test_interface_helpers():
    from integrations.governed_net import client
    # a sample macOS ifconfig block and a Linux `ip -o` line
    mac = "en1: flags=8863\n\tinet 203.0.113.40 netmask 0xffffff00 broadcast 203.0.113.255\n\tinet6 fe80::1\n"
    linux = "3: en1    inet 203.0.113.40/24 brd 203.0.113.255 scope global en1\n"
    assert client.ipv4_addresses(mac) == ["203.0.113.40"]
    assert client.ipv4_addresses(linux) == ["203.0.113.40"]
    assert client.in_network("203.0.113.40", "203.0.113.0/24")
    assert not client.in_network("203.0.113.40", "198.51.100.0/24")


def test_choose_source_refuses_wrong_interface(monkeypatch):
    from integrations.governed_net import client
    monkeypatch.setattr(client, "interface_ipv4s", lambda ifname: ["198.51.100.5"])   # the tunnel, not the LAN
    with pytest.raises(RuntimeError):
        client.choose_source("utun3", "203.0.113.0/24")
    monkeypatch.setattr(client, "interface_ipv4s", lambda ifname: ["203.0.113.40"])
    assert client.choose_source("en1", "203.0.113.0/24") == "203.0.113.40"


def test_loader_self_test_passes():
    spec = importlib.util.spec_from_file_location("gn_loader", STANDALONE[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.self_test() == 0
    with pytest.raises(SystemExit):
        module.main(["fill", "--maps-dir", "/x", "--table", "t", "--actions", "a", "--server-ip", "bad", "--port", "1"])
