# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A workload's SPIFFE ID as a gateway reading (spec-policy-distribution.md, section 13.1, ID1 to ID8): the two
artifact kinds `identity.bundle` and `identity.map`, their readers, their widening comparators, the gateway's
`workload` class from the client certificate its front proxy passes on, and the CLI that writes the bodies. Every
certificate is made here with `cryptography`, and nothing touches the network beyond loopback. Each test names the
conformance case of section 20 it covers."""
import base64
import datetime
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from prismpath import canon  # noqa: E402
from prismpath.agent import commands  # noqa: E402
from prismpath.distribution import envelope as env, kinds, trust as trust_module, widening  # noqa: E402
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER, agent_home  # noqa: E402
from prismpath.distribution.verify import PepView, verify  # noqa: E402
from prismpath.gateway import cli as gcli, identity, proxy, reading as rd  # noqa: E402
from prismpath.kernel import canon2, policy_source  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import NOW, STREAM, seal  # noqa: E402
from prismpath.tests.test_distribution_gateway import DEMO, ROUTES, GatewayHome, _read  # noqa: E402
from prismpath.tests.test_gateway import Running, Upstream, receipts  # noqa: E402

H = canon.sha256_hex
HEADER = "X-Client-Cert"
LOOPBACK = identity.Setting.of(HEADER, ["127.0.0.1"])

# The demo policy with a `workload` field: an invalid certificate is refused with every unreadable field, the admin
# routes are read only by the `ops` workload, the orders are read by anyone, and every other path is read only by a
# workload with a valid certificate (`ops`, `billing` or one the map does not name).
_SOURCE = gcli.DEMO_POLICY.with_name("demo.rules.md").read_text(encoding="utf-8")
WORKLOAD_POLICY = policy_source.compile_source(
    _SOURCE.replace("field.grant: category", "field.grant: category\nfield.workload: category")
    .replace('or grant == "invalid"', 'or grant == "invalid" or workload == "invalid"')
    .replace('-> allow: when path_class == "admin" and method_class == "read" and body_class == "none" and grant == "valid"',
             '-> allow: when path_class == "admin" and method_class == "read" and body_class == "none" and grant == "valid" and workload == "ops"')
    .replace('-> allow: when path_class == "other" and method_class == "read" and body_class == "none"',
             '-> allow: when path_class == "other" and method_class == "read" and body_class == "none" and workload in ["ops", "billing", "other"]'))
WORKLOAD_POLICY = WORKLOAD_POLICY[:-1] if WORKLOAD_POLICY.endswith(b"\n") else WORKLOAD_POLICY


# ------------------------------------------------------------------ test certificates

def _time(offset: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(NOW + offset, datetime.timezone.utc)


CA_USAGE = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                         encipher_only=False, decipher_only=False)
LEAF_USAGE = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                           data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                           encipher_only=False, decipher_only=False)


def make_cert(key, issuer_key, issuer_name, *, subject="", ca=False, uris=(), dns=(), usage="auto", constraints=True,
              start=-3600, end=86400):
    """A certificate for `key` signed by `issuer_key`: a CA with keyCertSign when `ca`, else a leaf with
    digitalSignature, its SANs the URIs and DNS names given. `usage` None leaves the key usage out."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]) if subject else x509.Name([])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(_time(start)).not_valid_after(_time(end)))
    if constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    usage = (CA_USAGE if ca else LEAF_USAGE) if usage == "auto" else usage
    if usage is not None:
        builder = builder.add_extension(usage, critical=True)
    names = [x509.UniformResourceIdentifier(uri) for uri in uris] + [x509.DNSName(d) for d in dns]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=not subject)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                                    critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


class CA:
    """A trust domain's root CA, which issues leaves and intermediates."""

    def __init__(self, domain: str, **kw):
        self.domain, self.key = domain, new_key()
        kw.setdefault("uris", (f"spiffe://{domain}",))
        self.cert = make_cert(self.key, self.key, None, subject=f"{domain} root", ca=True, **kw)

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def leaf(self, path="/billing/api", *, uris=None, **kw):
        return make_cert(new_key(), self.key, self.cert.subject,
                         uris=(f"spiffe://{self.domain}{path}",) if uris is None else uris, **kw)

    def intermediate(self, **kw):
        sub = CA.__new__(CA)
        sub.domain, sub.key = self.domain, new_key()
        sub.cert = make_cert(sub.key, self.key, self.cert.subject, subject=f"{self.domain} intermediate", ca=True, **kw)
        return sub


def header(*certs) -> str:
    """The header value a front proxy writes: the percent encoded PEM of the leaf and then its intermediates."""
    return quote("".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs), safe="")


ORG = CA("example.org")
OTHER = CA("other.test")
BUNDLE = identity.bundle_body({"example.org": [ORG.der], "other.test": [OTHER.der]})
MAP = identity.map_body([{"match": "spiffe://example.org/ops/*", "class": "ops"},
                         {"match": "spiffe://example.org/billing/*", "class": "billing"},
                         {"match": "spiffe://other.test/ops/admin", "class": "ops"}])


def reader(bundle=BUNDLE, mapping=MAP, setting=LOOPBACK, now=NOW):
    return identity.Identity.from_bodies(bundle, mapping, setting, clock=lambda: now)


def read(value, peer="127.0.0.1", **kw):
    return reader(**kw).read({HEADER.lower(): value if isinstance(value, list) else [value]}, peer)


def check(artifact: str, body: bytes):
    return kinds.ARTIFACTS[artifact].check(None, body, None)


def bundle_doc(domains) -> bytes:
    return canon.canon2_bytes({"domains": domains, "encoding": "canon/2", "format": identity.BUNDLE_FORMAT})


def map_doc(entries) -> bytes:
    return canon.canon2_bytes({"encoding": "canon/2", "entries": entries, "format": identity.MAP_FORMAT})


def b64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


# ------------------------------------------------------------------ a gateway PEP whose releases carry identity

def release(gw, policy: bytes, seq: int, extra=None, *, widens=True, froms=(), statement=True, routes=ROUTES):
    """Stage a release of `policy`, `routes` and the `extra` artifacts at `seq`, with a widening statement when
    `statement`, then commit. The records, last the commit's."""
    bodies = {"policy.core": policy, "gateway.routes": routes, **(extra or {})}
    release_id = env.release_id(sorted((name, H(body)) for name, body in bodies.items()))
    active = gw.pep.active.policy_sha256 if gw.pep.active else ""
    args = {"release": release_id, "policy_sha256": H(policy), "replaces": active, "widens": widens}
    acks = []
    if statement:
        body = _dist.widening(froms)
        acks.append(gw.pep.stage(seal("trust.widening", body, seq=seq, targets=("gateway",), **args), body))
    for name, body in sorted(bodies.items()):
        acks.append(gw.pep.stage(seal(name, body, seq=seq, targets=("gateway",), **args), body))
    acks.append(gw.pep.commit(STREAM, seq, H(policy)))
    return [_read(gw, ack) for ack in acks]


@pytest.fixture
def gw(tmp_path, monkeypatch):
    """A gateway PEP that committed the workload policy with the bundle and the map at seq 1."""
    monkeypatch.setattr(agent_home, "clock", lambda: NOW)
    point = GatewayHome(tmp_path / "gateway")
    records = release(point, WORKLOAD_POLICY, 1, {"identity.bundle": BUNDLE, "identity.map": MAP})
    assert records[-1].event == "committed", records
    return point


# ------------------------------------------------------------------ the two kinds (ID1, ID2, ID8)

def test_case_281_the_identity_kinds_are_artifacts_every_pep_reads_and_only_a_gateway_uses(gw):
    """case_281: E8, ID8. An envelope of `identity.bundle` or `identity.map` for target `gateway` is well formed, so
    a `host` or a `mesh` PEP refuses it with `dist:target-mismatch` and not `dist:bad-format`, a gateway accepts it,
    and an artifact name the list does not hold is still `dist:bad-format`."""
    store = trust_module.TrustStore.with_keys([_dist.GEN.public_raw(_dist.GEN.test_key("A"))])
    for artifact, body in (("identity.bundle", BUNDLE), ("identity.map", MAP)):
        sealed = seal(artifact, body, seq=2, targets=("gateway",))
        for kind in ("host", "mesh"):
            verdict = verify(sealed, body, trust=store, pep=PepView(kind, STREAM), now=NOW)
            assert verdict.cause == "dist:target-mismatch", (artifact, kind, verdict.cause)
        assert verify(sealed, body, trust=gw.pep.trust, pep=PepView("gateway", STREAM), now=NOW).ok
    with pytest.raises(kinds.Refused) as refused:
        env.build("identity.other", MAP, stream=STREAM, seq=1, targets=("gateway",), not_before=NOW,
                  expires=NOW + 60, policy_sha256=H(MAP), release=env.release_id([("identity.map", H(MAP))]))
    assert refused.value.cause == "dist:bad-format"


def test_case_282_an_identity_bundle_reads_only_as_sorted_ca_certificates_per_trust_domain():
    """case_282: ID1, V11. A bundle of CA certificates reads, and each of these is `dist:bad-format`: a leaf or a
    CA without keyCertSign in it, a CA whose URI SAN names another trust domain, a list unsorted, with a repeat or
    empty, a trust domain name in capitals, no domain, base64 that is not canonical, DER that is not a certificate, an
    extra member. The same bundle spelled out of order is `document:not-canonical`."""
    assert check("identity.bundle", BUNDLE) is None
    assert set(kinds.read_identity_bundle(BUNDLE)) == {"example.org", "other.test"}
    second = CA("example.org")
    no_sign = CA("example.org", usage=x509.KeyUsage(True, False, False, False, False, False, False, False, False))
    foreign = CA("example.org", uris=("spiffe://other.test",))
    leaf = ORG.leaf().public_bytes(serialization.Encoding.DER)
    pair = sorted([b64(ORG.der), b64(second.der)])
    assert check("identity.bundle", bundle_doc({"example.org": pair})) is None
    bad = [bundle_doc({"example.org": [b64(leaf)]}), bundle_doc({"example.org": [b64(no_sign.der)]}),
           bundle_doc({"example.org": [b64(foreign.der)]}), bundle_doc({"example.org": pair[::-1]}),
           bundle_doc({"example.org": [b64(ORG.der)] * 2}), bundle_doc({"example.org": []}),
           bundle_doc({"Example.org": [b64(ORG.der)]}), bundle_doc({}),
           bundle_doc({"example.org": [b64(ORG.der).rstrip("=") + "\n"]}),
           bundle_doc({"example.org": [b64(b"not a certificate")]}),
           canon.canon2_bytes({"domains": {"example.org": [b64(ORG.der)]}, "encoding": "canon/2",
                               "format": identity.BUNDLE_FORMAT, "extra": 1})]
    assert [check("identity.bundle", body) for body in bad] == ["dist:bad-format"] * len(bad)
    assert check("identity.bundle", json.dumps({"format": identity.BUNDLE_FORMAT, "encoding": "canon/2",
                                               "domains": canon2.loads(BUNDLE)["domains"]},
                                              separators=(",", ":")).encode()) == "document:not-canonical"


def test_case_283_an_identity_map_reads_spiffe_id_patterns_to_classes_in_order():
    """case_283: ID2, V11. A map reads, the first entry that matches wins, `/*` matches its path and everything
    below it, an entry without it that one ID, and an ID no entry matches is `other`. Each of these is
    `dist:bad-format`: a match that is not a SPIFFE ID, a trust domain alone without `/*`, a `*` that is not a
    closing `/*`, a `..` segment, a trailing `/`, a percent escape, a capital in the trust domain, a reserved class,
    a match listed twice and no entries."""
    assert check("identity.map", MAP) is None
    entries = kinds.read_identity_map(map_doc([{"class": "admin", "match": "spiffe://example.org/ops/admin"},
                                               {"class": "ops", "match": "spiffe://example.org/ops/*"},
                                               {"class": "all", "match": "spiffe://example.org/*"}]))
    found = [identity.classify(entries, f"spiffe://example.org{path}") for path in
             ("/ops/admin", "/ops/admin/x", "/ops", "/ops/a/b", "/opsx", "/billing")]
    assert found == ["admin", "ops", "ops", "ops", "all", "all"]
    assert identity.classify(entries, "spiffe://other.test/ops") == "other"
    bad = ["https://example.org/ops", "spiffe://example.org", "spiffe://example.org/o*", "spiffe://example.org/*/x",
           "spiffe://example.org/a/../b", "spiffe://example.org/a/", "spiffe://example.org/a%20b",
           "spiffe://Example.org/a", "spiffe://example.org:443/a", "spiffe://user@example.org/a"]
    for match in bad:
        assert check("identity.map", map_doc([{"class": "x", "match": match}])) == "dist:bad-format", match
    for name in ("other", "none", "invalid", "unknown", "Ops", "1x"):
        assert check("identity.map", map_doc([{"class": name, "match": "spiffe://a.test/x"}])) == "dist:bad-format"
    twice = [{"class": "a", "match": "spiffe://a.test/x"}, {"class": "b", "match": "spiffe://a.test/x"}]
    assert check("identity.map", map_doc(twice)) == "dist:bad-format"
    assert check("identity.map", map_doc([])) == "dist:bad-format"


# ------------------------------------------------------------------ the reading (ID4 to ID6)

def test_case_284_a_running_gateway_reads_the_workload_class_from_the_front_proxys_header(gw):
    """case_284: ID4, ID6. Behind a front proxy on loopback the gateway reads no header as `none`, a valid SPIFFE
    ID the map names as its class and one it does not name as `other`, through an intermediate as well. The policy
    decides each, every receipt's reading carries it, and the header never reaches the service."""
    up = Upstream()
    g = Running(up, gw.state_dir, routes=None, identity_setting=LOOPBACK)
    ops = ORG.intermediate()
    try:
        assert g.gateway.failure is None
        assert g.request("GET", "/api/orders/7")[0] == 200                                  # orders: anyone
        assert g.request("GET", "/health")[0] == 403                                        # none
        assert g.request("GET", "/health", headers={HEADER: header(ORG.leaf("/web"))})[0] == 200      # other
        assert g.request("GET", "/health", headers={HEADER: header(ORG.leaf("/billing/api"))})[0] == 200
        leaf = make_cert(new_key(), ops.key, ops.cert.subject, uris=("spiffe://example.org/ops/deploy",))
        assert g.request("GET", "/health", headers={HEADER: header(leaf, ops.cert)})[0] == 200        # ops
        assert g.request("GET", "/health", headers={HEADER: header(OTHER.leaf("/web"))})[0] == 200
    finally:
        g.close()
        up.close()
    workloads = [canon2.loads(bytes.fromhex(line["reading"]))["workload"] for line in receipts(gw.state_dir)]
    assert workloads == ["none", "none", "other", "billing", "ops", "other"]
    assert all(HEADER.lower() not in {name.lower() for name in seen["headers"]} for seen in up.seen)


def test_case_285_a_certificate_that_fails_the_svid_checks_reads_invalid(gw):
    """case_285: ID4, ID5, ID6. Each of these reads `invalid`, and the policy refuses it: two URI SANs, none, a DNS
    name alone, a URI that is not a SPIFFE ID, a SPIFFE ID without a path, a leaf that is a CA, one without basic
    constraints, without a key usage, with keyCertSign, without digitalSignature, expired, not yet valid, signed by
    another trust domain's CA, of a trust domain the bundle does not hold, self signed, with its signature changed,
    through an intermediate that is not a CA, a chain longer than four, a header that is not percent encoded PEM or
    has more after it, two headers, and a valid header from a peer that is not the front proxy."""
    rogue = CA("example.org")
    stranger = CA("stranger.test")
    self_key = new_key()
    good = ORG.leaf("/web")
    tampered = bytearray(good.public_bytes(serialization.Encoding.DER))
    tampered[-3] ^= 1
    tampered_pem = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(tampered)).decode() + "-----END CERTIFICATE-----\n"
    mid_key = new_key()
    not_ca = make_cert(mid_key, ORG.key, ORG.cert.subject, subject="mid", uris=("spiffe://example.org/mid",))
    chain = [ORG.intermediate()]
    for _ in range(3):
        chain.append(chain[-1].intermediate())
    long_leaf = make_cert(new_key(), chain[-1].key, chain[-1].cert.subject, uris=("spiffe://example.org/web",))
    cases = {
        "two uris": header(ORG.leaf(uris=("spiffe://example.org/a", "spiffe://example.org/b"))),
        "no san": header(ORG.leaf(uris=(), subject="x")),
        "dns only": header(ORG.leaf(uris=(), dns=("web.example.org",))),
        "not spiffe": header(ORG.leaf(uris=("https://example.org/web",))),
        "no path": header(ORG.leaf(uris=("spiffe://example.org",))),
        "a ca": header(ORG.leaf(ca=True, usage=LEAF_USAGE)),
        "no constraints": header(ORG.leaf(constraints=False)),
        "no usage": header(ORG.leaf(usage=None)),
        "cert sign": header(ORG.leaf(usage=x509.KeyUsage(True, False, False, False, False, True, False, False, False))),
        "no signature use": header(ORG.leaf(usage=x509.KeyUsage(False, False, True, False, False, False, False, False, False))),
        "expired": header(ORG.leaf(start=-7200, end=-60)),
        "not yet": header(ORG.leaf(start=60, end=7200)),
        "another domain's ca": header(make_cert(new_key(), OTHER.key, OTHER.cert.subject,
                                                uris=("spiffe://example.org/web",))),
        "a rogue ca": header(rogue.leaf("/ops/admin")),
        "unknown domain": header(stranger.leaf("/web")),
        "self signed": header(make_cert(self_key, self_key, None, uris=("spiffe://example.org/web",))),
        "tampered": quote(tampered_pem, safe=""),
        "not a ca between": header(make_cert(new_key(), mid_key, not_ca.subject, uris=("spiffe://example.org/web",)),
                                   not_ca),
        "too long": header(long_leaf, *[ca.cert for ca in reversed(chain)]),
        "garbled": "not%20pem",
        "trailing": header(good) + quote("junk", safe=""),
        "bad escape": header(good).replace("%0A", "%0", 1),
        "raw base64": base64.b64encode(good.public_bytes(serialization.Encoding.DER)).decode(),
    }
    assert read(header(good)) == "other"
    found = {name: read(value) for name, value in cases.items()}
    assert found == {name: "invalid" for name in cases}
    assert read([header(good), header(good)]) == "invalid"                                   # two headers
    assert read(header(good), peer="192.0.2.7") == "invalid"                                 # not the front proxy
    assert read([], peer="192.0.2.7") == "none"
    up = Upstream()
    g = Running(up, gw.state_dir, routes=None, identity_setting=identity.Setting.of(HEADER, ["192.0.2.7"]))
    try:
        assert g.request("GET", "/api/orders/7", headers={HEADER: header(ORG.leaf("/ops/x"))})[0] == 403
        assert g.request("GET", "/api/orders/7")[0] == 200
    finally:
        g.close()
        up.close()
    assert up.seen and len(up.seen) == 1


# ------------------------------------------------------------------ widening (ID7)

def test_case_286_a_changed_bundle_or_map_is_larger_unless_it_only_removes_entries(gw):
    """case_286: ID7, W1. A bundle that only drops a CA or a trust domain and a map that only drops entries, which
    no later entry would take the IDs of, are not larger, so a release of them commits without a widening statement.
    A CA added or moved, an entry added, moved or with another class, and a drop whose IDs a later entry takes are
    larger, and such a release without a statement is `dist:widening-unsigned`."""
    second = CA("example.org")
    rows = [{"match": "spiffe://example.org/ops/admin", "class": "admin"},
            {"match": "spiffe://example.org/ops/*", "class": "ops"},
            {"match": "spiffe://example.org/billing/*", "class": "billing"}]
    full = identity.map_body(rows)

    def cmp(artifact, active, staged):
        return widening.compare_artifact(artifact, active, staged)

    both = identity.bundle_body({"example.org": [ORG.der, second.der], "other.test": [OTHER.der]})
    assert cmp("identity.bundle", both, identity.bundle_body({"example.org": [ORG.der]})) == NOT_LARGER
    assert cmp("identity.bundle", both, both) == NOT_LARGER
    assert cmp("identity.bundle", BUNDLE, both) == LARGER                                    # a CA added
    plain = CA("other.test", uris=())                                                        # a CA with no URI SAN
    held = identity.bundle_body({"example.org": [ORG.der], "other.test": [plain.der]})
    assert cmp("identity.bundle", held, identity.bundle_body({"example.org": [ORG.der, plain.der]})) == LARGER
    assert cmp("identity.bundle", BUNDLE, b"{}") == CANNOT_DECIDE
    assert cmp("identity.map", full, identity.map_body(rows[1:])) == LARGER                  # /ops/admin falls to ops
    assert cmp("identity.map", full, identity.map_body(rows[:1] + rows[2:])) == NOT_LARGER
    assert cmp("identity.map", full, identity.map_body(rows[:2])) == NOT_LARGER
    assert cmp("identity.map", full, identity.map_body([rows[0], rows[2], rows[1]])) == LARGER   # moved
    assert cmp("identity.map", full, identity.map_body(rows + [{"match": "spiffe://a.test/*", "class": "a"}])) == LARGER
    assert cmp("identity.map", full, identity.map_body([dict(rows[0], **{"class": "ops"})] + rows[1:])) == LARGER
    narrower = identity.bundle_body({"example.org": [ORG.der]})
    fewer = identity.map_body([{"match": "spiffe://example.org/ops/*", "class": "ops"},
                               {"match": "spiffe://example.org/billing/*", "class": "billing"}])
    records = release(gw, WORKLOAD_POLICY, 2, {"identity.bundle": narrower, "identity.map": fewer}, widens=False,
                      statement=False)
    assert records[-1].event == "committed", records
    records = release(gw, WORKLOAD_POLICY, 3, {"identity.bundle": BUNDLE, "identity.map": MAP}, widens=False,
                      statement=False)
    assert "dist:widening-unsigned" in [record.cause for record in records]
    assert gw.pep.active.bodies["identity.bundle"] == narrower
    assert release(gw, WORKLOAD_POLICY, 4, {"identity.bundle": BUNDLE, "identity.map": MAP},
                   froms=[H(WORKLOAD_POLICY)])[-1].event == "committed"


# ------------------------------------------------------------------ the release (ID3)

def test_case_287_a_gateway_release_carries_the_identity_kinds_exactly_when_its_policy_reads_workload(gw, monkeypatch):
    """case_287: ID3, C2. A release whose policy reads `workload` without the bundle or the map, one whose map names
    a trust domain its bundle does not hold, and one with the identity kinds whose policy reads no workload are each
    `dist:incomplete`. A complete release commits, and a running gateway reads the next request under its new
    bundle: a CA taken out makes its leaves read `invalid`."""
    other_map = identity.map_body([{"match": "spiffe://stranger.test/*", "class": "ops"}])
    for seq, (policy, extra) in enumerate([
            (WORKLOAD_POLICY, {}), (WORKLOAD_POLICY, {"identity.map": MAP}), (WORKLOAD_POLICY, {"identity.bundle": BUNDLE}),
            (WORKLOAD_POLICY, {"identity.bundle": BUNDLE, "identity.map": other_map}),
            (DEMO, {"identity.bundle": BUNDLE, "identity.map": MAP})], start=2):
        assert release(gw, policy, seq, extra, froms=[])[-1].cause == "dist:incomplete", (seq, sorted(extra))
    up = Upstream()
    g = Running(up, gw.state_dir, routes=None, identity_setting=LOOPBACK)
    try:
        assert g.request("GET", "/health", headers={HEADER: header(OTHER.leaf("/web"))})[0] == 200
        only_org = identity.bundle_body({"example.org": [ORG.der]})
        org_map = identity.map_body([{"match": "spiffe://example.org/ops/*", "class": "ops"}])
        assert release(gw, WORKLOAD_POLICY, 9, {"identity.bundle": only_org, "identity.map": org_map},
                       widens=False, statement=False)[-1].event == "committed"
        assert g.request("GET", "/health", headers={HEADER: header(OTHER.leaf("/web"))})[0] == 403
        assert g.request("GET", "/health", headers={HEADER: header(ORG.leaf("/ops/x"))})[0] == 200
    finally:
        g.close()
        up.close()
    assert canon2.loads(bytes.fromhex(receipts(gw.state_dir)[1]["reading"]))["workload"] == "invalid"
    no_setting = proxy.Gateway("http://127.0.0.1:9", None, gw.state_dir)
    assert no_setting.failure and "front proxy" in no_setting.failure


# ------------------------------------------------------------------ the CLI (ID1, ID2)

def test_case_288_the_cli_writes_both_bodies_and_dist_seal_seals_them_for_a_gateway(tmp_path, gw, monkeypatch):
    """case_288: ID1, ID2, W7. `prismpath gateway identity-bundle` and `identity-map` write the canonical bodies,
    `prismpath dist seal` seals them for target `gateway` with `widens` set as W7 sets it, and the gateway's verifier
    accepts each. A home that holds its own policy takes the bodies at `serve`, and a home that follows a stream
    refuses them there."""
    from prismpath import cli as main_cli
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    pem = tmp_path / "org.pem"
    pem.write_bytes(ORG.cert.public_bytes(serialization.Encoding.PEM))
    other = tmp_path / "other.pem"
    other.write_bytes(OTHER.cert.public_bytes(serialization.Encoding.PEM))
    entries = tmp_path / "map.json"
    entries.write_text(json.dumps({"entries": [{"match": "spiffe://example.org/ops/*", "class": "ops"},
                                               {"match": "spiffe://example.org/billing/*", "class": "billing"},
                                               {"match": "spiffe://other.test/ops/admin", "class": "ops"}]}))
    devnull = open(os.devnull, "w")  # noqa: SIM115 - the test's sink, closed with the process
    assert gcli.identity_bundle([f"example.org={pem}", f"other.test={other}"], str(tmp_path / "bundle.body"),
                                out=devnull) == 0
    assert gcli.identity_map(str(entries), str(tmp_path / "map.body"), out=devnull) == 0
    assert (tmp_path / "bundle.body").read_bytes() == BUNDLE and (tmp_path / "map.body").read_bytes() == MAP
    for bad in (["example.org"], [f"Example.org={pem}"], [f"example.org={entries}"]):
        with pytest.raises(commands.AgentError):
            gcli.identity_bundle(bad, str(tmp_path / "x"), out=devnull)
    entries.write_text(json.dumps({"entries": [{"match": "spiffe://example.org", "class": "ops"}]}))
    with pytest.raises(commands.AgentError):
        gcli.identity_map(str(entries), str(tmp_path / "x"), out=devnull)
    from cryptography.hazmat.primitives import serialization as ser
    key = tmp_path / "a.pem"
    key.write_bytes(_dist.GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                         ser.NoEncryption()))
    for artifact, name in (("identity.bundle", "bundle"), ("identity.map", "map")):
        out = tmp_path / f"{name}.sealed"
        code = main_cli.main(["dist", "seal", "--artifact", artifact, "--body", str(tmp_path / f"{name}.body"),
                              "--stream", STREAM, "--seq", "5", "--target", "gateway", "--key", str(key),
                              "--not-before", str(NOW), "--expires", str(NOW + 3600), "--policy", H(WORKLOAD_POLICY),
                              "--out", str(out)])
        assert code == 0
        sealed, body = out.read_bytes(), (tmp_path / f"{name}.body").read_bytes()
        envelope = env.read(env.unseal(sealed)[0])
        assert (envelope.artifact, envelope.targets, envelope.widens) == (artifact, ("gateway",), True)
        assert verify(sealed, body, trust=gw.pep.trust, pep=PepView("gateway", STREAM), now=NOW).ok
    home = tmp_path / "local"
    rules = tmp_path / "workload.core.json"
    rules.write_bytes(WORKLOAD_POLICY)
    assert gcli.init(home, str(rules), out=devnull) == 0
    with pytest.raises(SystemExit, match="refused here"):
        gcli.serve(SimpleNamespace(upstream="http://127.0.0.1:9", listen="127.0.0.1:0", routes=None,
                                   home=str(gw.state_dir), identity_bundle=str(tmp_path / "bundle.body"),
                                   identity_map=str(tmp_path / "map.body"), client_cert_header=HEADER,
                                   front_proxy=["127.0.0.1"]))
    # a home that holds its own policy reads at the real time, so its trust domain's CA is valid now
    import time
    offset = int(time.time()) - NOW
    here = CA("example.org", start=offset - 3600, end=offset + 3600)
    local_bundle = identity.bundle_body({"example.org": [here.der]})
    local_map = identity.map_body([{"match": "spiffe://example.org/billing/*", "class": "billing"}])
    up = Upstream()
    g = Running(up, home, identity_setting=LOOPBACK, identity_bodies=(local_bundle, local_map))
    bare = proxy.Gateway(up.url, rd.Routes.load(gcli.DEMO_ROUTES), home, session="t2")
    try:
        assert g.gateway.failure is None and "workload" in bare.failure
        leaf = here.leaf("/billing/x", start=offset - 60, end=offset + 60)
        assert g.request("GET", "/health", headers={HEADER: header(leaf)})[0] == 200
        assert g.request("GET", "/health")[0] == 403
    finally:
        g.close()
        up.close()


def test_the_front_proxy_setting_refuses_a_header_the_gateway_reads_or_passes_on():
    """ID4: the certificate header is never one the gateway reads for itself or passes on, and is read only from a
    front proxy address that is named."""
    for name in ("Content-Type", "X-PrismPath-Grant", "Host", "bad header"):
        with pytest.raises(identity.IdentityError):
            identity.Setting.of(name, ["127.0.0.1"])
    with pytest.raises(identity.IdentityError):
        identity.Setting.of(HEADER, [])
    with pytest.raises(identity.IdentityError):
        identity.Setting.of(HEADER, ["front.example"])
    with pytest.raises(identity.IdentityError):
        identity.Setting.of(None, ["127.0.0.1"])
    assert identity.Setting.of(None, []) is None
    with pytest.raises(ValueError):
        proxy.Gateway("http://127.0.0.1:9", rd.Routes.load(gcli.DEMO_ROUTES), Path("/nonexistent"),
                      forward_headers=[HEADER], identity_setting=LOOPBACK)


def test_a_spiffe_id_reads_by_the_grammar_of_spiffe_id_section_2():
    """ID2, ID5: the scheme and trust domain are lower case, the path segments are letters, digits, `.`, `-` and
    `_` and never `.` or `..`, and an ID is at most 2048 bytes."""
    assert identity.parse_id("spiffe://example.org/ns/prod/sa/web") == ("example.org", ("ns", "prod", "sa", "web"))
    assert identity.parse_id("spiffe://example.org") == ("example.org", ())
    for bad in ("SPIFFE://example.org/a", "spiffe://example.org/a/", "spiffe://example.org//a", "spiffe:///a",
                "spiffe://example.org/a?b", "spiffe://example.org/a#b", "spiffe://example.org/." ,
                "spiffe://exa mple.org/a", "spiffe://example.org/" + "a" * 2040, None):
        assert identity.parse_id(bad) is None, bad
