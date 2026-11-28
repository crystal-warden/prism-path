# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A workload's SPIFFE ID as one more field of the gateway's reading (spec-policy-distribution.md, section 13.1,
ID1 to ID8).

Two artifact kinds carry what the gateway needs, each in an ordinary envelope.

    identity.bundle  {"domains": {"example.org": ["<base64 DER of a CA certificate>", ...]},
                      "encoding": "canon/2", "format": "prismpath.dist-identity-bundle/1"}
    identity.map     {"encoding": "canon/2", "entries": [{"class": "billing", "match": "spiffe://example.org/billing/*"}],
                      "format": "prismpath.dist-identity-map/1"}

The bundle is each trust domain's X.509 CA certificates, the map is SPIFFE ID patterns to classes, read in order as
the route table is: the first entry that matches wins, `/*` at the end matches that path and everything below it,
and an entry without it matches that one ID.

The gateway does not terminate TLS. The front proxy that does passes the client's certificate chain in one header
the owner names, as the percent encoded PEM of the leaf followed by its intermediates (the form of nginx's
`$ssl_client_escaped_cert` and of the `Cert` and `Chain` members of Envoy's XFCC). The header is read only from a
peer address the owner lists as the front proxy.

The reading's `workload` is
  none     no certificate header;
  invalid  a header from a peer that is not the front proxy, more than one header, a value that does not read, or a
           chain that fails the check of ID5;
  other    a valid SPIFFE ID that no entry of the map matches;
  a class  the class of the first entry that matches it.

ID5 is a bounded check, not a general path validator. The leaf is an X.509 v3 certificate with exactly one URI SAN,
a SPIFFE ID with a path (X509-SVID section 2), basic constraints with `cA` false and a key usage with
digitalSignature and without keyCertSign or cRLSign (section 4.3). Its chain is built and checked by the
`cryptography` package's RFC 5280 verifier (signatures, validity at the gateway's time, issuer and subject chaining,
basic constraints and key usage of every CA, at most MAX_CHAIN certificates) against the CA certificates of the
leaf's own trust domain alone (section 5), so a CA of another trust domain never vouches for it. Every CA of the
bundle was held to `cA` true and keyCertSign when the bundle was read (section 4.1), and so is every intermediate.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

FIELD = "workload"
BUNDLE_FORMAT = "prismpath.dist-identity-bundle/1"
MAP_FORMAT = "prismpath.dist-identity-map/1"
RESERVED = ("invalid", "none", "other", "unknown")   # classes the reading gives itself, never a map's
SCHEME = "spiffe://"
MAX_ID = 2048                                       # SPIFFE-ID 2.3: a SPIFFE ID is at most 2048 bytes
MAX_DOMAIN = 255                                    # SPIFFE-ID 2.1: a trust domain name is at most 255 bytes
BUNDLE_DOMAINS, BUNDLE_CAS, CA_MAX = 16, 16, 8192   # ID1: trust domains, CAs per domain, bytes of one CA's DER
MAP_ENTRIES = 1000                                  # ID2
MAX_HEADER, MAX_CHAIN = 16384, 4                    # ID4, ID5: bytes of the header value, certificates in the chain

_DOMAIN = re.compile(r"[a-z0-9._-]{1,255}")
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_CLASS = re.compile(r"[a-z][a-z0-9_]{0,31}")
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


class IdentityError(ValueError):
    """A bundle, a map or a setting that does not read. The text says why."""


# ------------------------------------------------------------------ SPIFFE IDs (SPIFFE-ID section 2)

def parse_id(text) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """(trust domain, path segments) of a SPIFFE ID, or None when `text` is not one. The scheme and the trust domain
    are lower case, the trust domain is letters, digits, `.`, `-` and `_`, each path segment is letters, digits,
    `.`, `-` and `_` and is not `.` or `..`, and there is no port, user, query, fragment, percent escape or trailing
    `/`. A trust domain alone has no segments."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_ID or not text.startswith(SCHEME):
        return None
    domain, slash, path = text[len(SCHEME):].partition("/")
    if not _DOMAIN.fullmatch(domain):
        return None
    if not slash:
        return domain, ()
    segments = tuple(path.split("/"))
    if not all(_SEGMENT.fullmatch(seg) and seg not in (".", "..") for seg in segments):
        return None
    return domain, segments


def domain_id(domain: str) -> str:
    return SCHEME + domain


# ------------------------------------------------------------------ certificates

def _x509():
    from cryptography import x509
    return x509


def _b64_der(text) -> bytes:
    if not isinstance(text, str) or not _B64.fullmatch(text) or len(text) % 4:
        raise IdentityError("a CA certificate is the standard base64 of its DER, with padding")
    raw = base64.b64decode(text, validate=True)
    if base64.b64encode(raw).decode("ascii") != text or not 0 < len(raw) <= CA_MAX:
        raise IdentityError(f"a CA certificate is the canonical base64 of at most {CA_MAX} bytes of DER")
    return raw


def _extension(cert, kind):
    x509 = _x509()
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _is_ca(cert) -> bool:
    """X509-SVID 4.1: a signing certificate has basic constraints with `cA` true and a key usage with keyCertSign."""
    x509 = _x509()
    constraints, usage = _extension(cert, x509.BasicConstraints), _extension(cert, x509.KeyUsage)
    return (cert.version == x509.Version.v3 and constraints is not None and constraints.ca
            and usage is not None and usage.key_cert_sign)


def _uris(cert) -> Optional[List[str]]:
    x509 = _x509()
    names = _extension(cert, x509.SubjectAlternativeName)
    return None if names is None else names.get_values_for_type(x509.UniformResourceIdentifier)


def read_ca(der: bytes, domain: str):
    """A CA certificate of `domain`'s bundle: DER that is its own canonical encoding, an X.509 v3 CA with
    keyCertSign, and, when it carries URI SANs, the one URI SAN `spiffe://<domain>` (X509-SVID 4.1)."""
    x509 = _x509()
    from cryptography.hazmat.primitives import serialization
    try:
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(serialization.Encoding.DER) != der:
            raise IdentityError("a CA certificate's DER is not its canonical encoding")
        uris = _uris(cert)
    except IdentityError:
        raise
    except Exception as error:   # noqa: BLE001 - a certificate that does not parse is not one
        raise IdentityError(f"a CA certificate of {domain} does not read ({type(error).__name__})") from None
    if not _is_ca(cert):
        raise IdentityError(f"a certificate of {domain}'s bundle is not a CA with keyCertSign")
    if uris is not None and uris and uris != [domain_id(domain)]:
        raise IdentityError(f"a CA certificate of {domain} names a URI SAN other than {domain_id(domain)}")
    return cert


def bundle_doc(doc) -> Dict[str, Tuple[str, ...]]:
    """ID1: the `domains` of a bundle document, each trust domain to its sorted base64 CA certificates, every one
    read by `read_ca`. IdentityError otherwise."""
    if not isinstance(doc, dict) or set(doc) != {"domains", "encoding", "format"} or doc["format"] != BUNDLE_FORMAT \
            or doc["encoding"] != "canon/2":
        raise IdentityError(f"an identity bundle is {{\"domains\", \"encoding\": \"canon/2\", \"format\": "
                            f"\"{BUNDLE_FORMAT}\"}}")
    domains = doc["domains"]
    if not isinstance(domains, dict) or not 0 < len(domains) <= BUNDLE_DOMAINS:
        raise IdentityError(f"an identity bundle names 1 to {BUNDLE_DOMAINS} trust domains")
    out: Dict[str, Tuple[str, ...]] = {}
    for domain, cas in domains.items():
        if not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
            raise IdentityError(f"{domain!r} is not a trust domain name")
        if not isinstance(cas, list) or not 0 < len(cas) <= BUNDLE_CAS or cas != sorted(set(cas)):
            raise IdentityError(f"{domain}'s CA certificates are 1 to {BUNDLE_CAS}, sorted, without repeats")
        for text in cas:
            read_ca(_b64_der(text), domain)
        out[domain] = tuple(cas)
    return out


def bundle_body(domains: Mapping[str, Sequence[bytes]]) -> bytes:
    """The canon/2 body of a bundle of these trust domains, each to the DER of its CA certificates."""
    from prismpath import canon
    doc = {"domains": {domain: sorted({base64.b64encode(der).decode("ascii") for der in ders})
                       for domain, ders in domains.items()},
           "encoding": canon.CANON2, "format": BUNDLE_FORMAT}
    bundle_doc(doc)
    return canon.canon2_bytes(doc)


# ------------------------------------------------------------------ the map (ID2)

@dataclass(frozen=True)
class Entry:
    domain: str
    segments: Tuple[str, ...]
    prefix: bool
    name: str

    def matches(self, domain: str, segments: Tuple[str, ...]) -> bool:
        if domain != self.domain:
            return False
        if self.prefix:
            return segments[:len(self.segments)] == self.segments
        return segments == self.segments

    def overlaps(self, other: "Entry") -> bool:
        """Whether some SPIFFE ID is matched by both entries."""
        if self.domain != other.domain:
            return False
        short, long_ = sorted((self, other), key=lambda entry: len(entry.segments))
        if long_.segments[:len(short.segments)] != short.segments:
            return False
        return short.prefix or len(short.segments) == len(long_.segments)

    @property
    def match(self) -> str:
        path = "/".join(self.segments)
        return domain_id(self.domain) + ("/" + path if path else "") + ("/*" if self.prefix else "")


def map_doc(doc) -> Tuple[Entry, ...]:
    """ID2: the entries of a map document, in order. A match is a SPIFFE ID with a path, or one followed by `/*`,
    or a trust domain followed by `/*`. No match is listed twice, a class is lower case letters, digits and `_`
    and not one the reading gives itself, and there are 1 to MAP_ENTRIES entries. IdentityError otherwise."""
    if not isinstance(doc, dict) or set(doc) != {"encoding", "entries", "format"} or doc["format"] != MAP_FORMAT \
            or doc["encoding"] != "canon/2":
        raise IdentityError(f"an identity map is {{\"encoding\": \"canon/2\", \"entries\", \"format\": \"{MAP_FORMAT}\"}}")
    rows = doc["entries"]
    if not isinstance(rows, list) or not 0 < len(rows) <= MAP_ENTRIES:
        raise IdentityError(f"an identity map has 1 to {MAP_ENTRIES} entries")
    entries: List[Entry] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"class", "match"}:
            raise IdentityError(f"an entry is {{\"class\": NAME, \"match\": SPIFFE ID}}, not {row!r}")
        match, name = row["match"], row["class"]
        if not isinstance(name, str) or not _CLASS.fullmatch(name) or name in RESERVED:
            raise IdentityError(f"class {name!r} must be lower case letters, digits and `_`, and not one of {RESERVED}")
        prefix = isinstance(match, str) and match.endswith("/*")
        parsed = parse_id(match[:-2] if prefix else match)
        if parsed is None or (not prefix and not parsed[1]):
            raise IdentityError(f"{match!r} is not a SPIFFE ID with a path, or one or a trust domain followed by `/*`")
        entries.append(Entry(parsed[0], parsed[1], prefix, name))
    if len({entry.match for entry in entries}) != len(entries):
        raise IdentityError("an identity map lists a match twice")
    return tuple(entries)


def map_body(rows: Sequence[Mapping[str, str]]) -> bytes:
    """The canon/2 body of a map of these {"match", "class"} rows, in order."""
    from prismpath import canon
    doc = {"encoding": canon.CANON2, "entries": [{"class": row["class"], "match": row["match"]} for row in rows],
           "format": MAP_FORMAT}
    map_doc(doc)
    return canon.canon2_bytes(doc)


def classify(entries: Sequence[Entry], spiffe_id: str) -> str:
    parsed = parse_id(spiffe_id)
    if parsed is None:
        return "invalid"
    for entry in entries:
        if entry.matches(*parsed):
            return entry.name
    return "other"


def classes(entries: Sequence[Entry]) -> List[str]:
    """Every value the reading's `workload` can take under this map."""
    return sorted({entry.name for entry in entries} | {"invalid", "none", "other"})


# ------------------------------------------------------------------ the chain (ID4, ID5)

def chain_of(value: str) -> Optional[list]:
    """The certificates of a header value: the percent encoded PEM of the leaf and then its intermediates, one to
    MAX_CHAIN of them and nothing else. None when it does not read."""
    from urllib.parse import unquote
    x509 = _x509()
    if not isinstance(value, str) or len(value) > MAX_HEADER or not value.isascii():
        return None
    if "%" in value and len(_ESCAPE.findall(value)) != value.count("%"):
        return None
    text = unquote(value, errors="strict")
    blocks = _PEM.findall(text)
    if not 0 < len(blocks) <= MAX_CHAIN or _PEM.sub("", text).strip():
        return None
    certs = []
    for block in blocks:
        body = "".join(block.split())
        try:
            der = base64.b64decode(body, validate=True)
            if base64.b64encode(der).decode("ascii") != body:
                return None
            certs.append(x509.load_der_x509_certificate(der))
        except Exception:   # noqa: BLE001 - anything that does not read is not a chain
            return None
    return certs


def _leaf_ok(cert) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """(trust domain, segments) of a leaf that holds X509-SVID sections 2 and 4.3, else None."""
    x509 = _x509()
    if cert.version != x509.Version.v3:
        return None
    uris = _uris(cert)
    if uris is None or len(uris) != 1:
        return None
    parsed = parse_id(uris[0])
    if parsed is None or not parsed[1]:
        return None
    constraints, usage = _extension(cert, x509.BasicConstraints), _extension(cert, x509.KeyUsage)
    if constraints is None or constraints.ca:
        return None
    if usage is None or not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
        return None
    return parsed


def validate(certs: list, bundle: Mapping[str, Sequence], now: int) -> Optional[str]:
    """ID5: the SPIFFE ID of the leaf `certs[0]` when it holds X509-SVID sections 2 and 4.3 and its chain, with
    `certs[1:]` as intermediates, ends at a CA of the leaf's own trust domain in `bundle` at time `now`. None
    otherwise."""
    import datetime
    from cryptography.x509 import verification
    leaf = _leaf_ok(certs[0]) if certs else None
    if leaf is None or leaf[0] not in bundle:
        return None
    if not all(_is_ca(cert) for cert in certs[1:]):
        return None
    try:
        verifier = (verification.PolicyBuilder().store(verification.Store(list(bundle[leaf[0]])))
                    .time(datetime.datetime.fromtimestamp(int(now), datetime.timezone.utc))
                    .max_chain_depth(MAX_CHAIN - 1).build_client_verifier())
        verified = verifier.verify(certs[0], certs[1:])
    except Exception:   # noqa: BLE001 - a chain the verifier refuses, for any reason, is invalid
        return None
    if not all(_is_ca(cert) for cert in verified.chain[1:]):
        return None
    return domain_id(leaf[0]) + "/" + "/".join(leaf[1])


# ------------------------------------------------------------------ the reader the gateway holds

def header_name(name: str) -> str:
    """The lower case name of the header the front proxy passes the chain in, or IdentityError."""
    from . import reading
    from .proxy import FORWARDED_REQUEST_HEADERS
    if not isinstance(name, str) or not _TOKEN.fullmatch(name):
        raise IdentityError(f"{name!r} is not a header name")
    low = name.lower()
    if low in FORWARDED_REQUEST_HEADERS or low in (reading.GRANT_HEADER.lower(), "content-length", "transfer-encoding",
                                                   "host", "connection"):
        raise IdentityError(f"{name} is a header the gateway reads or passes on for another purpose")
    return low


def front_addresses(values: Sequence[str]) -> FrozenSet[str]:
    """The front proxy's peer addresses, normalized, or IdentityError. At least one."""
    out = set()
    for value in values:
        try:
            out.add(str(ipaddress.ip_address(value)))
        except ValueError:
            raise IdentityError(f"{value!r} is not an IP address") from None
    if not out:
        raise IdentityError("name the front proxy's address, from which alone the certificate header is read")
    return frozenset(out)


@dataclass(frozen=True)
class Setting:
    """Where the chain comes from: the header the front proxy writes and the peer addresses it connects from."""
    header: str
    front: FrozenSet[str]

    @classmethod
    def of(cls, header: Optional[str], front: Sequence[str]) -> Optional["Setting"]:
        if header is None and not front:
            return None
        if header is None:
            raise IdentityError("a front proxy is named without the header it passes the client certificate in")
        return cls(header_name(header), front_addresses(front))


@dataclass(frozen=True)
class Identity:
    """The workload reader of one gateway: the bundle's CAs per trust domain, the map's entries, where the chain is
    read from and the gateway's clock."""
    bundle: Mapping[str, Tuple]
    entries: Tuple[Entry, ...]
    setting: Setting
    clock: Callable[[], float]
    map_sha256: str = ""
    bundle_sha256: str = ""
    _cas: Dict = field(default_factory=dict, compare=False)

    @classmethod
    def from_bodies(cls, bundle: bytes, mapping: bytes, setting: Setting, clock: Callable[[], float]) -> "Identity":
        """IdentityError when a body does not read or the map names a trust domain the bundle does not hold."""
        import hashlib
        from prismpath.distribution.kinds import Refused
        from prismpath.gateway import dist_kind
        try:
            domains = dist_kind.read_identity_bundle(bundle)
            entries = dist_kind.read_identity_map(mapping)
        except Refused as refused:
            raise IdentityError(str(refused)) from None
        missing = sorted({entry.domain for entry in entries} - set(domains))
        if missing:
            raise IdentityError(f"the identity map names trust domains the bundle does not hold: {', '.join(missing)}")
        x509 = _x509()
        cas = {domain: tuple(x509.load_der_x509_certificate(base64.b64decode(text)) for text in texts)
               for domain, texts in domains.items()}
        return cls(cas, entries, setting, clock, hashlib.sha256(mapping).hexdigest(),
                   hashlib.sha256(bundle).hexdigest())

    def read(self, headers: Mapping[str, Sequence[str]], peer: Optional[str]) -> str:
        """The `workload` of a request with these headers from this peer address."""
        values = headers.get(self.setting.header, ())
        if not values:
            return "none"
        try:
            from_front = peer is not None and str(ipaddress.ip_address(peer)) in self.setting.front
        except ValueError:
            from_front = False
        if not from_front or len(values) != 1:
            return "invalid"
        certs = chain_of(values[0].strip())
        if certs is None:
            return "invalid"
        spiffe_id = validate(certs, self.bundle, int(self.clock()))
        return "invalid" if spiffe_id is None else classify(self.entries, spiffe_id)
