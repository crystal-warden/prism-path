// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Policy distribution (docs/design/spec-policy-distribution.md) in Rust: the twin of
//! `prismpath/distribution/`, held to the Python reference by the shared corpus
//! `tests/fixtures/distribution.json`, replayed by `tests/test_distribution_conformance.rs`.
//!
//! This module is `kinds.py`: the closed lists of artifact and target kinds in one table, so a new kind
//! is one row, each artifact's own check (V11), the trust bodies read as their formats, and the value
//! forms every distribution document shares. Every document here derives the one canon/2 reader and
//! writer (`prismpath_rs::canon2::codec`), so its field list is its member list and a member missing or
//! extra is refused by the type. `envelope` is the envelope and the sealed container, `trust` the trust
//! store and `verify` the one verifier.
//!
//! What a trust statement does to the trust store (R1 to R7, O1 to O4) and the widening rule (W1 to
//! W7) are applied by the code that owns them, not by this table.

pub mod envelope;
pub mod trust;
pub mod verify;

use self::envelope::Envelope;
use self::verify::PepView;
use prismpath_rs::canon2::{self, codec, Doc};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const BAD_FORMAT: &str = "dist:bad-format";
pub const NOT_CANONICAL: &str = prismpath_rs::durable::NOT_CANONICAL_CAUSE;
pub const UNKNOWN_KEY: &str = "dist:unknown-key";
pub const TARGET_MISMATCH: &str = "dist:target-mismatch";
pub const BODY_MISMATCH: &str = "dist:body-mismatch";
pub const SEQ_REPLAY: &str = "dist:seq-replay";
pub const NOT_YET_VALID: &str = "dist:not-yet-valid";
pub const EXPIRED: &str = "dist:expired";
pub const REVOKED: &str = "dist:revoked";
pub const TRUST_REPLAY: &str = "dist:trust-replay";
pub const TOO_LARGE: &str = "dist:too-large";
pub const INCOMPLETE: &str = "dist:incomplete";
pub const SIG_INVALID: &str = "sig:invalid";
pub const SIG_REVOKED_KEY: &str = "sig:revoked-key";
/// Every cause this module reports itself, each a registered name (`tests` checks the registry).
pub const CAUSES: [&str; 14] = [
    BAD_FORMAT, NOT_CANONICAL, UNKNOWN_KEY, TARGET_MISMATCH, BODY_MISMATCH, SEQ_REPLAY, NOT_YET_VALID,
    EXPIRED, REVOKED, TRUST_REPLAY, TOO_LARGE, INCOMPLETE, SIG_INVALID, SIG_REVOKED_KEY,
];

/// E1 `seq`, and every integer the format carries: canon/2's exact range.
pub const MAX_SEQ: i64 = canon2::EXACT_LIMIT;

/// K4: the key role every artifact kind needs in this version.
pub const AUTHORITY: &str = "authority";
/// K4: the key roles this version knows.
pub const ROLES: [&str; 1] = [AUTHORITY];

/// A distribution check failed. `cause` is the registered cause name, the only thing reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub cause: &'static str,
    pub detail: String,
}

impl Refused {
    pub fn new(cause: &'static str, detail: impl Into<String>) -> Refused {
        Refused { cause, detail: detail.into() }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            formatter.write_str(self.cause)
        } else {
            write!(formatter, "{}: {}", self.cause, self.detail)
        }
    }
}

impl std::error::Error for Refused {}

/// `dist:bad-format` unless `condition` holds.
pub(crate) fn require(condition: bool, detail: &str) -> Result<(), Refused> {
    if condition {
        Ok(())
    } else {
        Err(Refused::new(BAD_FORMAT, detail))
    }
}

/// What a check decided: `cause` None when it passed, else the one registered cause. `envelope` is the
/// parsed envelope once it read. `unchanged` is an envelope accepted that changes nothing (Q3, R1).
/// `time_floor` is the enforcement point's time floor after V6 passed (V13), for the PEP to make durable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    pub cause: Option<String>,
    pub envelope: Option<Envelope>,
    pub unchanged: bool,
    pub time_floor: Option<i64>,
}

impl Verdict {
    pub fn refused(cause: &str) -> Verdict {
        Verdict { cause: Some(cause.to_string()), ..Verdict::default() }
    }

    pub fn ok(&self) -> bool {
        self.cause.is_none()
    }
}

/// The value `T` of the canon/2 bytes `raw`, read strictly (E2): `document:not-canonical` for canon/2 in
/// another spelling, `dist:bad-format` for anything that is not canon/2 or not the form of `T`. Never
/// respelled.
pub fn load<T: DeserializeOwned>(raw: &[u8], what: &str) -> Result<T, Refused> {
    codec::from_bytes(raw).map_err(|error| {
        if error.is_not_canonical() {
            Refused::new(NOT_CANONICAL, format!("the {what} is not its canonical spelling"))
        } else {
            Refused::new(BAD_FORMAT, format!("the {what} is not its form ({error})"))
        }
    })
}

// ------------------------------------------------------------------ the value forms

pub fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_stream(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-'))
}

/// 64 lower case hex digits: a SHA-256, a key id, an envelope id or a release id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hex64(String);

impl Hex64 {
    /// The SHA-256 of `data`.
    pub fn of(data: &[u8]) -> Hex64 {
        Hex64(crate::sha256_hex(data))
    }

    /// The 64 zeros a `@trust` envelope carries as its policy hash and release (E1).
    pub fn zero() -> Hex64 {
        Hex64("0".repeat(64))
    }

    /// The hex of 32 raw bytes.
    pub fn from_raw(raw: &[u8; 32]) -> Hex64 {
        Hex64(hex::encode(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 32 raw bytes.
    pub fn raw(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.0, &mut out).expect("a Hex64 is 64 hex digits");
        out
    }
}

impl TryFrom<String> for Hex64 {
    type Error = String;
    fn try_from(text: String) -> Result<Hex64, String> {
        if is_hex64(&text) {
            Ok(Hex64(text))
        } else {
            Err(format!("{text:?} is not 64 lower case hex digits"))
        }
    }
}

impl TryFrom<&str> for Hex64 {
    type Error = String;
    fn try_from(text: &str) -> Result<Hex64, String> {
        Hex64::try_from(text.to_string())
    }
}

impl From<Hex64> for String {
    fn from(value: Hex64) -> String {
        value.0
    }
}

impl fmt::Display for Hex64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A hash or the empty string: `replaces`, a rotation's `retire` and the trust store's `trust_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MaybeHex64(pub Option<Hex64>);

impl TryFrom<String> for MaybeHex64 {
    type Error = String;
    fn try_from(text: String) -> Result<MaybeHex64, String> {
        if text.is_empty() {
            Ok(MaybeHex64(None))
        } else {
            Hex64::try_from(text).map(|hash| MaybeHex64(Some(hash)))
        }
    }
}

impl From<MaybeHex64> for String {
    fn from(value: MaybeHex64) -> String {
        value.0.map(String::from).unwrap_or_default()
    }
}

impl MaybeHex64 {
    pub fn as_str(&self) -> &str {
        self.0.as_ref().map_or("", Hex64::as_str)
    }
}

/// A stream name, 1 to 64 of `a-z`, `0-9`, `.`, `_`, `/` and `-`. `@trust` is not one (E1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Stream(String);

impl Stream {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Stream {
    type Error = String;
    fn try_from(text: String) -> Result<Stream, String> {
        if is_stream(&text) {
            Ok(Stream(text))
        } else {
            Err(format!("{text:?} is not a stream name"))
        }
    }
}

impl TryFrom<&str> for Stream {
    type Error = String;
    fn try_from(text: &str) -> Result<Stream, String> {
        Stream::try_from(text.to_string())
    }
}

impl From<Stream> for String {
    fn from(value: Stream) -> String {
        value.0
    }
}

/// A set written as an array sorted without repeats, and read only in that form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortedSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> Default for SortedSet<T> {
    fn default() -> SortedSet<T> {
        SortedSet(BTreeSet::new())
    }
}

impl<T: Ord> std::ops::Deref for SortedSet<T> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &BTreeSet<T> {
        &self.0
    }
}

impl<T: Ord> std::ops::DerefMut for SortedSet<T> {
    fn deref_mut(&mut self) -> &mut BTreeSet<T> {
        &mut self.0
    }
}

impl<T: Ord> FromIterator<T> for SortedSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> SortedSet<T> {
        SortedSet(items.into_iter().collect())
    }
}

impl<T: Ord + Serialize> Serialize for SortedSet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.0)
    }
}

impl<'de, T: Ord + Deserialize<'de>> Deserialize<'de> for SortedSet<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SortedSet<T>, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        if items.windows(2).all(|pair| pair[0] < pair[1]) {
            Ok(SortedSet(items.into_iter().collect()))
        } else {
            Err(de::Error::custom("a list that is not sorted or repeats an item"))
        }
    }
}

/// A member whose value is one fixed string, such as `encoding` `canon/2` or a document's `format`.
macro_rules! fixed_string {
    ($(#[$meta:meta])* $name:ident = $text:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            pub const TEXT: &'static str = $text;
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(Self::TEXT)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$name, D::Error> {
                let text = String::deserialize(deserializer)?;
                if text == Self::TEXT {
                    Ok($name)
                } else {
                    Err(de::Error::custom(format!("{text:?} where {:?} is required", Self::TEXT)))
                }
            }
        }
    };
}

fixed_string!(
    /// `encoding`, which every signed document names.
    Canon2Tag = prismpath_rs::durable::CANON2
);
fixed_string!(
    /// E1 `format`.
    DistFormat = "prismpath.dist/1"
);
fixed_string!(
    /// K1: the trust store's durable form.
    TrustStoreFormat = "prismpath.dist-trust-store/1"
);
fixed_string!(RevocationFormat = "prismpath.dist-revocation/1");
fixed_string!(RotationFormat = "prismpath.dist-rotation/1");
fixed_string!(WideningFormat = "prismpath.dist-widening/1");

/// A closed list of names (E8), each variant written as its name and ordered by it.
macro_rules! kind_names {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn name(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }

            pub fn from_name(name: &str) -> Option<$name> {
                $name::ALL.iter().copied().find(|kind| kind.name() == name)
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.name().cmp(other.name())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.name())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.name())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$name, D::Error> {
                let text = String::deserialize(deserializer)?;
                $name::from_name(&text)
                    .ok_or_else(|| de::Error::custom(format!("an unknown {} {text:?}", stringify!($name))))
            }
        }
    };
}

kind_names!(
    /// An artifact kind of section 3.
    ArtifactKind {
        PolicyCore = "policy.core",
        PolicyPpt = "policy.ppt",
        PolicySpiral = "policy.spiral",
        SandboxProfile = "sandbox.profile",
        EgressHosts = "egress.hosts",
        GatewayRoutes = "gateway.routes",
        NetDests = "net.dests",
        NetEdge = "net.edge",
        CfsTable = "cfs.table",
        Grant = "grant",
        TrustWidening = "trust.widening",
        TrustRevocation = "trust.revocation",
        TrustRotation = "trust.rotation",
    }
);

kind_names!(
    /// A target kind of section 3: a kind of enforcement point.
    TargetKind {
        Agent = "agent",
        Cfs = "cfs",
        Gateway = "gateway",
        Host = "host",
        Mesh = "mesh",
        Xdp = "xdp",
    }
);

// ------------------------------------------------------------------ the table

/// An artifact's own check (V11): None when it passes, else the cause.
pub type Check = fn(&Envelope, &[u8], &PepView) -> Option<String>;

/// Reads an artifact's `meta` as its form (E11).
pub type MetaReader = fn(Doc) -> Result<Meta, codec::Error>;

/// An artifact kind's row: the form of its `meta` (E1, E11), its own check (V11), None when no built
/// target uses it yet, and the key role it needs (K4).
#[derive(Clone, Copy)]
pub struct Artifact {
    pub meta: MetaReader,
    pub check: Option<Check>,
    pub role: &'static str,
}

const PLAIN: Artifact = Artifact { meta: |doc| codec::from_doc::<NoMeta>(doc).map(|_| Meta::None), check: None, role: AUTHORITY };

impl ArtifactKind {
    pub fn row(self) -> Artifact {
        use ArtifactKind::*;
        match self {
            PolicyPpt => Artifact {
                meta: |doc| codec::from_doc(doc).map(Meta::PolicyPpt),
                check: Some(check_policy_ppt),
                ..PLAIN
            },
            PolicySpiral => Artifact { check: Some(check_policy_spiral), ..PLAIN },
            SandboxProfile => Artifact { meta: |doc| codec::from_doc(doc).map(Meta::SandboxProfile), ..PLAIN },
            NetEdge => Artifact { meta: |doc| codec::from_doc(doc).map(Meta::NetEdge), ..PLAIN },
            TrustWidening => Artifact { check: Some(|_, body, _| read_widening(body).err().map(cause_of)), ..PLAIN },
            TrustRevocation => Artifact { check: Some(|_, body, _| read_revocation(body).err().map(cause_of)), ..PLAIN },
            TrustRotation => Artifact { check: Some(|_, body, _| read_rotation(body).err().map(cause_of)), ..PLAIN },
            PolicyCore | EgressHosts | GatewayRoutes | NetDests | CfsTable | Grant => PLAIN,
        }
    }

    /// One of the three trust kinds, whose `expires` is 0 (E5) and which a target admits when its machine applies it (V5).
    pub fn is_trust(self) -> bool {
        matches!(self, ArtifactKind::TrustWidening | ArtifactKind::TrustRevocation | ArtifactKind::TrustRotation)
    }

    /// A kind that travels on `@trust` in the one trust sequence (R1, O1).
    pub fn on_trust_stream(self) -> bool {
        matches!(self, ArtifactKind::TrustRevocation | ArtifactKind::TrustRotation)
    }
}

fn cause_of(refused: Refused) -> String {
    refused.cause.to_string()
}

/// A target kind's row: the artifacts it needs before it commits (C2), those it needs only when another
/// artifact of the release asks for them (`policy.spiral`, when the `policy.ppt` declares packing),
/// whether it can decide larger (W1), the trust kinds its machine applies, its bound on the body of an
/// artifact it uses and its bound on a trust body, 16,384 bytes for every kind (E6).
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub needs: &'static [ArtifactKind],
    pub decides: bool,
    pub when_declared: &'static [ArtifactKind],
    pub applies: &'static [ArtifactKind],
    pub body_bound: i64,
    pub trust_bound: i64,
}

/// E6: every kind takes the largest revocation list R7 allows.
pub const TRUST_BOUND: i64 = 16_384;
/// R7: the entries of each list of a revocation, and the streams of its floors.
pub const REVOCATION_ENTRIES: usize = 64;
pub const REVOCATION_FLOORS: usize = 16;

impl Target {
    /// The artifacts this kind uses, besides the trust kinds it applies.
    pub fn uses(&self, artifact: ArtifactKind) -> bool {
        self.needs.contains(&artifact) || self.when_declared.contains(&artifact)
    }

    /// What V5 admits: an artifact this kind uses or a trust kind its machine applies.
    pub fn admits(&self, artifact: ArtifactKind) -> bool {
        self.uses(artifact) || self.applies.contains(&artifact)
    }
}

impl TargetKind {
    /// The row of a kind whose enforcement point is built, None for the others. This crate has `host`.
    pub fn target(self) -> Option<Target> {
        match self {
            TargetKind::Host => Some(Target {
                needs: &[ArtifactKind::PolicyPpt],
                decides: false,
                when_declared: &[ArtifactKind::PolicySpiral],
                applies: &[ArtifactKind::TrustWidening, ArtifactKind::TrustRevocation],
                body_bound: envelope::MAX_BODY,
                trust_bound: TRUST_BOUND,
            }),
            TargetKind::Agent | TargetKind::Cfs | TargetKind::Gateway | TargetKind::Mesh | TargetKind::Xdp => None,
        }
    }
}

// ------------------------------------------------------------------ the meta forms (E11)

/// A string of 1 to `MAX` characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Text<const MAX: usize>(String);

impl<const MAX: usize> Text<MAX> {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> TryFrom<String> for Text<MAX> {
    type Error = String;
    fn try_from(text: String) -> Result<Text<MAX>, String> {
        if (1..=MAX).contains(&text.chars().count()) {
            Ok(Text(text))
        } else {
            Err(format!("a string of 1 to {MAX} characters, not {} characters", text.chars().count()))
        }
    }
}

impl<const MAX: usize> From<Text<MAX>> for String {
    fn from(text: Text<MAX>) -> String {
        text.0
    }
}

/// An optional member: absent is None, and present it has the member's form (null is not absent).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// The `meta` of an artifact kind that has no members: the empty object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoMeta {}

/// `policy.ppt` `counts`: exactly the six header counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub atoms: u16,
    pub nodes: u16,
    pub edges: u16,
    pub prog_words: u16,
    pub max_steps: u16,
    pub max_stack: u16,
}

/// `policy.ppt` `packing`: the profile, checked at V11, and the sidecar's hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packing {
    pub profile: Text<32>,
    pub sidecar_sha256: Hex64,
}

/// `policy.ppt` `meta`. The members mean what the same members of a `ppt-pack/1` manifest mean, and
/// `qualification` is its `envelope_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PptMeta {
    pub fields: BTreeMap<String, String>,
    pub counts: Counts,
    pub wcet_cycles: u64,
    pub qualification: Text<128>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub packing: Option<Packing>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub flow_sha256: Option<Hex64>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub overlay_of: Option<Text<128>>,
}

/// `net.edge` `meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetEdgeMeta {
    pub flow_sha256: Hex64,
    pub names_sha256: Hex64,
    pub qualification: Text<128>,
}

/// `sandbox.profile` `meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileMeta {
    pub compiler: std::num::NonZeroU64,
}

/// An envelope's `meta` read as its artifact's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Meta {
    None,
    PolicyPpt(PptMeta),
    NetEdge(NetEdgeMeta),
    SandboxProfile(ProfileMeta),
}

// ------------------------------------------------------------------ the artifact checks (V11)

fn first_cause(reasons: &[String]) -> Option<String> {
    reasons.first().map(|reason| crate::reason_name(reason).to_string())
}

/// `policy.ppt` on a target that reads `meta` (V11): `validate_image`, the signed counts, the recomputed
/// WCET, the packing profile, and the qualification envelope gate the PEP holds, each with its existing
/// cause. The members' forms were read at V4 (E11), so no check here meets another form.
pub fn check_policy_ppt(envelope: &Envelope, body: &[u8], pep: &PepView) -> Option<String> {
    let Meta::PolicyPpt(ppt) = envelope.form() else {
        return Some(BAD_FORMAT.to_string());
    };
    let meta = serde_json::to_value(ppt).expect("a policy.ppt meta is a JSON object");
    let (ok, reasons) = crate::validate_image(body, None);
    if !ok {
        return first_cause(&reasons);
    }
    if let Some(cause) = first_cause(&crate::check_counts(&meta, body)) {
        return Some(cause);
    }
    if ppt.packing.as_ref().is_some_and(|packing| packing.profile.as_str() != "spiral") {
        return Some("packing:unknown-profile".to_string());
    }
    let Some(qualification) = &pep.qualification else {
        return Some("envelope:missing".to_string());
    };
    let signed = serde_json::json!({"envelope_id": meta["qualification"], "fields": meta["fields"]});
    let (ok, reasons) = crate::check_envelope(&signed, body, qualification);
    if ok {
        None
    } else {
        first_cause(&reasons)
    }
}

/// `policy.spiral` has no check of its own when it is verified. Its SHA-256 is held against the
/// `sidecar_sha256` of the staged `policy.ppt` envelope's `meta.packing` when the release commits (C2),
/// with `spiral:sidecar-missing` and `spiral:sidecar-hash-mismatch`, by the host.
pub fn check_policy_spiral(_envelope: &Envelope, _body: &[u8], _pep: &PepView) -> Option<String> {
    None
}

/// Section 10: a revocation list. `envelopes`, `keys` and `policies` are sorted hash lists without
/// repeats, and `floors` maps a stream name to a `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub encoding: Canon2Tag,
    pub envelopes: SortedSet<Hex64>,
    pub floors: BTreeMap<Stream, i64>,
    pub format: RevocationFormat,
    pub keys: SortedSet<Hex64>,
    pub policies: SortedSet<Hex64>,
}

/// Section 11: a rotation, the new public key in `add` and the key id it retires, or none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub add: Hex64,
    pub encoding: Canon2Tag,
    pub format: RotationFormat,
    pub retire: MaybeHex64,
}

/// W4: a widening statement, the sorted policy hashes it may replace in `from`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Widening {
    pub encoding: Canon2Tag,
    pub format: WideningFormat,
    pub from: SortedSet<Hex64>,
}

pub fn read_revocation(body: &[u8]) -> Result<Revocation, Refused> {
    let doc: Revocation = load(body, "revocation body")?;
    require(doc.floors.values().all(|seq| (1..=MAX_SEQ).contains(seq)), "revocation floors")?;
    if [doc.envelopes.len(), doc.keys.len(), doc.policies.len()].iter().any(|length| *length > REVOCATION_ENTRIES)
        || doc.floors.len() > REVOCATION_FLOORS
    {
        return Err(Refused::new(TOO_LARGE, "a revocation list beyond 64 entries or 16 streams")); // R7
    }
    Ok(doc)
}

pub fn read_rotation(body: &[u8]) -> Result<Rotation, Refused> {
    load(body, "rotation body")
}

pub fn read_widening(body: &[u8]) -> Result<Widening, Refused> {
    load(body, "widening body")
}

#[cfg(test)]
mod tests {
    use super::*;
    use prismpath_rs::causes;

    #[test]
    fn every_cause_reported_here_is_registered() {
        for name in CAUSES {
            assert!(causes::code(name).is_some(), "{name} is not in the registry");
        }
    }

    #[test]
    fn each_kind_reads_and_writes_its_name_and_orders_by_it() {
        for kind in ArtifactKind::ALL {
            assert_eq!(codec::from_doc::<ArtifactKind>(codec::to_doc(kind).unwrap()).unwrap(), *kind);
        }
        let mut names: Vec<&str> = TargetKind::ALL.iter().map(|kind| kind.name()).collect();
        let mut kinds = TargetKind::ALL.to_vec();
        names.sort();
        kinds.sort();
        assert_eq!(kinds.iter().map(|kind| kind.name()).collect::<Vec<_>>(), names);
        assert!(codec::from_doc::<TargetKind>(Doc::Str("toaster".to_string())).is_err());
    }

    #[test]
    fn every_artifact_a_built_target_admits_has_a_check() {
        for target in TargetKind::ALL.iter().filter_map(|kind| kind.target()) {
            for artifact in ArtifactKind::ALL.iter().filter(|artifact| target.admits(**artifact)) {
                assert!(artifact.row().check.is_some(), "{artifact} has no check");
                assert_eq!(artifact.is_trust(), target.applies.contains(artifact), "{artifact} is used or applied by its kind");
            }
            assert!((0..=envelope::MAX_BODY).contains(&target.body_bound));
            assert_eq!(target.trust_bound, TRUST_BOUND);
        }
        assert!(ArtifactKind::ALL.iter().all(|artifact| ROLES.contains(&artifact.row().role)));
    }

    #[test]
    fn a_sorted_set_reads_only_sorted_without_repeats() {
        let ok: Result<SortedSet<i64>, _> = codec::from_bytes(b"[1,2,5]");
        assert_eq!(ok.unwrap().iter().copied().collect::<Vec<_>>(), vec![1, 2, 5]);
        assert!(codec::from_bytes::<SortedSet<i64>>(b"[2,1]").is_err());
        assert!(codec::from_bytes::<SortedSet<i64>>(b"[1,1]").is_err());
    }

    #[test]
    fn the_value_forms_refuse_what_the_format_refuses() {
        assert!(Hex64::try_from("A".repeat(64)).is_err());
        assert!(Hex64::try_from("a".repeat(63)).is_err());
        assert!(Stream::try_from("@trust").is_err());
        assert!(Stream::try_from("x".repeat(65)).is_err());
        assert!(Stream::try_from("host/demo-1.a_b").is_ok());
        assert_eq!(codec::from_bytes::<MaybeHex64>(b"\"\"").unwrap(), MaybeHex64(None));
        assert!(codec::from_bytes::<Canon2Tag>(b"\"canon/1\"").is_err());
    }

    fn body(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn the_trust_bodies_read_as_their_formats() {
        let hash = "ab".repeat(32);
        let revocation = format!(
            "{{\"encoding\":\"canon/2\",\"envelopes\":[\"{hash}\"],\"floors\":{{\"host/demo\":9}},\
             \"format\":\"prismpath.dist-revocation/1\",\"keys\":[],\"policies\":[]}}"
        );
        let read = read_revocation(&body(&revocation)).unwrap();
        assert_eq!(read.floors[&Stream::try_from("host/demo").unwrap()], 9);
        assert_eq!(codec::to_bytes(&read).unwrap(), body(&revocation));
        assert_eq!(read_revocation(&body(&revocation.replace(":9", ":0"))).unwrap_err().cause, BAD_FORMAT);
        let twice = revocation.replace(&format!("[\"{hash}\"]"), &format!("[\"{hash}\",\"{hash}\"]"));
        assert_eq!(read_revocation(&body(&twice)).unwrap_err().cause, BAD_FORMAT);
        let spaced = revocation.replace(",\"keys\"", ", \"keys\"");
        assert_eq!(read_revocation(&body(&spaced)).unwrap_err().cause, NOT_CANONICAL);

        let rotation = format!("{{\"add\":\"{hash}\",\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-rotation/1\",\"retire\":\"\"}}");
        assert_eq!(read_rotation(&body(&rotation)).unwrap().retire, MaybeHex64(None));
        assert_eq!(read_rotation(&body(&rotation.replace("rotation/1", "rotation/2"))).unwrap_err().cause, BAD_FORMAT);

        let widening = "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-widening/1\",\"from\":[]}".to_string();
        assert!(read_widening(&body(&widening)).unwrap().from.is_empty());
        let extra = widening.replace("\"from\":[]", "\"from\":[],\"note\":\"x\"");
        assert_eq!(read_widening(&body(&extra)).unwrap_err().cause, BAD_FORMAT);
    }
}
