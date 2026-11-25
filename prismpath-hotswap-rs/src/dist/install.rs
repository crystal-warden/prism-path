// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The install statements of policy distribution (spec-policy-distribution.md, sections 21.1, 21.3 and 21.4),
//! `prismpath/distribution/install.py` in Rust for the `host` kind: the install record, the install trust
//! statement, the held and the staged install sets, the ceiling and the comparisons an install set is held to.
//!
//! The engineer who installs PrismPath on a resource signs three bounds with install keys, held apart from the
//! trust store in the install record (IS10, K3): the action floor, the fallback policy and the ceiling.
//!
//! ```text
//! Record          IS10: the install keys and threshold, the operator keys, the retired ids, the install trust
//!                 sequence and id, the three install sequences, the held sets and the counts of H10
//! counting        S3 to S5 for the role `install`, against the install threshold (IS2)
//! check_trust     IS11: what an `install.trust` must be beyond its signatures
//! Installed       the PEP's install part on disk: two copies of the record and of every held statement (IS10),
//!                 the staged sets (IS4), and the marks kept in the anchor part (IS9, IS10, L2)
//! inside          CL1: whether a release or an install set is inside a ceiling list
//! widens_ok       IS12: whether an install set stands out, and whether its `widens` false is a wrong one
//! ```
//!
//! An empty install set (IS1) withdraws its kind: the PEP then holds none of that kind at that `seq`, its install
//! id counts zeros for it, and the next set of the kind replaces nothing, so its `replaces` is empty. That is the
//! C core's reading of the spec, which the Python machine is to follow.
//!
//! Files, under the PEP's `dist/` directory and its second medium (`copy`, `dist/install-copy` when the
//! deployment gives none), each written whole:
//!
//! ```text
//! install/record.json   the install record, and the same document at <copy>/record.json
//! install/blobs/        every held and staged statement and body under its SHA-256, the held ones also at
//!                       <copy>/blobs/
//! install/staged.json   the staged install sets, at most one per install kind (IS4)
//! install/rates.json    the rate counts of AF8, and the same document at <copy>/rates.json
//! marks.json            the marks of the anchor part: an install statement was held (IS9), a ceiling is held
//!                       (IS10) and a release was committed (L2)
//! ```

use super::envelope::{self as env, Entry, Envelope};
use super::pep::HeldDoc;
use super::trust::TrustStore;
use super::{
    load, require, ArtifactKind, Canon2Tag, CeilingFormat, ChangeBasis, Hex64, InstallChangeFormat, InstallTrustFormat, MarksFormat, MaybeHex64, Meta, PepView,
    RecordFormat, Refused, SortedSet, StagedSetsFormat, Verdict, BAD_FORMAT, MAX_SEQ, ROTATION_INVALID, SIG_INVALID, SIG_REVOKED_KEY, TOO_LARGE, UNKNOWN_KEY, WIDENING_UNSIGNED,
};
use crate::host::{atomic_write_bytes, HostError};
use prismpath_rs::canon2::{codec, Doc};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// IS10: the retired install and operator key ids a record remembers.
pub const MAX_RETIRED: usize = 8;
/// IS11, OP1: the install keys and the operator keys a record holds.
pub const INSTALL_KEYS: usize = 4;
pub const OPERATOR_KEYS: usize = 4;
/// CL1: the hashes a policy list holds.
pub const CEILING_BODIES: usize = 64;
pub const POLICY_LIST: &str = "policy.list";
pub const NONE: &str = "none";

// ------------------------------------------------------------------ IS1, E11: what `as` names

/// E11: what an install set's `as` names: an artifact a release holds, the policy list of a ceiling (CL1) or
/// `none`, the empty set (IS1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AsName {
    Artifact(ArtifactKind),
    PolicyList,
    None,
}

impl AsName {
    pub fn name(self) -> &'static str {
        match self {
            AsName::Artifact(artifact) => artifact.name(),
            AsName::PolicyList => POLICY_LIST,
            AsName::None => NONE,
        }
    }

    pub fn from_name(name: &str) -> Option<AsName> {
        match name {
            POLICY_LIST => Some(AsName::PolicyList),
            NONE => Some(AsName::None),
            _ => ArtifactKind::from_name(name).filter(|artifact| artifact.may_be_installed()).map(AsName::Artifact),
        }
    }
}

impl Serialize for AsName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for AsName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<AsName, D::Error> {
        let text = String::deserialize(deserializer)?;
        AsName::from_name(&text).ok_or_else(|| de::Error::custom(format!("{text:?} is not what an install set holds")))
    }
}

/// The three install kinds whose statements make a set, in the order of the install id (H10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SetKind {
    Floor = 0,
    Fallback = 1,
    Ceiling = 2,
}

impl SetKind {
    pub const ALL: [SetKind; 3] = [SetKind::Floor, SetKind::Fallback, SetKind::Ceiling];

    pub fn of(artifact: ArtifactKind) -> Option<SetKind> {
        match artifact {
            ArtifactKind::InstallFloor => Some(SetKind::Floor),
            ArtifactKind::InstallFallback => Some(SetKind::Fallback),
            ArtifactKind::InstallCeiling => Some(SetKind::Ceiling),
            _ => None,
        }
    }

    pub fn artifact(self) -> ArtifactKind {
        match self {
            SetKind::Floor => ArtifactKind::InstallFloor,
            SetKind::Fallback => ArtifactKind::InstallFallback,
            SetKind::Ceiling => ArtifactKind::InstallCeiling,
        }
    }

    pub fn name(self) -> &'static str {
        self.artifact().name()
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// AF8, OP4: `allows` in each `window` of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RateDoc")]
pub struct Rate {
    pub allows: i64,
    pub window: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateDoc {
    allows: i64,
    window: i64,
}

impl TryFrom<RateDoc> for Rate {
    type Error = String;
    fn try_from(doc: RateDoc) -> Result<Rate, String> {
        if (1..=65_535).contains(&doc.allows) && (1..=86_400).contains(&doc.window) {
            Ok(Rate { allows: doc.allows, window: doc.window })
        } else {
            Err("a rate's allows is 1 to 65535 and its window 1 to 86400 seconds".to_string())
        }
    }
}

/// E11, IS1: the `meta` of an install set's statement: `as`, the members of the artifact it names, read as that
/// artifact's own form, and on an action floor `rate`, `answer_rate`, `command` and `layout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMeta {
    pub as_name: AsName,
    pub inner: Meta,
    pub rate: Option<Rate>,
    pub answer_rate: Option<Rate>,
    pub command: Option<i64>,
    pub layout: Option<Hex64>,
}

/// E11 for an install kind's `meta`. An `install.trust` has none (`floor` false and no `as`), which the
/// envelope reader holds it to (IS11).
pub fn read_meta(doc: Doc, floor: bool) -> Result<Meta, codec::Error> {
    let Doc::Obj(members) = doc else { return Err(de::Error::custom("meta is not an object")) };
    if members.is_empty() {
        return Ok(Meta::None); // an install.trust; a set's statement without `as` is refused by the reader
    }
    let mut rest = Vec::new();
    let (mut as_name, mut rate, mut answer_rate, mut command, mut layout) = (None, None, None, None, None);
    for (name, value) in members {
        match name.as_str() {
            "as" => as_name = Some(codec::from_doc::<AsName>(value)?),
            "rate" if floor => rate = Some(codec::from_doc::<Rate>(value)?),
            "answer_rate" if floor => answer_rate = Some(codec::from_doc::<Rate>(value)?),
            "command" if floor => {
                let register = codec::from_doc::<i64>(value)?;
                if !(0..=255).contains(&register) {
                    return Err(de::Error::custom("a floor's command register is 0 to 255"));
                }
                command = Some(register);
            }
            "layout" if floor => layout = Some(codec::from_doc::<Hex64>(value)?),
            _ => rest.push((name, value)),
        }
    }
    let as_name = as_name.ok_or_else(|| de::Error::custom("an install statement names its artifact in as"))?;
    let inner = match as_name {
        AsName::Artifact(artifact) => (artifact.row().meta)(Doc::Obj(rest))?,
        AsName::PolicyList | AsName::None => codec::from_doc::<super::NoMeta>(Doc::Obj(rest)).map(|_| Meta::None)?,
    };
    Ok(Meta::Install(Box::new(InstallMeta { as_name, inner, rate, answer_rate, command, layout })))
}

/// The install meta of an envelope of an install set's kind.
pub fn install_meta(envelope: &Envelope) -> Option<&InstallMeta> {
    match envelope.form() {
        Meta::Install(meta) => Some(meta),
        _ => None,
    }
}

/// The SHA-256 of no bytes, the body hash of the empty set.
pub fn empty_sha256() -> Hex64 {
    Hex64::of(b"")
}

/// IS1: the release id of an install set, E10 over its `[as, body_sha256]` pairs, sorted.
pub fn install_release_id(pairs: &[(AsName, Hex64)]) -> Result<Hex64, Refused> {
    let mut named: Vec<(&str, &str)> = pairs.iter().map(|(name, body)| (name.name(), body.as_str())).collect();
    named.sort_unstable();
    require(!named.is_empty() && named.windows(2).all(|pair| pair[0].0 != pair[1].0), "a set names each artifact once")?;
    let bytes = codec::to_bytes(&named).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    Ok(Hex64::of(&bytes))
}

/// IS1: the set id, the SHA-256 of the envelope ids of the set, sorted, as raw bytes.
pub fn set_id<'a>(envelope_ids: impl IntoIterator<Item = &'a Hex64>) -> Hex64 {
    let mut ids: Vec<[u8; 32]> = envelope_ids.into_iter().map(Hex64::raw).collect();
    ids.sort_unstable();
    Hex64::of(&ids.concat())
}

/// IS1, IS11, OP2: an install statement's and an answer's own members, which E1's forms do not carry. A set names
/// exactly one kind and the PEP's stream. The empty set has `as` `none`, an empty body, 64 zeros for its policy hash
/// and the release id of `[none, the hash of no bytes]`. A policy list is a ceiling's, and its policy hash is the
/// list's. An `install.trust` carries 64 zeros for its policy hash and release, no `replaces` and no `meta`. An
/// answer lives at most 600 seconds, at `seq` 1, with no release, no `replaces`, `widens` false and one target.
pub fn check_envelope(envelope: &Envelope) -> Result<(), Refused> {
    let on_trust = envelope.stream == env::TRUST_STREAM;
    match envelope.artifact {
        ArtifactKind::OperatorAnswer => require(
            envelope.expires - envelope.not_before <= 600
                && envelope.seq == 1
                && envelope.release == Hex64::zero()
                && envelope.replaces.0.is_none()
                && !envelope.widens
                && envelope.targets.len() == 1
                && !on_trust,
            "an answer's lifetime, seq, release, replaces, widens, targets or stream (OP2)",
        ),
        ArtifactKind::InstallTrust => require(
            !on_trust
                && envelope.policy_sha256 == Hex64::zero()
                && envelope.release == Hex64::zero()
                && envelope.replaces.0.is_none()
                && matches!(envelope.form(), Meta::None),
            "an install trust statement's stream, policy hash, release, replaces and meta (IS11)",
        ),
        ArtifactKind::InstallChange => require(
            !on_trust && envelope.targets.len() == 1 && matches!(envelope.form(), Meta::None),
            "an install change statement's stream, target and meta (IS14)",
        ),
        _ => {
            require(!on_trust && envelope.targets.len() == 1, "an install set names exactly one kind and the PEP's stream")?;
            let meta = install_meta(envelope).ok_or_else(|| Refused::new(BAD_FORMAT, "an install statement names its artifact in as"))?;
            match meta.as_name {
                AsName::None => require(
                    envelope.body_size == 0
                        && envelope.policy_sha256 == Hex64::zero()
                        && envelope.release == install_release_id(&[(AsName::None, empty_sha256())])?,
                    "the empty set (IS1)",
                ),
                AsName::PolicyList => require(
                    envelope.artifact == ArtifactKind::InstallCeiling && envelope.policy_sha256 == envelope.body_sha256,
                    "a policy list is a ceiling's, and its policy hash is the list's (CL1)",
                ),
                AsName::Artifact(_) => Ok(()),
            }
        }
    }
}

// ------------------------------------------------------------------ the bodies (IS11, IS14, CL1)

/// IS14: an install change statement's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallChangeDoc {
    basis: ChangeBasis,
    encoding: Canon2Tag,
    format: InstallChangeFormat,
    from: Hex64,
    set: String,
}

/// IS14: the set kind an install change statement carries, an action floor or a fallback policy, and the policy hash
/// `from` of the set it replaces, resting on the table comparator. A ceiling's is `dist:bad-format`, since a `host`
/// PEP compares two policy lists itself.
pub fn read_install_change(body: &[u8]) -> Result<(SetKind, Hex64), Refused> {
    let doc: InstallChangeDoc = load(body, "install change body")?;
    match doc.set.as_str() {
        "install.floor" => Ok((SetKind::Floor, doc.from)),
        "install.fallback" => Ok((SetKind::Fallback, doc.from)),
        _ => Err(Refused::new(BAD_FORMAT, "an install change statement carries an action floor or a fallback policy (IS14)")),
    }
}

/// `install.change` (V11, IS14): the body reads, its `from` is the envelope's `replaces`, the envelope does not widen,
/// and its policy hash is a set's and not the empty set's 64 zeros. Anything else is `dist:bad-format`.
pub fn check_install_change(envelope: &Envelope, body: &[u8], _pep: &PepView) -> Option<String> {
    match read_install_change(body) {
        Err(refused) => Some(refused.cause.to_string()),
        Ok((_, from))
            if envelope.widens || envelope.replaces.0.as_ref() != Some(&from) || envelope.policy_sha256 == Hex64::zero() =>
        {
            Some(BAD_FORMAT.to_string())
        }
        Ok(_) => None,
    }
}

/// IS15: an install change statement stands for a set of `kind` on a PEP whose held set of that kind has the policy
/// hash `held`. A PEP that holds no set of the kind has none, so none stands for a first set.
pub fn changes_set(change: Option<&[u8]>, kind: SetKind, held: Option<&Hex64>) -> bool {
    let (Some(change), Some(held)) = (change, held) else { return false };
    read_install_change(change).is_ok_and(|(set, from)| set == kind && from == *held)
}

/// IS11: an install trust statement's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTrust {
    pub encoding: Canon2Tag,
    pub format: InstallTrustFormat,
    pub keys: SortedSet<Hex64>,
    pub operators: SortedSet<Hex64>,
    pub threshold: i64,
}

/// IS11: the sorted install `keys`, 1 to 4 (`dist:too-large` past 4), the sorted `operators`, 0 to 4, and the
/// install `threshold`, from 1 to the number of keys.
pub fn read_install_trust(body: &[u8]) -> Result<InstallTrust, Refused> {
    let doc: InstallTrust = load(body, "install trust body")?;
    // IS11 in its own order, as Python and the C core read it: no install key is a body that does not read, before
    // either list is held to its bound
    require(!doc.keys.is_empty(), "an install trust statement with no install key")?;
    if doc.keys.len() > INSTALL_KEYS || doc.operators.len() > OPERATOR_KEYS {
        return Err(Refused::new(TOO_LARGE, "an install trust statement past 4 install or 4 operator keys"));
    }
    require((1..=doc.keys.len() as i64).contains(&doc.threshold), "an install threshold outside 1 to the number of keys")?;
    Ok(doc)
}

/// The canon/2 body of an install trust statement, for the engineer's tool.
pub fn trust_body(keys: &[[u8; 32]], threshold: i64, operators: &[[u8; 32]]) -> Result<Vec<u8>, Refused> {
    let doc = InstallTrust {
        encoding: Canon2Tag,
        format: InstallTrustFormat,
        keys: keys.iter().map(Hex64::from_raw).collect(),
        operators: operators.iter().map(Hex64::from_raw).collect(),
        threshold,
    };
    let body = codec::to_bytes(&doc).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    read_install_trust(&body)?;
    Ok(body)
}

/// CL1: a ceiling's policy list, the sorted `body_sha256` of every table qualified for the kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeilingList {
    pub bodies: SortedSet<Hex64>,
    pub encoding: Canon2Tag,
    pub format: CeilingFormat,
}

/// CL1: at most 64 hashes, `dist:too-large` past that.
pub fn read_ceiling_list(body: &[u8]) -> Result<CeilingList, Refused> {
    let doc: CeilingList = load(body, "policy list")?;
    if doc.bodies.len() > CEILING_BODIES {
        return Err(Refused::new(TOO_LARGE, "a policy list past 64 hashes"));
    }
    Ok(doc)
}

/// CL1: the policy list of the tables `tables`, by their body hash. The engineer's tool.
pub fn ceiling_body(tables: &[&[u8]]) -> Result<Vec<u8>, Refused> {
    let doc = CeilingList { bodies: tables.iter().map(|table| Hex64::of(table)).collect(), encoding: Canon2Tag, format: CeilingFormat };
    let body = codec::to_bytes(&doc).map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    read_ceiling_list(&body)?;
    Ok(body)
}

// ------------------------------------------------------------------ the held and the staged sets

/// One install set as the store names it: what its statements share (V10) and, per `as`, the blobs of its statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDoc {
    pub policy_sha256: Hex64,
    pub release: Hex64,
    pub replaces: MaybeHex64,
    pub seq: i64,
    pub statements: BTreeMap<AsName, HeldDoc>,
    pub widens: bool,
    /// IS15: the install change statement staged before the set, on a staged set only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<HeldDoc>,
}

/// One install set as the PEP holds it, held or staged, with its envelopes and bodies read from the blobs, and the
/// body of the install change statement staged before it (IS15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSet {
    pub kind: SetKind,
    pub doc: SetDoc,
    pub envelopes: BTreeMap<AsName, Envelope>,
    pub bodies: BTreeMap<AsName, Vec<u8>>,
    pub change_body: Option<Vec<u8>>,
}

impl InstallSet {
    /// A set of `kind` with nothing staged yet, sharing what the statement `envelope` says of its set.
    pub fn of(kind: SetKind, envelope: &Envelope) -> InstallSet {
        InstallSet {
            kind,
            doc: SetDoc {
                policy_sha256: envelope.policy_sha256.clone(),
                release: envelope.release.clone(),
                replaces: envelope.replaces.clone(),
                seq: envelope.seq,
                statements: BTreeMap::new(),
                widens: envelope.widens,
                change: None,
            },
            envelopes: BTreeMap::new(),
            bodies: BTreeMap::new(),
            change_body: None,
        }
    }

    pub fn seq(&self) -> i64 {
        self.doc.seq
    }

    pub fn policy_sha256(&self) -> &Hex64 {
        &self.doc.policy_sha256
    }

    pub fn envelope_ids(&self) -> BTreeSet<Hex64> {
        self.doc.statements.values().map(|held| held.envelope_id.clone()).collect()
    }

    /// IS1: the SHA-256 of the envelope ids of the set.
    pub fn set_id(&self) -> Hex64 {
        set_id(self.envelope_ids().iter())
    }

    /// IS1: the empty set, which withdraws its install kind.
    pub fn is_empty_set(&self) -> bool {
        self.doc.statements.keys().all(|name| *name == AsName::None)
    }

    /// The bodies of the artifacts the set holds, by artifact kind, which is how a release holds them.
    pub fn artifacts(&self) -> BTreeMap<ArtifactKind, Vec<u8>> {
        self.bodies
            .iter()
            .filter_map(|(name, body)| match name {
                AsName::Artifact(artifact) => Some((*artifact, body.clone())),
                _ => None,
            })
            .collect()
    }

    /// AF8: the signed rate of an action floor, shared by every statement (V10).
    pub fn rate(&self) -> Option<Rate> {
        self.envelopes.values().next().and_then(install_meta).and_then(|meta| meta.rate)
    }

    /// AF9, AF10: the `layout` and the `command` register a table floor is read with.
    fn reading(&self) -> (Option<Hex64>, Option<i64>) {
        let meta = self.envelopes.values().next().and_then(install_meta);
        (meta.and_then(|meta| meta.layout.clone()), meta.and_then(|meta| meta.command))
    }

    /// IS4: the set is whole when it holds what the `host` kind needs, a `policy.ppt`, and the release id computed
    /// over its statements is the signed one. The empty set and a policy list are whole alone.
    pub fn whole(&self) -> bool {
        let names: BTreeSet<AsName> = self.doc.statements.keys().copied().collect();
        let alone = names.contains(&AsName::None) || names.contains(&AsName::PolicyList);
        if !alone && !names.contains(&AsName::Artifact(ArtifactKind::PolicyPpt)) {
            return false;
        }
        let pairs: Vec<(AsName, Hex64)> = self.envelopes.iter().map(|(name, envelope)| (*name, envelope.body_sha256.clone())).collect();
        install_release_id(&pairs).is_ok_and(|release| release == self.doc.release)
    }
}

/// IS3: the `as` a set of `kind` may hold on a `host` PEP. An action floor and a fallback policy are a
/// `policy.ppt`, with a `policy.spiral` when it declares packing, and a ceiling is one policy list (CL1). The
/// empty set is allowed of every kind.
pub fn allowed_as(kind: SetKind, name: AsName) -> bool {
    match (kind, name) {
        (_, AsName::None) => true,
        (SetKind::Ceiling, named) => named == AsName::PolicyList,
        (_, AsName::Artifact(ArtifactKind::PolicyPpt | ArtifactKind::PolicySpiral)) => true,
        _ => false,
    }
}

// ------------------------------------------------------------------ the install record (IS10)

/// IS10: what a PEP holds of its install part. `keys` and `operators` map a key id to its public key. `retired` is
/// the retired install and operator key ids, oldest first, at most 8. `seqs` is the install sequence of each set
/// kind, `sets` the set held of each, None when none is (also after the empty set), and `applied` the set id of
/// the set last applied of each kind, the empty set included, so the same statement again changes nothing (IS6).
/// `answers` and `overrides` are the counts of H10. `domain` is the hash of the reading domain the anchor named
/// (P4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub keys: BTreeMap<Hex64, Hex64>,
    pub threshold: i64,
    pub operators: BTreeMap<Hex64, Hex64>,
    pub retired: Vec<Hex64>,
    pub trust_seq: i64,
    pub trust_id: Option<Hex64>,
    pub seqs: [i64; 3],
    pub sets: [Option<InstallSet>; 3],
    pub applied: [Option<Hex64>; 3],
    pub answers: u32,
    pub overrides: u32,
    pub domain: Hex64,
}

/// The durable form of the record, a canon/2 document with format `prismpath.dist-install/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDoc {
    answers: u32,
    applied: BTreeMap<String, Option<Hex64>>,
    domain: Hex64,
    encoding: Canon2Tag,
    format: RecordFormat,
    keys: SortedSet<Hex64>,
    operators: SortedSet<Hex64>,
    overrides: u32,
    retired: Vec<Hex64>,
    seqs: BTreeMap<String, i64>,
    sets: BTreeMap<String, Option<SetDoc>>,
    threshold: i64,
    trust_id: MaybeHex64,
    trust_seq: i64,
}


fn by_id(publics: &SortedSet<Hex64>) -> BTreeMap<Hex64, Hex64> {
    publics.iter().map(|public| (Hex64::of(&public.raw()), public.clone())).collect()
}

/// IS10: append the ids `dropped`, sorted, to `retired`, keeping the last 8.
fn retire(retired: &[Hex64], dropped: impl IntoIterator<Item = Hex64>) -> Vec<Hex64> {
    let mut out = retired.to_vec();
    let mut dropped: Vec<Hex64> = dropped.into_iter().filter(|kid| !retired.contains(kid)).collect();
    dropped.sort();
    dropped.dedup();
    out.extend(dropped);
    let excess = out.len().saturating_sub(MAX_RETIRED);
    out.drain(..excess);
    out
}

impl Record {
    /// P4: the record an anchor's install part brings, its sequences at their start.
    pub fn new(keys: BTreeMap<Hex64, Hex64>, threshold: i64, operators: BTreeMap<Hex64, Hex64>, trust_seq: i64, domain: Hex64) -> Record {
        Record {
            keys,
            threshold,
            operators,
            retired: Vec::new(),
            trust_seq,
            trust_id: None,
            seqs: [0; 3],
            sets: [None, None, None],
            applied: [None, None, None],
            answers: 0,
            overrides: 0,
            domain,
        }
    }

    pub fn held(&self, kind: SetKind) -> Option<&InstallSet> {
        self.sets[kind.index()].as_ref()
    }

    pub fn seq(&self, kind: SetKind) -> i64 {
        self.seqs[kind.index()]
    }

    pub fn applied(&self, kind: SetKind) -> Option<&Hex64> {
        self.applied[kind.index()].as_ref()
    }

    fn document(&self) -> RecordDoc {
        let names = |kind: SetKind| kind.name().to_string();
        RecordDoc {
            answers: self.answers,
            applied: SetKind::ALL.iter().map(|kind| (names(*kind), self.applied[kind.index()].clone())).collect(),
            domain: self.domain.clone(),
            encoding: Canon2Tag,
            format: RecordFormat,
            keys: self.keys.values().cloned().collect(),
            operators: self.operators.values().cloned().collect(),
            overrides: self.overrides,
            retired: self.retired.clone(),
            seqs: SetKind::ALL.iter().map(|kind| (names(*kind), self.seqs[kind.index()])).collect(),
            sets: SetKind::ALL.iter().map(|kind| (names(*kind), self.sets[kind.index()].as_ref().map(|set| set.doc.clone()))).collect(),
            threshold: self.threshold,
            trust_id: MaybeHex64(self.trust_id.clone()),
            trust_seq: self.trust_seq,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, HostError> {
        codec::to_bytes(&self.document()).map_err(|error| HostError::Canonical(format!("install record: {error}")))
    }

    /// The record a document holds, its sets named and not yet read from their blobs.
    fn from_bytes(raw: &[u8]) -> Result<(Record, [Option<SetDoc>; 3]), Refused> {
        let doc: RecordDoc = load(raw, "install record")?;
        let kinds: BTreeSet<String> = SetKind::ALL.iter().map(|kind| kind.name().to_string()).collect();
        require(
            doc.seqs.keys().cloned().collect::<BTreeSet<_>>() == kinds
                && doc.sets.keys().cloned().collect::<BTreeSet<_>>() == kinds
                && doc.applied.keys().cloned().collect::<BTreeSet<_>>() == kinds,
            "an install record names each set kind",
        )?;
        require(
            (1..=INSTALL_KEYS).contains(&doc.keys.len())
                && doc.operators.len() <= OPERATOR_KEYS
                && doc.retired.len() <= MAX_RETIRED
                && (1..=doc.keys.len() as i64).contains(&doc.threshold)
                && (0..=MAX_SEQ).contains(&doc.trust_seq)
                && doc.seqs.values().all(|seq| (0..=MAX_SEQ).contains(seq)),
            "an install record's keys, threshold or sequences",
        )?;
        let at = |kind: SetKind| kind.name().to_string();
        let record = Record {
            keys: by_id(&doc.keys),
            threshold: doc.threshold,
            operators: by_id(&doc.operators),
            retired: doc.retired.clone(),
            trust_seq: doc.trust_seq,
            trust_id: doc.trust_id.0.clone(),
            seqs: SetKind::ALL.map(|kind| doc.seqs[&at(kind)]),
            sets: [None, None, None],
            applied: SetKind::ALL.map(|kind| doc.applied[&at(kind)].clone()),
            answers: doc.answers,
            overrides: doc.overrides,
            domain: doc.domain.clone(),
        };
        let named = SetKind::ALL.map(|kind| doc.sets[&at(kind)].clone());
        Ok((record, named))
    }

    /// IS2, S3 to S5: an entry counts when its key id names an install key the record holds and its signature
    /// verifies, and the statement is signed when at least the install threshold count. Otherwise
    /// `sig:revoked-key` when an entry names a retired install or operator key, `sig:invalid` when one names a
    /// held key and does not verify, and `dist:unknown-key`. A retired id past the eight remembered reads as unknown.
    pub fn counting(&self, entries: &[Entry], message: &[u8]) -> Verdict {
        let (mut counted, mut held_fails) = (0i64, false);
        for entry in entries {
            let Some(public) = self.keys.get(&entry.key_id_hex()) else { continue };
            if crate::verify_ed25519(&public.raw(), message, &entry.signature) {
                counted += 1;
            } else {
                held_fails = true;
            }
        }
        if counted >= self.threshold {
            Verdict::default()
        } else if entries.iter().any(|entry| self.retired.contains(&entry.key_id_hex())) {
            Verdict::refused(SIG_REVOKED_KEY)
        } else if held_fails {
            Verdict::refused(SIG_INVALID)
        } else {
            Verdict::refused(UNKNOWN_KEY)
        }
    }

    /// OP1, S3 to S5 for the role `operator`: one signature by an operator key the record holds is enough.
    pub fn answering(&self, entries: &[Entry], message: &[u8]) -> Verdict {
        let mut held_fails = false;
        for entry in entries {
            let Some(public) = self.operators.get(&entry.key_id_hex()) else { continue };
            if crate::verify_ed25519(&public.raw(), message, &entry.signature) {
                return Verdict::default();
            }
            held_fails = true;
        }
        if entries.iter().any(|entry| self.retired.contains(&entry.key_id_hex())) {
            Verdict::refused(SIG_REVOKED_KEY)
        } else if held_fails {
            Verdict::refused(SIG_INVALID)
        } else {
            Verdict::refused(UNKNOWN_KEY)
        }
    }

    /// K4: every install and operator key id the record holds or remembers as retired.
    pub fn ids(&self) -> BTreeSet<Hex64> {
        self.keys.keys().chain(self.operators.keys()).chain(self.retired.iter()).cloned().collect()
    }

    /// H10: the first 16 bytes of the SHA-256 of the set id and `seq` of the action floor, the fallback policy and
    /// the ceiling held, zeros for a set not held, then the install trust sequence and the install trust id.
    pub fn install_id(&self) -> [u8; 16] {
        let mut out = Vec::with_capacity(160);
        for set in &self.sets {
            match set {
                Some(set) => {
                    out.extend_from_slice(&set.set_id().raw());
                    out.extend_from_slice(&(set.seq() as u64).to_le_bytes());
                }
                None => out.extend_from_slice(&[0u8; 40]),
            }
        }
        out.extend_from_slice(&(self.trust_seq as u64).to_le_bytes());
        out.extend_from_slice(&self.trust_id.as_ref().map_or([0u8; 32], Hex64::raw));
        debug_assert_eq!(out.len(), 160);
        let digest = Sha256::digest(&out);
        digest[..16].try_into().expect("sixteen bytes")
    }

    /// IS11: the record after a verified `install.trust`. Its keys, operators and threshold replace the held ones,
    /// every key it leaves out is retired, the ninth retired id forgets the oldest, and its `seq` and envelope id
    /// are the install trust sequence and id.
    pub fn apply_trust(&self, envelope: &Envelope, body: &[u8]) -> Result<Record, Refused> {
        let doc = read_install_trust(body)?;
        let (keys, operators) = (by_id(&doc.keys), by_id(&doc.operators));
        let dropped: Vec<Hex64> =
            self.keys.keys().chain(self.operators.keys()).filter(|kid| !keys.contains_key(*kid) && !operators.contains_key(*kid)).cloned().collect();
        Ok(Record {
            retired: retire(&self.retired, dropped),
            keys,
            operators,
            threshold: doc.threshold,
            trust_seq: envelope.seq,
            trust_id: Some(envelope.envelope_id()),
            ..self.clone()
        })
    }
}

/// IS11: an `install.trust` widens when it adds a key of either role or lowers the threshold.
pub fn trust_widens(record: &Record, body: &[u8]) -> bool {
    let Ok(doc) = read_install_trust(body) else { return false };
    let added = doc.keys.iter().chain(doc.operators.iter()).map(|public| Hex64::of(&public.raw())).any(|kid| {
        !record.keys.contains_key(&kid) && !record.operators.contains_key(&kid)
    });
    added || doc.threshold < record.threshold
}

/// IS11, K4 for an `install.trust` that already counts under the record (V3) and reads (V11). Every key it adds
/// signs it (`dist:rotation-invalid`), and none it adds is the PEP's instance key, a key the trust store holds or
/// has retired, a key id on the revocation list or a retired install or operator key. A key it adds to `keys` is
/// not a held operator key, one it adds to `operators` not a held install key, and no key is in both lists. A
/// wrong `widens` false is `dist:widening-unsigned`. None when it may be applied.
pub fn check_trust(
    record: &Record,
    body: &[u8],
    entries: &[Entry],
    message: &[u8],
    widens: bool,
    instance_key_id: Option<&Hex64>,
    trust: &TrustStore,
) -> Option<&'static str> {
    let doc = read_install_trust(body).ok()?;
    let (keys, operators) = (by_id(&doc.keys), by_id(&doc.operators));
    if keys.keys().any(|kid| operators.contains_key(kid)) {
        return Some(ROTATION_INVALID);
    }
    let added: BTreeMap<&Hex64, &Hex64> = keys
        .iter()
        .filter(|(kid, _)| !record.keys.contains_key(*kid))
        .chain(operators.iter().filter(|(kid, _)| !record.operators.contains_key(*kid)))
        .collect();
    for kid in added.keys() {
        let elsewhere = trust.keys.contains_key(*kid) || trust.retired.contains(kid) || trust.revoked_keys.contains(*kid);
        let crossed = (keys.contains_key(*kid) && record.operators.contains_key(*kid))
            || (operators.contains_key(*kid) && record.keys.contains_key(*kid));
        if instance_key_id == Some(*kid) || elsewhere || record.retired.contains(kid) || crossed {
            return Some(ROTATION_INVALID);
        }
    }
    for (kid, public) in &added {
        let signed = entries.iter().find(|entry| entry.key_id_hex() == **kid);
        if !signed.is_some_and(|entry| crate::verify_ed25519(&public.raw(), message, &entry.signature)) {
            return Some(ROTATION_INVALID);
        }
    }
    (!widens && trust_widens(record, body)).then_some(WIDENING_UNSIGNED)
}

// ------------------------------------------------------------------ the install part of an anchor (P4)

/// P4: the `install` member of a `/2` anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorPart {
    pub domain: Hex64,
    pub keys: SortedSet<Hex64>,
    pub operators: SortedSet<Hex64>,
    pub seq: i64,
    pub threshold: i64,
}

/// P4: the record an anchor's install part brings, held to the rules of an `install.trust` body (IS11). No key is
/// both an install and an operator key (K4).
pub fn read_anchor_part(part: &AnchorPart) -> Result<Record, Refused> {
    let body = codec::to_bytes(&InstallTrust {
        encoding: Canon2Tag,
        format: InstallTrustFormat,
        keys: part.keys.iter().cloned().collect(),
        operators: part.operators.iter().cloned().collect(),
        threshold: part.threshold,
    })
    .map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    let doc = read_install_trust(&body)?;
    require((0..=MAX_SEQ).contains(&part.seq), "an anchor's install seq")?;
    let (keys, operators) = (by_id(&doc.keys), by_id(&doc.operators));
    require(!keys.keys().any(|kid| operators.contains_key(kid)), "an anchor that holds one key as an install and an operator key (K4)")?;
    Ok(Record::new(keys, doc.threshold, operators, part.seq, part.domain.clone()))
}

/// The `install` member of an anchor, for the engineer's tool.
pub fn anchor_part(keys: &[[u8; 32]], threshold: i64, operators: &[[u8; 32]], seq: i64, domain: &Hex64) -> AnchorPart {
    AnchorPart {
        domain: domain.clone(),
        keys: keys.iter().map(Hex64::from_raw).collect(),
        operators: operators.iter().map(Hex64::from_raw).collect(),
        seq,
        threshold,
    }
}

/// P4, CL4: the hash of the reading domain a `host` PEP was built with: the canon/2 bytes of its kind and the
/// fields of the qualification envelope its tables are admitted under, as the Python machine hashes it.
pub fn domain_sha256(qualification: Option<&serde_json::Value>) -> Hex64 {
    let fields = qualification.and_then(|value| value.get("fields")).cloned().unwrap_or_else(|| serde_json::json!({}));
    let bytes = prismpath_rs::canon2::write_json(&serde_json::json!({"fields": fields, "kind": "host"})).unwrap_or_default();
    Hex64::of(&bytes)
}

// ------------------------------------------------------------------ CL1, IS12: the comparisons

/// CL1 on a kind that cannot decide: the `body_sha256` of `table` is on the held ceiling's list. No ceiling holds
/// everything in, and the empty list nothing.
pub fn table_inside(ceiling: Option<&InstallSet>, table: Option<&[u8]>) -> bool {
    let Some(ceiling) = ceiling else { return true };
    let Some(table) = table else { return true };
    let Some(list) = ceiling.bodies.get(&AsName::PolicyList).and_then(|body| read_ceiling_list(body).ok()) else { return false };
    list.bodies.contains(&Hex64::of(table))
}

fn list_of(set: &InstallSet) -> BTreeSet<Hex64> {
    set.bodies.get(&AsName::PolicyList).and_then(|body| read_ceiling_list(body).ok()).map(|list| list.bodies.iter().cloned().collect()).unwrap_or_default()
}

/// AF8, IS12: a rate is looser when it is removed, or allows more in a window or has a shorter window.
pub fn looser(old: Option<Rate>, new: Option<Rate>) -> bool {
    match (old, new) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(old), Some(new)) => new.allows > old.allows || new.window < old.window,
    }
}

/// IS12 on `host`: whether `new` allows more than `held`, the set it follows or None. A first action floor and a
/// first fallback policy widen and the empty one does not. A first ceiling does not widen, the empty ceiling does,
/// and a list that holds a hash the one before did not is larger. A looser `rate` widens. Otherwise a table that
/// is not byte for byte the held one is larger (W2).
///
/// With `carried`, an install change statement from the held set's policy hash stands for the tables of an action
/// floor or a fallback policy (IS15): their bytes are not compared, and everything else is, the rate and a floor's
/// `layout` and `command` included, and the set holds the same artifacts as the held one.
pub fn set_larger(kind: SetKind, held: Option<&InstallSet>, new: &InstallSet, carried: bool) -> bool {
    let empty = new.is_empty_set();
    if kind == SetKind::Ceiling {
        return match (empty, held) {
            (true, held) => held.is_some(),
            (false, None) => false,
            (false, Some(held)) => !list_of(new).is_subset(&list_of(held)),
        };
    }
    let Some(held) = held else { return !empty };
    if empty {
        return false;
    }
    if kind == SetKind::Floor && looser(held.rate(), new.rate()) {
        return true;
    }
    if carried {
        return held.bodies.keys().ne(new.bodies.keys()) || held.reading() != new.reading();
    }
    held.bodies != new.bodies
}

/// IS12: (cause, stands out) of a set whose signer said `widens` and `replaces`. A set the PEP computes as larger
/// whose `widens` is false is `dist:widening-unsigned`, and a `host` PEP, which cannot decide, takes `widens` false
/// only when `replaces` is the policy hash of the set it holds, empty when it holds none. A set stands out, with
/// event `install-widened`, when its `widens` is true or it is larger. The install change statement staged before
/// `new`, from the held set's policy hash, stands for its table when `new` says it does not widen and replaces that
/// hash (IS15), so the set is applied with event `install-applied`.
pub fn widens_ok(kind: SetKind, held: Option<&InstallSet>, new: &InstallSet) -> (Option<&'static str>, bool) {
    let held_policy = held.map(InstallSet::policy_sha256);
    let carried = kind != SetKind::Ceiling
        && !new.doc.widens
        && held_policy.is_some()
        && new.doc.replaces.0.as_ref() == held_policy
        && changes_set(new.change_body.as_deref(), kind, held_policy);
    let larger = set_larger(kind, held, new, carried);
    if new.doc.widens {
        return (None, true);
    }
    if larger || new.doc.replaces.0.as_ref() != held.map(InstallSet::policy_sha256) {
        return (Some(WIDENING_UNSIGNED), true);
    }
    (None, false)
}

// ------------------------------------------------------------------ the PEP's install part on disk

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedSetsDoc {
    encoding: Canon2Tag,
    format: StagedSetsFormat,
    sets: BTreeMap<String, SetDoc>,
}

/// The marks of the anchor part (IS9, IS10, L2), each set once and never cleared but the ceiling's, which is the
/// mark that a ceiling is held and goes with the empty ceiling (the C core's reading).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marks {
    pub ceiling: bool,
    pub encoding: Canon2Tag,
    pub format: MarksFormat,
    pub install: bool,
    pub legacy: bool,
}

/// L2, IS9: whether the older signed forms are closed in the state directory whose `dist/` is `dist`: a release
/// was committed or an install statement held there, or the marks do not read, which is answered the same way.
pub fn older_forms_closed(dist: &str) -> bool {
    match std::fs::read(format!("{dist}/marks.json")) {
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        Ok(raw) => load::<Marks>(&raw, "marks").map_or(true, |marks| marks.install || marks.legacy),
    }
}

fn get(directory: &str, name: &Hex64) -> Option<Vec<u8>> {
    std::fs::read(format!("{directory}/{name}")).ok().filter(|data| Hex64::of(data) == *name)
}

fn write(path: &str, data: &[u8]) -> Result<(), HostError> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|error| HostError::Io(format!("{}: {error}", parent.display())))?;
    }
    atomic_write_bytes(path, data)
}

/// The install part of one PEP over its `dist/` directory, the second copies at `copy` (IS10). `load` reads it as
/// a start does and answers the install kinds whose set was lost. `record` is None when the PEP holds no install
/// record, and `record_lost` is true when it held one and no copy reads.
#[derive(Debug)]
pub struct Installed {
    dist: String,
    dir: String,
    copy: String,
    pub record: Option<Record>,
    pub record_lost: bool,
    pub ceiling_lost: bool,
    pub staged: BTreeMap<SetKind, InstallSet>,
    pub marks: Marks,
}

impl Installed {
    pub fn new(dist: &str, copy: Option<&str>) -> Installed {
        let dir = format!("{dist}/install");
        let copy = copy.map_or_else(|| format!("{dist}/install-copy"), str::to_string);
        Installed {
            dist: dist.to_string(),
            dir,
            copy,
            record: None,
            record_lost: false,
            ceiling_lost: false,
            staged: BTreeMap::new(),
            marks: Marks::default(),
        }
    }

    fn record_paths(&self) -> [String; 2] {
        [format!("{}/record.json", self.dir), format!("{}/record.json", self.copy)]
    }

    fn blob_dirs(&self) -> [String; 2] {
        [format!("{}/blobs", self.dir), format!("{}/blobs", self.copy)]
    }

    /// The paths of the two copies of a document beside the record, `rates.json` say.
    pub fn paths(&self, name: &str) -> [String; 2] {
        [format!("{}/{name}", self.dir), format!("{}/{name}", self.copy)]
    }

    fn read_marks(&mut self) {
        self.marks = match std::fs::read(format!("{}/marks.json", self.dist)) {
            Err(_) => Marks::default(),
            // IS9, IS10: a mark that does not read is taken as set, so a lost file never reopens anything
            Ok(raw) => load::<Marks>(&raw, "marks").unwrap_or(Marks { ceiling: true, install: true, legacy: true, ..Marks::default() }),
        };
    }

    /// Set the marks of the anchor part, durably before anything they guard (IS9, L2), and the ceiling's mark to
    /// whether a ceiling is held (IS10).
    pub fn mark(&mut self, install: bool, legacy: bool, ceiling: Option<bool>) -> Result<(), HostError> {
        let marks = Marks {
            install: self.marks.install || install,
            legacy: self.marks.legacy || legacy,
            ceiling: ceiling.unwrap_or(self.marks.ceiling),
            ..self.marks
        };
        if marks == self.marks && std::path::Path::new(&format!("{}/marks.json", self.dist)).exists() {
            return Ok(());
        }
        let raw = codec::to_bytes(&marks).map_err(|error| HostError::Canonical(format!("marks: {error}")))?;
        write(&format!("{}/marks.json", self.dist), &raw)?;
        self.marks = marks;
        Ok(())
    }

    /// IS10: the record from the first copy that reads, and each held statement from the first copy that is the one
    /// the record names with the signed body hash. A set none of whose copies passes is lost and left out. Returns
    /// the install kinds lost this start. A record no copy reads is lost when a mark says one was held.
    pub fn load(&mut self) -> Vec<SetKind> {
        self.read_marks();
        (self.record, self.record_lost, self.ceiling_lost) = (None, false, false);
        self.staged.clear();
        let read = self.record_paths().iter().find_map(|path| std::fs::read(path).ok().and_then(|raw| Record::from_bytes(&raw).ok()));
        let Some((mut record, named)) = read else {
            self.record_lost = self.marks.install || self.record_paths().iter().any(|path| std::path::Path::new(path).exists());
            self.ceiling_lost = self.record_lost && self.marks.ceiling;
            return Vec::new();
        };
        let mut lost = Vec::new();
        for kind in SetKind::ALL {
            let Some(doc) = &named[kind.index()] else { continue };
            match self.read_set(kind, doc, true) {
                Some(set) => record.sets[kind.index()] = Some(set),
                None => lost.push(kind),
            }
        }
        if lost.contains(&SetKind::Ceiling) || (record.held(SetKind::Ceiling).is_none() && self.marks.ceiling) {
            self.ceiling_lost = true;
        }
        self.record = Some(record);
        self.read_staged();
        lost
    }

    /// One statement from the first copy whose sealed envelope is the one named, with the signed body hash. The
    /// signatures are not checked again, since a key retired later does not remove what it signed (AF3).
    fn read_statement(&self, held: &HeldDoc, both: bool) -> Option<(Envelope, Vec<u8>)> {
        let dirs = self.blob_dirs();
        dirs.iter().take(if both { 2 } else { 1 }).find_map(|dir| {
            let (sealed, body) = (get(dir, &held.sealed)?, get(dir, &held.body)?);
            let envelope = env::read(env::unseal(&sealed).ok()?.0).ok()?;
            (envelope.envelope_id() == held.envelope_id && envelope.body_sha256 == Hex64::of(&body)).then_some((envelope, body))
        })
    }

    fn read_set(&self, kind: SetKind, doc: &SetDoc, both: bool) -> Option<InstallSet> {
        let mut set = InstallSet { kind, doc: doc.clone(), envelopes: BTreeMap::new(), bodies: BTreeMap::new(), change_body: None };
        for (name, held) in &doc.statements {
            let (envelope, body) = self.read_statement(held, both)?;
            set.envelopes.insert(*name, envelope);
            set.bodies.insert(*name, body);
        }
        if let Some(change) = &doc.change {
            set.change_body = Some(self.read_statement(change, both)?.1); // IS15: it survives a restart
        }
        Some(set)
    }

    fn read_staged(&mut self) {
        let Ok(raw) = std::fs::read(format!("{}/staged.json", self.dir)) else { return };
        let Ok(doc) = load::<StagedSetsDoc>(&raw, "staged install sets") else { return };
        for kind in SetKind::ALL {
            // a staged set that does not read is dropped, as a staged release is
            if let Some(set) = doc.sets.get(kind.name()).and_then(|one| self.read_set(kind, one, false)) {
                self.staged.insert(kind, set);
            }
        }
    }

    /// The blobs of a statement, in the first copy and, for a held one, in the second (IS10).
    pub fn put(&self, sealed: &[u8], body: &[u8], both: bool) -> Result<(Hex64, Hex64), HostError> {
        let dirs = self.blob_dirs();
        for data in [sealed, body] {
            let name = Hex64::of(data);
            for dir in dirs.iter().take(if both { 2 } else { 1 }) {
                if get(dir, &name).is_none() {
                    write(&format!("{dir}/{name}"), data)?;
                }
            }
        }
        Ok((Hex64::of(sealed), Hex64::of(body)))
    }

    /// Stage one verified statement of a set (IS4). A set at another `seq` replaces the one staged of its kind.
    pub fn stage(&mut self, kind: SetKind, envelope: &Envelope, sealed: &[u8], body: &[u8]) -> Result<&InstallSet, HostError> {
        let name = install_meta(envelope).map(|meta| meta.as_name).ok_or_else(|| HostError::Io("an install statement names no as".into()))?;
        let mut set = match self.staged.get(&kind) {
            Some(staged) if staged.seq() == envelope.seq => staged.clone(),
            _ => InstallSet::of(kind, envelope),
        };
        let (sealed_name, body_name) = self.put(sealed, body, false)?;
        set.doc.statements.insert(name, HeldDoc { body: body_name, envelope_id: envelope.envelope_id(), sealed: sealed_name });
        set.envelopes.insert(name, envelope.clone());
        set.bodies.insert(name, body.to_vec());
        self.staged.insert(kind, set);
        self.save_staged()?;
        Ok(&self.staged[&kind])
    }

    /// IS15: stage a verified install change statement for the set of `kind` it carries, before that set. A set at
    /// another `seq` staged of the kind is replaced.
    pub fn stage_change(&mut self, kind: SetKind, envelope: &Envelope, sealed: &[u8], body: &[u8]) -> Result<(), HostError> {
        let mut set = match self.staged.get(&kind) {
            Some(staged) if staged.seq() == envelope.seq => staged.clone(),
            _ => InstallSet::of(kind, envelope),
        };
        let (sealed_name, body_name) = self.put(sealed, body, false)?;
        set.doc.change = Some(HeldDoc { body: body_name, envelope_id: envelope.envelope_id(), sealed: sealed_name });
        set.change_body = Some(body.to_vec());
        self.staged.insert(kind, set);
        self.save_staged()
    }

    /// Drop every staged set, as a provisioning does.
    pub fn clear_staged(&mut self) -> Result<(), HostError> {
        self.staged.clear();
        self.save_staged()
    }

    pub fn drop_staged(&mut self, kind: SetKind) -> Result<(), HostError> {
        if self.staged.remove(&kind).is_some() {
            self.save_staged()?;
        }
        Ok(())
    }

    /// Both copies of every statement of `set`, before the record that names it (IS10).
    pub fn keep_both(&self, set: &InstallSet) -> Result<(), HostError> {
        for (name, held) in &set.doc.statements {
            let sealed = get(&self.blob_dirs()[0], &held.sealed).or_else(|| get(&self.blob_dirs()[1], &held.sealed));
            let sealed = sealed.ok_or_else(|| HostError::Io(format!("the staged statement {name:?} is gone")))?;
            self.put(&sealed, &set.bodies[name], true)?;
        }
        Ok(())
    }

    /// Both copies of the record, the first then the second, each whole. Every statement it names is already in
    /// both copies.
    pub fn save(&mut self, record: Record) -> Result<(), HostError> {
        let raw = record.to_bytes()?;
        for path in self.record_paths() {
            write(&path, &raw)?;
        }
        self.record = Some(record);
        self.record_lost = false;
        self.keep();
        Ok(())
    }

    fn save_staged(&self) -> Result<(), HostError> {
        let doc = StagedSetsDoc {
            encoding: Canon2Tag,
            format: StagedSetsFormat,
            sets: self.staged.iter().map(|(kind, set)| (kind.name().to_string(), set.doc.clone())).collect(),
        };
        let raw = codec::to_bytes(&doc).map_err(|error| HostError::Canonical(format!("staged install sets: {error}")))?;
        write(&format!("{}/staged.json", self.dir), &raw)?;
        self.keep();
        Ok(())
    }

    /// Remove every blob neither a held nor a staged statement names. A removal that fails leaves a file nothing
    /// reads.
    fn keep(&self) {
        let held = self.record.iter().flat_map(|record| record.sets.iter().flatten());
        let keep: BTreeSet<Hex64> = held
            .chain(self.staged.values())
            .flat_map(|set| set.doc.statements.values().chain(set.doc.change.as_ref()).flat_map(|one| [one.sealed.clone(), one.body.clone()]))
            .collect();
        for dir in self.blob_dirs() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !Hex64::try_from(name.as_str()).is_ok_and(|hash| keep.contains(&hash)) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    /// A provisioning that leaves no install part: nothing is held, and the marks stay (IS9).
    pub fn clear(&mut self) -> Result<(), HostError> {
        for path in self.record_paths().into_iter().chain([format!("{}/staged.json", self.dir)]) {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(HostError::Io(format!("{path}: {error}"))),
            }
        }
        (self.record, self.record_lost, self.ceiling_lost) = (None, false, false);
        self.staged.clear();
        self.keep();
        Ok(())
    }

    /// The held set of `kind`, None when none is held or the record is lost.
    pub fn held(&self, kind: SetKind) -> Option<&InstallSet> {
        if self.record_lost {
            return None;
        }
        self.record.as_ref().and_then(|record| record.held(kind))
    }

    /// The path of the first copy of a held body that reads, for a runtime that runs the set (FB1).
    pub fn body_path(&self, held: &HeldDoc) -> String {
        let [first, second] = self.blob_dirs();
        if get(&first, &held.body).is_some() {
            format!("{first}/{}", held.body)
        } else {
            format!("{second}/{}", held.body)
        }
    }

    /// IS8: the envelope ids of every install statement held.
    pub fn statement_ids(&self) -> Vec<Hex64> {
        let mut ids: Vec<Hex64> = self.record.iter().flat_map(|record| record.sets.iter().flatten()).flat_map(InstallSet::envelope_ids).collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retired_list_keeps_the_last_eight_sorted_per_drop() {
        let ids: Vec<Hex64> = (0u8..10).map(|byte| Hex64::of(&[byte])).collect();
        let mut retired = Vec::new();
        for id in &ids {
            retired = retire(&retired, [id.clone()]);
        }
        assert_eq!(retired, ids[2..].to_vec());
        assert_eq!(retire(&retired, [ids[5].clone()]), retired, "a retired id is not retired twice");
    }

    #[test]
    fn an_install_trust_body_reads_within_its_bounds() {
        let key = |byte: u8| [byte; 32];
        assert!(trust_body(&[key(1), key(2)], 2, &[key(9)]).is_ok());
        assert_eq!(trust_body(&[key(1)], 2, &[]).unwrap_err().cause, BAD_FORMAT);
        assert_eq!(trust_body(&[key(1), key(2), key(3), key(4), key(5)], 1, &[]).unwrap_err().cause, TOO_LARGE);
        assert_eq!(trust_body(&[], 1, &[]).unwrap_err().cause, BAD_FORMAT);
    }

    #[test]
    fn as_names_only_what_a_release_holds() {
        assert_eq!(AsName::from_name("policy.ppt"), Some(AsName::Artifact(ArtifactKind::PolicyPpt)));
        assert_eq!(AsName::from_name("none"), Some(AsName::None));
        for name in ["trust.widening", "grant", "install.floor", "operator.answer", "nothing"] {
            assert_eq!(AsName::from_name(name), None, "{name}");
        }
    }
}
