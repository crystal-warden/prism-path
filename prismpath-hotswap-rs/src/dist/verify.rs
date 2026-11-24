// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The one verifier of policy distribution (spec-policy-distribution.md, section 9.1),
//! `prismpath/distribution/verify.py` in Rust.
//!
//! The rules run in the order V2 to V11 and the first that fails is the only cause reported (V1). The
//! verifier is a function of its arguments: it reads no clock, no file and no floor of its own. What the
//! enforcement point holds comes in as a `PepView` and its trust store, and the time floor the PEP
//! should make durable after V6 passed comes back in the `Verdict` (V13). The widening rule V12 joins
//! with W1 to W7.

use super::envelope::{self as env, Entry, Envelope};
use super::install::{self, AsName, InstallSet, Record, SetKind};
use super::trust::TrustStore;
use super::{
    ArtifactKind, Hex64, MaybeHex64, Stream, Target, TargetKind, Verdict, ABOVE_CEILING, AUTHORITY, BAD_FORMAT, BODY_MISMATCH,
    EXPIRED, INCOMPLETE, NOT_YET_VALID, REVOKED, SEQ_REPLAY, TARGET_MISMATCH, TOO_LARGE, TRUST_REPLAY, UNKNOWN_KEY,
};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Section 7: a PEP's clock is within 300 seconds of true time.
pub const SKEW: i64 = 300;

/// Q1: the highest `seq` committed on the PEP's stream and the envelope ids committed at it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub seq: i64,
    pub ids: BTreeSet<Hex64>,
}

/// What a staged release shares (E7): its stream, `seq`, policy hash, release id, `replaces` and
/// `widens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Staged {
    pub stream: String,
    pub seq: i64,
    pub policy_sha256: Hex64,
    pub release: Hex64,
    pub replaces: MaybeHex64,
    pub widens: bool,
}

/// A target kind whose enforcement point is built (`TargetKind::target` has its row). A PEP of any
/// other kind cannot be described to the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TargetKind", into = "TargetKind")]
pub struct PepKind(TargetKind);

impl TryFrom<TargetKind> for PepKind {
    type Error = String;
    fn try_from(kind: TargetKind) -> Result<PepKind, String> {
        match kind.target() {
            Some(_) => Ok(PepKind(kind)),
            None => Err(format!("no enforcement point of kind {kind} is built")),
        }
    }
}

impl From<PepKind> for TargetKind {
    fn from(kind: PepKind) -> TargetKind {
        kind.0
    }
}

impl PepKind {
    pub fn kind(self) -> TargetKind {
        self.0
    }

    pub fn target(self) -> Target {
        self.0.target().expect("a PepKind is a built kind")
    }
}

/// What the verifier needs of an enforcement point. `qualification` is the qualification envelope a
/// `host` PEP admits images under, already verified, `body_bound` is the PEP's own bound on a body,
/// within its kind's (E6), and `has_clock` is false for a PEP with no real time clock, whose `now` is its time floor plus
/// its monotonic count (T2) and which never applies T3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PepView {
    pub kind: PepKind,
    pub stream: Stream,
    pub floor: Floor,
    pub active: Option<Hex64>,
    pub staged: Option<Staged>,
    pub qualification: Option<serde_json::Value>,
    pub body_bound: i64,
    pub has_clock: bool,
    /// The PEP's own instance key id, which a rotation may never add (O4).
    #[serde(default)]
    pub instance_key_id: Option<Hex64>,
    /// The PEP's install part (section 21), or None for one that holds none.
    #[serde(skip)]
    pub install: Option<InstallView>,
}

/// What the verifier needs of a PEP's install part (section 21): the install record, the staged install sets by
/// kind, the held ceiling, whether the statement came in a message, where an install threshold of 1 takes no
/// install statement (IS4), or by provisioning, and the layout document a table kind was built with (AF10).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InstallView {
    pub record: Option<Record>,
    pub staged: BTreeMap<SetKind, InstallSet>,
    pub ceiling: Option<InstallSet>,
    pub message: bool,
    pub layout: Option<Vec<u8>>,
}

impl PepView {
    /// A PEP of `kind` on `stream` with nothing committed, nothing staged and no qualification.
    pub fn new(kind: TargetKind, stream: &str) -> Result<PepView, String> {
        Ok(PepView {
            kind: PepKind::try_from(kind)?,
            stream: Stream::try_from(stream)?,
            floor: Floor::default(),
            active: None,
            staged: None,
            qualification: None,
            body_bound: env::MAX_BODY,
            has_clock: true,
            instance_key_id: None,
            install: None,
        })
    }
}

/// V8. None to go on, or the verdict: a refusal, or an envelope at its floor that changes nothing.
fn floor_check(envelope: &Envelope, trust: &TrustStore, pep: &PepView) -> Option<(&'static str, bool)> {
    let envelope_id = envelope.envelope_id();
    if envelope.artifact.on_trust_stream() {
        // R1, O1: one trust sequence, no step skipped
        if envelope.seq == trust.trust_seq + 1 {
            return None;
        }
        if envelope.seq == trust.trust_seq && trust.trust_id.0.as_ref() == Some(&envelope_id) {
            return Some(("", true));
        }
        return Some((TRUST_REPLAY, false));
    }
    let raised = Stream::try_from(envelope.stream.as_str()).ok().and_then(|stream| trust.floors.get(&stream).copied());
    let floor = pep.floor.seq.max(raised.unwrap_or(0)); // Q2, Q3, and R4's raised floor
    if envelope.seq > floor {
        return None;
    }
    if envelope.seq == pep.floor.seq && pep.floor.seq == floor && pep.floor.ids.contains(&envelope_id) {
        return Some(("", true));
    }
    Some((SEQ_REPLAY, false))
}

/// V1: the sealed envelope and its body checked in the order V2 to V11 for `pep` at the PEP's clock
/// reading `now` (Unix seconds). The first failure's cause, or the accepted envelope.
pub fn verify(sealed: &[u8], body: &[u8], trust: &TrustStore, pep: &PepView, now: i64) -> Verdict {
    // V2: the container reads, and the envelope and body fit the bounds (B9: nothing past either is read)
    let (envelope_bytes, entries) = match env::unseal(sealed) {
        Ok(unsealed) => unsealed,
        Err(refused) => return Verdict::refused(refused.cause),
    };
    // E6: the PEP's artifact bound within its kind's, and the trust bound every kind has; V2 keeps the larger
    let target = pep.kind.target();
    let artifact_bound = pep.body_bound.min(target.body_bound);
    if i64::try_from(body.len()).map_or(true, |length| length > artifact_bound.max(target.trust_bound)) {
        return Verdict::refused(TOO_LARGE);
    }
    // V3: the signatures, over the bytes as they came and before anything reads them (E9). K4: every role under
    // which the envelope is signed is found, the authority's in the trust store and the install and operator keys'
    // in the install record (IS2, OP1), and V3 fails only when there is none
    let message = env::signed_message(envelope_bytes);
    let counted = trust.counting(&entries, &message, AUTHORITY);
    let record = pep.install.as_ref().and_then(|view| view.record.as_ref());
    let installed = record.map(|record| record.counting(&entries, &message));
    let answering = record.map(|record| record.answering(&entries, &message));
    let any = |verdict: &Option<Verdict>| verdict.as_ref().is_some_and(Verdict::ok);
    if !counted.ok() && !any(&installed) && !any(&answering) {
        if env::read(envelope_bytes).is_ok_and(|envelope| envelope.artifact == ArtifactKind::OperatorAnswer) {
            return Verdict::refused(TARGET_MISMATCH); // OP1: no answer on a kind with no escalation, whatever signs it
        }
        if counted.cause.as_deref() == Some(UNKNOWN_KEY) {
            if let Some(installed) = installed {
                let first = if installed.cause.as_deref() != Some(UNKNOWN_KEY) { installed } else { answering.expect("beside installed") };
                return first;
            }
        }
        return counted;
    }
    // V4: the envelope reads
    let envelope = match env::read(envelope_bytes) {
        Ok(envelope) => envelope,
        Err(refused) => return Verdict::refused(refused.cause),
    };
    // V5, K4: the role the artifact needs is one it is signed under. An install kind is checked on its own path, and an
    // answer is for a kind with escalation, which `host` is not (AF2, OP1)
    if envelope.artifact.is_install() {
        return verify_install(envelope, &entries, &message, body, trust, pep, now, installed);
    }
    if envelope.artifact == ArtifactKind::OperatorAnswer {
        return Verdict { cause: Some(TARGET_MISMATCH.to_string()), envelope: Some(envelope), ..Verdict::default() };
    }
    if !counted.ok() {
        return Verdict { envelope: Some(envelope), ..counted };
    }
    let refuse = |cause: &str, envelope: Envelope, time_floor: Option<i64>| Verdict {
        cause: Some(cause.to_string()),
        envelope: Some(envelope),
        unchanged: false,
        time_floor,
    };
    // V5: for this PEP's kind, an artifact its kind uses or a trust kind its machine applies, on its stream
    // or `@trust`. A revocation, a rotation or a controller key statement is for every PEP whatever `targets`
    // says, since one trust sequence counts the same for all of them (R1, K7)
    let on_trust = envelope.artifact.on_trust_stream();
    let stream = if on_trust { env::TRUST_STREAM } else { pep.stream.as_str() };
    let named = on_trust || envelope.targets.contains(&pep.kind.kind());
    if !named || envelope.stream != stream || !target.admits(envelope.artifact) {
        return refuse(TARGET_MISMATCH, envelope, None);
    }
    // ...then the signed size against the bound of that artifact, before any body is read (E6, B9)
    let bound = if envelope.artifact.is_trust() { target.trust_bound } else { artifact_bound };
    if envelope.body_size > bound {
        return refuse(TOO_LARGE, envelope, None);
    }
    // V6: time, against the larger of the clock and the time floor (T1, T3, T4; X4 a trust kind never
    // expires). A PEP with no clock has no ground to call an envelope early (T3) and catches up by V13 (T2).
    let time = now.max(trust.time_floor);
    if pep.has_clock && envelope.not_before - time > SKEW {
        return refuse(NOT_YET_VALID, envelope, None);
    }
    if envelope.expires != 0 && time >= envelope.expires {
        return refuse(EXPIRED, envelope, None);
    }
    let time_floor = Some(trust.time_floor.max(envelope.not_before)); // V13
    // V7: revocation
    if trust.revoked_envelopes.contains(&envelope.envelope_id()) || trust.revoked_policies.contains(&envelope.policy_sha256) {
        return refuse(REVOKED, envelope, time_floor);
    }
    // V8: the sequence
    match floor_check(&envelope, trust, pep) {
        None => {}
        Some((_, true)) => return Verdict { cause: None, envelope: Some(envelope), unchanged: true, time_floor },
        Some((cause, false)) => return refuse(cause, envelope, time_floor),
    }
    // V9: the body
    if i64::try_from(body.len()).ok() != Some(envelope.body_size) || Hex64::of(body) != envelope.body_sha256 {
        return refuse(BODY_MISMATCH, envelope, time_floor);
    }
    // V10: the release already staged at this seq agrees (E7)
    if let Some(staged) = &pep.staged {
        let disagrees = (&staged.policy_sha256, &staged.release, &staged.replaces, staged.widens)
            != (&envelope.policy_sha256, &envelope.release, &envelope.replaces, envelope.widens);
        if !envelope.artifact.on_trust_stream() && staged.stream == envelope.stream && staged.seq == envelope.seq && disagrees {
            return refuse(INCOMPLETE, envelope, time_floor);
        }
    }
    // V11: the artifact's own check
    if let Some(cause) = envelope.artifact.row().check.and_then(|check| check(&envelope, body, pep)) {
        return refuse(&cause, envelope, time_floor);
    }
    // O2 to O4, K5: the rotation's own rules
    if envelope.artifact == ArtifactKind::TrustRotation {
        let others = record.map(Record::ids).unwrap_or_default();
        if let Some(cause) = trust.check_rotation(body, &entries, &message, pep.instance_key_id.as_ref(), &others) {
            return refuse(cause, envelope, time_floor);
        }
    }
    // K7, K4, K5: a controller key statement names no key held or retired in another role and makes no ninth key
    if envelope.artifact == ArtifactKind::TrustController {
        let others = record.map(Record::ids).unwrap_or_default();
        if let Some(cause) = trust.check_controller(body, pep.instance_key_id.as_ref(), &others) {
            return refuse(cause, envelope, time_floor);
        }
    }
    // R6: a revocation list holds every key id the current one holds, so a revoked key stays revoked
    if envelope.artifact == ArtifactKind::TrustRevocation {
        if let Ok(listed) = super::read_revocation(body) {
            if !trust.revoked_keys.iter().all(|kid| listed.keys.contains(kid)) {
                return refuse(TRUST_REPLAY, envelope, time_floor);
            }
        }
    }
    // CL2: an artifact a release holds is inside the ceiling the PEP holds
    let ceiling = pep.install.as_ref().and_then(|view| view.ceiling.as_ref());
    if envelope.artifact == ArtifactKind::PolicyPpt && !install::table_inside(ceiling, Some(body)) {
        return refuse(ABOVE_CEILING, envelope, time_floor);
    }
    Verdict { cause: None, envelope: Some(envelope), unchanged: false, time_floor }
}

/// IS5: an install statement through V5 to V11 with the differences section 21 gives them. V3 counted the install
/// keys against the install threshold. V5 takes an install kind on the PEP's own stream, by provisioning or, where
/// the install threshold is 2 or more, in a message (IS4), and a set in the form of its kind (IS3). V6 applies T3 and
/// never raises the time floor (V13). V7 is never read against an install kind (IS7). V8 is IS6, or IS11 for an
/// `install.trust`. V10 holds a set's statements to one set. V11 is the check of the artifact `as` names, the
/// narrowness of an action floor (AF9, AF10), then the ceiling (CL3). V12 is the PEP's when the set is whole (IS12).
#[allow(clippy::too_many_arguments)]
fn verify_install(
    envelope: Envelope,
    entries: &[Entry],
    message: &[u8],
    body: &[u8],
    trust: &TrustStore,
    pep: &PepView,
    now: i64,
    installed: Option<Verdict>,
) -> Verdict {
    let refuse = |cause: &str, envelope: Envelope| Verdict { cause: Some(cause.to_string()), envelope: Some(envelope), ..Verdict::default() };
    let (Some(view), Some(installed)) = (pep.install.as_ref(), installed) else { return refuse(UNKNOWN_KEY, envelope) };
    let record = view.record.as_ref().expect("an installed verdict comes from a record");
    if let Some(cause) = installed.cause {
        return refuse(&cause, envelope);
    }
    let target = pep.kind.target();
    let artifact = envelope.artifact;
    let named = install::install_meta(&envelope).map(|meta| meta.as_name);
    // V5
    if view.message && record.threshold < 2 {
        return refuse(TARGET_MISMATCH, envelope); // IS4: by provisioning only
    }
    if envelope.stream != pep.stream.as_str() {
        return refuse(TARGET_MISMATCH, envelope);
    }
    let kind = SetKind::of(artifact);
    if let Some(kind) = kind {
        let allowed = named.is_some_and(|name| install::allowed_as(kind, name));
        if !envelope.targets.contains(&pep.kind.kind()) || !allowed {
            return refuse(TARGET_MISMATCH, envelope);
        }
    }
    let listed = artifact == ArtifactKind::InstallTrust || named == Some(AsName::PolicyList);
    let bound = if listed { target.trust_bound } else { pep.body_bound.min(target.body_bound) };
    if envelope.body_size > bound || i64::try_from(body.len()).map_or(true, |length| length > bound) {
        return refuse(TOO_LARGE, envelope);
    }
    // V6: T3 where the PEP has a clock; an install statement never raises the time floor (T1, V13)
    let time = now.max(if trust.is_readable() { trust.time_floor } else { 0 });
    if pep.has_clock && envelope.not_before - time > SKEW {
        return refuse(NOT_YET_VALID, envelope);
    }
    // V8: IS6, IS11
    let envelope_id = envelope.envelope_id();
    match kind {
        None => {
            if envelope.seq == record.trust_seq && record.trust_id.as_ref() == Some(&envelope_id) {
                return Verdict { envelope: Some(envelope), unchanged: true, ..Verdict::default() };
            }
            if envelope.seq != record.trust_seq + 1 {
                return refuse(TRUST_REPLAY, envelope);
            }
        }
        Some(kind) => {
            let again = record.held(kind).is_some_and(|held| held.envelope_ids().contains(&envelope_id))
                || record.applied(kind) == Some(&install::set_id([&envelope_id]));
            if envelope.seq == record.seq(kind) && again {
                return Verdict { envelope: Some(envelope), unchanged: true, ..Verdict::default() };
            }
            if envelope.seq <= record.seq(kind) || view.staged.get(&kind).is_some_and(|staged| envelope.seq < staged.seq()) {
                return refuse(SEQ_REPLAY, envelope); // IS6, IS4, G2
            }
        }
    }
    // V9
    if i64::try_from(body.len()).ok() != Some(envelope.body_size) || Hex64::of(body) != envelope.body_sha256 {
        return refuse(BODY_MISMATCH, envelope);
    }
    // V10: the statements of one set share stream, seq, policy hash, release id, replaces, widens and rate
    if let Some(staged) = kind.and_then(|kind| view.staged.get(&kind)).filter(|staged| staged.seq() == envelope.seq) {
        let first = staged.envelopes.values().next();
        let rates = |one: &Envelope| install::install_meta(one).map(|meta| (meta.rate, meta.answer_rate));
        let agrees = first.is_some_and(|first| {
            (&first.policy_sha256, &first.release, &first.replaces, first.widens, rates(first))
                == (&envelope.policy_sha256, &envelope.release, &envelope.replaces, envelope.widens, rates(&envelope))
        });
        let other = named.and_then(|name| staged.doc.statements.get(&name)).is_some_and(|held| held.envelope_id != envelope_id);
        if !agrees || other {
            return refuse(INCOMPLETE, envelope);
        }
    }
    // V11: the check of the artifact `as` names, then the floor's narrowness, then the ceiling
    let cause = match (kind, named) {
        (None, _) => install::read_install_trust(body)
            .err()
            .map(|refused| refused.cause)
            .or_else(|| install::check_trust(record, body, entries, message, envelope.widens, pep.instance_key_id.as_ref(), trust)),
        (_, Some(AsName::None)) => None,
        (_, Some(AsName::PolicyList)) => install::read_ceiling_list(body).err().map(|refused| refused.cause),
        (Some(kind), Some(AsName::Artifact(inner))) => {
            let own = inner.row().check.and_then(|check| check(&envelope, body, pep));
            let floor = || {
                let meta = install::install_meta(&envelope).expect("a set's statement has its install meta");
                (kind == SetKind::Floor && inner == ArtifactKind::PolicyPpt)
                    .then(|| super::floor::narrow(body, meta.command, meta.layout.as_ref(), view.layout.as_deref()))
                    .flatten()
                    .map(str::to_string)
            };
            let ceiling = || {
                (kind != SetKind::Ceiling && inner == ArtifactKind::PolicyPpt && !install::table_inside(view.ceiling.as_ref(), Some(body)))
                    .then(|| ABOVE_CEILING.to_string())
            };
            return match own.or_else(floor).or_else(ceiling) {
                Some(cause) => refuse(&cause, envelope),
                None => Verdict { envelope: Some(envelope), ..Verdict::default() },
            };
        }
        (_, None) => Some(BAD_FORMAT),
    };
    match cause {
        Some(cause) => refuse(cause, envelope),
        None => Verdict { envelope: Some(envelope), ..Verdict::default() },
    }
}
