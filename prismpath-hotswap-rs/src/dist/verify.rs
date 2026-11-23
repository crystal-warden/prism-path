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

use super::envelope::{self as env, Envelope};
use super::trust::TrustStore;
use super::{
    ArtifactKind, Hex64, MaybeHex64, Stream, Target, TargetKind, Verdict, AUTHORITY, BODY_MISMATCH, EXPIRED, INCOMPLETE,
    NOT_YET_VALID, REVOKED, SEQ_REPLAY, TARGET_MISMATCH, TOO_LARGE, TRUST_REPLAY,
};
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
    // V3: the signatures, over the bytes as they came and before anything reads them (E9)
    let counted = trust.counting(&entries, &env::signed_message(envelope_bytes), AUTHORITY); // K4
    if !counted.ok() {
        return counted;
    }
    // V4: the envelope reads
    let envelope = match env::read(envelope_bytes) {
        Ok(envelope) => envelope,
        Err(refused) => return Verdict::refused(refused.cause),
    };
    let refuse = |cause: &str, envelope: Envelope, time_floor: Option<i64>| Verdict {
        cause: Some(cause.to_string()),
        envelope: Some(envelope),
        unchanged: false,
        time_floor,
    };
    // V5: for this PEP's kind, an artifact its kind uses or a trust kind its machine applies, on its stream
    // or `@trust`
    let stream = if envelope.artifact.on_trust_stream() { env::TRUST_STREAM } else { pep.stream.as_str() };
    if !envelope.targets.contains(&pep.kind.kind()) || envelope.stream != stream || !target.admits(envelope.artifact) {
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
        if let Some(cause) = trust.check_rotation(body, &entries, &env::signed_message(envelope_bytes), pep.instance_key_id.as_ref()) {
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
    Verdict { cause: None, envelope: Some(envelope), unchanged: false, time_floor }
}
