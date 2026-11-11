-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Scope
import Core.Main
/-!
# The verified core: evidence and the semantics

A differential run is evidence (docs/design/spec-verified-core.md, section 11): image attestations under
the authority key, one receipt per decision, and one root statement under the instance key over the
Merkle root of the receipts. This file states what a verified run says about `Core.verdict`, over a model
of the run and of its verifier, with the cryptography as parameters and its security as hypotheses.

* The exclusions are recomputed from the image, the engine counter by `counterRefusal` (`Core/Scope.lean`),
  the check the producers use.
* `verifyRun` models the verifier (`core_evidence.verify` and its Rust twin with `--sample all` and pinned
  keys): the pinned keys, the image attestations, the root statement's signature, its Merkle root and leaf
  count, the exclusions recomputed from the image, every receipt binding its case and reading by hash in
  order, and every receipt's decision replayed through the oracle's spelling of `Core.verdict`.
* `verified_receipt_is_verdict`: every receipt of a verified run records `Core.verdict` on the image and the
  reading whose hashes it carries. `receipt_is_verdict_of_hashes`: on any bytes with those hashes that
  collide with no document of the run. `verified_run_complete`: every reading of every case the run does
  not exclude has its receipt. `verified_refusal_registered`: a recorded refusal carries the verdict's registered nonzero code.
  `verified_excluded_counter`: a case excluded as `engine-counter` is refused for that on every reading.
* `evidence_sound` puts them together: if signatures under the pinned instance key are unforgeable, its
  holder signed the root; a list of receipts under that root that exhibits no hash collision is exactly the
  verified one; and each receipt records `Core.verdict` on any bytes with its hashes that exhibit no
  collision with the run's documents.

The cryptography is stated for the objects at hand (`Unforgeable`, `NoTreeCollision`, `NoCollision`), each
an explicit hypothesis of the theorem that uses it, never for all inputs, which no hash onto a finite set
satisfies. What is assumed and not proven: those hypotheses (Ed25519 and SHA-256), that the Python and Rust
verifiers compute `verifyRun`, and that the oracle binary computes `Core.verdict` (the Lean compiler, the C
compiler and the hardware). Section 7 of the spec lists them.
-/

namespace Core

namespace Evidence

/-! ## Receipts -/

/-- A receipt's decision members: `route` with its target, or `refuse` with the code, the cause, and the
field and reason where the refusal has them (`core_evidence._decision`, Rust `refusal`). -/
inductive Decision where
  | route (target : String)
  | refuse (code : Nat) (cause : String) (field : Option String) (reason : Option String)
  deriving DecidableEq, Repr

/-- A spelled member as a receipt carries it: an empty field (the oracle's spelling of a threshold on no
field) is no field. -/
def present : Option String → Option String
  | some s => if s.isEmpty then none else some s
  | none => none

/-- The decision a receipt records for a verdict: the oracle's spelling (`spellRefusal`). -/
def record : Verdict → Decision
  | .route t => .route t
  | .refuse r =>
    let s := spellRefusal r
    .refuse s.code s.cause (present s.field) (present s.reason)

/-- What the verifier checks of a decision by itself: a refusal carries a registered nonzero code. -/
def Decision.registered : Decision → Bool
  | .route _ => true
  | .refuse code cause _ _ => code != 0 && causeRegistry.contains (code, cause)

structure Receipt (D : Type) where
  idx : Nat
  case : String
  reading : Nat
  imageSha : D
  readingSha : D
  decider : String
  decision : Decision

structure Case where
  id : String
  image : ByteArray
  readings : List ByteArray

/-- The reasons a case is outside the core that depend on its flow rendering, not on the image alone. -/
inductive FlowReason where
  | unrenderable
  | inferredPath
  deriving DecidableEq, Repr

/-- Why a case is excluded (`core_evidence.outside_core`). -/
inductive Why where
  | engineCounter
  | flow (r : FlowReason)
  deriving DecidableEq, Repr

/-- The cryptography and the canon/2 writer, as parameters: a hash (SHA-256), the bytes of a receipt (its
canon/2 line), the Merkle root of a list of leaves (`merkle_root`), signature verification (Ed25519), and
the messages the two keys sign (each a domain prefix and canon/2 bytes). -/
structure Crypto (D K S : Type) where
  hash : ByteArray → D
  encode : Receipt D → ByteArray
  merkle : List D → D
  verify : K → ByteArray → S → Bool
  imageMessage : ByteArray → ByteArray
  rootMessage : D → Nat → D → ByteArray

/-- A run as the verifier reads it: the cases, the image signatures, the excluded cases with their reasons,
the receipts in order, the manifest, and the root statement (its root, leaf count, the manifest's hash and
the signature), with the two public keys. -/
structure Run (D K S : Type) where
  cases : List Case
  imageSigs : List S
  excluded : List (String × Why)
  receipts : List (Receipt D)
  decider : String
  manifest : ByteArray
  manifestSha : D
  root : D
  leaves : Nat
  authorityKey : K
  instanceKey : K
  sig : S

variable {D K S : Type} [DecidableEq D] [DecidableEq K]

/-- The leaf of a receipt: the hash of its canon/2 line. -/
def leaf (C : Crypto D K S) (r : Receipt D) : D := C.hash (C.encode r)

/-- The exclusion the image says, the engine counter decided by the oracle's own check. -/
def why (other : Case → Option FlowReason) (c : Case) : Option Why :=
  if counterRefusal c.image then some .engineCounter else (other c).map .flow

def excludedOf (run : Run D K S) (id : String) : Option Why :=
  (run.excluded.find? (fun e => e.1 == id)).map (·.2)

def indexed {α : Type} : List α → Nat → List (Nat × α)
  | [], _ => []
  | x :: xs, n => (n, x) :: indexed xs (n + 1)

/-- Every reading of every case the run does not exclude, in order: the decisions it must receipt. -/
def expected (run : Run D K S) : List (Case × Nat × ByteArray) :=
  (run.cases.filter (fun c => (excludedOf run c.id).isNone)).flatMap
    (fun c => (indexed c.readings 0).map (fun p => (c, p.1, p.2)))

/-- A receipt binds its position, its case and reading by id and by hash, the run's decider, and a
registered decision. -/
def binds (C : Crypto D K S) (run : Run D K S) (k : Nat) (e : Case × Nat × ByteArray) (r : Receipt D) : Bool :=
  r.idx == k && r.case == e.1.id && r.reading == e.2.1 && r.imageSha == C.hash e.1.image &&
    r.readingSha == C.hash e.2.2 && r.decider == run.decider && r.decision.registered

/-- The replay: the receipt's decision is the oracle's on the case's image and the reading. -/
def replays (e : Case × Nat × ByteArray) (r : Receipt D) : Bool :=
  r.decision == record (verdictBytes e.1.image e.2.2)

def checkReceipts (C : Crypto D K S) (run : Run D K S) : Nat → List (Case × Nat × ByteArray) → List (Receipt D) → Bool
  | _, [], [] => true
  | k, e :: es, r :: rs => binds C run k e r && replays e r && checkReceipts C run (k + 1) es rs
  | _, _, _ => false

/-- The verifier with every receipt replayed and both keys pinned. -/
def verifyRun (C : Crypto D K S) (other : Case → Option FlowReason) (pinAuthority pinInstance : K)
    (run : Run D K S) : Bool :=
  run.authorityKey == pinAuthority && run.instanceKey == pinInstance && run.authorityKey != run.instanceKey &&
    run.imageSigs.length == run.cases.length &&
    (run.cases.zip run.imageSigs).all (fun p => C.verify run.authorityKey (C.imageMessage p.1.image) p.2) &&
    C.verify run.instanceKey (C.rootMessage run.root run.leaves run.manifestSha) run.sig &&
    run.manifestSha == C.hash run.manifest &&
    run.root == C.merkle (run.receipts.map (leaf C)) && run.leaves == run.receipts.length &&
    run.cases.all (fun c => excludedOf run c.id == why other c) &&
    checkReceipts C run 0 (expected run) run.receipts

/-! ## What the checks give -/

omit [DecidableEq K] in
theorem checkReceipts_sound {C : Crypto D K S} {run : Run D K S} :
    ∀ {k : Nat} {es : List (Case × Nat × ByteArray)} {rs : List (Receipt D)},
      checkReceipts C run k es rs = true → ∀ r ∈ rs, ∃ e ∈ es,
        r.case = e.1.id ∧ r.reading = e.2.1 ∧ r.imageSha = C.hash e.1.image ∧ r.readingSha = C.hash e.2.2 ∧
          r.decision = record (verdictBytes e.1.image e.2.2)
  | _, [], [], _ => by simp
  | _, [], _ :: _, h => by simp [checkReceipts] at h
  | _, _ :: _, [], h => by simp [checkReceipts] at h
  | k, e :: es, r :: rs, h => by
    simp only [checkReceipts, Bool.and_eq_true] at h
    obtain ⟨⟨hb, hr⟩, hrest⟩ := h
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · simp only [binds, replays, Bool.and_eq_true, beq_iff_eq] at hb hr
      exact ⟨e, List.mem_cons_self .., hb.1.1.1.1.1.2, hb.1.1.1.1.2, hb.1.1.1.2, hb.1.1.2, hr⟩
    · obtain ⟨e', he', h'⟩ := checkReceipts_sound hrest x hx
      exact ⟨e', List.mem_cons_of_mem _ he', h'⟩

omit [DecidableEq K] in
theorem checkReceipts_complete {C : Crypto D K S} {run : Run D K S} :
    ∀ {k : Nat} {es : List (Case × Nat × ByteArray)} {rs : List (Receipt D)},
      checkReceipts C run k es rs = true → ∀ e ∈ es, ∃ r ∈ rs,
        r.case = e.1.id ∧ r.reading = e.2.1 ∧ r.decision = record (verdictBytes e.1.image e.2.2)
  | _, [], _, _ => by simp
  | _, _ :: _, [], h => by simp [checkReceipts] at h
  | k, e :: es, r :: rs, h => by
    simp only [checkReceipts, Bool.and_eq_true] at h
    obtain ⟨⟨hb, hr⟩, hrest⟩ := h
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · simp only [binds, replays, Bool.and_eq_true, beq_iff_eq] at hb hr
      exact ⟨r, List.mem_cons_self .., hb.1.1.1.1.1.2, hb.1.1.1.1.2, hr⟩
    · obtain ⟨r', hr', h'⟩ := checkReceipts_complete hrest x hx
      exact ⟨r', List.mem_cons_of_mem _ hr', h'⟩

theorem mem_indexed {α : Type} {p : Nat × α} : ∀ {xs : List α} {n : Nat}, p ∈ indexed xs n → p.2 ∈ xs
  | [], _, h => by simp [indexed] at h
  | x :: xs, n, h => by
    simp only [indexed, List.mem_cons] at h
    rcases h with rfl | h
    · exact List.mem_cons_self ..
    · exact List.mem_cons_of_mem _ (mem_indexed h)

omit [DecidableEq D] [DecidableEq K] in
theorem mem_expected {run : Run D K S} {e : Case × Nat × ByteArray} (h : e ∈ expected run) :
    e.1 ∈ run.cases ∧ e.2.2 ∈ e.1.readings ∧ excludedOf run e.1.id = none := by
  simp only [expected, List.mem_flatMap, List.mem_filter, List.mem_map] at h
  obtain ⟨c, ⟨hc, hnone⟩, p, hp, rfl⟩ := h
  exact ⟨hc, mem_indexed hp, Option.isNone_iff_eq_none.mp hnone⟩

theorem verifyRun_parts {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K} {run : Run D K S}
    (h : verifyRun C other pa pi run = true) :
    run.instanceKey = pi ∧ C.verify run.instanceKey (C.rootMessage run.root run.leaves run.manifestSha) run.sig = true ∧
      run.root = C.merkle (run.receipts.map (leaf C)) ∧
      (∀ c ∈ run.cases, excludedOf run c.id = why other c) ∧
      checkReceipts C run 0 (expected run) run.receipts = true := by
  simp only [verifyRun, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_, hB⟩, _⟩, _⟩, _⟩, hF⟩, _⟩, hH⟩, _⟩, hJ⟩, hK⟩ := h
  exact ⟨hB, hF, hH, hJ, hK⟩

/-- **A verified receipt records the verdict.** Every receipt of a run the verifier accepts records
`Core.verdict` (as the oracle spells it) on the image and the reading of a case of the run, and carries
those two documents' hashes. -/
theorem verified_receipt_is_verdict {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K}
    {run : Run D K S} (h : verifyRun C other pa pi run = true) {r : Receipt D} (hr : r ∈ run.receipts) :
    ∃ c ∈ run.cases, ∃ rd ∈ c.readings, r.case = c.id ∧ r.imageSha = C.hash c.image ∧ r.readingSha = C.hash rd ∧
      r.decision = record (verdictBytes c.image rd) := by
  obtain ⟨_, _, _, _, hcheck⟩ := verifyRun_parts h
  obtain ⟨e, he, hcase, _, himg, hrd, hdec⟩ := checkReceipts_sound hcheck r hr
  obtain ⟨hc, hrdmem, _⟩ := mem_expected he
  exact ⟨e.1, hc, e.2.2, hrdmem, hcase, himg, hrd, hdec⟩

/-- No document of the run shares its hash with `a` unless it is `a`: collision resistance of the hash,
stated for one byte string at hand. It is not stated for all inputs, which no hash onto a finite set
satisfies; it fails for `a` only if `a` is a second preimage of a document of the run. -/
def NoCollision (C : Crypto D K S) (run : Run D K S) (a : ByteArray) : Prop :=
  (∀ c ∈ run.cases, C.hash a = C.hash c.image → a = c.image) ∧
    (∀ c ∈ run.cases, ∀ rd ∈ c.readings, C.hash a = C.hash rd → a = rd)

/-- **The decision is a function of the hashes the receipt carries.** A verified receipt records
`Core.verdict` on any image and reading bytes that have the hashes it carries and collide with no document
of the run. -/
theorem receipt_is_verdict_of_hashes {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K}
    {run : Run D K S} (h : verifyRun C other pa pi run = true) {r : Receipt D} (hr : r ∈ run.receipts)
    {image reading : ByteArray} (hi : C.hash image = r.imageSha) (hd : C.hash reading = r.readingSha)
    (hci : NoCollision C run image) (hcd : NoCollision C run reading) :
    r.decision = record (verdictBytes image reading) := by
  obtain ⟨c, hc, rd, hrd, _, himg, hrdh, hdec⟩ := verified_receipt_is_verdict h hr
  rw [hci.1 c hc (hi.trans himg), hcd.2 c hc rd hrd (hd.trans hrdh)]
  exact hdec

/-- **A verified run is complete.** Every reading of every case the run does not exclude has a receipt
naming that case and reading, recording `Core.verdict` on them. -/
theorem verified_run_complete {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K}
    {run : Run D K S} (h : verifyRun C other pa pi run = true) {c : Case} (hc : c ∈ run.cases)
    (hnot : excludedOf run c.id = none) {i : Nat} {rd : ByteArray} (hrd : (i, rd) ∈ indexed c.readings 0) :
    ∃ r ∈ run.receipts, r.case = c.id ∧ r.reading = i ∧ r.decision = record (verdictBytes c.image rd) := by
  obtain ⟨_, _, _, _, hcheck⟩ := verifyRun_parts h
  have he : (c, i, rd) ∈ expected run := by
    simp only [expected, List.mem_flatMap, List.mem_filter, List.mem_map]
    exact ⟨c, ⟨hc, by simp [hnot]⟩, (i, rd), hrd, rfl⟩
  exact checkReceipts_complete hcheck _ he

theorem spellRefusal_code_cause (r : Refusal) : (spellRefusal r).code = r.code ∧ (spellRefusal r).cause = r.cause := by
  cases r with
  | policy e => cases e <;> exact ⟨rfl, rfl⟩
  | readingUnreadable _ => exact ⟨rfl, rfl⟩
  | readingNotObject => exact ⟨rfl, rfl⟩
  | contract _ _ => exact ⟨rfl, rfl⟩
  | noMatch => exact ⟨rfl, rfl⟩

/-- **A recorded refusal is the verdict's, with a registered code.** A verified receipt that records a
refusal records the code and the cause of the refusal `Core.verdict` computes, a nonzero row of the cause
registry. -/
theorem verified_refusal_registered {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K}
    {run : Run D K S} (h : verifyRun C other pa pi run = true) {r : Receipt D} (hr : r ∈ run.receipts)
    {code : Nat} {cause : String} {field reason : Option String} (hd : r.decision = .refuse code cause field reason) :
    ∃ c ∈ run.cases, ∃ rd ∈ c.readings, ∃ x, verdictBytes c.image rd = .refuse x ∧ code = x.code ∧ cause = x.cause ∧
      code ≠ 0 ∧ (code, cause) ∈ causeRegistry := by
  obtain ⟨c, hc, rd, hrd, _, _, _, hdec⟩ := verified_receipt_is_verdict h hr
  rw [hd] at hdec
  cases hv : verdictBytes c.image rd with
  | route t => rw [hv] at hdec; simp [record] at hdec
  | refuse x =>
    rw [hv] at hdec
    simp only [record, Decision.refuse.injEq] at hdec
    obtain ⟨hcode, hcause, _, _⟩ := hdec
    obtain ⟨sc, sn⟩ := spellRefusal_code_cause x
    refine ⟨c, hc, rd, hrd, x, hv, hcode.trans sc, hcause.trans sn, ?_, ?_⟩
    · rw [hcode.trans sc]; exact refusal_code_ne_zero x
    · rw [hcode.trans sc, hcause.trans sn]; exact refusal_registered x

/-- **An engine counter exclusion is the oracle's.** A case a verified run excludes as `engine-counter` is
one whose image the oracle refuses with `policy:engine-counter` on every reading. -/
theorem verified_excluded_counter {C : Crypto D K S} {other : Case → Option FlowReason} {pa pi : K}
    {run : Run D K S} (h : verifyRun C other pa pi run = true) {c : Case} (hc : c ∈ run.cases)
    (hx : excludedOf run c.id = some .engineCounter) (reading : ByteArray) :
    ∃ f, verdictBytes c.image reading = .refuse (.policy (.engineCounter f)) := by
  obtain ⟨_, _, _, hwhy, _⟩ := verifyRun_parts h
  have hw := (hwhy c hc).symm.trans hx
  unfold why at hw
  split at hw
  · rename_i hcr; exact counter_excluded_refused hcr reading
  · cases ho : other c <;> simp [ho] at hw

/-- A list of receipts collides with the run's in neither the Merkle tree nor a leaf: if it has the run's
root its leaves are the run's leaves, and each of its receipts with the leaf of a receipt of the run is that
receipt (collision resistance of SHA-256 in the tree and over the canon/2 writer, which writes distinct
receipts as distinct bytes), stated for the list at hand: it fails only on an exhibited collision. -/
def NoTreeCollision (C : Crypto D K S) (run : Run D K S) (rs : List (Receipt D)) : Prop :=
  (C.merkle (rs.map (leaf C)) = C.merkle (run.receipts.map (leaf C)) → rs.map (leaf C) = run.receipts.map (leaf C)) ∧
    ∀ r ∈ rs, ∀ r' ∈ run.receipts, leaf C r = leaf C r' → r = r'

/-- Unforgeability of the instance key's signatures (Ed25519), as a hypothesis: a signature that verifies
under the key was made by its holder. -/
def Unforgeable (C : Crypto D K S) (signedBy : K → ByteArray → Prop) (key : K) : Prop :=
  ∀ m s, C.verify key m s = true → signedBy key m

omit [DecidableEq D] [DecidableEq K] in
theorem map_eq_of_binding {C : Crypto D K S} :
    ∀ {rs ts : List (Receipt D)}, (∀ r ∈ rs, ∀ r' ∈ ts, leaf C r = leaf C r' → r = r') →
      rs.map (leaf C) = ts.map (leaf C) → rs = ts
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp at h
  | _ :: _, [], _, h => by simp at h
  | r :: rs, t :: ts, hb, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [hb r (List.mem_cons_self ..) t (List.mem_cons_self ..) h.1,
      map_eq_of_binding (fun a ha b hb' hab => hb a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb') hab) h.2]

/-- **Evidence is sound.** A run the verifier accepts with every receipt replayed and both keys pinned
shows: if the pinned instance key's signatures are unforgeable, its holder signed the root statement; any
list of as many receipts as the statement counts, under its Merkle root, that collides with the run's in no
hash, is exactly the run's receipts; and every receipt records `Core.verdict` on every image and reading
with the hashes it carries that collide with no document of the run. -/
theorem evidence_sound {C : Crypto D K S} {signedBy : K → ByteArray → Prop} {other : Case → Option FlowReason}
    {pa pi : K} {run : Run D K S} (h : verifyRun C other pa pi run = true) :
    (Unforgeable C signedBy pi → signedBy pi (C.rootMessage run.root run.leaves run.manifestSha)) ∧
      (∀ rs : List (Receipt D), rs.length = run.leaves → C.merkle (rs.map (leaf C)) = run.root →
        NoTreeCollision C run rs → rs = run.receipts) ∧
      (∀ r ∈ run.receipts, ∀ image reading : ByteArray, C.hash image = r.imageSha → C.hash reading = r.readingSha →
        NoCollision C run image → NoCollision C run reading → r.decision = record (verdictBytes image reading)) := by
  obtain ⟨hpin, hsig, hroot, _, _⟩ := verifyRun_parts h
  refine ⟨fun hu => hu _ _ (hpin ▸ hsig), ?_, ?_⟩
  · intro rs _ hrs hnc
    exact map_eq_of_binding hnc.2 (hnc.1 (hrs.trans hroot))
  · intro r hr image reading hi hd hci hcd
    exact receipt_is_verdict_of_hashes h hr hi hd hci hcd

end Evidence

end Core
