-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Lean
/-!
# Grants can only narrow what the signed policy allows

A grant (docs/design/spec-policy-distribution.md, section 13) is an envelope the owner signs. It names route classes
and method classes, the policy it was issued under, and a lifetime. The gateway reads it as one more field of the
request, `grant`, with one of four values (none, valid, invalid, expired), and the signed policy decides what each
value is worth (`prismpath/gateway/grants.py`, `Verifier.read`).

This file models that reading and proves what it can and cannot do, for every policy.

* `read_valid_iff`: a grant reads `valid` exactly when its signatures count, it is not revoked, it names the policy
  the gateway runs, it is in force now, and it covers the request's route class and method class.
* `decision_through_state`: the grant reaches the decision only through those four values. Two grants that read the
  same give the same decision, whatever else their bytes say.
* `grant_only_narrows`: for a policy that never rewards a bad grant over no grant (`GrantMonotone`), a request
  allowed with a grant is allowed without one, or it lies inside the grant's scope and the policy allows it with a
  valid grant. A grant adds at most the part of the policy's own grant rules that the grant covers.
* `attenuate_valid`, `attenuate_allowed`: a grant whose classes and lifetime lie inside another's, for the same
  policy, validates fewer requests, so it opens no more.
* `other_policy_invalid`, `revoked_invalid`, `expired_not_valid`: a grant for another policy, a revoked grant and a
  grant past its end never read `valid`.

The policy is any function from a reading to a verdict, so the theorems hold for the core's evaluator and for any
other. Only the grant field is modelled. The rest of the reading is a parameter the grant cannot change.
-/

namespace Grant

/-- The four values the gateway reads a grant as. -/
inductive State where
  | none | valid | invalid | expired
  deriving DecidableEq, Repr

/-- What the gateway knows of one grant envelope after the distribution verifier has read it. `signed` is V2 to V7 and
V9 of GR2 passing apart from time (the signatures count under the trust store, the target and stream are this
gateway's). `revoked` is GR3. -/
structure Envelope where
  signed : Bool
  revoked : Bool
  seq : Nat
  policy : String
  notBefore : Nat
  expires : Nat
  paths : List String
  methods : List String

/-- The longest lifetime a grant may have, in seconds (`MAX_LIFETIME`). -/
def maxLifetime : Nat := 30 * 24 * 3600

/-- The request as the grant sees it: its route class and method class. -/
structure Request where
  pathClass : String
  methodClass : String

/-- `_covers`: the grant's form, the gateway's policy, in force at `now`, and the request's classes. -/
def covers (g : Envelope) (policy : String) (r : Request) (now : Nat) : Prop :=
  g.seq = 1 ∧ g.notBefore < g.expires ∧ g.expires - g.notBefore ≤ maxLifetime ∧ g.policy = policy ∧
    g.notBefore ≤ now ∧ r.pathClass ∈ g.paths ∧ r.methodClass ∈ g.methods

instance (g : Envelope) (policy : String) (r : Request) (now : Nat) : Decidable (covers g policy r now) := by
  unfold covers; infer_instance

/-- `Verifier.read` for a grant envelope: none without one, invalid when it does not count, valid when it covers
the request now, expired when it is all of that except that its time ended (read just before the end), else
invalid. -/
def read (policy : String) (now : Nat) (header : Option Envelope) (r : Request) : State :=
  match header with
  | Option.none => .none
  | some g =>
    if g.signed = false ∨ g.revoked = true then .invalid
    else if now < g.expires then (if covers g policy r now then .valid else .invalid)
    else if covers g policy r (g.expires - 1) then .expired else .invalid

/-- A reading: the grant field and everything else, which the grant does not touch. -/
structure Reading (α : Type) where
  rest : α
  grant : State

/-- The reading of a request with a grant header: the rest as the request gives it, the grant as `read` gives it. -/
def reading {α : Type} (rest : α) (policy : String) (now : Nat) (header : Option Envelope) (r : Request) :
    Reading α :=
  ⟨rest, read policy now header r⟩

-- The signed policy: any function from a reading to a verdict. `allow` is the verdict that lets the request through.
variable {α V : Type} (P : Reading α → V) (allow : V)

theorem read_valid_iff (policy : String) (now : Nat) (g : Envelope) (r : Request) :
    read policy now (some g) r = .valid ↔
      g.signed = true ∧ g.revoked = false ∧ now < g.expires ∧ covers g policy r now := by
  unfold read
  by_cases hs : g.signed = true <;> by_cases hr : g.revoked = false
  · have hs' : g.signed ≠ false := by simp [hs]
    have hr' : g.revoked ≠ true := by simp [hr]
    simp only [hs', hr', true_and]
    by_cases ht : now < g.expires
    · by_cases hc : covers g policy r now <;> simp [ht, hc]
    · by_cases hc : covers g policy r (g.expires - 1) <;> simp [ht, hc]
  all_goals
    have hb : (g.signed = false ∨ g.revoked = true) := by
      cases h1 : g.signed <;> cases h2 : g.revoked <;> simp_all
    simp [hb]
    intros; simp_all

theorem none_reads_none (policy : String) (now : Nat) (r : Request) : read policy now Option.none r = .none := rfl

/-- The grant reaches the decision only through its state. -/
theorem decision_through_state (rest : α) (policy : String) (now : Nat) (h₁ h₂ : Option Envelope) (r : Request)
    (h : read policy now h₁ r = read policy now h₂ r) :
    P (reading rest policy now h₁ r) = P (reading rest policy now h₂ r) := by
  simp [reading, h]

/-- The grant changes nothing of the reading but the grant field. -/
theorem frame (rest : α) (policy : String) (now : Nat) (h : Option Envelope) (r : Request) :
    (reading rest policy now h r).rest = rest := rfl

/-- A policy that never lets a bad grant through where no grant would not be let through: an `invalid` or `expired`
grant is worth no more than none. The shipped gateway policy refuses `invalid` first and reads `expired` nowhere. -/
def GrantMonotone : Prop :=
  ∀ rest : α, (P ⟨rest, .invalid⟩ = allow → P ⟨rest, .none⟩ = allow) ∧
    (P ⟨rest, .expired⟩ = allow → P ⟨rest, .none⟩ = allow)

/-- **A grant can only narrow what the signed policy allows.** Under a grant monotone policy, a request allowed with
a grant header is allowed with none, or the grant reads `valid` for it and the policy allows it with a valid grant. -/
theorem grant_only_narrows (hm : GrantMonotone P allow) (rest : α) (policy : String) (now : Nat) (g : Envelope)
    (r : Request) (h : P (reading rest policy now (some g) r) = allow) :
    P (reading rest policy now Option.none r) = allow ∨
      (read policy now (some g) r = .valid ∧ P ⟨rest, .valid⟩ = allow) := by
  have hn : reading rest policy now Option.none r = ⟨rest, .none⟩ := rfl
  rw [hn]
  have hr : reading rest policy now (some g) r = ⟨rest, read policy now (some g) r⟩ := rfl
  rw [hr] at h
  cases hst : read policy now (some g) r with
  | none => left; rw [hst] at h; exact h
  | valid => right; rw [hst] at h; exact ⟨rfl, h⟩
  | invalid => left; rw [hst] at h; exact (hm rest).1 h
  | expired => left; rw [hst] at h; exact (hm rest).2 h

/-- The same in terms of the grant itself: what a grant opens beyond no grant is inside its classes and lifetime,
names the gateway's policy, and is allowed by the policy's own rules for a valid grant. -/
theorem grant_adds_only_its_scope (hm : GrantMonotone P allow) (rest : α) (policy : String) (now : Nat) (g : Envelope)
    (r : Request) (h : P (reading rest policy now (some g) r) = allow)
    (hno : P (reading rest policy now Option.none r) ≠ allow) :
    r.pathClass ∈ g.paths ∧ r.methodClass ∈ g.methods ∧ g.policy = policy ∧ g.notBefore ≤ now ∧ now < g.expires ∧
      P ⟨rest, .valid⟩ = allow := by
  rcases grant_only_narrows P allow hm rest policy now g r h with h' | ⟨hv, hp⟩
  · exact absurd h' hno
  · obtain ⟨_, _, ht, ⟨_, _, _, hpol, hnb, hpc, hmc⟩⟩ := (read_valid_iff policy now g r).1 hv
    exact ⟨hpc, hmc, hpol, hnb, ht, hp⟩

/-- `g'` lies inside `g`: the same signed standing and policy, classes that are a subset, and a lifetime inside one
that is itself no longer than `maxLifetime` (as every grant `issue` seals). -/
def Within (g' g : Envelope) : Prop :=
  g'.signed = g.signed ∧ g'.revoked = g.revoked ∧ g'.seq = g.seq ∧ g'.policy = g.policy ∧
    g.notBefore ≤ g'.notBefore ∧ g'.expires ≤ g.expires ∧ g.expires - g.notBefore ≤ maxLifetime ∧
    (∀ p, p ∈ g'.paths → p ∈ g.paths) ∧ (∀ m, m ∈ g'.methods → m ∈ g.methods)

/-- **Attenuation.** A grant inside another validates no request the other does not. -/
theorem attenuate_valid (policy : String) (now : Nat) (g' g : Envelope) (r : Request) (hw : Within g' g)
    (h : read policy now (some g') r = .valid) : read policy now (some g) r = .valid := by
  obtain ⟨hs, hr, ht, ⟨hseq, hlt, _, hpol, hnb, hp, hmth⟩⟩ := (read_valid_iff policy now g' r).1 h
  obtain ⟨ws, wr, wseq, wpol, wnb, wexp, wlife, wp, wm⟩ := hw
  refine (read_valid_iff policy now g r).2 ⟨ws ▸ hs, wr ▸ hr, Nat.lt_of_lt_of_le ht wexp, ?_⟩
  exact ⟨wseq ▸ hseq, by omega, wlife, wpol ▸ hpol, by omega, wp _ hp, wm _ hmth⟩

/-- **Attenuation, decided.** Under a grant monotone policy, what the inner grant opens beyond no grant the outer
grant opens too. -/
theorem attenuate_allowed (hm : GrantMonotone P allow) (rest : α) (policy : String) (now : Nat) (g' g : Envelope)
    (r : Request) (hw : Within g' g) (h : P (reading rest policy now (some g') r) = allow) :
    P (reading rest policy now Option.none r) = allow ∨ P (reading rest policy now (some g) r) = allow := by
  rcases grant_only_narrows P allow hm rest policy now g' r h with h' | ⟨hv, hp⟩
  · exact Or.inl h'
  · right
    have hg : read policy now (some g) r = .valid := attenuate_valid policy now g' g r hw hv
    have hr : reading rest policy now (some g) r = ⟨rest, read policy now (some g) r⟩ := rfl
    rw [hr, hg]; exact hp

theorem other_policy_invalid (policy : String) (now : Nat) (g : Envelope) (r : Request) (h : g.policy ≠ policy) :
    read policy now (some g) r ≠ .valid := by
  intro hv; exact h ((read_valid_iff policy now g r).1 hv).2.2.2.2.2.2.1

theorem revoked_invalid (policy : String) (now : Nat) (g : Envelope) (r : Request) (h : g.revoked = true) :
    read policy now (some g) r = .invalid := by
  simp [read, h]

theorem expired_not_valid (policy : String) (now : Nat) (g : Envelope) (r : Request) (h : g.expires ≤ now) :
    read policy now (some g) r ≠ .valid := by
  intro hv; have := ((read_valid_iff policy now g r).1 hv).2.2.1; omega

theorem not_yet_not_valid (policy : String) (now : Nat) (g : Envelope) (r : Request) (h : now < g.notBefore) :
    read policy now (some g) r ≠ .valid := by
  intro hv; have := ((read_valid_iff policy now g r).1 hv).2.2.2.2.2.2.2.1; omega

theorem uncovered_not_valid (policy : String) (now : Nat) (g : Envelope) (r : Request)
    (h : r.pathClass ∉ g.paths ∨ r.methodClass ∉ g.methods) : read policy now (some g) r ≠ .valid := by
  intro hv
  obtain ⟨_, _, _, ⟨_, _, _, _, _, hp, hm⟩⟩ := (read_valid_iff policy now g r).1 hv
  rcases h with h | h
  · exact h hp
  · exact h hm

end Grant

/-! ## The axiom audit

Each theorem above depends on Lean's three standard axioms at most, so an unfinished proof (`sorryAx`) cannot build. -/

open Lean Elab Command in
elab "#assert_grant_axioms " id:ident : command => do
  let n ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo id
  let axs ← liftCoreM <| Lean.collectAxioms n
  unless axs.all (fun a => a == ``propext || a == ``Classical.choice || a == ``Quot.sound) do
    throwError "{n} depends on axioms beyond the standard three: {axs}"

#assert_grant_axioms Grant.read_valid_iff
#assert_grant_axioms Grant.decision_through_state
#assert_grant_axioms Grant.frame
#assert_grant_axioms Grant.grant_only_narrows
#assert_grant_axioms Grant.grant_adds_only_its_scope
#assert_grant_axioms Grant.attenuate_valid
#assert_grant_axioms Grant.attenuate_allowed
#assert_grant_axioms Grant.other_policy_invalid
#assert_grant_axioms Grant.revoked_invalid
#assert_grant_axioms Grant.expired_not_valid
#assert_grant_axioms Grant.not_yet_not_valid
#assert_grant_axioms Grant.uncovered_not_valid
