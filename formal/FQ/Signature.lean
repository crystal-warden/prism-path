-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Mathlib.Tactic
import FQ.Syntax
/-!
# Field group signatures: the decision from the groups' signatures (`prismpath/telemetry/spiral_groups.py`)

For a policy whose joint grid is too large to list, the signature tier splits the fields into groups.
A group's signature at a reading is, for each rule in order, the rule's condition with that group's
fields fixed from the reading and every other field left open, cut after the first rule that holds
whatever the other fields are. The receiver rebuilds a reading by taking each group's fields from any
reading with the same signature, and routes it.

This file proves that rebuilding is exact. A signature is modeled by its meaning, the truth function of
the condition over the other fields (`rf`), which is what the reference's canonical residual form
refines: two cells with the same canonical residual have the same truth function. The theorem
`route_eq_of_signatures` says that two readings whose groups have equal signatures route alike, when the
groups are disjoint and cover every field the policy reads. `decision_from_signatures` is the same fact
as a function: the decision is a function of the signatures alone.

Not modeled: the reference's canonical form (flattened and deduplicated `and`/`or` sets), whose
equality implies equal truth functions by the laws of boolean algebra but is not mechanized here.
-/

namespace FQ.Signature

open FQ Classical

/-- The reading that takes the fields of `G` from `r` and every other field from `s`. -/
def merge (G : List String) (r s : Reading) : Reading := fun f => if f ∈ G then r f else s f

/-- The truth function of a condition over the fields outside `G`, with `G`'s fields fixed from `r`. -/
def rf (G : List String) (r : Reading) (c : Cond) : Reading → Bool := fun s => evalCond (merge G r s) c

/-- The signature of a group at a reading: the rules' truth functions in order, cut after the first rule
that holds whatever the other fields are. -/
noncomputable def sig (G : List String) (r : Reading) {α : Type} : Policy α → List (Reading → Bool)
  | [] => []
  | rule :: rs =>
      if ∀ s, rf G r rule.cond s = true then [rf G r rule.cond] else rf G r rule.cond :: sig G r rs

/-- The fields a condition reads. -/
def Cond.reads (f : String) : Cond → Prop
  | .cmp g _ _ => f = g
  | .mem g _ => f = g
  | .nmem g _ => f = g
  | .truthy g => f = g
  | .and a b => Cond.reads f a ∨ Cond.reads f b
  | .or a b => Cond.reads f a ∨ Cond.reads f b
  | .not a => Cond.reads f a
  | .tt => False

/-- The fields a policy reads. -/
def Policy.reads {α : Type} (p : Policy α) (f : String) : Prop := ∃ rule ∈ p, Cond.reads f rule.cond

theorem evalCond_congr {r r' : Reading} : ∀ c : Cond, (∀ f, Cond.reads f c → r f = r' f) →
    evalCond r c = evalCond r' c := by
  intro c
  induction c with
  | cmp g op k => intro h; simp [evalCond, h g rfl]
  | mem g cs => intro h; simp [evalCond, h g rfl]
  | nmem g cs => intro h; simp [evalCond, h g rfl]
  | truthy g => intro h; simp [evalCond, h g rfl]
  | and a b iha ihb =>
    intro h
    simp only [evalCond]
    rw [iha (fun f hf => h f (Or.inl hf)), ihb (fun f hf => h f (Or.inr hf))]
  | or a b iha ihb =>
    intro h
    simp only [evalCond]
    rw [iha (fun f hf => h f (Or.inl hf)), ihb (fun f hf => h f (Or.inr hf))]
  | not a ih => intro h; simp only [evalCond]; rw [ih h]
  | tt => intro _; rfl

theorem route_cons {α : Type} (rule : Rule α) (rs : Policy α) (r : Reading) :
    route (rule :: rs) r = if evalCond r rule.cond = true then some rule.act else route rs r := by
  unfold route
  by_cases h : evalCond r rule.cond = true <;> simp [h]

theorem route_congr {α : Type} : ∀ (p : Policy α) {r r' : Reading},
    (∀ f, Policy.reads p f → r f = r' f) → route p r = route p r' := by
  intro p
  induction p with
  | nil => intro r r' _; simp [route]
  | cons rule rs ih =>
    intro r r' h
    rw [route_cons, route_cons,
      evalCond_congr rule.cond (fun f hf => h f ⟨rule, by simp, hf⟩),
      ih (fun f hf => by obtain ⟨q, hq, hr⟩ := hf; exact h f ⟨q, by simp [hq], hr⟩)]

/-- A signature depends on the reading only through the group's own fields. -/
theorem sig_congr {α : Type} (G : List String) {r r' : Reading} (h : ∀ f ∈ G, r f = r' f) :
    ∀ p : Policy α, sig G r p = sig G r' p := by
  have hm : ∀ s, merge G r s = merge G r' s := by
    intro s; funext f; unfold merge; split_ifs with hf
    · exact h f hf
    · rfl
  intro p
  induction p with
  | nil => rfl
  | cons rule rs ih =>
    have : rf G r rule.cond = rf G r' rule.cond := by funext s; simp [rf, hm]
    simp only [sig, this, ih]

/-- Swapping one group's fields for those of a reading with the same signature, the readings agreeing
elsewhere, does not change the decision. -/
theorem route_eq_of_group {α : Type} (G : List String) (p : Policy α) {r r1 : Reading}
    (hagree : ∀ f, f ∉ G → r f = r1 f) (h : sig G r p = sig G r1 p) : route p r = route p r1 := by
  have hmr : merge G r1 r = r1 := by
    funext f; unfold merge; split_ifs with hf
    · rfl
    · exact hagree f hf
  have hmr' : merge G r r = r := by
    funext f; unfold merge; split_ifs <;> rfl
  induction p with
  | nil => simp [route]
  | cons rule rs ih =>
    by_cases ht : ∀ s, rf G r rule.cond s = true
    · -- the head holds whatever the other fields are, and so it does on the other side
      have hs : sig G r (rule :: rs) = [rf G r rule.cond] := by simp [sig, ht]
      have hhead : rf G r rule.cond = rf G r1 rule.cond := by
        by_cases ht1 : ∀ s, rf G r1 rule.cond s = true
        · have : sig G r1 (rule :: rs) = [rf G r1 rule.cond] := by simp [sig, ht1]
          rw [hs, this] at h; exact (List.cons.inj h).1
        · have : sig G r1 (rule :: rs) = rf G r1 rule.cond :: sig G r1 rs := by simp [sig, ht1]
          rw [hs, this] at h; exact (List.cons.inj h).1
      have hmr1 : merge G r1 r1 = r1 := by
        funext f; unfold merge; split_ifs <;> rfl
      have e1 : evalCond r rule.cond = true := by simpa [rf, hmr'] using ht r
      have e2 : evalCond r1 rule.cond = true := by
        have h3 := ht r1
        rw [hhead] at h3
        simpa [rf, hmr1] using h3
      rw [route_cons, route_cons, if_pos e1, if_pos e2]
    · have hs : sig G r (rule :: rs) = rf G r rule.cond :: sig G r rs := by simp [sig, ht]
      have ht1 : ¬ ∀ s, rf G r1 rule.cond s = true := by
        intro ht1
        have : sig G r1 (rule :: rs) = [rf G r1 rule.cond] := by simp [sig, ht1]
        rw [hs, this] at h
        have hh := (List.cons.inj h).1
        exact ht (fun s => by rw [hh]; exact ht1 s)
      have hs1 : sig G r1 (rule :: rs) = rf G r1 rule.cond :: sig G r1 rs := by simp [sig, ht1]
      rw [hs, hs1] at h
      obtain ⟨hhead, htail⟩ := List.cons.inj h
      have e : evalCond r rule.cond = evalCond r1 rule.cond := by
        have := congrFun hhead r
        simpa only [rf, hmr', hmr] using this
      rw [route_cons, route_cons, e, ih htail]

/-- **The decision from the signatures.** Two readings whose groups have equal signatures route alike,
when the groups are pairwise disjoint and every field the policy reads is in one of them. -/
theorem route_eq_of_signatures {α : Type} (p : Policy α) :
    ∀ (groups : List (List String)) {r r' : Reading},
    groups.Pairwise (fun a b => ∀ f, f ∈ a → f ∉ b) →
    (∀ f, Policy.reads p f → r f = r' f ∨ ∃ G ∈ groups, f ∈ G) →
    (∀ G ∈ groups, sig G r p = sig G r' p) → route p r = route p r' := by
  intro groups
  induction groups with
  | nil =>
    intro r r' _ hcov _
    exact route_congr p (fun f hf => by
      rcases hcov f hf with h | ⟨G, hG, _⟩
      · exact h
      · simp at hG)
  | cons G gs ih =>
    intro r r' hdis hcov hsig
    have hdis' := List.pairwise_cons.mp hdis
    let r1 : Reading := merge G r' r
    have hagree : ∀ f, f ∉ G → r f = r1 f := by
      intro f hf; simp [r1, merge, hf]
    have hG : sig G r p = sig G r1 p := by
      rw [hsig G (by simp)]
      exact sig_congr G (fun f hf => by simp [r1, merge, hf]) p |>.symm
    have step := route_eq_of_group G p hagree hG
    rw [step]
    apply ih hdis'.2
    · intro f hf
      rcases hcov f hf with h | ⟨H, hH, hfH⟩
      · by_cases hfG : f ∈ G
        · left; simp [r1, merge, hfG]
        · left; simp [r1, merge, hfG, h]
      · rcases List.mem_cons.mp hH with rfl | hH'
        · left; simp [r1, merge, hfH]
        · right; exact ⟨H, hH', hfH⟩
    · intro H hH
      have hdisj : ∀ f, f ∈ G → f ∉ H := fun f hf => hdis'.1 H hH f hf
      have e : sig H r1 p = sig H r p :=
        sig_congr H (fun f hf => by
          have : f ∉ G := fun hg => hdisj f hg hf
          simp [r1, merge, this]) p
      rw [e]
      exact hsig H (by simp [hH])

/-- The decision is a function of the signatures alone. -/
theorem decision_from_signatures {α : Type} (p : Policy α) (groups : List (List String))
    (hdis : groups.Pairwise (fun a b => ∀ f, f ∈ a → f ∉ b))
    (hcov : ∀ f, Policy.reads p f → ∃ G ∈ groups, f ∈ G) :
    ∃ D : List (List (Reading → Bool)) → Option α,
      ∀ r, route p r = D (groups.map (fun G => sig G r p)) := by
  refine ⟨fun x => if h : ∃ r, groups.map (fun G => sig G r p) = x
      then route p (Classical.choose h) else none, ?_⟩
  intro r
  have hex : ∃ r', groups.map (fun G => sig G r' p) = groups.map (fun G => sig G r p) := ⟨r, rfl⟩
  simp only [dif_pos hex]
  have hc := Classical.choose_spec hex
  symm
  apply route_eq_of_signatures p groups hdis (fun f hf => Or.inr (hcov f hf))
  intro G hG
  exact List.map_inj_left.mp hc G hG

end FQ.Signature
