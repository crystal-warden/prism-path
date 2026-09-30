-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
/-
  Governance.lean -- the general theory of governed autonomous execution, first machine-checked core.

  This file is deliberately self contained: it imports nothing, not
  mathlib and not the FQ project, so steps 1 through 6 are results of the GENERAL theory, checkable on
  their own. FQ enters only through FQBridge.lean, as one instantiation of an admissible transformation; keeping
  it out here is the point, so the general results never read as a generalization of a PrismPath proof.

  The outcome codomain is a parameter, never hardcoded to Bool. Authority outputs an Outcome carrying a
  "no more permissive than" preorder. The Boolean case appears only inside step 6 as one instance.

  Targets (the formal targets of the paper's section 6):
    1. Authority, state equivalence ~_A, admissible transformation.        [definitions]
    2. ~_A is an equivalence relation.                                      [simA_equiv]
    3. Admissible transformations preserve authorization.                  [admissible_preserves]
    4. Conservative, non-expanding transformation.                         [definition]
    5. Admissibility implies non-expansion.                                [admissible_nonexpanding]
    6. Non-expansion does NOT imply admissibility.                         [nonexp_not_admissible]
-/

namespace Governance

/-- Outcomes carry a "no more permissive than" preorder `⊑`. Not hardcoded to Bool; the Boolean two
    element codomain is one instance (given in step 6). `a ⊑ b` reads: a is no more permissive than b. -/
class Permissive (O : Type) where
  le       : O → O → Prop
  le_refl  : ∀ o, le o o
  le_trans : ∀ {a b c}, le a b → le b c → le a c

infix:50 " ⊑ " => Permissive.le

variable {State Act O : Type}

/-- Step 1. An authority relation: the outcome for a state and a candidate action. -/
abbrev Authority (State Act O : Type) : Type := State → Act → O

/-- Step 1. The state equivalence induced by an authority: two states are ~_A when they authorize every
    action identically. This is the STATE relation; an action relation would be defined separately. -/
def simA (A : Authority State Act O) (s t : State) : Prop := ∀ a, A s a = A t a

/-- A domain is the set of states over which a transformation's claims are made. -/
abbrev Domain (State : Type) : Type := State → Prop

/-- Step 1. `T` is admissible for `A` over `D` when it preserves the committed outcome for every action on
    every state in the domain. This is the constructive admissibility criterion (argument transform form). -/
def Admissible (A : Authority State Act O) (D : Domain State) (T : State → State) : Prop :=
  ∀ s a, D s → A (T s) a = A s a

/-- Step 4. `T` is non-expanding for `A` over `D` when, after transformation, every outcome is no more
    permissive than before. Requires only the preorder, not equality. -/
def NonExpanding [Permissive O] (A : Authority State Act O) (D : Domain State) (T : State → State) : Prop :=
  ∀ s a, D s → A (T s) a ⊑ A s a

/- ---------- Step 2: ~_A is an equivalence relation ---------- -/

theorem simA_refl (A : Authority State Act O) (s : State) : simA A s s :=
  fun _ => rfl

theorem simA_symm (A : Authority State Act O) {s t : State} (h : simA A s t) : simA A t s :=
  fun a => (h a).symm

theorem simA_trans (A : Authority State Act O) {s t u : State}
    (h1 : simA A s t) (h2 : simA A t u) : simA A s u :=
  fun a => (h1 a).trans (h2 a)

/-- Step 2, packaged: ~_A is reflexive, symmetric, and transitive. -/
theorem simA_equiv (A : Authority State Act O) : Equivalence (simA A) :=
  { refl := simA_refl A, symm := simA_symm A, trans := simA_trans A }

/- ---------- Step 3: admissible transformations preserve authorization ---------- -/

/-- Step 3. On its domain, an admissible transformation lands the state back in its own authority
    equivalence class: `s ~_A (T s)`. Authorization is preserved, exactly. -/
theorem admissible_preserves
    (A : Authority State Act O) (D : Domain State) (T : State → State)
    (hadm : Admissible A D T) {s : State} (hs : D s) : simA A s (T s) :=
  fun a => (hadm s a hs).symm

/- ---------- Step 5: admissibility implies non-expansion ---------- -/

/-- Step 5. Exact preservation is stronger than non-expansion: an admissible transformation is
    non-expanding, for any outcome preorder (uses only reflexivity of ⊑). This is the arrow
    `admissible ⟹ non-expanding` in the ordering `exact ⟹ admissible ⟹ non-expanding`. -/
theorem admissible_nonexpanding [Permissive O]
    (A : Authority State Act O) (D : Domain State) (T : State → State)
    (hadm : Admissible A D T) : NonExpanding A D T := by
  intro s a hs
  have h : A (T s) a = A s a := hadm s a hs
  rw [h]
  exact Permissive.le_refl (A s a)

/- ---------- Step 6: non-expansion does NOT imply admissibility ---------- -/

/-- The Boolean outcome instance, appearing only here as one codomain among many. `false` is deny,
    `true` is authorize; `x ⊑ y` is "x is no more permissive than y", i.e. Boolean implication. -/
instance : Permissive Bool where
  le a b := a = true → b = true
  le_refl _ := id
  le_trans hab hbc := fun ha => hbc (hab ha)

/-- Step 6. A concrete witness that non-expansion is strictly weaker than admissibility: an authority,
    a transformation, and a domain where `T` is non-expanding but NOT admissible. `T` collapses every
    state to deny, which can only reduce permissiveness (non-expanding), yet on a state that was
    authorized it changes the outcome (not admissible). This is the permitted asymmetry made concrete:
    autonomy is lost, authority is never expanded. -/
theorem nonexp_not_admissible :
    ∃ (A : Authority Bool Unit Bool) (D : Domain Bool) (T : Bool → Bool),
      NonExpanding A D T ∧ ¬ Admissible A D T := by
  -- state Bool is read directly as the outcome; T sends everything to `false` (deny); domain = all.
  refine ⟨(fun s _ => s), (fun _ => True), (fun _ => false), ?_, ?_⟩
  · -- non-expanding: false ⊑ s for every s, vacuously (the antecedent false = true is impossible)
    intro s a _
    refine fun hfalse => ?_
    simp at hfalse
  · -- not admissible: on s = true, A (T s) () = false ≠ true = A s ()
    intro hadm
    have h : (false : Bool) = true := hadm true () trivial
    simp at h

/- ---------- Composition: the safety properties are closed under chaining ---------- -/

/-- Admissibility composes when the first transform preserves the domain: the composite preserves the
    committed outcome. Relevance analyses can be chained without re-proving the composite exact. -/
theorem admissible_comp
    (A : Authority State Act O) (D : Domain State) (T1 T2 : State → State)
    (hD1 : ∀ s, D s → D (T1 s))
    (h1 : Admissible A D T1) (h2 : Admissible A D T2) :
    Admissible A D (fun s => T2 (T1 s)) := by
  intro s a hs
  have e2 : A (T2 (T1 s)) a = A (T1 s) a := h2 (T1 s) a (hD1 s hs)
  have e1 : A (T1 s) a = A s a := h1 s a hs
  exact e2.trans e1

/-- Non-expansion composes: chaining two non-expanding transformations never expands authority. This is
    why safe relevance analyses can be applied in sequence without a safety review of the composite. Uses
    transitivity of the permissiveness preorder. -/
theorem nonexpanding_comp [Permissive O]
    (A : Authority State Act O) (D : Domain State) (T1 T2 : State → State)
    (hD1 : ∀ s, D s → D (T1 s))
    (h1 : NonExpanding A D T1) (h2 : NonExpanding A D T2) :
    NonExpanding A D (fun s => T2 (T1 s)) := by
  intro s a hs
  have e2 : A (T2 (T1 s)) a ⊑ A (T1 s) a := h2 (T1 s) a (hD1 s hs)
  have e1 : A (T1 s) a ⊑ A s a := h1 s a hs
  exact Permissive.le_trans e2 e1

/- ---------- The relevance layer ---------- -/

/-- A relevance analysis is modeled by the state transformation it induces: it collapses a state to a
    representative it judges decision equivalent, or abstains toward a less permissive outcome. -/
abbrev RelevanceAnalysis (State : Type) : Type := State → State

/-- EXACT relevance: the transform preserves the committed outcome (admissible). It collapsed only
    decision irrelevant distinctions. -/
def Exact (A : Authority State Act O) (D : Domain State) (R : RelevanceAnalysis State) : Prop :=
  Admissible A D R

/-- SAFE relevance: the transform never expands authority. It may abstain (reduce permissiveness) where
    it cannot establish a collapse is decision irrelevant, but never authorizes what was not authorized.
    This is the safety notion the theory requires of an incomplete analysis. -/
def Safe [Permissive O] (A : Authority State Act O) (D : Domain State) (R : RelevanceAnalysis State) : Prop :=
  NonExpanding A D R

/-- Exact relevance is safe. The strength arrow exact implies safe, at the relevance layer. -/
theorem exact_safe [Permissive O]
    (A : Authority State Act O) (D : Domain State) (R : RelevanceAnalysis State)
    (h : Exact A D R) : Safe A D R :=
  admissible_nonexpanding A D R h

/-- The permitted asymmetry as a relevance corollary: a relevance analysis can be safe but not exact,
    losing an authorization (abstaining) without ever creating one. Autonomy may be reduced; authority
    may not be expanded. -/
theorem safe_not_exact :
    ∃ (A : Authority Bool Unit Bool) (D : Domain Bool) (R : RelevanceAnalysis Bool),
      Safe A D R ∧ ¬ Exact A D R :=
  nonexp_not_admissible

/- ---------- The relevance CRITERION: soundness stated independently, safety derived ---------- -/

/-- A relevance criterion is a binary relation on states: `R s t` declares s and t interchangeable for
    governance. A transformation `T` is induced by `R` when it only maps a state to something `R` already
    declares interchangeable with it. Criterion and inducement are defined with no reference to
    admissibility or non-expansion, which is what closes the earlier circularity. -/
def Induces (R : State → State → Prop) (T : State → State) : Prop := ∀ s, R s (T s)

/-- EXACT soundness of a criterion: every declared-interchangeable pair is authority equal on every
    action. Stated on `R` alone. -/
def Sound (A : Authority State Act O) (R : State → State → Prop) : Prop :=
  ∀ s t, R s t → ∀ a, A s a = A t a

/-- Gap-closer. A sound criterion whose induced transform respects it yields an ADMISSIBLE transform, so
    exactness (hence, via `exact_safe`, safety) now FOLLOWS from a criterion stated independently of
    either, rather than `Safe` being defined as non-expansion. -/
theorem sound_induces_admissible
    (A : Authority State Act O) (D : Domain State) (R : State → State → Prop) (T : State → State)
    (hS : Sound A R) (hI : Induces R T) : Admissible A D T := by
  intro s a _
  exact (hS s (T s) (hI s) a).symm

/-- CONSERVATIVE soundness: a declared collapse toward `t` never increases permissiveness. Strictly
    weaker than exact soundness, still stated on `R` alone (not via NonExpanding), and it yields
    non-expansion, not admissibility. This is the tier that may lose autonomy while staying safe. -/
def SoundConservative [Permissive O] (A : Authority State Act O) (R : State → State → Prop) : Prop :=
  ∀ s t, R s t → ∀ a, A t a ⊑ A s a

theorem soundcons_induces_nonexpanding [Permissive O]
    (A : Authority State Act O) (D : Domain State) (R : State → State → Prop) (T : State → State)
    (hS : SoundConservative A R) (hI : Induces R T) : NonExpanding A D T := by
  intro s a _
  exact hS s (T s) (hI s) a

/- ---------- Transitive closure: which criteria are safe to bucket ---------- -/

/-- The transitive closure of a criterion, as an implementation forms buckets by chaining declarations. -/
inductive TC (R : State → State → Prop) : State → State → Prop
  | base {s t}   : R s t → TC R s t
  | step {s t u} : TC R s t → R t u → TC R s u

/-- Exact soundness is preserved by transitive closure: chaining sound declarations stays sound, because
    authority equality is transitive. So bucketing under an EXACT criterion is safe. -/
theorem sound_tc (A : Authority State Act O) (R : State → State → Prop) (h : Sound A R) :
    Sound A (TC R) := by
  intro s t hst
  induction hst with
  | base hR => exact h _ _ hR
  | step _ hR ih => intro a; exact (ih a).trans (h _ _ hR a)

/- ---------- The new condition: a criterion weaker than exact soundness is not safe to bucket ---------- -/

/-- Three states over two actions. State 0 authorizes both; state 1 authorizes the first action only;
    state 2 authorizes neither. States 0 and 1 overlap on the first action, 1 and 2 on the second, 0 and 2
    on nothing. -/
private def exA : Authority (Fin 3) Bool Bool := fun s a =>
  match s.val, a with
  | 0, _     => true
  | 1, false => true
  | 1, true  => false
  | _, _     => false

/-- A relevance criterion declaring 0~1 and 1~2 (and reflexive), but not 0~2. Each declared pair overlaps
    on some action, a plausible but too-weak "similar enough" heuristic. -/
private def exR : Fin 3 → Fin 3 → Prop := fun s t =>
  s = t ∨ (s = 0 ∧ t = 1) ∨ (s = 1 ∧ t = 0) ∨ (s = 1 ∧ t = 2) ∨ (s = 2 ∧ t = 1)

/-- The condition the formalization forces. A relevance criterion that only requires "agree on some
    action" (weaker than exact soundness) is NOT closed under transitive closure: every declared pair
    overlaps on an action, yet chaining merges states 0 and 2, which share no action, so naive bucketing
    collapses a decision relevant distinction. Exact soundness, which IS closure safe (`sound_tc`), is the
    condition that rules this out. This is `R 0 1`, `R 1 2`, `not R 0 2` made concrete. -/
theorem weak_criterion_not_closed :
    (∀ s t, exR s t → ∃ a, exA s a = exA t a)
    ∧ TC exR 0 2
    ∧ ¬ (∀ a, exA 0 a = exA 2 a) := by
  refine ⟨?_, ?_, ?_⟩
  · intro s t h
    cases h with
    | inl he => subst he; exact ⟨false, rfl⟩
    | inr h1 => cases h1 with
      | inl h => cases h with | intro e0 e1 => subst e0; subst e1; exact ⟨false, by decide⟩
      | inr h2 => cases h2 with
        | inl h => cases h with | intro e0 e1 => subst e0; subst e1; exact ⟨false, by decide⟩
        | inr h3 => cases h3 with
          | inl h => cases h with | intro e0 e1 => subst e0; subst e1; exact ⟨true, by decide⟩
          | inr h => cases h with | intro e0 e1 => subst e0; subst e1; exact ⟨true, by decide⟩
  · exact TC.step (TC.base (Or.inr (Or.inl ⟨rfl, rfl⟩)))
                  (Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))))
  · intro h
    exact absurd (h true) (by decide)

/- ---------- The richer outcome codomain, past Bool ---------- -/

/-- The five valued decision codomain PrismPath actually uses. `authorize` lets the action proceed; the
    rest do not, at increasing restrictiveness. The permissiveness order is what matters for safety. -/
inductive Verdict
  | refuse | deny | park | abstain | authorize
deriving DecidableEq

/-- Permissiveness rank: higher is more permissive (closer to letting the action proceed). The only
    safety critical fact is that `authorize` is the unique top; the order among the negatives is a
    modeling choice that does not affect non-expansion of authority. -/
def Verdict.rank : Verdict → Nat
  | .refuse => 0 | .deny => 1 | .park => 2 | .abstain => 3 | .authorize => 4

/-- Verdict as a permissiveness preorder, so the general theorems instantiate on it, not only on Bool. -/
instance : Permissive Verdict where
  le a b := a.rank ≤ b.rank
  le_refl a := Nat.le_refl a.rank
  le_trans hab hbc := Nat.le_trans hab hbc

theorem verdict_authorize_top (o : Verdict) : o ⊑ Verdict.authorize := by
  have h : o.rank ≤ Verdict.authorize.rank := by cases o <;> decide
  exact h

theorem verdict_refuse_bot (o : Verdict) : Verdict.refuse ⊑ o := by
  have h : (0 : Nat) ≤ o.rank := Nat.zero_le _
  exact h

/-- The general safety order catches a rubber stamp on the five valued codomain: mapping a denied state to
    authorize expands authority, so it is not non-expanding. The Verdict order distinguishes this, exactly
    as the Bool order did, which is the point of keeping the codomain a parameter. -/
theorem verdict_rubberstamp_unsafe :
    ∃ (A : Authority Bool Unit Verdict) (D : Domain Bool) (T : Bool → Bool),
      ¬ NonExpanding A D T := by
  refine ⟨(fun s _ => if s then Verdict.authorize else Verdict.deny),
          (fun _ => True), (fun _ => true), ?_⟩
  intro h
  have hle : (4 : Nat) ≤ 1 := h false () trivial
  exact absurd hle (by decide)

/-- And it permits genuine escalation: lowering authorize to park is non-expanding (safe, autonomy
    reduced), the permitted-cost direction, on the same codomain. -/
theorem verdict_escalate_safe (D : Domain Bool) :
    NonExpanding (fun (s : Bool) (_ : Unit) => if s then Verdict.authorize else Verdict.park)
                 D (fun _ => false) := by
  intro s a _
  have h : Verdict.park.rank ≤ (if s then Verdict.authorize else Verdict.park).rank := by
    cases s <;> decide
  exact h

/- ---------- Completeness of a criterion, and false abstention ---------- -/

/-- A floored codomain: a least permissive element the analysis emits when it abstains. -/
class HasFloor (O : Type) [Permissive O] where
  bot : O
  bot_le : ∀ o, bot ⊑ o

instance : HasFloor Verdict where
  bot := Verdict.refuse
  bot_le := verdict_refuse_bot

/-- COMPLETE criterion: it declares interchangeable every pair that actually is authority equal, the
    converse of `Sound`. Completeness is the no-unnecessary-abstention half; soundness is the no-unsafe
    -merge half. -/
def Complete (A : Authority State Act O) (R : State → State → Prop) : Prop :=
  ∀ s t, (∀ a, A s a = A t a) → R s t

/-- A sound and complete criterion is exactly authority equality: it declares interchangeable all and only
    the pairs it may. -/
theorem sound_complete_char
    (A : Authority State Act O) (R : State → State → Prop)
    (hS : Sound A R) (hC : Complete A R) :
    ∀ s t, R s t ↔ (∀ a, A s a = A t a) := by
  intro s t
  exact ⟨fun h => hS s t h, fun h => hC s t h⟩

/-- The verdict an analysis actually emits, `A_R`, against the true authority `A`. SOUND analysis: never
    more permissive than the truth (authority is never expanded). COMPLETE analysis: it commits to the
    true verdict everywhere, never abstaining unnecessarily. -/
def AnalysisSound [Permissive O] (A A_R : Authority State Act O) (D : Domain State) : Prop :=
  ∀ s a, D s → A_R s a ⊑ A s a

def AnalysisComplete (A A_R : Authority State Act O) (D : Domain State) : Prop :=
  ∀ s a, D s → A_R s a = A s a

/-- A FALSE ABSTAIN at (s, a): the analysis emitted the floor where the true authority was not the floor.
    This is autonomy the analysis needlessly gave up, the completeness failure. -/
def FalseAbstain [Permissive O] [HasFloor O]
    (A A_R : Authority State Act O) (s : State) (a : Act) : Prop :=
  A_R s a = HasFloor.bot ∧ A s a ≠ HasFloor.bot

/-- Completeness rules out false abstention: a complete analysis, committing to the truth, never abstains
    where the truth was not itself the floor. -/
theorem complete_no_false_abstain [Permissive O] [HasFloor O]
    (A A_R : Authority State Act O) (D : Domain State)
    (hC : AnalysisComplete A A_R D) {s : State} {a : Act} (hs : D s) :
    ¬ FalseAbstain A A_R s a := by
  intro hfa
  have h : A s a = HasFloor.bot := (hC s a hs).symm.trans hfa.1
  exact hfa.2 h

/-- A sound criterion with a total induced transform yields a COMPLETE analysis, hence no false abstention:
    it always found a safe representative, so it never needed the floor. False abstention is therefore a
    symptom of a criterion too weak to place some state, not of uncertainty as such. -/
theorem sound_induces_complete_analysis
    (A : Authority State Act O) (D : Domain State) (R : State → State → Prop) (T : State → State)
    (hS : Sound A R) (hI : Induces R T) :
    AnalysisComplete A (fun s a => A (T s) a) D := by
  intro s a _
  exact (hS s (T s) (hI s) a).symm

/-- The permitted asymmetry at the analysis level: an analysis can be SOUND (never expands authority) yet
    abstain where the truth was higher, losing autonomy. Soundness alone does not buy completeness. -/
theorem sound_allows_false_abstain :
    ∃ (A A_R : Authority Bool Unit Verdict) (D : Domain Bool),
      AnalysisSound A A_R D ∧ ∃ s a, D s ∧ FalseAbstain A A_R s a := by
  refine ⟨(fun _ _ => Verdict.authorize), (fun _ _ => Verdict.refuse), (fun _ => True), ?_, ?_⟩
  · intro s a _; exact verdict_refuse_bot _
  · exact ⟨true, (), trivial, ⟨rfl, by decide⟩⟩

/- ---------- The quantitative false-abstain rate ---------- -/

/-- The false-abstain COUNT over a finite domain of situations: how many (s, a) the analysis floored while
    the true authority was not the floor. The false-abstain RATE is this count over `dom.length`; the count
    is the numerator and carries all the content, so the results below are stated on it (Nat, no rationals).
    `bot` is the floor the analysis emits when it abstains. -/
def faCount [DecidableEq O] (bot : O) (A A_R : Authority State Act O) :
    List (State × Act) → Nat
  | []      => 0
  | p :: rest =>
      (if A_R p.1 p.2 = bot ∧ A p.1 p.2 ≠ bot then 1 else 0) + faCount bot A A_R rest

/-- The count never exceeds the domain size: the rate is at most one. -/
theorem faCount_le_length [DecidableEq O] (bot : O) (A A_R : Authority State Act O)
    (dom : List (State × Act)) : faCount bot A A_R dom ≤ dom.length := by
  induction dom with
  | nil => simp [faCount]
  | cons p rest ih => simp only [faCount, List.length_cons]; split <;> omega

/-- No false abstention anywhere gives a zero count: the rate is zero. Completeness (the analysis commits to
    the truth) is the special case, since committing to the truth never floors where the truth is not the
    floor. -/
theorem faCount_eq_zero_of_no_false_abstain [DecidableEq O] (bot : O)
    (A A_R : Authority State Act O) (dom : List (State × Act))
    (h : ∀ s a, ¬ (A_R s a = bot ∧ A s a ≠ bot)) : faCount bot A A_R dom = 0 := by
  induction dom with
  | nil => rfl
  | cons p rest ih => simp only [faCount, if_neg (h p.1 p.2), ih]

theorem faCount_eq_zero_of_complete [DecidableEq O] (bot : O)
    (A A_R : Authority State Act O) (dom : List (State × Act))
    (h : ∀ s a, A_R s a = A s a) : faCount bot A A_R dom = 0 :=
  faCount_eq_zero_of_no_false_abstain bot A A_R dom
    (fun s a hc => hc.2 ((h s a).symm.trans hc.1))

/-- Monotonicity, the quantitative content: if every false abstain of the second analysis is also one of the
    first (the second is at least as committal), its count is no larger. Refining a relevance analysis so it
    floors in fewer situations can only lower the false-abstain rate, never raise it. -/
theorem faCount_mono [DecidableEq O] (bot : O)
    (A A_R1 A_R2 : Authority State Act O) (dom : List (State × Act))
    (h : ∀ s a, (A_R2 s a = bot ∧ A s a ≠ bot) → (A_R1 s a = bot ∧ A s a ≠ bot)) :
    faCount bot A A_R2 dom ≤ faCount bot A A_R1 dom := by
  induction dom with
  | nil => simp [faCount]
  | cons p rest ih =>
    simp only [faCount]
    have hstep :
        (if A_R2 p.1 p.2 = bot ∧ A p.1 p.2 ≠ bot then 1 else 0)
          ≤ (if A_R1 p.1 p.2 = bot ∧ A p.1 p.2 ≠ bot then 1 else 0) := by
      split
      · rename_i h2c
        rw [if_pos (h p.1 p.2 h2c)]
        exact Nat.le_refl 1
      · exact Nat.zero_le _
    exact Nat.add_le_add hstep ih

/-- Refinement strictly lowers the rate, concretely: an analysis that floors an authorized situation has
    count one on it; committing to the truth there drops the count to zero. The permitted asymmetry made
    quantitative, over the Verdict codomain. -/
theorem faCount_strictly_decreases :
    ∃ (A A_R1 A_R2 : Authority Bool Unit Verdict) (dom : List (Bool × Unit)),
      faCount Verdict.refuse A A_R2 dom < faCount Verdict.refuse A A_R1 dom := by
  refine ⟨fun _ _ => Verdict.authorize, fun _ _ => Verdict.refuse, fun _ _ => Verdict.authorize,
          [(true, ())], ?_⟩
  decide

/-- The chain, end to end: a SOUND criterion whose induced transform places every state yields an analysis
    with a ZERO false-abstain count on any domain. So the quantitative rate is zero exactly when the
    criterion is strong enough to place every state; a nonzero rate measures the states the criterion could
    not place, not irreducible uncertainty. -/
theorem sound_total_faCount_zero [DecidableEq O] (bot : O)
    (A : Authority State Act O) (R : State → State → Prop) (T : State → State)
    (dom : List (State × Act)) (hS : Sound A R) (hI : Induces R T) :
    faCount bot A (fun s a => A (T s) a) dom = 0 :=
  faCount_eq_zero_of_complete bot A _ dom (fun s a => (hS s (T s) (hI s) a).symm)

end Governance
