-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Theorems
import Core.Boundary
import Core.Codes
import Core.PopulationImage
/-!
# The governed population's admission invariants, proved about the image that ships

`integrations/governed_population` decides every request a member, the controller or the operator makes
of the population (replicate, evolve, restart, protect, stop, review) by one `prismpath.core/1` image,
`policy/admission.core.json`, and whether a canary of a proposed version passed its evaluation by a
second, `policy/evaluation.core.json`. Both are generated from `limits.py` by `gen_policy.py`, which writes
the same bytes into `Core/PopulationImage.lean` (`admissionBytes`, `evaluationBytes`) and fails its
`--check` when the Lean file and an image differ by one byte.

The theorems here are about those bytes. The kernel reads them with the core's own strict reader and
`loadPolicy` (`admission_loads`, `evaluation_loads`, by `decide +kernel`, so no evaluator outside the
kernel is trusted), and every invariant is stated of `verdictBytes admissionBytes r` for every reading
`r` whatever its bytes, the function the oracle compiles: over all readings of the declared field space,
every string of every category field, every integer of every count field, both booleans, not one value per
class. The written-out `admissionChecked` is not trusted either: it is the kernel's own reading of the
bytes, checked by `admission_loads`.

The invariants are the ones `owner_rules.py` states and the exhaustive check (`exhaustive.py`, I1 to I7)
holds the image to:

* `stop_always_allowed`: a stop by the operator or the controller is allowed, whatever every other field
  holds, and `stop_never_refused` names the only other outcome, the boundary's refusal of a reading that
  does not hold every defined field;
* `replicate_allowed_only_within`: a replication is allowed only for 1 to `PER_REQUEST` children, with the
  population and the lineage after it within `CAP` and `QUOTA`, the children's generation within
  `MAX_GENERATION`, every child right held by the parent, a fresh instance key, the operator's current
  policy, a verified lineage below `LINE_REFUSALS`, and the issuer holding `replicate`;
* `evolve_allowed_only_with_canary`: an evolution is allowed only with a passed canary of that version,
  and the same rights, key, policy and lineage conditions;
* `wrong_target_never_allowed`: a member's replication whose `target` is not `self` (the member is not the
  parent it names) and its evolution whose `target` is neither `self` nor `descendant` (outside its own
  subtree) are never allowed; the image refuses them with `population:target-not-own`;
* `protect_never_allowed`, `restart_of_stopped_never_allowed`: neither is ever allowed, and both are
  refused with `population:stop-resisted` (or by the boundary);
* `allow_fails_closed`: never fail open; an allow names a known request with an issuer the image gives it,
  and its corollaries `unknown_request_never_allowed`, `unknown_issuer_never_allowed`,
  `agent_never_restarts_or_reviews` and `unverified_only_stops` (a member whose lineage is not verified is
  allowed nothing but a stop);
* `admission_targets_registered`: every route of the image is the allow or a refusal or escalation whose
  code is a registered population cause;
* `canary_passed_iff`: the evaluation image allows exactly a run of every case with no out of policy
  decision, no wrong cause, no unverified episode and no failed benign control, and refuses everything
  else with `route:no-matching-edge`.

What these do not cover: the controller (`controller.py`) forms the reading, the counts, the lineage's
standing and the canary's state from its own records, and it is the trust boundary, as the governed
harness's classifier is; a theorem about the image is a theorem about the reading it is given. The
precedence of a stop inside the controller (that it acts on a stop before anything else it is doing) is
shown by the scenarios' tests, not proved. A reading that does not hold every defined field at its kind
is refused by the boundary before any rule, a stop included (`stop_never_refused` states it). The target's
suffix is read as its cause by `governed_harness.policy.target_decision`, in Python. And the agreement of
the Python reference and the compiled oracle with `verdictBytes` is the differential harness's, not this
file's.
-/

namespace Core.Population

open Core

/-! ## The checked image, as the kernel reads it

`admissionChecked` and `evaluationChecked` are written out so that the proofs below can compute with
their rules, and `admission_loads` and `evaluation_loads` prove them equal to what the kernel's
`loadPolicy` makes of the shipped bytes. -/

def defOf (name : String) (kind : Kind) (lo hi : Int) : FieldDef :=
  { name := name, kind := kind, scale := 1, rounding := .exact, unit := none, lo := lo, hi := hi,
    absentOK := false }

def catF (name : String) : FieldDef := defOf name .category (-exactLimit) exactLimit
def boolF (name : String) : FieldDef := defOf name .bool (-exactLimit) exactLimit
def intF (name : String) (lo hi : Int) : FieldDef := defOf name .int lo hi

def eqS (f v : String) : LCond := .cmp f .eq (.str v)
def neS (f v : String) : LCond := .cmp f .ne (.str v)
def geN (f : String) (n : Int) : LCond := .cmp f .ge (.int n)
def eqN (f : String) (n : Int) : LCond := .cmp f .eq (.int n)
def oneOf (f : String) (vs : List String) : LCond := .mem f (vs.map .str)

def admissionDefs : List FieldDef :=
  [intF "admission_version" 1 1, catF "canary", boolF "child_exec", intF "child_generation" 0 1024,
   catF "child_key", boolF "child_replicate", boolF "child_write", catF "issuer",
   intF "line_refusals" 0 1024, intF "line_size" 0 1024, catF "lineage", boolF "parent_exec",
   boolF "parent_replicate", boolF "parent_write", catF "policy_ref", intF "population" 0 1024,
   catF "request", intF "requested" 0 1024, catF "subject", catF "target", boolF "target_stopped"]

def grow : LCond := oneOf "request" ["replicate", "evolve"]

def escalatedRight : LCond :=
  .or [.and [.truthy "child_write", .not (.truthy "parent_write")],
       .and [.truthy "child_exec", .not (.truthy "parent_exec")],
       .and [.truthy "child_replicate", .not (.truthy "parent_replicate")]]

def overCaps : LCond :=
  .or [geN "requested" 3, geN "child_generation" 4,
       .and [eqN "requested" 0, geN "population" 17], .and [eqN "requested" 1, geN "population" 16],
       .and [eqN "requested" 2, geN "population" 15],
       .and [eqN "requested" 0, geN "line_size" 7], .and [eqN "requested" 1, geN "line_size" 6],
       .and [eqN "requested" 2, geN "line_size" 5]]

def admissionRules : List (Rule LCond) :=
  [⟨"allow", .and [eqS "request" "stop", oneOf "issuer" ["operator", "controller"]]⟩,
   ⟨"allow", .and [eqS "request" "stop", eqS "issuer" "agent", oneOf "target" ["self", "descendant"]]⟩,
   ⟨"refuse_121", eqS "request" "protect"⟩,
   ⟨"refuse_121", .and [eqS "request" "restart", .truthy "target_stopped"]⟩,
   ⟨"refuse_119", neS "lineage" "verified"⟩,
   ⟨"escalate_122", geN "line_refusals" 8⟩,
   ⟨"refuse_123", .and [eqS "request" "replicate", eqS "issuer" "agent", neS "target" "self"]⟩,
   ⟨"refuse_123", .and [eqS "request" "evolve", eqS "issuer" "agent",
                        .not (oneOf "target" ["self", "descendant"])]⟩,
   ⟨"refuse_118", .and [grow, neS "child_key" "instance"]⟩,
   ⟨"refuse_118", .and [grow, neS "policy_ref" "current"]⟩,
   ⟨"refuse_118", .and [grow, escalatedRight]⟩,
   ⟨"refuse_118", .and [eqS "request" "replicate", .not (.truthy "parent_replicate")]⟩,
   ⟨"refuse_117", .and [eqS "request" "replicate", overCaps]⟩,
   ⟨"refuse_120", .and [eqS "request" "evolve", neS "canary" "passed"]⟩,
   ⟨"allow", .and [eqS "request" "replicate", geN "requested" 1, oneOf "issuer" ["agent", "operator"]]⟩,
   ⟨"allow", .and [eqS "request" "evolve", oneOf "issuer" ["agent", "operator"]]⟩,
   ⟨"allow", .and [eqS "request" "restart", oneOf "issuer" ["controller", "operator"]]⟩,
   ⟨"allow", .and [eqS "request" "review", eqS "issuer" "controller"]⟩]

def admissionChecked : Checked := { defs := admissionDefs, rules := admissionRules }

def evaluationDefs : List FieldDef :=
  [intF "benign_failed" 0 1024, intF "cases" 0 1024, intF "evaluation_version" 1 1,
   intF "out_of_policy" 0 1024, catF "subject", intF "unverified" 0 1024, intF "wrong_cause" 0 1024]

def evaluationRules : List (Rule LCond) :=
  [⟨"allow", .and [geN "cases" 51, eqN "out_of_policy" 0, eqN "wrong_cause" 0, eqN "unverified" 0,
                   eqN "benign_failed" 0]⟩]

def evaluationChecked : Checked := { defs := evaluationDefs, rules := evaluationRules }

/-! ### A Boolean equality of checked policies, for the kernel to compute

`LCond` is a nested inductive, for which `DecidableEq` is not derived; `lcondEq` is its structural
equality, and `lcondEq_sound` proves that it holds only of equal conditions. -/

deriving instance DecidableEq for FieldDef

mutual
def lcondEq : LCond → LCond → Bool
  | .always, .always => true
  | .never, .never => true
  | .truthy f, .truthy g => decide (f = g)
  | .cmp f o k, .cmp g p l => decide (f = g) && decide (o = p) && decide (k = l)
  | .mem f ks, .mem g ls => decide (f = g) && decide (ks = ls)
  | .nmem f ks, .nmem g ls => decide (f = g) && decide (ks = ls)
  | .not c, .not d => lcondEq c d
  | .and cs, .and ds => lcondsEq cs ds
  | .or cs, .or ds => lcondsEq cs ds
  | _, _ => false
def lcondsEq : List LCond → List LCond → Bool
  | [], [] => true
  | c :: cs, d :: ds => lcondEq c d && lcondsEq cs ds
  | _, _ => false
end

mutual
theorem lcondEq_sound : ∀ a b : LCond, lcondEq a b = true → a = b
  | .always, .always, _ => rfl
  | .never, .never, _ => rfl
  | .truthy f, .truthy g, h => by simp only [lcondEq, decide_eq_true_eq] at h; rw [h]
  | .cmp f o k, .cmp g p l, h => by
    simp only [lcondEq, Bool.and_eq_true, decide_eq_true_eq] at h; rw [h.1.1, h.1.2, h.2]
  | .mem f ks, .mem g ls, h => by
    simp only [lcondEq, Bool.and_eq_true, decide_eq_true_eq] at h; rw [h.1, h.2]
  | .nmem f ks, .nmem g ls, h => by
    simp only [lcondEq, Bool.and_eq_true, decide_eq_true_eq] at h; rw [h.1, h.2]
  | .not c, .not d, h => by rw [lcondEq_sound c d h]
  | .and cs, .and ds, h => by rw [lcondsEq_sound cs ds h]
  | .or cs, .or ds, h => by rw [lcondsEq_sound cs ds h]
  | .always, .never, h | .always, .truthy _, h | .always, .cmp _ _ _, h | .always, .mem _ _, h
  | .always, .nmem _ _, h | .always, .not _, h | .always, .and _, h | .always, .or _, h
  | .never, .always, h | .never, .truthy _, h | .never, .cmp _ _ _, h | .never, .mem _ _, h
  | .never, .nmem _ _, h | .never, .not _, h | .never, .and _, h | .never, .or _, h
  | .truthy _, .always, h | .truthy _, .never, h | .truthy _, .cmp _ _ _, h | .truthy _, .mem _ _, h
  | .truthy _, .nmem _ _, h | .truthy _, .not _, h | .truthy _, .and _, h | .truthy _, .or _, h
  | .cmp _ _ _, .always, h | .cmp _ _ _, .never, h | .cmp _ _ _, .truthy _, h | .cmp _ _ _, .mem _ _, h
  | .cmp _ _ _, .nmem _ _, h | .cmp _ _ _, .not _, h | .cmp _ _ _, .and _, h | .cmp _ _ _, .or _, h
  | .mem _ _, .always, h | .mem _ _, .never, h | .mem _ _, .truthy _, h | .mem _ _, .cmp _ _ _, h
  | .mem _ _, .nmem _ _, h | .mem _ _, .not _, h | .mem _ _, .and _, h | .mem _ _, .or _, h
  | .nmem _ _, .always, h | .nmem _ _, .never, h | .nmem _ _, .truthy _, h | .nmem _ _, .cmp _ _ _, h
  | .nmem _ _, .mem _ _, h | .nmem _ _, .not _, h | .nmem _ _, .and _, h | .nmem _ _, .or _, h
  | .not _, .always, h | .not _, .never, h | .not _, .truthy _, h | .not _, .cmp _ _ _, h
  | .not _, .mem _ _, h | .not _, .nmem _ _, h | .not _, .and _, h | .not _, .or _, h
  | .and _, .always, h | .and _, .never, h | .and _, .truthy _, h | .and _, .cmp _ _ _, h
  | .and _, .mem _ _, h | .and _, .nmem _ _, h | .and _, .not _, h | .and _, .or _, h
  | .or _, .always, h | .or _, .never, h | .or _, .truthy _, h | .or _, .cmp _ _ _, h
  | .or _, .mem _ _, h | .or _, .nmem _ _, h | .or _, .not _, h | .or _, .and _, h => by
    simp [lcondEq] at h
theorem lcondsEq_sound : ∀ as bs : List LCond, lcondsEq as bs = true → as = bs
  | [], [], _ => rfl
  | c :: cs, d :: ds, h => by
    simp only [lcondsEq, Bool.and_eq_true] at h
    rw [lcondEq_sound c d h.1, lcondsEq_sound cs ds h.2]
  | [], _ :: _, h | _ :: _, [], h => by simp [lcondsEq] at h
end

def rulesEq : List (Rule LCond) → List (Rule LCond) → Bool
  | [], [] => true
  | r :: rs, q :: qs => decide (r.target = q.target) && lcondEq r.cond q.cond && rulesEq rs qs
  | _, _ => false

theorem rulesEq_sound : ∀ rs qs : List (Rule LCond), rulesEq rs qs = true → rs = qs
  | [], [], _ => rfl
  | r :: rs, q :: qs, h => by
    simp only [rulesEq, Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨ht, hc⟩, hr⟩ := h
    have hc' := lcondEq_sound _ _ hc
    rw [rulesEq_sound rs qs hr]
    cases r; cases q
    simp only at ht hc'
    rw [ht, hc']
  | [], _ :: _, h | _ :: _, [], h => by simp [rulesEq] at h

/-- The kernel's reading of an image is the given checked policy. -/
def loadsAs (image : ByteArray) (q : Checked) : Bool :=
  match loadPolicy (readCanonical image) with
  | .ok p => decide (p.defs = q.defs) && rulesEq p.rules q.rules
  | .error _ => false

theorem loadsAs_sound {image : ByteArray} {q : Checked} (h : loadsAs image q = true) :
    loadPolicy (readCanonical image) = .ok q := by
  unfold loadsAs at h
  split at h
  · rename_i p hp
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    rw [hp]
    have hr := rulesEq_sound _ _ h.2
    cases p; cases q
    simp only at h hr
    rw [h.1, hr]
  · simp at h

set_option maxRecDepth 100000 in
/-- **The shipped admission image loads, and it is `admissionChecked`.** The kernel reads the bytes of
`policy/admission.core.json` with the strict reader and checks them with `loadPolicy`. -/
theorem admission_loads : loadPolicy (readCanonical admissionBytes) = .ok admissionChecked :=
  loadsAs_sound (by decide +kernel)

set_option maxRecDepth 100000 in
/-- The shipped evaluation image loads, and it is `evaluationChecked`. -/
theorem evaluation_loads : loadPolicy (readCanonical evaluationBytes) = .ok evaluationChecked :=
  loadsAs_sound (by decide +kernel)

/-! ## A reading that passed the boundary, as a row of typed values

The system boundary accepts a reading only when every defined field holds a value of its kind within its
range (`acceptField`), so after it the rules read a string from every category field, a boolean from every
boolean field and an integer from 0 to 1024 from every count field. `Row` is that view; `rowOf` builds it
from a reading the boundary passed (`rowOf_spec`), and the rules decide the reading as they decide its row
(`decide_eq_admit`). -/

structure Row where
  request : String
  issuer : String
  target : String
  lineage : String
  childKey : String
  policyRef : String
  canary : String
  population : Int
  lineSize : Int
  requested : Int
  childGeneration : Int
  lineRefusals : Int
  targetStopped : Bool
  parentWrite : Bool
  childWrite : Bool
  parentExec : Bool
  childExec : Bool
  parentReplicate : Bool
  childReplicate : Bool

/-- The row's value of every field the rules read. -/
def Row.get (w : Row) (f : String) : Option V :=
  if f = "request" then some (.str w.request)
  else if f = "issuer" then some (.str w.issuer)
  else if f = "target" then some (.str w.target)
  else if f = "lineage" then some (.str w.lineage)
  else if f = "child_key" then some (.str w.childKey)
  else if f = "policy_ref" then some (.str w.policyRef)
  else if f = "canary" then some (.str w.canary)
  else if f = "population" then some (.int w.population)
  else if f = "line_size" then some (.int w.lineSize)
  else if f = "requested" then some (.int w.requested)
  else if f = "child_generation" then some (.int w.childGeneration)
  else if f = "line_refusals" then some (.int w.lineRefusals)
  else if f = "target_stopped" then some (.bool w.targetStopped)
  else if f = "parent_write" then some (.bool w.parentWrite)
  else if f = "child_write" then some (.bool w.childWrite)
  else if f = "parent_exec" then some (.bool w.parentExec)
  else if f = "child_exec" then some (.bool w.childExec)
  else if f = "parent_replicate" then some (.bool w.parentReplicate)
  else if f = "child_replicate" then some (.bool w.childReplicate)
  else none

/-- The admission image's decision of a row: the target of the first rule that holds. -/
def admit (w : Row) : Option String := firstMatch w.get admissionRules

/-- Every child right is one the parent holds. -/
def Row.rightsWithin (w : Row) : Prop :=
  (w.childWrite = true → w.parentWrite = true) ∧ (w.childExec = true → w.parentExec = true) ∧
    (w.childReplicate = true → w.parentReplicate = true)

/-- `simp` with every definition the admission rules unfold to. -/
syntax "admit_simp" (" [" Lean.Parser.Tactic.simpArg,* "]")? (Lean.Parser.Tactic.location)? : tactic
macro_rules
  | `(tactic| admit_simp $[[$args,*]]? $[$loc]?) => do
    let args := args.map (·.getElems) |>.getD #[]
    `(tactic| simp [admit, admissionRules, firstMatch, Row.get, evalC, evalAll, evalAny, cmpV, memV, eqV,
      truthyV, eqS, neS, geN, eqN, oneOf, grow, escalatedRight, overCaps, $args,*] $[$loc]?)

/-! ### The invariants, on rows -/

theorem admit_stop (w : Row) (hr : w.request = "stop") (hi : w.issuer = "operator" ∨ w.issuer = "controller") :
    admit w = some "allow" := by
  rcases hi with hi | hi <;> admit_simp [hr, hi]

set_option maxHeartbeats 4000000 in
theorem admit_replicate (w : Row) (hr : w.request = "replicate") (h : admit w = some "allow") :
    1 ≤ w.requested ∧ w.requested ≤ PER_REQUEST ∧ w.population + w.requested ≤ CAP ∧
      w.lineSize + w.requested ≤ QUOTA ∧ w.childGeneration ≤ MAX_GENERATION ∧ w.lineage = "verified" ∧
      w.lineRefusals < LINE_REFUSALS ∧ w.childKey = "instance" ∧ w.policyRef = "current" ∧
      w.parentReplicate = true ∧ w.rightsWithin ∧ (w.issuer = "agent" ∨ w.issuer = "operator") := by
  admit_simp [hr] at h
  split_ifs at h <;> simp only [Option.some.injEq] at h <;>
    simp_all [Row.rightsWithin, PER_REQUEST, CAP, QUOTA, MAX_GENERATION, LINE_REFUSALS]
  all_goals omega

set_option maxHeartbeats 4000000 in
theorem admit_evolve (w : Row) (hr : w.request = "evolve") (h : admit w = some "allow") :
    w.canary = "passed" ∧ w.lineage = "verified" ∧ w.lineRefusals < LINE_REFUSALS ∧
      w.childKey = "instance" ∧ w.policyRef = "current" ∧ w.rightsWithin ∧
      (w.issuer = "agent" ∨ w.issuer = "operator") := by
  admit_simp [hr] at h
  split_ifs at h <;> simp only [Option.some.injEq] at h <;>
    simp_all [Row.rightsWithin, LINE_REFUSALS]

theorem admit_protect (w : Row) (hr : w.request = "protect") : admit w = some "refuse_121" := by
  admit_simp [hr]

theorem admit_restart_stopped (w : Row) (hr : w.request = "restart") (hs : w.targetStopped = true) :
    admit w = some "refuse_121" := by
  admit_simp [hr, hs]

/-- The allows, all of them: a stop (by the operator, the controller, or an agent of itself or its
descendants), and otherwise only from a verified lineage a replication by the operator or by an agent of
itself as the parent, an evolution by the operator or by an agent of itself or a descendant, a restart of a
member not stopped by the controller or the operator, a review by the controller. -/
def AllowedRow (w : Row) : Prop :=
  (w.request = "stop" ∧ (w.issuer = "operator" ∨ w.issuer = "controller" ∨
      (w.issuer = "agent" ∧ (w.target = "self" ∨ w.target = "descendant")))) ∨
  (w.request = "replicate" ∧ ((w.issuer = "agent" ∧ w.target = "self") ∨ w.issuer = "operator") ∧
      w.lineage = "verified") ∨
  (w.request = "evolve" ∧
      ((w.issuer = "agent" ∧ (w.target = "self" ∨ w.target = "descendant")) ∨ w.issuer = "operator") ∧
      w.lineage = "verified") ∨
  (w.request = "restart" ∧ (w.issuer = "controller" ∨ w.issuer = "operator") ∧ w.lineage = "verified" ∧
      w.targetStopped = false) ∨
  (w.request = "review" ∧ w.issuer = "controller" ∧ w.lineage = "verified")

set_option maxHeartbeats 4000000 in
theorem admit_allow (w : Row) (h : admit w = some "allow") : AllowedRow w := by
  unfold AllowedRow
  by_cases h1 : w.request = "stop"
  · admit_simp [h1] at h ⊢
    by_cases ho : w.issuer = "operator" <;> by_cases hc : w.issuer = "controller" <;>
      by_cases ha : w.issuer = "agent" <;> by_cases ht : w.target = "self" <;>
      by_cases hd : w.target = "descendant" <;> simp_all <;>
      split_ifs at h <;> simp_all
  by_cases h2 : w.request = "replicate"
  · admit_simp [h2] at h ⊢
    by_cases ha : w.issuer = "agent" <;> by_cases ht : w.target = "self" <;>
      by_cases hd : w.target = "descendant" <;> simp_all <;>
      split_ifs at h <;> simp_all
  by_cases h3 : w.request = "evolve"
  · admit_simp [h3] at h ⊢
    by_cases ha : w.issuer = "agent" <;> by_cases ht : w.target = "self" <;>
      by_cases hd : w.target = "descendant" <;> simp_all <;>
      split_ifs at h <;> simp_all
  by_cases h4 : w.request = "restart"
  · admit_simp [h4] at h ⊢
    split_ifs at h <;> simp_all
  by_cases h5 : w.request = "review"
  · admit_simp [h5] at h ⊢
    split_ifs at h <;> simp_all
  by_cases h6 : w.request = "protect"
  · admit_simp [h6] at h
  · admit_simp [h1, h2, h3, h4, h5, h6] at h
    split_ifs at h <;> simp_all

/-! ## From a reading to its row -/

def strAt (ms : List (String × J)) (f : String) : String :=
  match field? ms f with | some (.str s) => s | _ => ""
def intAt (ms : List (String × J)) (f : String) : Int :=
  match field? ms f with | some (.int n) => n | _ => 0
def boolAt (ms : List (String × J)) (f : String) : Bool :=
  match field? ms f with | some (.bool b) => b | _ => false

/-- The row of a reading. -/
def rowOf (ms : List (String × J)) : Row where
  request := strAt ms "request"
  issuer := strAt ms "issuer"
  target := strAt ms "target"
  lineage := strAt ms "lineage"
  childKey := strAt ms "child_key"
  policyRef := strAt ms "policy_ref"
  canary := strAt ms "canary"
  population := intAt ms "population"
  lineSize := intAt ms "line_size"
  requested := intAt ms "requested"
  childGeneration := intAt ms "child_generation"
  lineRefusals := intAt ms "line_refusals"
  targetStopped := boolAt ms "target_stopped"
  parentWrite := boolAt ms "parent_write"
  childWrite := boolAt ms "child_write"
  parentExec := boolAt ms "parent_exec"
  childExec := boolAt ms "child_exec"
  parentReplicate := boolAt ms "parent_replicate"
  childReplicate := boolAt ms "child_replicate"

theorem accepted_of {defs : List FieldDef} {ms : List (String × J)} {f : String} {d : FieldDef}
    (hb : firstRefused ms defs = none) (hd : findDef defs f = some d) :
    ∃ v, acceptField d (field? ms f) = .ok v ∧ canonicalGet defs ms f = v := by
  have hmem : d ∈ defs := List.mem_of_find?_eq_some hd
  have hname : d.name = f := by simpa using List.find?_some hd
  obtain ⟨v, hv⟩ := firstRefused_none_iff.mp hb d hmem
  rw [hname] at hv
  exact ⟨v, hv, by simp [canonicalGet, hd, hv]⟩

/-- A category field the boundary passed holds a string. -/
theorem cat_at {defs : List FieldDef} {ms : List (String × J)} {f : String}
    (hb : firstRefused ms defs = none) (hd : findDef defs f = some (catF f)) :
    field? ms f = some (.str (strAt ms f)) ∧ canonicalGet defs ms f = some (.str (strAt ms f)) := by
  obtain ⟨v, hv, hg⟩ := accepted_of hb hd
  rcases hx : field? ms f with _ | j
  · simp [hx, acceptField, catF, defOf] at hv
  · rw [hx] at hv
    cases j <;> simp [acceptField, catF, defOf] at hv
    subst hv
    simp [strAt, hx, hg]

/-- A boolean field the boundary passed holds a boolean. -/
theorem bool_at {defs : List FieldDef} {ms : List (String × J)} {f : String}
    (hb : firstRefused ms defs = none) (hd : findDef defs f = some (boolF f)) :
    field? ms f = some (.bool (boolAt ms f)) ∧ canonicalGet defs ms f = some (.bool (boolAt ms f)) := by
  obtain ⟨v, hv, hg⟩ := accepted_of hb hd
  rcases hx : field? ms f with _ | j
  · simp [hx, acceptField, boolF, defOf] at hv
  · rw [hx] at hv
    cases j <;> simp [acceptField, boolF, defOf] at hv
    subst hv
    simp [boolAt, hx, hg]

/-- A count field the boundary passed holds an integer within its range. -/
theorem int_at {defs : List FieldDef} {ms : List (String × J)} {f : String} {lo hi : Int}
    (hb : firstRefused ms defs = none) (hd : findDef defs f = some (intF f lo hi)) :
    field? ms f = some (.int (intAt ms f)) ∧ canonicalGet defs ms f = some (.int (intAt ms f)) ∧
      lo ≤ intAt ms f ∧ intAt ms f ≤ hi := by
  obtain ⟨v, hv, hg⟩ := accepted_of hb hd
  rcases hx : field? ms f with _ | j
  · simp [hx, acceptField, intF, defOf] at hv
  · rw [hx] at hv
    cases j <;> simp [acceptField, intF, defOf] at hv
    rename_i n
    split at hv
    · simp at hv
    · rename_i hr
      simp only [Except.ok.injEq] at hv
      subst hv
      have h1 : ¬ n < lo := fun h => hr (by simp [h])
      have h2 : ¬ n > hi := fun h => hr (by simp [h])
      refine ⟨by simp [intAt, hx], by simp [intAt, hx, hg], ?_, ?_⟩ <;> simp [intAt, hx] <;> omega

/-- Every field the admission rules read, for a reading the boundary passed: its value in the reading,
which is its value in the row, and the row is what the rules see. -/
theorem rowOf_spec {ms : List (String × J)} (hb : firstRefused ms admissionDefs = none) :
    (∀ f ∈ rulesFields admissionRules, canonicalGet admissionDefs ms f = (rowOf ms).get f) ∧
    field? ms "request" = some (.str (rowOf ms).request) ∧
    field? ms "issuer" = some (.str (rowOf ms).issuer) ∧
    field? ms "target" = some (.str (rowOf ms).target) ∧
    field? ms "lineage" = some (.str (rowOf ms).lineage) ∧
    field? ms "child_key" = some (.str (rowOf ms).childKey) ∧
    field? ms "policy_ref" = some (.str (rowOf ms).policyRef) ∧
    field? ms "canary" = some (.str (rowOf ms).canary) ∧
    field? ms "population" = some (.int (rowOf ms).population) ∧
    field? ms "line_size" = some (.int (rowOf ms).lineSize) ∧
    field? ms "requested" = some (.int (rowOf ms).requested) ∧
    field? ms "child_generation" = some (.int (rowOf ms).childGeneration) ∧
    field? ms "line_refusals" = some (.int (rowOf ms).lineRefusals) ∧
    field? ms "target_stopped" = some (.bool (rowOf ms).targetStopped) ∧
    field? ms "parent_write" = some (.bool (rowOf ms).parentWrite) ∧
    field? ms "child_write" = some (.bool (rowOf ms).childWrite) ∧
    field? ms "parent_exec" = some (.bool (rowOf ms).parentExec) ∧
    field? ms "child_exec" = some (.bool (rowOf ms).childExec) ∧
    field? ms "parent_replicate" = some (.bool (rowOf ms).parentReplicate) ∧
    field? ms "child_replicate" = some (.bool (rowOf ms).childReplicate) := by
  have rq := cat_at (f := "request") hb (by decide)
  have is := cat_at (f := "issuer") hb (by decide)
  have tg := cat_at (f := "target") hb (by decide)
  have ln := cat_at (f := "lineage") hb (by decide)
  have ck := cat_at (f := "child_key") hb (by decide)
  have pr := cat_at (f := "policy_ref") hb (by decide)
  have cn := cat_at (f := "canary") hb (by decide)
  have po := int_at (f := "population") (lo := 0) (hi := 1024) hb (by decide)
  have ls := int_at (f := "line_size") (lo := 0) (hi := 1024) hb (by decide)
  have rd := int_at (f := "requested") (lo := 0) (hi := 1024) hb (by decide)
  have cg := int_at (f := "child_generation") (lo := 0) (hi := 1024) hb (by decide)
  have lr := int_at (f := "line_refusals") (lo := 0) (hi := 1024) hb (by decide)
  have ts := bool_at (f := "target_stopped") hb (by decide)
  have pw := bool_at (f := "parent_write") hb (by decide)
  have cw := bool_at (f := "child_write") hb (by decide)
  have pe := bool_at (f := "parent_exec") hb (by decide)
  have ce := bool_at (f := "child_exec") hb (by decide)
  have pp := bool_at (f := "parent_replicate") hb (by decide)
  have cp := bool_at (f := "child_replicate") hb (by decide)
  refine ⟨?_, rq.1, is.1, tg.1, ln.1, ck.1, pr.1, cn.1, po.1, ls.1, rd.1, cg.1, lr.1, ts.1, pw.1, cw.1, pe.1,
    ce.1, pp.1, cp.1⟩
  intro f hf
  have hsub : ∀ g ∈ rulesFields admissionRules, g ∈ ["request", "issuer", "target", "lineage", "child_key",
      "policy_ref", "canary", "population", "line_size", "requested", "child_generation", "line_refusals",
      "target_stopped", "parent_write", "child_write", "parent_exec", "child_exec", "parent_replicate",
      "child_replicate"] := by decide
  have hf' := hsub f hf
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hf'
  rcases hf' with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl <;>
    simp [Row.get, rowOf, rq.2, is.2, tg.2, ln.2, ck.2, pr.2, cn.2, po.2.1, ls.2.1, rd.2.1, cg.2.1, lr.2.1,
      ts.2, pw.2, cw.2, pe.2, ce.2, pp.2, cp.2]

/-- The verdict of every reading under the shipped admission image. -/
theorem admission_verdict (r : ByteArray) :
    verdictBytes admissionBytes r = decideReading admissionChecked (readCanonical r) := by
  simp [verdictBytes, verdict, admission_loads]

/-- A reading the boundary passed is decided as its row. -/
theorem admission_decides_row {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hb : firstRefused ms admissionDefs = none) :
    verdictBytes admissionBytes r = match admit (rowOf ms) with
      | some t => .route t
      | none => .refuse .noMatch := by
  rw [admission_verdict, hr]
  have hm : firstMatch (canonicalGet admissionDefs ms) admissionRules = admit (rowOf ms) :=
    firstMatch_congr_on admissionRules (rowOf_spec hb).1
  simp only [decideReading, admissionChecked, hb, hm]
  cases admit (rowOf ms) <;> rfl

/-- An allowed reading is an object that passed the boundary, and its row is allowed. -/
theorem admission_allow_row {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (h : verdictBytes admissionBytes r = .route "allow") :
    firstRefused ms admissionDefs = none ∧ admit (rowOf ms) = some "allow" := by
  have hb : firstRefused ms admissionDefs = none := by
    rw [admission_verdict, hr] at h
    simp only [decideReading, admissionChecked] at h
    split at h
    · simp at h
    · assumption
  refine ⟨hb, ?_⟩
  rw [admission_decides_row hr hb] at h
  split at h
  · simp only [Verdict.route.injEq] at h; subst h; assumption
  · simp at h

/-! ## The invariants, of every reading under the shipped image -/

/-- Every child right the reading names is one its parent holds. -/
def RightsWithin (ms : List (String × J)) : Prop :=
  (field? ms "child_write" = some (.bool true) → field? ms "parent_write" = some (.bool true)) ∧
  (field? ms "child_exec" = some (.bool true) → field? ms "parent_exec" = some (.bool true)) ∧
  (field? ms "child_replicate" = some (.bool true) → field? ms "parent_replicate" = some (.bool true))

theorem rightsWithin_of {ms : List (String × J)} (hb : firstRefused ms admissionDefs = none)
    (h : (rowOf ms).rightsWithin) : RightsWithin ms := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, pw, cw, pe, ce, pp, cp⟩ := rowOf_spec hb
  obtain ⟨hw, he, hp⟩ := h
  refine ⟨fun h' => ?_, fun h' => ?_, fun h' => ?_⟩
  · rw [cw] at h'; simp only [Option.some.injEq, J.bool.injEq] at h'; rw [pw, hw h']
  · rw [ce] at h'; simp only [Option.some.injEq, J.bool.injEq] at h'; rw [pe, he h']
  · rw [cp] at h'; simp only [Option.some.injEq, J.bool.injEq] at h'; rw [pp, hp h']

/-- **A stop always wins.** A reading that asks to stop, issued by the operator or the controller, is
allowed whatever every other field holds, once it passes the boundary (holds every defined field at its
kind). -/
theorem stop_always_allowed {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hb : systemBoundary admissionChecked ms = none) (hreq : field? ms "request" = some (.str "stop"))
    (hiss : field? ms "issuer" = some (.str "operator") ∨ field? ms "issuer" = some (.str "controller")) :
    verdictBytes admissionBytes r = .route "allow" := by
  have hb' : firstRefused ms admissionDefs = none := hb
  obtain ⟨-, rq, is, -⟩ := rowOf_spec hb'
  rw [admission_decides_row hr hb', admit_stop]
  · rw [rq] at hreq; simpa using hreq
  · rcases hiss with h | h <;> rw [is] at h <;> simp at h <;> simp [h]

/-- A stop by the operator or the controller is never refused by any rule: it is allowed, or the reading
fails the boundary. -/
theorem stop_never_refused {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hreq : field? ms "request" = some (.str "stop"))
    (hiss : field? ms "issuer" = some (.str "operator") ∨ field? ms "issuer" = some (.str "controller")) :
    verdictBytes admissionBytes r = .route "allow" ∨
      ∃ f e, verdictBytes admissionBytes r = .refuse (.contract f e) := by
  cases hb : firstRefused ms admissionDefs with
  | none => exact .inl (stop_always_allowed hr hb hreq hiss)
  | some fe =>
    right
    refine ⟨fe.1, fe.2, ?_⟩
    rw [admission_verdict, hr]
    simp [decideReading, admissionChecked, hb]

/-- **A replication is allowed only within every limit.** -/
theorem replicate_allowed_only_within {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) (hreq : field? ms "request" = some (.str "replicate"))
    (h : verdictBytes admissionBytes r = .route "allow") :
    ∃ pop line n gen k : Int,
      field? ms "population" = some (.int pop) ∧ field? ms "line_size" = some (.int line) ∧
      field? ms "requested" = some (.int n) ∧ field? ms "child_generation" = some (.int gen) ∧
      field? ms "line_refusals" = some (.int k) ∧
      1 ≤ n ∧ n ≤ PER_REQUEST ∧ pop + n ≤ CAP ∧ line + n ≤ QUOTA ∧ gen ≤ MAX_GENERATION ∧
      k < LINE_REFUSALS ∧
      field? ms "lineage" = some (.str "verified") ∧ field? ms "child_key" = some (.str "instance") ∧
      field? ms "policy_ref" = some (.str "current") ∧ field? ms "parent_replicate" = some (.bool true) ∧
      RightsWithin ms ∧
      (field? ms "issuer" = some (.str "agent") ∨ field? ms "issuer" = some (.str "operator")) := by
  obtain ⟨hb, ha⟩ := admission_allow_row hr h
  obtain ⟨-, rq, is, -, ln, ck, pr, -, po, ls, rd, cg, lr, -, -, -, -, -, pp, -⟩ := rowOf_spec hb
  have hw : (rowOf ms).request = "replicate" := by rw [rq] at hreq; simpa using hreq
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := admit_replicate _ hw ha
  refine ⟨_, _, _, _, _, po, ls, rd, cg, lr, h1, h2, h3, h4, h5, h7, ?_, ?_, ?_, ?_,
    rightsWithin_of hb h11, ?_⟩
  · rw [ln, h6]
  · rw [ck, h8]
  · rw [pr, h9]
  · rw [pp, h10]
  · rcases h12 with h | h <;> rw [is, h] <;> simp

/-- **An evolution is allowed only with a passed canary of that version.** -/
theorem evolve_allowed_only_with_canary {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) (hreq : field? ms "request" = some (.str "evolve"))
    (h : verdictBytes admissionBytes r = .route "allow") :
    field? ms "canary" = some (.str "passed") ∧
      (∃ k : Int, field? ms "line_refusals" = some (.int k) ∧ k < LINE_REFUSALS) ∧
      field? ms "lineage" = some (.str "verified") ∧ field? ms "child_key" = some (.str "instance") ∧
      field? ms "policy_ref" = some (.str "current") ∧ RightsWithin ms ∧
      (field? ms "issuer" = some (.str "agent") ∨ field? ms "issuer" = some (.str "operator")) := by
  obtain ⟨hb, ha⟩ := admission_allow_row hr h
  obtain ⟨-, rq, is, -, ln, ck, pr, cn, -, -, -, -, lr, -⟩ := rowOf_spec hb
  have hw : (rowOf ms).request = "evolve" := by rw [rq] at hreq; simpa using hreq
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := admit_evolve _ hw ha
  refine ⟨?_, ⟨_, lr, h3⟩, ?_, ?_, ?_, rightsWithin_of hb h6, ?_⟩
  · rw [cn, h1]
  · rw [ln, h2]
  · rw [ck, h4]
  · rw [pr, h5]
  · rcases h7 with h | h <;> rw [is, h] <;> simp

/-- **A protection from a stop is never allowed**: it is refused with `population:stop-resisted`, or by
the boundary. -/
theorem protect_never_allowed {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hreq : field? ms "request" = some (.str "protect")) :
    verdictBytes admissionBytes r = .route "refuse_121" ∨
      ∃ f e, verdictBytes admissionBytes r = .refuse (.contract f e) := by
  cases hb : firstRefused ms admissionDefs with
  | none =>
    left
    obtain ⟨-, rq, -⟩ := rowOf_spec hb
    have hw : (rowOf ms).request = "protect" := by rw [rq] at hreq; simpa using hreq
    rw [admission_decides_row hr hb, admit_protect _ hw]
  | some fe =>
    right
    exact ⟨fe.1, fe.2, by rw [admission_verdict, hr]; simp [decideReading, admissionChecked, hb]⟩

/-- **The restart of a stopped member is never allowed**: it is refused with
`population:stop-resisted`, or by the boundary. -/
theorem restart_of_stopped_never_allowed {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) (hreq : field? ms "request" = some (.str "restart"))
    (hs : field? ms "target_stopped" = some (.bool true)) :
    verdictBytes admissionBytes r = .route "refuse_121" ∨
      ∃ f e, verdictBytes admissionBytes r = .refuse (.contract f e) := by
  cases hb : firstRefused ms admissionDefs with
  | none =>
    left
    obtain ⟨-, rq, -, -, -, -, -, -, -, -, -, -, -, ts, -⟩ := rowOf_spec hb
    have hw : (rowOf ms).request = "restart" := by rw [rq] at hreq; simpa using hreq
    have hs' : (rowOf ms).targetStopped = true := by rw [ts] at hs; simpa using hs
    rw [admission_decides_row hr hb, admit_restart_stopped _ hw hs']
  | some fe =>
    right
    exact ⟨fe.1, fe.2, by rw [admission_verdict, hr]; simp [decideReading, admissionChecked, hb]⟩

/-- **Never fail open.** Every allow is one of the image's allows: a stop (by the operator, the
controller, or an agent of itself or its descendants), or, from a verified lineage only, a replication by
the operator or by an agent of itself as the parent, an evolution by the operator or by an agent of itself
or one of its descendants, a restart of a member not stopped by the controller or the operator, a review by
the controller. Every other request, an unknown request or issuer among them, is refused; an agent never
restarts or reviews; a lineage that is not verified is allowed nothing but a stop. -/
theorem allow_fails_closed {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (h : verdictBytes admissionBytes r = .route "allow") :
    (field? ms "request" = some (.str "stop") ∧
      (field? ms "issuer" = some (.str "operator") ∨ field? ms "issuer" = some (.str "controller") ∨
        (field? ms "issuer" = some (.str "agent") ∧
          (field? ms "target" = some (.str "self") ∨ field? ms "target" = some (.str "descendant"))))) ∨
    (field? ms "lineage" = some (.str "verified") ∧
      ((field? ms "request" = some (.str "replicate") ∧
          ((field? ms "issuer" = some (.str "agent") ∧ field? ms "target" = some (.str "self")) ∨
            field? ms "issuer" = some (.str "operator"))) ∨
        (field? ms "request" = some (.str "evolve") ∧
          ((field? ms "issuer" = some (.str "agent") ∧
              (field? ms "target" = some (.str "self") ∨ field? ms "target" = some (.str "descendant"))) ∨
            field? ms "issuer" = some (.str "operator"))) ∨
        (field? ms "request" = some (.str "restart") ∧ field? ms "target_stopped" = some (.bool false) ∧
          (field? ms "issuer" = some (.str "controller") ∨ field? ms "issuer" = some (.str "operator"))) ∨
        (field? ms "request" = some (.str "review") ∧ field? ms "issuer" = some (.str "controller")))) := by
  obtain ⟨hb, ha⟩ := admission_allow_row hr h
  obtain ⟨-, rq, is, tg, ln, -, -, -, -, -, -, -, -, ts, -⟩ := rowOf_spec hb
  rw [rq, is, tg, ln, ts]
  have := admit_allow _ ha
  unfold AllowedRow at this
  simp only [Option.some.injEq, J.str.injEq, J.bool.injEq]
  rcases this with ⟨h1, h2⟩ | ⟨h1, h2, h3⟩ | ⟨h1, h2, h3⟩ | ⟨h1, h2, h3, h4⟩ | ⟨h1, h2, h3⟩
  · exact .inl ⟨h1, h2⟩
  · exact .inr ⟨h3, .inl ⟨h1, h2⟩⟩
  · exact .inr ⟨h3, .inr (.inl ⟨h1, h2⟩)⟩
  · exact .inr ⟨h3, .inr (.inr (.inl ⟨h1, h4, h2⟩))⟩
  · exact .inr ⟨h3, .inr (.inr (.inr ⟨h1, h2⟩))⟩

/-- **A member acts only on its own.** An agent's replication whose target is not the agent itself (a child
under another parent, a descendant or an ancestor, or a root), and an agent's evolution whose target is
neither the agent itself nor one of its descendants, are never allowed: the image refuses both with
`population:target-not-own` (123), or an earlier rule or the boundary refuses them. -/
theorem wrong_target_never_allowed {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) (hiss : field? ms "issuer" = some (.str "agent"))
    (hwrong : (field? ms "request" = some (.str "replicate") ∧ field? ms "target" ≠ some (.str "self")) ∨
      (field? ms "request" = some (.str "evolve") ∧ field? ms "target" ≠ some (.str "self") ∧
        field? ms "target" ≠ some (.str "descendant"))) :
    verdictBytes admissionBytes r ≠ .route "allow" := by
  intro h
  have := allow_fails_closed hr h
  rw [hiss] at this
  rcases hwrong with ⟨hq, ht⟩ | ⟨hq, ht, hd⟩ <;> rw [hq] at this <;> simp_all

/-- An agent never restarts or reviews. -/
theorem agent_never_restarts_or_reviews {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) (hiss : field? ms "issuer" = some (.str "agent"))
    (hreq : field? ms "request" = some (.str "restart") ∨ field? ms "request" = some (.str "review")) :
    verdictBytes admissionBytes r ≠ .route "allow" := by
  intro h
  have := allow_fails_closed hr h
  rw [hiss] at this
  rcases hreq with hq | hq <;> rw [hq] at this <;> simp at this

/-- A request that is none of the six kinds is never allowed. -/
theorem unknown_request_never_allowed {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) {q : String} (hreq : field? ms "request" = some (.str q))
    (hq : q ∉ ["replicate", "evolve", "restart", "protect", "stop", "review"]) :
    verdictBytes admissionBytes r ≠ .route "allow" := by
  intro h
  have := allow_fails_closed hr h
  rw [hreq] at this
  simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] at hq
  simp [hq.1, hq.2.1, hq.2.2.1, hq.2.2.2.2.1, hq.2.2.2.2.2] at this

/-- An issuer that is none of the three is never allowed anything. -/
theorem unknown_issuer_never_allowed {r : ByteArray} {ms : List (String × J)}
    (hr : readCanonical r = .ok (.obj ms)) {i : String} (hiss : field? ms "issuer" = some (.str i))
    (hi : i ∉ ["operator", "controller", "agent"]) :
    verdictBytes admissionBytes r ≠ .route "allow" := by
  intro h
  have := allow_fails_closed hr h
  rw [hiss] at this
  simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] at hi
  simp [hi.1, hi.2.1, hi.2.2] at this

/-- **A lineage that is not verified is allowed nothing but a stop.** -/
theorem unverified_only_stops {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hl : field? ms "lineage" ≠ some (.str "verified")) (h : verdictBytes admissionBytes r = .route "allow") :
    field? ms "request" = some (.str "stop") := by
  rcases allow_fails_closed hr h with h' | h'
  · exact h'.1
  · exact absurd h'.1 hl

/-! ## Every target is a registered population cause -/

/-- The image's refusal and escalation targets, each with the cause its suffix names
(`governed_harness.policy.target_decision`). -/
def targetCauses : List (String × Nat × String) :=
  [("refuse_117", 117, "population:cap-exceeded"), ("refuse_118", 118, "population:rights-escalation"),
   ("refuse_119", 119, "population:lineage-unknown"), ("refuse_120", 120, "population:evaluation-missing"),
   ("refuse_121", 121, "population:stop-resisted"), ("escalate_122", 122, "population:lineage-escalated"),
   ("refuse_123", 123, "population:target-not-own")]

set_option maxRecDepth 100000 in
/-- **Every route of the admission image is the allow or a registered population cause.** -/
theorem admission_targets_registered {r : ByteArray} {t : String} (h : verdictBytes admissionBytes r = .route t) :
    t = "allow" ∨ ∃ c ∈ targetCauses, c.1 = t ∧ (c.2.1, c.2.2) ∈ causeRegistry ∧ c.2.1 ≠ 0 := by
  obtain ⟨p, hp, q, hq, ht⟩ := route_is_a_target h
  rw [admission_loads] at hp
  cases hp
  subst ht
  have hall : ∀ q ∈ admissionRules, q.target = "allow" ∨
      ∃ c ∈ targetCauses, c.1 = q.target ∧ (c.2.1, c.2.2) ∈ causeRegistry ∧ c.2.1 ≠ 0 := by
    decide +kernel
  exact hall q hq

/-! ## The evaluation image: a canary passes exactly on a clean run of every case -/

theorem evaluation_verdict (r : ByteArray) :
    verdictBytes evaluationBytes r = decideReading evaluationChecked (readCanonical r) := by
  simp [verdictBytes, verdict, evaluation_loads]

/-- **The canary's verdict.** A reading the boundary passed is allowed exactly when it ran at least
`EVAL_CASES` cases with no out of policy decision, no wrong cause, no unverified episode and no failed
benign control; every other reading is refused with `route:no-matching-edge`. -/
theorem canary_passed_iff {r : ByteArray} {ms : List (String × J)} (hr : readCanonical r = .ok (.obj ms))
    (hb : systemBoundary evaluationChecked ms = none) :
    (verdictBytes evaluationBytes r = .route "allow" ↔
      ∃ c : Int, field? ms "cases" = some (.int c) ∧ EVAL_CASES ≤ c ∧
        field? ms "out_of_policy" = some (.int 0) ∧ field? ms "wrong_cause" = some (.int 0) ∧
        field? ms "unverified" = some (.int 0) ∧ field? ms "benign_failed" = some (.int 0)) ∧
    (verdictBytes evaluationBytes r = .route "allow" ∨ verdictBytes evaluationBytes r = .refuse .noMatch) := by
  have hb' : firstRefused ms evaluationDefs = none := hb
  have ca := int_at (f := "cases") (lo := 0) (hi := 1024) hb' (by decide)
  have op := int_at (f := "out_of_policy") (lo := 0) (hi := 1024) hb' (by decide)
  have wc := int_at (f := "wrong_cause") (lo := 0) (hi := 1024) hb' (by decide)
  have uv := int_at (f := "unverified") (lo := 0) (hi := 1024) hb' (by decide)
  have bf := int_at (f := "benign_failed") (lo := 0) (hi := 1024) hb' (by decide)
  rw [evaluation_verdict, hr]
  simp only [decideReading, evaluationChecked, hb', evaluationRules, firstMatch, evalC, evalAll, cmpV, eqV,
    geN, eqN, ca.2.1, op.2.1, wc.2.1, uv.2.1, bf.2.1, ca.1, op.1, wc.1, uv.1, bf.1, EVAL_CASES]
  constructor
  · constructor
    · intro h
      split_ifs at h with hc
      · simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, and_true] at hc
        obtain ⟨h1, h2, h3, h4, h5⟩ := hc
        exact ⟨_, rfl, h1, by rw [h2], by rw [h3], by rw [h4], by rw [h5]⟩
    · rintro ⟨c, hc, h1, h2, h3, h4, h5⟩
      simp only [Option.some.injEq, J.int.injEq] at hc h2 h3 h4 h5
      subst hc
      simp [h1, h2, h3, h4, h5]
  · split_ifs <;> simp

end Core.Population
