-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Policy
import Core.Causes
import Core.Canon2
/-!
# The verified core: the canonical boundary, evaluation, and the verdict

A reading is a canon/2 object. The boundary checks every defined field, in code point order of the
names, against its definition (`field_definitions.accept_canonical`); the first failure refuses the
reading with `route:contract-violation`. A canonical reading is then routed by the first rule whose
condition holds; when none holds the reading is refused with `route:no-matching-edge`. A policy that
failed its checks refuses every reading with its own cause. There is no other outcome: `Verdict` has
two constructors, and only the last stage can produce `route`.
-/

namespace Core

/-- A present canonical value. -/
inductive V where
  | int (n : Int)
  | bool (b : Bool)
  | str (s : String)
  deriving DecidableEq, Repr, Inhabited

/-- Why the boundary refuses a value (the reference's refusal reasons that a canon/2 reading can
reach: a fractional or binary float never arrives, since canon/2 has no float). -/
inductive BoundaryErr where
  | missing
  | wrongType
  | outOfRange
  deriving DecidableEq, Repr, Inhabited

def BoundaryErr.name : BoundaryErr → String
  | .missing => "missing" | .wrongType => "wrong_type" | .outOfRange => "out_of_range"

inductive Refusal where
  | policy (e : PolicyErr)
  | readingUnreadable (e : DocErr)
  | readingNotObject
  | contract (field : String) (reason : BoundaryErr)
  | noMatch
  deriving DecidableEq, Repr, Inhabited

/-! ## Registered causes

Every refusal is spelled as a row of the cause registry (`prismpath/kernel/causes.py`, generated into
`Core/Causes.lean`): its canonical name and its code. The pairs are written here once; the theorem
`refusal_registered` proves each is a registry row, so a refusal with no code, or with a code the
registry gives another name, does not type check as a theorem. -/

def PolicyErr.cause : PolicyErr → String
  | .unreadable .notCanonical => "policy:not-canonical"
  | .unreadable _ => "policy:unreadable"
  | .shape _ => "policy:shape"
  | .unknownOp _ => "image:unknown-op"
  | .unknownType _ => "image:unknown-type"
  | .notLevelM _ => "policy:not-level-m"
  | .definition _ _ => "policy:definition"
  | .undefinedField _ => "image:field-index-oob"
  | .engineCounter _ => "policy:engine-counter"
  | .kindMismatch _ => "policy:kind-mismatch"
  | .rounding _ => "policy:rounding"
  | .threshold _ _ => "policy:threshold"
  | .noneMisuse _ _ => "policy:none"
  | .absenceUntested _ => "policy:absence-untested"

def PolicyErr.code : PolicyErr → Nat
  | .unreadable .notCanonical => 101
  | .unreadable _ => 89
  | .shape _ => 90
  | .unknownOp _ => 74
  | .unknownType _ => 75
  | .notLevelM _ => 91
  | .definition _ _ => 92
  | .undefinedField _ => 76
  | .engineCounter _ => 93
  | .kindMismatch _ => 94
  | .rounding _ => 95
  | .threshold _ _ => 96
  | .noneMisuse _ _ => 97
  | .absenceUntested _ => 98

def Refusal.cause : Refusal → String
  | .policy e => e.cause
  | .readingUnreadable .notCanonical => "reading:not-canonical"
  | .readingUnreadable _ => "reading:unreadable"
  | .readingNotObject => "reading:not-object"
  | .contract _ _ => "route:contract-violation"
  | .noMatch => "route:no-matching-edge"

def Refusal.code : Refusal → Nat
  | .policy e => e.code
  | .readingUnreadable .notCanonical => 102
  | .readingUnreadable _ => 99
  | .readingNotObject => 100
  | .contract _ _ => 37
  | .noMatch => 32

inductive Verdict where
  | route (target : String)
  | refuse (r : Refusal)
  deriving DecidableEq, Repr, Inhabited

/-! ## The boundary -/

/-- `accept_canonical`: `none` is the absent value, accepted when the definition allows absence. -/
def acceptField (d : FieldDef) : Option J → Except BoundaryErr (Option V)
  | none | some .null => if d.absentOK then .ok none else .error .missing
  | some v =>
    match d.kind, v with
    | .bool, .bool b => .ok (some (.bool b))
    | .category, .str s => .ok (some (.str s))
    | .int, .int n | .fixed, .int n => if n < d.lo || n > d.hi then .error .outOfRange else .ok (some (.int n))
    | _, _ => .error .wrongType

/-- The first defined field the boundary refuses, in the order of `defs` (code point order). -/
def firstRefused (ms : List (String × J)) : List FieldDef → Option (String × BoundaryErr)
  | [] => none
  | d :: ds =>
    match acceptField d (field? ms d.name) with
    | .error e => some (d.name, e)
    | .ok _ => firstRefused ms ds

/-- The canonical value of a field in a reading that passed the boundary. Undefined names read as
absent; the policy rules guarantee that no condition reads one. -/
def canonicalGet (defs : List FieldDef) (ms : List (String × J)) (f : String) : Option V :=
  match findDef defs f with
  | none => none
  | some d => match acceptField d (field? ms f) with
    | .ok v => v
    | .error _ => none

/-! ## The two checks of a reading

Which fields a reading must hold canonically depends on who is checking (spec section 6.1). The
**system boundary** validates the soundness of the system: every defined field, in code point order;
it is the core's runtime boundary, the one `decideReading` applies. The **policy check** validates the
soundness of a policy: only the defined fields some rule reads (`routed`), as SPEC.md section 4.5 calls
a reading canonical and as the Facet quantizer checks the fields it partitions. `Core/Boundary.lean`
proves how they relate. -/

mutual
/-- The fields a lowered condition reads. -/
def LCond.fields : LCond → List String
  | .always | .never => []
  | .truthy f | .cmp f _ _ | .mem f _ | .nmem f _ => [f]
  | .not c => c.fields
  | .and cs | .or cs => fieldsOf cs
def fieldsOf : List LCond → List String
  | [] => []
  | c :: cs => c.fields ++ fieldsOf cs
end

/-- The fields the rules of a policy read. -/
def rulesFields : List (Rule LCond) → List String
  | [] => []
  | r :: rs => r.cond.fields ++ rulesFields rs

/-- The defined fields the policy routes on, in the order of its definitions (code point order). -/
def Checked.routedDefs (p : Checked) : List FieldDef :=
  p.defs.filter (fun d => (rulesFields p.rules).contains d.name)

/-- The system boundary: the first defined field the reading does not hold canonically. -/
def systemBoundary (p : Checked) (ms : List (String × J)) : Option (String × BoundaryErr) :=
  firstRefused ms p.defs

/-- The policy check: the first routed field the reading does not hold canonically. -/
def policyCheck (p : Checked) (ms : List (String × J)) : Option (String × BoundaryErr) :=
  firstRefused ms p.routedDefs

/-! ## Evaluation -/

def truthyV : V → Bool
  | .int n => n != 0
  | .bool b => b
  | .str s => s != ""

def eqV : V → Lit → Bool
  | .int a, .int b => a == b
  | .bool a, .bool b => a == b
  | .str a, .str b => a == b
  | _, _ => false

/-- One comparison on a value that may be absent (SPEC.md section 4.2 on null): `== None` holds
exactly on absence, `!= c` holds on absence, every other comparison of an absent value fails, and an
ordering is defined on integers only. -/
def cmpV : Option V → Op → Lit → Bool
  | v, .eq, .none => v.isNone
  | v, .ne, .none => v.isSome
  | _, _, .none => false
  | none, op, _ => op == .ne
  | some v, .eq, k => eqV v k
  | some v, .ne, k => !(eqV v k)
  | some (.int a), .lt, .int b => decide (a < b)
  | some (.int a), .le, .int b => decide (a ≤ b)
  | some (.int a), .gt, .int b => decide (a > b)
  | some (.int a), .ge, .int b => decide (a ≥ b)
  | _, _, _ => false

def memV : Option V → List Lit → Bool
  | none, _ => false
  | some v, ks => ks.any (eqV v)

mutual
/-- The truth of a lowered condition. `and` and `or` read every operand, as the reference does. -/
def evalC (get : String → Option V) : LCond → Bool
  | .always => true
  | .never => false
  | .truthy f => match get f with | some v => truthyV v | none => false
  | .cmp f op k => cmpV (get f) op k
  | .mem f ks => memV (get f) ks
  | .nmem f ks => !(memV (get f) ks)
  | .not c => !(evalC get c)
  | .and cs => evalAll get cs
  | .or cs => evalAny get cs
def evalAll (get : String → Option V) : List LCond → Bool
  | [] => true
  | c :: cs => evalC get c && evalAll get cs
def evalAny (get : String → Option V) : List LCond → Bool
  | [] => false
  | c :: cs => evalC get c || evalAny get cs
end

/-- The first rule whose condition holds (SPEC.md section 3 step 1). -/
def firstMatch (get : String → Option V) : List (Rule LCond) → Option String
  | [] => none
  | r :: rs => if evalC get r.cond then some r.target else firstMatch get rs

/-! ## The verdict -/

/-- A reading's verdict under a checked policy. -/
def decideReading (p : Checked) (doc : Except DocErr J) : Verdict :=
  match doc with
  | .error e => .refuse (.readingUnreadable e)
  | .ok (.obj ms) =>
    match firstRefused ms p.defs with
    | some (f, e) => .refuse (.contract f e)
    | none =>
      match firstMatch (canonicalGet p.defs ms) p.rules with
      | some t => .route t
      | none => .refuse .noMatch
  | .ok _ => .refuse .readingNotObject

/-- The core's meaning: an image's text and a reading's text to a verdict. -/
def verdict (image reading : Except DocErr J) : Verdict :=
  match loadPolicy image with
  | .error e => .refuse (.policy e)
  | .ok p => decideReading p reading

/-- The same on bytes, read by the strict reader: an image or a reading that is not the exact canonical
canon/2 spelling of its value is refused (`policy:not-canonical`, `reading:not-canonical`), never read
under another spelling (docs/design/spec-verified-core.md, section 3.2). -/
def verdictBytes (image reading : ByteArray) : Verdict :=
  verdict (readCanonical image) (readCanonical reading)

end Core
