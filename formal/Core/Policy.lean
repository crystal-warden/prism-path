-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Json
/-!
# The verified core: a policy image and its checks

The abstract syntax of a Level M policy with field definitions (docs/design/spec-verified-core.md,
section 2), its decoding from a canon/2 document, the field definition grammar, exact decimal
thresholds and their lowering, and the policy rules of SPEC.md section 4.5. The result of a successful
check is a `Checked` policy: definitions plus ordered rules whose conditions hold only canonical
literals. Every failure is one `PolicyErr`, the first met in the order the spec fixes.

Everything is structural recursion over the syntax or over lists; nothing is `partial` and nothing
computes through `Classical`.
-/

namespace Core

/-! ## Abstract syntax -/

inductive Op where
  | lt | le | gt | ge | eq | ne
  deriving DecidableEq, Repr, Inhabited

def Op.isOrder : Op → Bool
  | .lt | .le | .gt | .ge => true
  | _ => false

/-- A decimal literal `± digits × 10^(exp - fracLen)`, read exactly from its text. `sig` is the
count of its significant digits as the reference counts them (every mantissa digit after leading
zeros) and `expWritten` the exponent as written; both are bounded. -/
structure Dec where
  neg : Bool
  digits : Nat
  fracLen : Nat
  expWritten : Int
  sig : Nat
  deriving DecidableEq, Repr, Inhabited

/-- A constant as an image states it, before lowering. -/
inductive Const where
  | int (n : Int)
  | dec (d : Dec)
  | bool (b : Bool)
  | str (s : String)
  | none
  deriving DecidableEq, Repr, Inhabited

/-- A Level M condition as an image states it. -/
inductive Cond where
  | always
  | never
  | truthy (f : String)
  | cmp (f : String) (op : Op) (k : Const)
  | mem (f : String) (ks : List Const)
  | nmem (f : String) (ks : List Const)
  | not (c : Cond)
  | and (cs : List Cond)
  | or (cs : List Cond)
  deriving Repr, Inhabited

/-- A canonical literal: what a condition compares with after lowering. -/
inductive Lit where
  | int (n : Int)
  | bool (b : Bool)
  | str (s : String)
  | none
  deriving DecidableEq, Repr, Inhabited

/-- A lowered condition: every number is a canonical integer. -/
inductive LCond where
  | always
  | never
  | truthy (f : String)
  | cmp (f : String) (op : Op) (k : Lit)
  | mem (f : String) (ks : List Lit)
  | nmem (f : String) (ks : List Lit)
  | not (c : LCond)
  | and (cs : List LCond)
  | or (cs : List LCond)
  deriving Repr, Inhabited

inductive Kind where
  | int | fixed | bool | category
  deriving DecidableEq, Repr, Inhabited

inductive Rounding where
  | floor | ceiling | exact
  deriving DecidableEq, Repr, Inhabited

/-- A field definition (SPEC.md section 4.5). `scale` and `rounding` are meaningful on `fixed` only. -/
structure FieldDef where
  name : String
  kind : Kind
  scale : Nat
  rounding : Rounding
  unit : Option String
  lo : Int
  hi : Int
  absentOK : Bool
  deriving Repr, Inhabited

structure Rule (C : Type) where
  target : String
  cond : C
  deriving Repr, Inhabited

/-- An image as decoded: definitions as text, rules as stated. -/
structure Image where
  fields : List (String × String)
  rules : List (Rule Cond)
  deriving Repr, Inhabited

/-- A policy that passed every check. -/
structure Checked where
  defs : List FieldDef
  rules : List (Rule LCond)
  deriving Repr, Inhabited

/-! ## Refusals of a policy -/

inductive PolicyErr where
  | unreadable (e : DocErr)
  | shape (what : String)
  | unknownOp (what : String)
  | unknownType (what : String)
  | notLevelM (what : String)
  | definition (field : String) (reason : String)
  | undefinedField (field : String)
  | engineCounter (field : String)
  | kindMismatch (field : String)
  | rounding (field : String)
  | threshold (field : String) (reason : String)
  | noneMisuse (field : String) (reason : String)
  | absenceUntested (field : String)
  deriving DecidableEq, Repr, Inhabited

abbrev PE := Except PolicyErr

/-! ## Names -/

def isAsciiAlpha (c : Char) : Bool := ('a' ≤ c && c ≤ 'z') || ('A' ≤ c && c ≤ 'Z')

/-- `[A-Za-z_][A-Za-z0-9_]*`, the field name of SPEC.md section 4.5. -/
def isIdent (s : String) : Bool :=
  match chars s with
  | [] => false
  | c :: cs => (isAsciiAlpha c || c == '_') && cs.all (fun c => isAsciiAlpha c || isDigit c || c == '_')

/-- Python's hard keywords (SPEC.md section 4.1): never names in a condition. -/
def hardKeywords : List String :=
  ["False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
   "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
   "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield"]

def engineCounters : List String := ["visits", "error_count"]

/-- An edge target: `[A-Za-z0-9_-]+`, the target of the flow grammar's edge line. -/
def isTarget (s : String) : Bool :=
  !s.isEmpty && (chars s).all (fun c => isAsciiAlpha c || isDigit c || c == '_' || c == '-')

/-! ## Exact decimal text -/

/-- The reference's DECIMAL_TEXT: `[+-]?(digits(.digits*)?|.digits)([eE][+-]?digits)?`, read exactly,
or `none`. -/
def parseDecimal (s : String) : Option Dec :=
  let cs := chars s
  let (neg, cs) : Bool × List Char :=
    match cs with
    | '-' :: r => (true, r)
    | '+' :: r => (false, r)
    | r => (false, r)
  let (ip, r) := spanDigits cs
  let fr : Option (List Char × List Char) :=
    match r with
    | '.' :: r' => let (fp, r'') := spanDigits r'; some (fp, r'')
    | _ => some ([], r)
  match fr with
  | none => none
  | some (fp, r2) =>
    if ip.isEmpty && fp.isEmpty then none
    else
      let ex : Option (Int × List Char) :=
        match r2 with
        | 'e' :: r' | 'E' :: r' =>
          let (eneg, r'') : Bool × List Char :=
            match r' with
            | '-' :: t => (true, t)
            | '+' :: t => (false, t)
            | t => (false, t)
          let (es, r3) := spanDigits r''
          if es.isEmpty then none
          else some ((if eneg then -(digitsValue es : Int) else (digitsValue es : Int)), r3)
        | _ => some (0, r2)
      match ex with
      | none => none
      | some (e, r3) =>
        if !r3.isEmpty then none
        else
          let all := ip ++ fp
          some { neg := neg, digits := digitsValue all, fracLen := fp.length, expWritten := e,
                 sig := (all.dropWhile (· == '0')).length }

/-- The bounds that keep the exact arithmetic within 128 bit integers in every implementation. -/
def decInBounds (d : Dec) : Bool := d.sig ≤ 28 && d.expWritten.natAbs ≤ 30

/-- `d × scale` as an integer, or `none` when it is not a whole number of units. -/
def Dec.scaled (d : Dec) (scale : Nat) : Option Int :=
  let m : Nat := d.digits * scale
  let t : Int := d.expWritten - d.fracLen
  if t ≥ 0 then some (if d.neg then -((m * 10 ^ t.toNat : Nat) : Int) else ((m * 10 ^ t.toNat : Nat) : Int))
  else if m % 10 ^ (-t).toNat == 0 then
    some (if d.neg then -((m / 10 ^ (-t).toNat : Nat) : Int) else ((m / 10 ^ (-t).toNat : Nat) : Int))
  else none

/-- Does the decimal text spell an integer canonically (`-?[1-9][0-9]*` or `0`)? -/
def isCanonicalIntText (s : String) : Bool :=
  match chars s with
  | ['0'] => true
  | '-' :: c :: cs => c != '0' && isDigit c && cs.all isDigit
  | c :: cs => c != '0' && isDigit c && cs.all isDigit
  | [] => false

def intOfCanonicalText (s : String) : Int :=
  match chars s with
  | '-' :: cs => -(digitsValue cs : Int)
  | cs => (digitsValue cs : Int)

/-! ## Decoding an image -/

def field? (ms : List (String × J)) (k : String) : Option J :=
  match ms.find? (fun m => m.1 == k) with
  | some (_, v) => some v
  | none => none

/-- The members of an object are exactly the given keys. -/
def onlyKeys (ms : List (String × J)) (ks : List String) : Bool :=
  ms.all (fun m => ks.contains m.1)

def decodeOp : String → Option Op
  | "<" => some .lt | "<=" => some .le | ">" => some .gt | ">=" => some .ge
  | "==" => some .eq | "!=" => some .ne | _ => none

/-- A constant. A number is a JSON integer, or a string: a decimal literal (a fraction or an
exponent), or an integer beyond the exact range in canonical spelling. -/
def decodeConst : J → PE Const
  | .arr [.str "num", .int n] => .ok (.int n)
  | .arr [.str "num", .str s] =>
    if isCanonicalIntText s then
      let n := intOfCanonicalText s
      if n > exactLimit || n < -exactLimit then .ok (.int n)
      else .error (.shape "integer-as-string")
    else match parseDecimal s with
      | some d =>
        if (chars s).any (fun c => c == '.' || c == 'e' || c == 'E') then
          if decInBounds d then .ok (.dec d) else .error (.threshold "" "digits")
        else .error (.shape "number-spelling")
      | none => .error (.shape "number-text")
  | .arr [.str "bool", .bool b] => .ok (.bool b)
  | .arr [.str "str", .str s] => .ok (.str s)
  | .arr [.str "none"] => .ok .none
  | .arr [.str "field", .str _] => .error (.unknownType "field-vs-field")
  | .arr (.str "list" :: _) => .error (.unknownType "nested-container")
  | _ => .error (.unknownType "constant")

def decodeConsts : List J → PE (List Const)
  | [] => .ok []
  | j :: js => do let k ← decodeConst j; let ks ← decodeConsts js; pure (k :: ks)

/-- A field name a condition reads. -/
def checkName (f : String) : PE Unit :=
  if !isIdent f || hardKeywords.contains f then .error (.notLevelM "name") else .ok ()

mutual
def decodeCond : J → PE Cond
  | .arr [.str "always"] => .ok .always
  | .arr [.str "never"] => .ok .never
  | .arr [.str "truthy", .str f] => do checkName f; pure (.truthy f)
  | .arr [.str "cmp", .str f, .str op, k] => do
    checkName f
    match decodeOp op with
    | none => .error (.unknownOp "operator")
    | some o =>
      let c ← decodeConst k
      match o.isOrder, c with
      | true, .str _ => .error (.unknownOp "string-ordering")
      | _, _ => pure (.cmp f o c)
  | .arr [.str "in", .str f, .arr ks] => do checkName f; let cs ← decodeConsts ks; pure (.mem f cs)
  | .arr [.str "not in", .str f, .arr ks] => do checkName f; let cs ← decodeConsts ks; pure (.nmem f cs)
  | .arr [.str "in", .str _, _] => .error (.unknownOp "membership-not-in-a-list")
  | .arr [.str "not in", .str _, _] => .error (.unknownOp "membership-not-in-a-list")
  | .arr [.str "not", c] => do let c' ← decodeCond c; pure (.not c')
  | .arr (.str "and" :: a :: b :: cs) => do let xs ← decodeConds (a :: b :: cs); pure (.and xs)
  | .arr (.str "or" :: a :: b :: cs) => do let xs ← decodeConds (a :: b :: cs); pure (.or xs)
  | _ => .error (.shape "condition")
def decodeConds : List J → PE (List Cond)
  | [] => .ok []
  | j :: js => do let c ← decodeCond j; let cs ← decodeConds js; pure (c :: cs)
end

mutual
/-- The structural depth the reference's static check measures on the condition's text
(`predicates._depth`, SPEC.md section 4.1): a name counts its load context, a list its own. -/
def Cond.depth : Cond → Nat
  | .always | .never => 0
  | .truthy _ => 1
  | .cmp _ _ _ | .mem _ _ | .nmem _ _ => 2
  | .not c => c.depth + 1
  | .and cs | .or cs => maxDepthOf cs + 1
def maxDepthOf : List Cond → Nat
  | [] => 0
  | c :: cs => max c.depth (maxDepthOf cs)
end

def maxCondDepth : Nat := 50

def decodeRule : J → PE (Rule Cond)
  | .obj ms =>
    if !onlyKeys ms ["target", "when"] then .error (.shape "rule-key")
    else match field? ms "target", field? ms "when" with
      | some (.str t), some w =>
        if !isTarget t then .error (.shape "target")
        else do
          let c ← decodeCond w
          if c.depth > maxCondDepth then .error (.notLevelM "depth") else pure { target := t, cond := c }
      | _, _ => .error (.shape "rule")
  | _ => .error (.shape "rule")

def decodeRules : List J → PE (List (Rule Cond))
  | [] => .ok []
  | j :: js => do let r ← decodeRule j; let rs ← decodeRules js; pure (r :: rs)

def decodeFields : List (String × J) → PE (List (String × String))
  | [] => .ok []
  | (k, .str v) :: ms => do let rest ← decodeFields ms; pure ((k, v) :: rest)
  | _ :: _ => .error (.shape "definition-not-text")

def formatTag : String := "prismpath.core/1"

def decodeImage : J → PE Image
  | .obj ms =>
    if !onlyKeys ms ["format", "fields", "rules"] then .error (.shape "image-key")
    else match field? ms "format", field? ms "fields", field? ms "rules" with
      | some (.str f), some (.obj fs), some (.arr rs) =>
        if f != formatTag then .error (.shape "format")
        else do
          let fields ← decodeFields fs
          let rules ← decodeRules rs
          pure { fields := fields, rules := rules }
      | _, _, _ => .error (.shape "image")
  | _ => .error (.shape "image")

/-! ## Field definitions -/

/-- Python's `str.isspace`, the separator `str.split()` uses on a definition. -/
def isPyWs (c : Char) : Bool :=
  let n := c.toNat
  (0x09 ≤ n && n ≤ 0x0D) || (0x1C ≤ n && n ≤ 0x20) || n == 0x85 || n == 0xA0 || n == 0x1680 ||
  (0x2000 ≤ n && n ≤ 0x200A) || n == 0x2028 || n == 0x2029 || n == 0x202F || n == 0x205F || n == 0x3000

/-- Words separated by runs of whitespace, as Python's `str.split()` with no argument. -/
def splitWords : List Char → List Char → List String
  | [], cur => if cur.isEmpty then [] else [String.ofList cur.reverse]
  | c :: cs, cur =>
    if isPyWs c then (if cur.isEmpty then splitWords cs [] else String.ofList cur.reverse :: splitWords cs [])
    else splitWords cs (c :: cur)

/-- `option=value` at the first `=`. -/
def splitOption (w : String) : Option (String × String) :=
  let cs := chars w
  match cs.findIdx? (· == '=') with
  | none => none
  | some i => some (String.ofList (cs.take i), String.ofList (cs.drop (i + 1)))

def optionsOf : Kind → List String
  | .int => ["min", "max", "absent"]
  | .fixed => ["scale", "rounding", "unit", "min", "max", "absent"]
  | .bool => ["absent"]
  | .category => ["absent"]

def kindOfWord : String → Option Kind
  | "int" => some .int | "fixed" => some .fixed | "bool" => some .bool | "category" => some .category
  | _ => none

/-- `[+-]?[0-9]+` as an integer. -/
def intOption (s : String) : Option Int :=
  match chars s with
  | '-' :: cs => if !cs.isEmpty && cs.all isDigit then some (-(digitsValue cs : Int)) else none
  | '+' :: cs => if !cs.isEmpty && cs.all isDigit then some (digitsValue cs : Int) else none
  | cs => if !cs.isEmpty && cs.all isDigit then some (digitsValue cs : Int) else none

def lookupOpt (os : List (String × String)) (k : String) : Option String :=
  match os.find? (fun o => o.1 == k) with
  | some (_, v) => some v
  | none => none

def collectOptions (name : String) (k : Kind) : List String → List (String × String) → PE (List (String × String))
  | [], acc => .ok acc
  | w :: ws, acc =>
    match splitOption w with
    | none => .error (.definition name "not-option")
    | some (o, v) =>
      if v.isEmpty then .error (.definition name "not-option")
      else if !(optionsOf k).contains o then .error (.definition name "option-not-taken")
      else if (acc.map (·.1)).contains o then .error (.definition name "option-repeated")
      else collectOptions name k ws (acc ++ [(o, v)])

def maxScale : Nat := 1000000000

/-- One definition (the reference's `parse_definition`). -/
def parseDef (name text : String) : PE FieldDef := do
  if !isIdent name then throw (.definition name "name")
  if engineCounters.contains name then throw (.definition name "engine-counter")
  let words := splitWords (chars text) []
  match words with
  | [] => throw (.definition name "empty")
  | kw :: rest =>
    match kindOfWord kw with
    | none => throw (.definition name "unknown-kind")
    | some k =>
      let os ← collectOptions name k rest []
      let absent := (lookupOpt os "absent").getD "refused"
      if absent != "refused" && absent != "allowed" then throw (.definition name "absent")
      let (scale, rounding) ← (if k == .fixed then
          match lookupOpt os "scale", lookupOpt os "rounding" with
          | some st, some rt =>
            match intOption st with
            | none => .error (.definition name "not-integer")
            | some s =>
              if s < 1 || s > maxScale then .error (.definition name "scale")
              else match rt with
                | "floor" => .ok (s.toNat, Rounding.floor)
                | "ceiling" => .ok (s.toNat, Rounding.ceiling)
                | "exact" => .ok (s.toNat, Rounding.exact)
                | _ => .error (.definition name "rounding")
          | _, _ => .error (.definition name "fixed-needs-scale-and-rounding")
        else .ok (1, Rounding.exact) : PE (Nat × Rounding))
      let lo ← (match lookupOpt os "min" with
        | none => .ok (-exactLimit)
        | some t => match intOption t with | some v => .ok v | none => .error (.definition name "not-integer") : PE Int)
      let hi ← (match lookupOpt os "max" with
        | none => .ok exactLimit
        | some t => match intOption t with | some v => .ok v | none => .error (.definition name "not-integer") : PE Int)
      if !(-exactLimit ≤ lo && lo ≤ hi && hi ≤ exactLimit) then throw (.definition name "range")
      pure { name := name, kind := k, scale := scale, rounding := rounding,
             unit := if k == .fixed then lookupOpt os "unit" else none,
             lo := lo, hi := hi, absentOK := absent == "allowed" }

/-! ## Code point order -/

/-- Lexicographic order on code points: Python's `sorted` on `str` and Rust's on UTF-8 bytes. -/
def charsLt : List Char → List Char → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a.toNat < b.toNat then true else if a.toNat == b.toNat then charsLt as bs else false

def nameLt (a b : String) : Bool := charsLt (chars a) (chars b)

def insertByName (d : String × String) : List (String × String) → List (String × String)
  | [] => [d]
  | e :: es => if nameLt d.1 e.1 then d :: e :: es else e :: insertByName d es

def sortByName : List (String × String) → List (String × String)
  | [] => []
  | d :: ds => insertByName d (sortByName ds)

def parseDefList : List (String × String) → PE (List FieldDef)
  | [] => .ok []
  | (n, t) :: ds => do let x ← parseDef n t; let xs ← parseDefList ds; pure (x :: xs)

/-- Every definition, in code point order of the field names, the first failure refusing. -/
def parseDefs (fs : List (String × String)) : PE (List FieldDef) := parseDefList (sortByName fs)

def findDef (defs : List FieldDef) (f : String) : Option FieldDef := defs.find? (fun d => d.name == f)

/-! ## Lowering and the policy rules -/

/-- The operators a rounding mode carries (SPEC.md section 4.5, rule 4). `none` stands for truthiness
and membership, which only `exact` carries. -/
def carries : Rounding → Option Op → Bool
  | .exact, _ => true
  | .floor, some .ge | .floor, some .lt => true
  | .ceiling, some .gt | .ceiling, some .le => true
  | _, _ => false

/-- One numeric constant of an `int` or `fixed` field, lowered to its canonical integer and checked
against the field's range. -/
def lowerNum (d : FieldDef) : Const → PE Lit
  | .int n =>
    let v : Int := if d.kind == .fixed then n * d.scale else n
    if v < d.lo || v > d.hi then
      .error (if d.kind == .fixed then .threshold d.name "out-of-range" else .threshold d.name "constant-range")
    else .ok (.int v)
  | .dec x =>
    if d.kind != .fixed then .error (.unknownType "float")
    else match x.scaled d.scale with
      | none => .error (.threshold d.name "off-grid")
      | some v => if v < d.lo || v > d.hi then .error (.threshold d.name "out-of-range") else .ok (.int v)
  | _ => .error (.kindMismatch d.name)

def isNumConst : Const → Bool
  | .int _ | .dec _ => true
  | _ => false

/-- A truthiness atom on a defined field. -/
def checkTruthy (d : FieldDef) : PE Unit :=
  if d.kind == .fixed && !carries d.rounding none then .error (.rounding d.name) else .ok ()

/-- A comparison atom, lowered. -/
def checkCmp (d : FieldDef) (op : Op) : Const → PE Lit
  | .none =>
    if op != .eq && op != .ne then .error (.noneMisuse d.name "ordered")
    else if !d.absentOK then .error (.noneMisuse d.name "absence-refused")
    else .ok .none
  | k =>
    match d.kind with
    | .bool => match k with
      | .bool b => if op == .eq || op == .ne then .ok (.bool b) else .error (.kindMismatch d.name)
      | .dec _ => .error (.unknownType "float")
      | _ => .error (.kindMismatch d.name)
    | .category => match k with
      | .str s => if op == .eq || op == .ne then .ok (.str s) else .error (.kindMismatch d.name)
      | .dec _ => .error (.unknownType "float")
      | _ => .error (.kindMismatch d.name)
    | .int | .fixed =>
      if d.kind == .fixed && !carries d.rounding (some op) && isNumConst k then .error (.rounding d.name)
      else do
        let l ← lowerNum d k
        if d.kind == .fixed && !carries d.rounding (some op) then .error (.rounding d.name) else pure l

def lowerMembers (d : FieldDef) : List Const → PE (List Lit)
  | [] => .ok []
  | k :: ks => do
    let l ← (match d.kind, k with
      | _, .none => .error (.noneMisuse d.name "in-list")
      | .category, .str s => .ok (.str s)
      | .int, _ | .fixed, _ => lowerNum d k
      | _, .dec _ => .error (.unknownType "float")
      | _, _ => .error (.kindMismatch d.name) : PE Lit)
    let ls ← lowerMembers d ks
    pure (l :: ls)

/-- A membership atom, lowered. -/
def checkMem (d : FieldDef) (ks : List Const) : PE (List Lit) := do
  if ks.contains .none then throw (.noneMisuse d.name "in-list")
  let ls ← lowerMembers d ks
  if d.kind == .fixed && !carries d.rounding none then throw (.rounding d.name)
  pure ls

def defined (defs : List FieldDef) (f : String) : PE FieldDef :=
  if engineCounters.contains f then .error (.engineCounter f)
  else match findDef defs f with
    | some d => .ok d
    | none => .error (.undefinedField f)

mutual
def lowerCond (defs : List FieldDef) : Cond → PE LCond
  | .always => .ok .always
  | .never => .ok .never
  | .truthy f => do let d ← defined defs f; checkTruthy d; pure (.truthy f)
  | .cmp f op k => do let d ← defined defs f; let l ← checkCmp d op k; pure (.cmp f op l)
  | .mem f ks => do let d ← defined defs f; let ls ← checkMem d ks; pure (.mem f ls)
  | .nmem f ks => do let d ← defined defs f; let ls ← checkMem d ks; pure (.nmem f ls)
  | .not c => do let c' ← lowerCond defs c; pure (.not c')
  | .and cs => do let cs' ← lowerConds defs cs; pure (.and cs')
  | .or cs => do let cs' ← lowerConds defs cs; pure (.or cs')
def lowerConds (defs : List FieldDef) : List Cond → PE (List LCond)
  | [] => .ok []
  | c :: cs => do let c' ← lowerCond defs c; let cs' ← lowerConds defs cs; pure (c' :: cs')
end

mutual
/-- The fields a lowered condition tests with `== None` or `!= None`. -/
def LCond.noneTested : LCond → List String
  | .cmp f _ .none => [f]
  | .not c => c.noneTested
  | .and cs | .or cs => noneTestedOf cs
  | _ => []
def noneTestedOf : List LCond → List String
  | [] => []
  | c :: cs => c.noneTested ++ noneTestedOf cs
end

def lowerRules (defs : List FieldDef) : List (Rule Cond) → PE (List (Rule LCond))
  | [] => .ok []
  | r :: rs => do
    let c ← lowerCond defs r.cond
    let rest ← lowerRules defs rs
    pure ({ target := r.target, cond := c } :: rest)

/-- Rule 6: a field that allows absence is tested for it by some rule. -/
def checkAbsence (rules : List (Rule LCond)) : List FieldDef → PE Unit
  | [] => .ok ()
  | d :: ds =>
    if d.absentOK && !(rules.any (fun r => r.cond.noneTested.contains d.name)) then .error (.absenceUntested d.name)
    else checkAbsence rules ds

/-- The whole check of a decoded image. -/
def checkImage (img : Image) : PE Checked := do
  let defs ← parseDefs img.fields
  let rules ← lowerRules defs img.rules
  checkAbsence rules defs
  pure { defs := defs, rules := rules }

/-- From the image's text to a checked policy. -/
def loadPolicy (doc : Except DocErr J) : PE Checked :=
  match doc with
  | .error e => .error (.unreadable e)
  | .ok j => do let img ← decodeImage j; checkImage img

end Core
