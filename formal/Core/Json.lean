-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
/-!
# The verified core: the canon/2 document reader

A policy image and a reading reach the core as text. This file is the one reader both go through: a
JSON reader restricted to the canon/2 profile (docs/design/spec-verified-core.md, section 3). It
accepts exactly the JSON documents (RFC 8259) whose numbers are integers within plus or minus 2^53
minus 1, written without a fraction, an exponent or a negative zero; whose objects hold no key twice;
whose strings hold no lone surrogate; and whose nesting is at most `maxDepth`. Every other text is a
refusal with one `DocErr` cause, the first one met reading left to right.

This reader alone accepts spellings that are not canonical (whitespace, members out of key order,
needless escapes). The core reads nothing with it directly: every image and reading goes through the
strict reader `Core.readCanonical` (Canon2.lean), which accepts exactly the canonical spelling of the
value this reader reads and refuses every other document with `notCanonical`, the one cause this reader
itself never returns.

Every function here is defined by structural recursion (on a fuel argument or on the input list), so
the reader is total by construction and no `partial` definition appears. No `Classical` reasoning is
used to compute: every test is a decidable comparison of characters or natural numbers.
-/

namespace Core

/-- The largest integer every reader represents exactly (canon/2 and SPEC.md section 4.5). -/
def exactLimit : Int := 9007199254740991

/-- The deepest nesting of arrays and objects a document may have. -/
def maxDepth : Nat := 128

/-- A canon/2 value. There is no float: a number is an integer within the exact range. -/
inductive J where
  | null
  | bool (b : Bool)
  | int (n : Int)
  | str (s : String)
  | arr (xs : List J)
  | obj (ms : List (String × J))
  deriving Repr, Inhabited

/-- Why a text is not a canon/2 document. -/
inductive DocErr where
  | utf8          -- the bytes are not UTF-8
  | syntax        -- not JSON (including NaN and Infinity tokens)
  | float         -- a number with a fraction or an exponent
  | intRange      -- an integer beyond plus or minus 2^53 minus 1
  | negZero       -- the integer written -0
  | dupKey        -- an object holds a key twice
  | loneSurrogate -- a \u escape naming half of a surrogate pair alone
  | depth         -- nesting deeper than maxDepth
  | notCanonical  -- a document, but not the canonical spelling of its value (`Core.readCanonical`)
  deriving DecidableEq, Repr, Inhabited

def DocErr.name : DocErr → String
  | .utf8 => "utf8" | .syntax => "syntax" | .float => "float" | .intRange => "integer-range"
  | .negZero => "negative-zero" | .dupKey => "duplicate-key" | .loneSurrogate => "lone-surrogate"
  | .depth => "depth" | .notCanonical => "not-canonical"

/-! ## UTF-8

The core decodes UTF-8 itself, strictly (RFC 3629): no overlong form, no encoded surrogate, nothing
above U+10FFFF, no truncated sequence. Lean's own `String.fromUTF8?` and `String.toList` would do the
same work, but their definitions carry `Classical.choice` in their proofs, and the evaluator is kept
free of it. -/

def isCont (b : UInt8) : Bool := 0x80 ≤ b.toNat && b.toNat < 0xC0

def contVal (b : UInt8) : Nat := b.toNat - 0x80

def utf8Decode : List UInt8 → List Char → Option (List Char)
  | [], acc => some acc.reverse
  | b :: rest, acc =>
    let n := b.toNat
    if n < 0x80 then utf8Decode rest (Char.ofNat n :: acc)
    else if n < 0xC2 then none
    else if n < 0xE0 then
      match rest with
      | c1 :: r => if isCont c1 then utf8Decode r (Char.ofNat ((n - 0xC0) * 64 + contVal c1) :: acc) else none
      | _ => none
    else if n < 0xF0 then
      match rest with
      | c1 :: c2 :: r =>
        if isCont c1 && isCont c2 then
          let cp := (n - 0xE0) * 4096 + contVal c1 * 64 + contVal c2
          if cp < 0x800 || (0xD800 ≤ cp && cp ≤ 0xDFFF) then none else utf8Decode r (Char.ofNat cp :: acc)
        else none
      | _ => none
    else if n < 0xF5 then
      match rest with
      | c1 :: c2 :: c3 :: r =>
        if isCont c1 && isCont c2 && isCont c3 then
          let cp := (n - 0xF0) * 262144 + contVal c1 * 4096 + contVal c2 * 64 + contVal c3
          if cp < 0x10000 || cp > 0x10FFFF then none else utf8Decode r (Char.ofNat cp :: acc)
        else none
      | _ => none
    else none

/-- The characters of a string, by its UTF-8 bytes. -/
def chars (s : String) : List Char := (utf8Decode s.toByteArray.data.toList []).getD []

/-- JSON whitespace: space, tab, line feed, carriage return, nothing else. -/
def isWs (c : Char) : Bool := c == ' ' || c == '\t' || c == '\n' || c == '\r'

def skipWs : List Char → List Char
  | c :: cs => if isWs c then skipWs cs else c :: cs
  | [] => []

def isDigit (c : Char) : Bool := '0' ≤ c && c ≤ '9'

/-- The leading decimal digits and the rest. -/
def spanDigits : List Char → List Char × List Char
  | c :: cs => if isDigit c then let (ds, r) := spanDigits cs; (c :: ds, r) else ([], c :: cs)
  | [] => ([], [])

def digitsValue (ds : List Char) : Nat :=
  ds.foldl (fun acc c => acc * 10 + (c.toNat - '0'.toNat)) 0

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def hex4 (a b c d : Char) : Option Nat := do
  let a ← hexVal a; let b ← hexVal b; let c ← hexVal c; let d ← hexVal d
  pure (((a * 16 + b) * 16 + c) * 16 + d)

def isHigh (h : Nat) : Bool := 0xD800 ≤ h && h ≤ 0xDBFF
def isLow (h : Nat) : Bool := 0xDC00 ≤ h && h ≤ 0xDFFF

/-- The body of a string after its opening quote, as reversed characters, and the rest. -/
def parseStr : List Char → List Char → Except DocErr (String × List Char)
  | [], _ => .error .syntax
  | '"' :: rest, acc => .ok (String.ofList acc.reverse, rest)
  | '\\' :: 'u' :: a :: b :: c :: d :: rest, acc =>
    match hex4 a b c d with
    | none => .error .syntax
    | some h =>
      if isHigh h then
        match rest with
        | '\\' :: 'u' :: e :: f :: g :: k :: rest2 =>
          match hex4 e f g k with
          | none => .error .syntax
          | some l =>
            if isLow l then parseStr rest2 (Char.ofNat (0x10000 + (h - 0xD800) * 0x400 + (l - 0xDC00)) :: acc)
            else .error .loneSurrogate
        | _ => .error .loneSurrogate
      else if isLow h then .error .loneSurrogate
      else parseStr rest (Char.ofNat h :: acc)
  | '\\' :: e :: rest, acc =>
    match e with
    | '"' => parseStr rest ('"' :: acc)
    | '\\' => parseStr rest ('\\' :: acc)
    | '/' => parseStr rest ('/' :: acc)
    | 'b' => parseStr rest ('\x08' :: acc)
    | 'f' => parseStr rest ('\x0c' :: acc)
    | 'n' => parseStr rest ('\n' :: acc)
    | 'r' => parseStr rest ('\r' :: acc)
    | 't' => parseStr rest ('\t' :: acc)
    | _ => .error .syntax
  | c :: rest, acc => if c.toNat < 0x20 then .error .syntax else parseStr rest (c :: acc)

/-- A number after its optional minus sign. JSON's grammar decides syntax first; a well formed
number with a fraction or an exponent is then a float, refused; an integer must not be -0 and must lie
within the exact range. -/
def parseNum (neg : Bool) (cs : List Char) : Except DocErr (J × List Char) :=
  let intPart : Option (List Char × List Char) :=
    match cs with
    | '0' :: r => some (['0'], r)
    | c :: r => if isDigit c then let (ds, r') := spanDigits r; some (c :: ds, r') else none
    | [] => none
  match intPart with
  | none => .error .syntax
  | some (ds, r) =>
    let fracOk : Option (Bool × List Char) :=   -- (seen a fraction, rest)
      match r with
      | '.' :: r' => let (fs, r'') := spanDigits r'; if fs.isEmpty then none else some (true, r'')
      | _ => some (false, r)
    match fracOk with
    | none => .error .syntax
    | some (hasFrac, r2) =>
      let expOk : Option (Bool × List Char) :=
        match r2 with
        | 'e' :: r' | 'E' :: r' =>
          let r'' := match r' with | '+' :: t => t | '-' :: t => t | t => t
          let (es, r3) := spanDigits r''
          if es.isEmpty then none else some (true, r3)
        | _ => some (false, r2)
      match expOk with
      | none => .error .syntax
      | some (hasExp, r3) =>
        if hasFrac || hasExp then .error .float
        else
          let v : Nat := digitsValue ds
          if neg && v == 0 then .error .negZero
          else
            let n : Int := if neg then -(v : Int) else (v : Int)
            if n > exactLimit || n < -exactLimit then .error .intRange
            else .ok (.int n, r3)

/-- Does a member list already hold the key. -/
def hasKey (k : String) : List (String × J) → Bool
  | [] => false
  | (k', _) :: ms => k == k' || hasKey k ms

mutual
/-- One value. `fuel` bounds the call chain (each call consumes input or opens a container), `d` is
the current nesting depth. -/
def pValue : Nat → Nat → List Char → Except DocErr (J × List Char)
  | 0, _, _ => .error .syntax
  | fuel + 1, d, cs =>
    match skipWs cs with
    | 'n' :: 'u' :: 'l' :: 'l' :: r => .ok (.null, r)
    | 't' :: 'r' :: 'u' :: 'e' :: r => .ok (.bool true, r)
    | 'f' :: 'a' :: 'l' :: 's' :: 'e' :: r => .ok (.bool false, r)
    | '"' :: r =>
      match parseStr r [] with
      | .ok (s, r') => .ok (.str s, r')
      | .error e => .error e
    | '-' :: r => parseNum true r
    | '[' :: r =>
      if d + 1 > maxDepth then .error .depth
      else match skipWs r with
        | ']' :: r' => .ok (.arr [], r')
        | r' =>
          match pValue fuel (d + 1) r' with
          | .error e => .error e
          | .ok (v, r'') => pArr fuel (d + 1) r'' [v]
    | '{' :: r =>
      if d + 1 > maxDepth then .error .depth
      else match skipWs r with
        | '}' :: r' => .ok (.obj [], r')
        | r' => pMember fuel (d + 1) r' []
    | c :: r => if isDigit c then parseNum false (c :: r) else .error .syntax
    | [] => .error .syntax

/-- The rest of an array after an element; `acc` holds the elements read, reversed. -/
def pArr : Nat → Nat → List Char → List J → Except DocErr (J × List Char)
  | 0, _, _, _ => .error .syntax
  | fuel + 1, d, cs, acc =>
    match skipWs cs with
    | ']' :: r => .ok (.arr acc.reverse, r)
    | ',' :: r =>
      match pValue fuel d r with
      | .error e => .error e
      | .ok (v, r') => pArr fuel d r' (v :: acc)
    | _ => .error .syntax

/-- One `"key": value` member and the rest of the object; `acc` holds the members read, reversed. -/
def pMember : Nat → Nat → List Char → List (String × J) → Except DocErr (J × List Char)
  | 0, _, _, _ => .error .syntax
  | fuel + 1, d, cs, acc =>
    match skipWs cs with
    | '"' :: r =>
      match parseStr r [] with
      | .error e => .error e
      | .ok (k, r') =>
        if hasKey k acc then .error .dupKey
        else match skipWs r' with
          | ':' :: r'' =>
            match pValue fuel d r'' with
            | .error e => .error e
            | .ok (v, r3) =>
              match skipWs r3 with
              | '}' :: r4 => .ok (.obj ((k, v) :: acc).reverse, r4)
              | ',' :: r4 => pMember fuel d r4 ((k, v) :: acc)
              | _ => .error .syntax
          | _ => .error .syntax
    | _ => .error .syntax
end

/-- No object anywhere in the value holds a key twice. The reader checks this as it reads; the
check is restated over the result so the property is visible to the theorems. -/
def keysDistinct : List (String × J) → Bool
  | [] => true
  | (k, _) :: ms => !hasKey k ms && keysDistinct ms

mutual
def wfJ : J → Bool
  | .arr xs => wfList xs
  | .obj ms => keysDistinct ms && wfMembers ms
  | _ => true
def wfList : List J → Bool
  | [] => true
  | x :: xs => wfJ x && wfList xs
def wfMembers : List (String × J) → Bool
  | [] => true
  | (_, v) :: ms => wfJ v && wfMembers ms
end

/-- The canon/2 reader on text already decoded from UTF-8. -/
def readChars (cs : List Char) : Except DocErr J :=
  match pValue (2 * cs.length + 4) 0 cs with
  | .error e => .error e
  | .ok (v, rest) =>
    if (skipWs rest).isEmpty then
      if wfJ v then .ok v else .error .dupKey
    else .error .syntax

/-- The canon/2 reader on bytes: UTF-8 first, then the document. -/
def readBytes (b : ByteArray) : Except DocErr J :=
  match utf8Decode b.data.toList [] with
  | none => .error .utf8
  | some cs => readChars cs

end Core
