-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Json
/-!
# The verified core: the canon/2 document writer

`Core.readBytes` (Json.lean) is the canon/2 reader. This file is its writer, the canonical spelling of a
value (docs/design/spec-verified-core.md, section 3): no whitespace; object members in order of the
UTF-16 code units of their keys; strings as raw UTF-8 with only `"`, `\` and the control characters
escaped (`\b \t \n \f \r`, otherwise lowercase `\u00xx`), as RFC 8785 escapes them; integers in decimal
with no leading zero, a minus sign only before a nonzero magnitude.

The writer is total: `write v` spells every value, and the theorems of `Core.Canon2Proofs` say on which
values the spelling is the canon/2 document of `v`. `Canon v` is that domain, decided by `canon`: the
reader's own conditions (no key twice in any object, every integer within plus or minus 2^53 minus 1,
nesting at most `maxDepth`) and, in every object, keys strictly increasing in UTF-16 code unit order.
A Lean `String` holds Unicode scalar values only, so no value holds a lone surrogate by its type.

`readCanonical` is the strict reader: it accepts a byte string exactly when it is the canonical
spelling of the value it reads to, and refuses every other byte string, with the reader's cause or
`notCanonical`.

Everything here is structural recursion or well founded recursion on a natural number, and nothing is
`partial`, so the writer is total by construction.
-/

namespace Core

/-! ## Strings -/

/-- A lowercase hexadecimal digit. -/
def hexDigit (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

/-- One character as RFC 8785 writes it inside a string. -/
def escChar (c : Char) : List Char :=
  if c = '"' then ['\\', '"']
  else if c = '\\' then ['\\', '\\']
  else if c.toNat < 32 then
    if c.toNat = 8 then ['\\', 'b']
    else if c.toNat = 9 then ['\\', 't']
    else if c.toNat = 10 then ['\\', 'n']
    else if c.toNat = 12 then ['\\', 'f']
    else if c.toNat = 13 then ['\\', 'r']
    else ['\\', 'u', '0', '0', hexDigit (c.toNat / 16), hexDigit (c.toNat % 16)]
  else [c]

def escStr : List Char → List Char
  | [] => []
  | c :: cs => escChar c ++ escStr cs

/-- A string with its quotes. -/
def wStr (s : String) : List Char := '"' :: (escStr s.toList ++ ['"'])

/-! ## Integers -/

/-- The decimal digits of a natural number, most significant first, with no leading zero. -/
def natDigits (n : Nat) : List Char :=
  if n < 10 then [Char.ofNat (48 + n)] else natDigits (n / 10) ++ [Char.ofNat (48 + n % 10)]
termination_by n
decreasing_by omega

def wInt (n : Int) : List Char := if n < 0 then '-' :: natDigits n.natAbs else natDigits n.natAbs

/-! ## Key order: UTF-16 code units, compared lexicographically -/

def utf16 (c : Char) : List Nat :=
  if c.toNat < 0x10000 then [c.toNat]
  else [0xD800 + (c.toNat - 0x10000) / 0x400, 0xDC00 + (c.toNat - 0x10000) % 0x400]

def units : List Char → List Nat
  | [] => []
  | c :: cs => utf16 c ++ units cs

def lexLt : List Nat → List Nat → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLt as bs)

/-- `a` sorts before `b`: the UTF-16 code units of `a` are lexicographically smaller. -/
def keyLt (a b : String) : Bool := lexLt (units a.toList) (units b.toList)

def insertM (m : String × J) : List (String × J) → List (String × J)
  | [] => [m]
  | n :: ns => if keyLt n.1 m.1 then n :: insertM m ns else m :: n :: ns

def sortM : List (String × J) → List (String × J)
  | [] => []
  | m :: ms => insertM m (sortM ms)

mutual
/-- The value with the members of every object in key order. -/
def norm : J → J
  | .arr xs => .arr (normL xs)
  | .obj ms => .obj (sortM (normM ms))
  | v => v
def normL : List J → List J
  | [] => []
  | x :: xs => norm x :: normL xs
def normM : List (String × J) → List (String × J)
  | [] => []
  | (k, v) :: ms => (k, norm v) :: normM ms
end

/-! ## The spelling -/

mutual
/-- The spelling of a value with members in the order given. -/
def wr : J → List Char
  | .null => ['n', 'u', 'l', 'l']
  | .bool true => ['t', 'r', 'u', 'e']
  | .bool false => ['f', 'a', 'l', 's', 'e']
  | .int n => wInt n
  | .str s => wStr s
  | .arr [] => ['[', ']']
  | .arr (x :: xs) => '[' :: (wr x ++ wrArr xs)
  | .obj [] => ['{', '}']
  | .obj ((k, v) :: ms) => '{' :: (wStr k ++ ':' :: (wr v ++ wrObj ms))
def wrArr : List J → List Char
  | [] => [']']
  | x :: xs => ',' :: (wr x ++ wrArr xs)
def wrObj : List (String × J) → List Char
  | [] => ['}']
  | (k, v) :: ms => ',' :: (wStr k ++ ':' :: (wr v ++ wrObj ms))
end

/-- The canonical characters of a value. -/
def writeChars (v : J) : List Char := wr (norm v)

/-! ## UTF-8 -/

def utf8Char (c : Char) : List UInt8 :=
  let n := c.toNat
  if n < 0x80 then [UInt8.ofNat n]
  else if n < 0x800 then [UInt8.ofNat (0xC0 + n / 64), UInt8.ofNat (0x80 + n % 64)]
  else if n < 0x10000 then
    [UInt8.ofNat (0xE0 + n / 4096), UInt8.ofNat (0x80 + n / 64 % 64), UInt8.ofNat (0x80 + n % 64)]
  else
    [UInt8.ofNat (0xF0 + n / 262144), UInt8.ofNat (0x80 + n / 4096 % 64),
     UInt8.ofNat (0x80 + n / 64 % 64), UInt8.ofNat (0x80 + n % 64)]

def utf8Enc : List Char → List UInt8
  | [] => []
  | c :: cs => utf8Char c ++ utf8Enc cs

/-- The canon/2 writer: the canonical bytes of a value. -/
def writeBytes (v : J) : ByteArray := ⟨(utf8Enc (writeChars v)).toArray⟩

/-- The canonical spelling as a `String`. -/
def write (v : J) : String := String.ofList (writeChars v)

/-! ## The writer's domain -/

def inRange (n : Int) : Bool := decide (-exactLimit ≤ n) && decide (n ≤ exactLimit)

mutual
def depth : J → Nat
  | .arr xs => depthL xs + 1
  | .obj ms => depthM ms + 1
  | _ => 0
def depthL : List J → Nat
  | [] => 0
  | x :: xs => max (depth x) (depthL xs)
def depthM : List (String × J) → Nat
  | [] => 0
  | (_, v) :: ms => max (depth v) (depthM ms)
end

mutual
/-- Every integer within the exact range. -/
def rangeJ : J → Bool
  | .int n => inRange n
  | .arr xs => rangeL xs
  | .obj ms => rangeM ms
  | _ => true
def rangeL : List J → Bool
  | [] => true
  | x :: xs => rangeJ x && rangeL xs
def rangeM : List (String × J) → Bool
  | [] => true
  | (_, v) :: ms => rangeJ v && rangeM ms
end

/-- Keys strictly increasing, each before every later one. -/
def keysSorted : List (String × J) → Bool
  | [] => true
  | (k, _) :: ms => ms.all (fun m => keyLt k m.1) && keysSorted ms

mutual
def sortedJ : J → Bool
  | .arr xs => sortedL xs
  | .obj ms => keysSorted ms && sortedM ms
  | _ => true
def sortedL : List J → Bool
  | [] => true
  | x :: xs => sortedJ x && sortedL xs
def sortedM : List (String × J) → Bool
  | [] => true
  | (_, v) :: ms => sortedJ v && sortedM ms
end

/-- What the reader produces: no key twice, integers in range, nesting within `maxDepth`. -/
def doc (v : J) : Bool := wfJ v && rangeJ v && decide (depth v ≤ maxDepth)

/-- The writer's domain, the canonical values: documents whose objects are in key order. -/
def canon (v : J) : Bool := doc v && sortedJ v

/-! ## The strict reader -/

/-- Why a byte string is not a canonical canon/2 document. -/
inductive CanonErr where
  | doc (e : DocErr)   -- not a canon/2 document at all
  | notCanonical       -- a document, but not the canonical spelling of its value
  deriving DecidableEq, Repr, Inhabited

def CanonErr.name : CanonErr → String
  | .doc e => e.name
  | .notCanonical => "not-canonical"

/-- The strict reader: a document, and the canonical spelling of its value. -/
def readCanonical (b : ByteArray) : Except CanonErr J :=
  match readBytes b with
  | .error e => .error (.doc e)
  | .ok v => if utf8Enc (writeChars v) = b.data.toList then .ok v else .error .notCanonical

end Core
