-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Eval
/-!
# The oracle

`lake exe core-oracle POLICY [READING ...]` reads a policy image and readings (canon/2 documents, as
files) and prints one JSON line for the policy and one per reading, in the stable format of
docs/design/spec-verified-core.md section 7. `lake exe core-oracle --batch` reads framed cases on
standard input (the differential harness's transport) and prints one JSON line per case.

Only this file does input and output. Everything it prints is computed by `Core.verdict`, the
function the theorems are about; the code here frames bytes and spells the result.
-/

namespace Core

def jsonEscape (s : String) : String :=
  let body := (chars s).foldl (fun acc c =>
    if c == '"' then acc ++ "\\\""
    else if c == '\\' then acc ++ "\\\\"
    else if c.toNat < 0x20 then
      let h := Nat.toDigits 16 c.toNat
      acc ++ "\\u" ++ String.ofList (List.replicate (4 - h.length) '0' ++ h)
    else acc.push c) ""
  "\"" ++ body ++ "\""

/-- A refusal as printed: its registered code and name (`Refusal.code`, `Refusal.cause`, proved to be a
registry row by `refusal_registered`), and the field and reason where it has them. -/
structure Spelled where
  code : Nat
  cause : String
  field : Option String := none
  reason : Option String := none

def spellPolicy (e : PolicyErr) : Spelled :=
  let base : Spelled := { code := e.code, cause := e.cause }
  match e with
  | .unreadable d => { base with reason := some d.name }
  | .shape w | .unknownOp w | .unknownType w | .notLevelM w => { base with reason := some w }
  | .definition f r | .threshold f r | .noneMisuse f r => { base with field := some f, reason := some r }
  | .undefinedField f | .engineCounter f | .kindMismatch f | .rounding f | .absenceUntested f =>
    { base with field := some f }

def spellRefusal (r : Refusal) : Spelled :=
  match r with
  | .policy e => spellPolicy e
  | .readingUnreadable e => { code := r.code, cause := r.cause, reason := some e.name }
  | .readingNotObject => { code := r.code, cause := r.cause }
  | .contract f e => { code := r.code, cause := r.cause, field := some f, reason := some e.name }
  | .noMatch => { code := r.code, cause := r.cause }

def spelledJson (s : Spelled) : String :=
  let code := toString s.code
  let fld := match s.field with | some f => ",\"field\":" ++ jsonEscape f | none => ""
  let rsn := match s.reason with | some r => ",\"reason\":" ++ jsonEscape r | none => ""
  "\"cause\":" ++ jsonEscape s.cause ++ ",\"code\":" ++ code ++ fld ++ rsn

def verdictJson : Verdict → String
  | .route t => "{\"verdict\":\"route\",\"target\":" ++ jsonEscape t ++ "}"
  | .refuse r => "{\"verdict\":\"refuse\"," ++ spelledJson (spellRefusal r) ++ "}"

def policyJson (doc : Except DocErr J) : String :=
  match loadPolicy doc with
  | .ok _ => "{\"policy\":\"accepted\"}"
  | .error e => "{\"policy\":\"refused\"," ++ spelledJson (spellPolicy e) ++ "}"

/-! ## Framing for the batch mode: `case <id> <n>\n` then `n + 1` documents, each `<bytes>\n` raw. -/

def readLine (b : ByteArray) (pos : Nat) : Option (String × Nat) :=
  let rec go (fuel i : Nat) : Option Nat :=
    match fuel with
    | 0 => none
    | fuel + 1 => if i ≥ b.size then none else if b.get! i == 10 then some i else go fuel (i + 1)
  match go (b.size - pos + 1) pos with
  | none => none
  | some e => (String.fromUTF8? (b.extract pos e)).map (fun s => (s, e + 1))

def readFrame (b : ByteArray) (pos : Nat) : Option (ByteArray × Nat) := do
  let (line, p) ← readLine b pos
  let n ← line.toNat?
  if p + n + 1 > b.size then none
  pure (b.extract p (p + n), p + n + 1)

def readFrames (b : ByteArray) : Nat → Nat → List ByteArray → Option (List ByteArray × Nat)
  | 0, pos, acc => some (acc.reverse, pos)
  | k + 1, pos, acc => do let (d, p) ← readFrame b pos; readFrames b k p (d :: acc)

def batch (b : ByteArray) (out : IO.FS.Stream) : IO UInt32 := do
  let mut pos := 0
  let mut fuel := b.size + 1
  while fuel > 0 && pos < b.size do
    fuel := fuel - 1
    match readLine b pos with
    | none => IO.eprintln "core-oracle: malformed frame header"; return 2
    | some (hdr, p) =>
      match hdr.splitOn " " with
      | ["case", ident, n] =>
        match n.toNat? with
        | none => IO.eprintln "core-oracle: malformed reading count"; return 2
        | some k =>
          match readFrames b (k + 1) p [] with
          | none => IO.eprintln "core-oracle: truncated case"; return 2
          | some (docs, p') =>
            pos := p'
            match docs with
            | [] => return 2
            | img :: rds =>
              let imgDoc := readBytes img
              let verdicts := rds.map (fun r => verdictJson (verdictBytes img r))
              out.putStrLn ("{\"id\":" ++ jsonEscape ident ++ ",\"policy\":" ++ policyJson imgDoc ++
                ",\"readings\":[" ++ ",".intercalate verdicts ++ "]}")
      | _ => IO.eprintln "core-oracle: malformed frame header"; return 2
  out.flush
  return 0

end Core

open Core in
def main (args : List String) : IO UInt32 := do
  match args with
  | ["--batch"] =>
    let input ← (← IO.getStdin).readBinToEnd
    batch input (← IO.getStdout)
  | policy :: readings =>
    let img ← IO.FS.readBinFile policy
    IO.println (policyJson (readBytes img))
    for r in readings do
      let rb ← IO.FS.readBinFile r
      IO.println (verdictJson (verdictBytes img rb))
    return 0
  | [] =>
    IO.eprintln "usage: core-oracle POLICY.json [READING.json ...] | core-oracle --batch < frames"
    return 2
