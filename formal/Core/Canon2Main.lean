-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Canon2
/-!
# The canon/2 oracle

`lake exe canon2-oracle FILE ...` reads each file as a canon/2 document and prints one line per file;
`lake exe canon2-oracle --batch` reads framed documents on standard input, each `<byte length>\n<bytes>\n`,
and prints one line per document. A line is

- `ok <c> <hex>`: the reader (`Core.readBytes`) accepts the document; `<hex>` is the writer's canonical
  bytes of its value (`Core.writeBytes`), and `<c>` is `1` when the strict reader (`Core.readCanonical`)
  accepts the input too, that is when the input is already those bytes, else `0`;
- `refuse <rule>`: the reader refuses it, with the first rule broken (`Core.DocErr.name`).

Only this file does input and output. What it prints is computed by `readBytes`, `writeBytes` and
`readCanonical`, the functions `Core.Canon2Proofs` is about.
-/

namespace Core.Canon2Oracle

def hexChar (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hex (b : ByteArray) : String :=
  b.foldl (fun s x => (s.push (hexChar (x.toNat / 16))).push (hexChar (x.toNat % 16))) ""

def line (b : ByteArray) : String :=
  match readBytes b with
  | .error e => "refuse " ++ e.name
  | .ok v =>
    let c := match readCanonical b with | .ok _ => "1" | .error _ => "0"
    "ok " ++ c ++ " " ++ hex (writeBytes v)

/-- The decimal length line at `pos` and the position after its line feed. -/
def header (b : ByteArray) (pos : Nat) : Option (Nat × Nat) :=
  let rec go (fuel i n : Nat) (seen : Bool) : Option (Nat × Nat) :=
    match fuel with
    | 0 => none
    | fuel + 1 =>
      if i ≥ b.size then none
      else
        let x := (b.get! i).toNat
        if x == 10 then (if seen then some (n, i + 1) else none)
        else if 48 ≤ x && x ≤ 57 then go fuel (i + 1) (n * 10 + (x - 48)) true
        else none
  go (b.size - pos + 1) pos 0 false

end Core.Canon2Oracle

open Core Core.Canon2Oracle in
def main (args : List String) : IO UInt32 := do
  match args with
  | ["--batch"] =>
    let input ← (← IO.getStdin).readBinToEnd
    let out ← IO.getStdout
    let mut pos := 0
    let mut fuel := input.size + 1
    while fuel > 0 && pos < input.size do
      fuel := fuel - 1
      match header input pos with
      | none => IO.eprintln "canon2-oracle: malformed frame header"; return 2
      | some (n, p) =>
        if p + n + 1 > input.size then
          IO.eprintln "canon2-oracle: truncated frame"; return 2
        out.putStrLn (line (input.extract p (p + n)))
        pos := p + n + 1
    out.flush
    return 0
  | [] =>
    IO.eprintln "usage: canon2-oracle FILE ... | canon2-oracle --batch < frames"
    return 2
  | files =>
    for f in files do
      IO.println (line (← IO.FS.readBinFile f))
    return 0
