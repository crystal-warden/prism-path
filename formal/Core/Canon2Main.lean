-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Canon2
/-!
# The canon/2 oracle

`lake exe canon2-oracle FILE ...` reads each file as a canon/2 document and prints one line per file;
`lake exe canon2-oracle --batch` reads framed documents on standard input, each `<byte length>\n<bytes>\n`,
and prints one line per document. A line is `<strict> ; <canonicalize>`:

- `<strict>` is the strict reader's answer (`Core.readCanonical`, the reader the core decides with):
  `ok <hex>` with the writer's bytes of the value (`Core.writeBytes`, which are the input), or
  `refuse <rule>` with the first rule broken or `not-canonical` (`Core.DocErr.name`);
- `<canonicalize>` is the canonicalize path's answer (`Core.canonicalize`, for text a person wrote):
  `canon <hex>` with the canonical bytes of the value read, or `refuse <rule>`.

Only this file does input and output. What it prints is computed by `readCanonical`, `writeBytes` and
`canonicalize`, the functions `Core.Canon2Proofs` is about.
-/

namespace Core.Canon2Oracle

def hexChar (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hex (b : ByteArray) : String :=
  b.foldl (fun s x => (s.push (hexChar (x.toNat / 16))).push (hexChar (x.toNat % 16))) ""

def line (b : ByteArray) : String :=
  let strict := match readCanonical b with
    | .error e => "refuse " ++ e.name
    | .ok v => "ok " ++ hex (writeBytes v)
  let canon := match canonicalize b with
    | .error e => "refuse " ++ e.name
    | .ok c => "canon " ++ hex c
  strict ++ " ; " ++ canon

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
