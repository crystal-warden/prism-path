# The verified policy core: Level M with field definitions

*Specification of the narrow core PrismPath proves once and every implementation is held to: one
decision of a match action policy over integers, booleans and strings, with the signed field
definitions that say what each integer means. November 2026, research line, branch `verified-core`;
step 2 on `verified-core-2`, step 3 on `verified-core-3`, step 4 on `verified-core-4`, the JavaScript and Go
kernels on `core-js-go`.*

This document defines the core precisely enough that its Lean semantics (`formal/Core`), the oracle
compiled from it, and the differential harness that holds the other implementations to it all refer
to one text. Where a rule comes from the Python reference, the reference is cited by file and line on
this branch; where the reference and another implementation disagree on the slice, the disagreement
is listed in section 9 with a reproducer and the side this specification takes. Those are bugs to
settle, not behaviours to prove around.

## 1. Scope

**In the core.**

1. One decision: a policy is an ordered list of rules, each a Level M condition (SPEC.md section 4.3)
   and a target, together with field definitions (SPEC.md section 4.5); a reading is routed to the
   target of the first rule whose condition holds.
2. The field definition grammar, the exact decimal thresholds of `fixed` fields and their lowering to
   canonical integers, and the six policy rules of SPEC.md section 4.5.
3. The canonical boundary on a reading (`field_definitions.accept_canonical`).
4. The document layer: a policy image and a reading are canon/2 documents (section 3), read by one
   reader with its own refusals.
5. A refusal, with a cause, for every input that is not routed.

**Outside the core, stated so.**

- The flow engine: several nodes, `visits` and `error_count`, the error and event tiers, suspension,
  `max_steps`, workers. A condition that reads an engine counter is refused by the core
  (`policy:engine-counter`), since the core has no registers.
- Semantic edges and every router.
- The inferred path of SPEC.md section 4.5 (a flow that defines no fields, whose kinds are inferred from
  its constants). The core reads only defined fields; an undefined field is refused.
- The Markdown flow text and the Python flavoured `when` surface. The core's syntax is the abstract
  syntax of section 2; the surface is a front end that lowers to it, and the harness's renderer
  (section 8) is one such front end.
- Signatures, envelopes, receipts, the `.ppt` table image and the table targets. The table image is a
  compilation target of the core (step 2, section 10), and a table target's narrower integer range
  (`int-out-of-i32`, SPEC.md section 4.3) is a target limit, not a rule of the core. The evidence a
  differential run writes (section 11) signs and receipts the core's decisions; it changes none of them.
- Floats of any kind. The core has none, in the image, in readings, or in its arithmetic.

## 2. Abstract syntax

### 2.1 The policy image

A policy image is a canon/2 document (section 3) that is an object with exactly the three keys
`format`, `fields` and `rules`, in any order:

```json
{"format": "prismpath.core/1",
 "fields": {"error_rate": "fixed scale=10000 unit=ratio rounding=floor min=0 max=10000",
            "label": "category absent=allowed"},
 "rules": [{"target": "hit",  "when": ["cmp", "error_rate", ">=", ["num", "0.85"]]},
           {"target": "gone", "when": ["cmp", "label", "==", ["none"]]},
           {"target": "low",  "when": ["and", ["cmp", "error_rate", "<", ["num", "0.25"]],
                                              ["cmp", "label", "==", ["str", "a"]]]},
           {"target": "miss", "when": ["always"]}]}
```

- `format` is the string `prismpath.core/1`.
- `fields` is an object from field name to definition text (section 2.5).
- `rules` is an array of objects with exactly the keys `target` and `when`. A target matches
  `[A-Za-z0-9_-]+`, the target of the flow grammar's edge line (`prismpath/kernel/parser.py:32`).

### 2.2 Conditions

A condition is an array whose first element names its form:

| form | meaning | Level M atom (SPEC.md 4.3) |
|---|---|---|
| `["always"]`, `["never"]` | the catch all rows | the keywords `always`/`else`/... and `false`/`never` (`predicates.py:27-28`) |
| `["truthy", f]` | truthiness of `f` | bare `field` |
| `["cmp", f, op, k]`, `op` one of `< <= > >= == !=` | `f op k`, the field on the left | `field OP constant` |
| `["in", f, [k...]]`, `["not in", f, [k...]]` | membership in a list of constants | `field in [...]` |
| `["not", c]` | negation | `not` |
| `["and", c1, c2, ...]`, `["or", c1, c2, ...]` | at least two operands | `and`, `or`, one n-ary node as Python's `BoolOp` |

A field name in a condition is `[A-Za-z_][A-Za-z0-9_]*` and not a Python hard keyword (SPEC.md 4.1;
`True`, `False` and `None` included); anything else is refused (`policy:not-level-m`, `name`). The
orientation of a comparison (`0.5 <= x`) and chained comparisons (`1 < x < 5`) are surface forms: the
front end writes them as field-left atoms and conjunctions (`level_m.py:86-102`, the one desugaring).

The forms outside the fragment that an image can still state are refused with the registered image
causes: a string constant under an ordering (`string-ordering`) and a membership whose right side is
not a list (`membership-not-in-a-list`, the substring test) are `image:unknown-op` (code 74); a
field reference as a constant (`["field", g]`, `field-vs-field`), a nested list
(`["list", ...]`, `nested-container`), an unknown constant tag, and a decimal literal on a field that
is not `fixed` (`float`) are `image:unknown-type` (code 75). These follow the classifier's reasons
(`level_m.py:18-26`, `_atom_reason` at `level_m.py:42-83`, `_scalar_const` at `level_m.py:32-39`).

### 2.3 Constants

| constant | meaning |
|---|---|
| `["num", n]`, `n` a JSON integer | the integer `n` |
| `["num", s]`, `s` in canonical integer spelling `-?[1-9][0-9]*`, outside the exact range | that integer, at any size (an integer literal of the reference, which Python holds exactly) |
| `["num", s]`, `s` decimal text with a `.` or an exponent | a decimal literal, read exactly (section 2.4) |
| `["bool", b]` | `True` or `False` |
| `["str", s]` | a string, compared by code points |
| `["none"]` | `None`, the absent value |

A string that spells an integer inside the exact range (`"5"`) is refused (`policy:shape`,
`integer-as-string`): canon/2 writes such an integer as a number, so the image has one spelling for
it. Other strings are refused as `number-spelling` (an integer spelling that is not canonical) or
`number-text` (not decimal text at all).

### 2.4 Decimal literals and depth

A decimal literal is the reference's DECIMAL_TEXT, `[+-]?(digits(.digits*)?|.digits)([eE][+-]?digits)?`
(`field_definitions.py:54`), read as the exact rational `± digits × 10^(exponent − fraction length)`
(`decimal_fraction`, `field_definitions.py:188-197`). It has at most 28 significant digits (every
mantissa digit after the leading zeros) and an exponent of at most 30 in magnitude
(`field_definitions.py:55-56`); a literal past either bound is refused (`policy:threshold`, `digits`).

The depth of a condition is the depth the reference's static check measures on its lowered text
(`predicates._depth`, `predicates.py:179-182`, applied at `predicates.py:169`): `truthy` 1, every
comparison and membership 2, `not c` one more than `c`, `and`/`or` one more than its deepest operand,
the keywords 0. A condition deeper than 50 (`predicates.py:32`) is refused (`policy:not-level-m`,
`depth`). Since step 3 the reference and the port measure it on the condition as the core decodes it
(`field_definitions.decode_condition`, Rust `decode_condition`), after the one desugaring of chains,
which is Lean's `Cond.depth` term for term. The harness confirms the measure: on 20,000 random conditions the core's depth exceeds 50
exactly when `check_predicate` reports the lowered condition nested too deeply.

### 2.5 Field definitions

A definition is a kind word followed by `option=value` words, as the reference's `parse_definition`
reads it (`field_definitions.py:134-178`):

- words are separated by runs of the whitespace Python's `str.split()` splits on (`str.isspace`:
  U+0009 to U+000D, U+001C to U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029,
  U+202F, U+205F, U+3000);
- the name is `[A-Za-z_][A-Za-z0-9_]*` and not `visits` or `error_count`;
- the kind is `int`, `fixed`, `bool` or `category`, and the options it takes are those of
  `field_definitions.py:62-67`; an option appears once and has a non-empty value after the first `=`;
- `absent` is `refused` (the default) or `allowed`;
- a `fixed` field has `scale`, an integer from 1 to 10^9, and `rounding`, one of `floor`, `ceiling`,
  `exact`; `unit` is free text and changes no rule;
- `min` and `max` are `[+-]?[0-9]+` (ASCII digits), default to plus or minus 2^53 minus 1, and satisfy
  `−(2^53−1) ≤ min ≤ max ≤ 2^53−1` (`field_definitions.py:170-177`).

Definitions are parsed in code point order of their names; the first that breaks a rule refuses the
policy (`policy:definition`, with the field and one of `name`, `engine-counter`, `empty`,
`unknown-kind`, `not-option`, `option-not-taken`, `option-repeated`, `absent`, `not-integer`, `scale`,
`rounding`, `fixed-needs-scale-and-rounding`, `range`).

## 3. The canon/2 document rules

A policy image and a reading are canon/2 documents. canon/2 is the no float profile of RFC 8785
proposed in the policy language research note: the documents are JSON (RFC 8259) and the reader
refuses, with the cause in parentheses:

1. bytes that are not UTF-8: overlong forms, encoded surrogates, anything past U+10FFFF, truncated
   sequences (`utf8`);
2. text that is not JSON, including `NaN`, `Infinity`, a byte order mark and trailing text (`syntax`);
3. a number with a fraction or an exponent, which is a float whatever its value (`float`);
4. an integer outside plus or minus 2^53 minus 1 (`integer-range`); wider values are decimal strings;
5. the integer written `-0` (`negative-zero`);
6. an object that holds a key twice (`duplicate-key`);
7. a `\u` escape that names half of a surrogate pair alone (`lone-surrogate`);
8. nesting of arrays and objects deeper than 128 (`depth`).

The first rule broken, reading left to right, names the refusal. A policy image that does not read
is refused as `policy:unreadable`; a reading that does not read is refused as `reading:unreadable`.

**Only the canonical bytes are read** (owner decision, 2026-11-10). A text that breaks none of the eight
rules is still refused unless it is exactly the canonical spelling of the value it reads to (the writer's
bytes below): whitespace anywhere, members out of key order, a needless escape (`\/`, `\u0041`, an
uppercase hex digit, a surrogate pair escape for a character that is written raw) are refused as
`not-canonical`. A policy image so refused is `policy:not-canonical` (code 101), a reading
`reading:not-canonical` (code 102), and every other hashed or signed document `document:not-canonical`
(code 103; SPEC.md section 8, which also fixes the one line feed a file or a line may end with). The rule
comes after the eight: a text that breaks one of them is refused for it, so `not-canonical` names exactly
the documents that read but are spelled otherwise. Nothing is re-canonicalized on the way in. Text a
person wrote is written through the **canonicalize path** first: `Core.canonicalize`, its twins
`canon2.canonicalize` (Python), `canon2::canonicalize` (Rust), `canon2Canonicalize` (JavaScript) and
`Canon2Canonicalize` (Go), and for whole documents `canon.canonicalize_document`, its Rust twin
`durable::canonicalize_document` and the command `prismpath canonicalize`, which read by every rule but the
spelling and return the canonical bytes. It is a writer's step; no reader calls it.

**The readers.** canon/2 is the one reader and writer of the core's documents, in five
implementations held to one table: the Lean strict reader `Core.readCanonical` (`formal/Core/Canon2.lean`)
over the rules of `Core.readBytes` (`formal/Core/Json.lean`), which define it; the Python reference `prismpath/kernel/canon2.py` (`loads`, `dumps`); its Rust twin
`prismpath-rs/src/canon2.rs` (`read`, `write`); and the two second tier kernels, JavaScript
(`canon2Read`, `canon2Write` in `prismpath/portable/prismpath.mjs`) and Go (`Canon2Read`, `Canon2Write` in
`prismpath-go/canon2.go`). The frozen vectors
`prismpath/portable/conformance/canon2.json` (written by `prismpath/portable/gen_canon2_fixtures.py`,
version 2, 87 byte strings, every rule above at least once and the first rule broken where several are,
18 spellings refused as `not-canonical` with the canonical bytes `canonicalize` gives them) are
replayed by `prismpath/tests/test_canon2.py`, which also runs every vector through the oracle, and by
`prismpath-rs/tests/test_canon2.rs`, `prismpath/portable/run_vectors.mjs` and `prismpath-go/conformance_test.go`.
The Lean writer `Core.writeBytes` and the strict reader `Core.readCanonical` (`formal/Core/Canon2.lean`) define the
canonical spelling, and section 3.2 states what is proved about them.
The writer emits RFC 8785 with no float: no whitespace, members in
order of the UTF-16 code units of their keys, strings as raw UTF-8 with only `"`, `\` and the control
characters escaped (`\b \t \n \f \r`, otherwise lowercase `\u00xx`), integers in decimal; it refuses
every value the reader would refuse, so a written document reads back to the same value and its bytes
are a fixed point. In the differential harness every leg reads the image and every reading with its
strict canon/2 reader, so a document level difference is a finding; there is no reader gap (section 8).
The generator sends images and readings as their canonical bytes, and 8 percent of them respelled, which
every leg must refuse with `policy:not-canonical` or `reading:not-canonical`.

**canon/1 is retired.** `prismpath.canon`'s Python `json` encodings (compact and spaced) and their Rust twin
`value::parse_strict` read and hashed everything signed before canon/2: policy packs and envelopes, audit logs
and their Merkle leaves, root statements, attestation manifests, lock hashes, checkpoints and every frozen
corpus. They are gone (section 3.1): canon/2 is the one encoding of everything hashed or signed, and a document
that does not name it is refused.

### 3.1 Migration of the rest (done on the canon2-migration and canon2-finish branches, 2026-11-10)

Signed bytes cannot be rewritten, so the rest moved by versioning, and then the old reading was removed:

1. **A name and a domain tag.** A document written under canon/2 says so: the core's image carries
   `prismpath.core/1` (whose definition includes canon/2), and every other artifact that moved gained an
   `encoding: "canon/2"` member, and its signature a `canon/2` domain prefix (root statements carry one of their
   own, `prismpath-root-statement/2`, now `/3`), so a verifier never guesses which reader to use. A differential
   run's root statement is `prismpath.core-run-root/1`, now `/2` (section 11: both were bumped when the tree
   became RFC 6962's).
2. **canon/1 is retired.** The first plan kept a verify only canon/1 reader and frozen canon/1 twins of the
   corpora. The owner decided (2026-11-10, evening) to retire it at once, since no one has used the system yet:
   no reader, no encoder and no corpus of canon/1 remains. A document with no tag, or any tag but canon/2, is
   refused with a named cause and never read under another encoding: an untagged audit line is skipped and the
   log does not verify (`bad_format`), an untagged root statement is `bad_format`, a `prismpath-root-statement/1`
   likewise, an untagged pack, flow manifest or registry is `manifest:bad-format` or `registry:bad-json`, an
   untagged envelope is `envelope:sig-invalid`, an untagged epoch journal line, lock or receipt is refused
   (`JournalCorrupt`, `LockError`, a receipt that does not verify). A complete line that is not canon/2 is never
   dropped as a torn write; only a line that is not JSON, at the end, is.
3. **Audit events.** `ts` is an integer count of microseconds since the epoch (`ts_us`); an event names its
   encoding. A float in an audit event's data is refused.
4. **A float in hashed content is refused.** In content PrismPath hashes but did not write (a connector's data, a
   decision outcome, a composer item, a ledger proof, the compliance adapter's receipts and catalogs, an
   operator's control data in Mission Control) a float anywhere raises `FloatRefused` in Python (an
   `EncodingError`) and the same words as a `CanonicalError` in Rust, which tell the caller to supply an integer
   of a stated unit or a decimal string. The earlier rule, a float written as its shortest decimal string, made
   PrismPath the author of a spelling and is gone. The one place a float is still carried is the lock file's two
   hyper-parameters (`delta`, `centroid_prior_weight`), which the lock format defines as decimal strings.
5. **Plain JSON stays plain, and is held out of every hash.** A durable run checkpoint, the connector's JSONL
   sink lines and the flow authority's version floor file are not hashed or signed. They are read and written with
   `canon.plain_load`, `plain_loads` and `plain_dumps` (Rust: `value::parse_plain`, `durable::plain_dumps`), the
   document `plain_loads` reads is a `PlainDict`, and every hashing helper of `prismpath.canon` refuses one
   (`PlainJSONRefused`). `prismpath/tests/test_plain_json_never_hashed.py` also holds, in the source of Python and
   Rust, that no function that reads or writes plain JSON also hashes or signs.
6. **Order.** Python first, then Rust, then JavaScript. The Go kernel and the table targets sign and hash nothing
   and hold no canon/1 (`prismpath/tests/test_canon2_migration.py` sweeps every language for it).

**What was done.** The rule is one pair of functions in each language: `prismpath.canon.document_bytes` and
`signed_message`, and `prismpath_rs::durable::document_bytes` and `signed_message` (JavaScript:
`documentString`), which require the document's own tag, and the writers' `canon2_bytes` and `tagged`. The
signature domain of a document without one of its own is `prismpath.canon/2` and a zero byte (`CANON2_DOMAIN`).

- The audit log's and the epoch chain's statements are `prismpath-root-statement/2` (canon/2, `encoding`,
  `time_us`, its own domain), and `/3` since the tree became RFC 6962's (section 11). Pack and flow manifests, envelopes and the crypto registry carry `encoding` and
  are signed over the canon/2 domain; so are the compliance adapter's receipts.
- `canon.loads_document` and `durable::read_document` read a document that names canon/2 with the strict
  canon/2 reader and refuse anything else, an object with another tag or none and a value that is not an object.
- Also moved: the policy host's intent and active records, the epoch journal's chain, gap and acknowledgment
  records and data files, the acknowledgment tag's message, attestation and OpenTimestamps manifests, the stamp
  request and proof bundle records, and the lock file.
- Removed with canon/1: `canonical_compact`, `canonical_spaced`, `CANON1`, `canon.loads` and `dumps_strict` (now
  `plain_loads` and `plain_dumps`), `try_py_canonical_string` (now `plain_dumps`, used only for the sink's
  line and a message), `parse_strict` (now `parse_plain`), `pyCanonicalString`, the `prismpath-root-statement/1`
  reader, the corpora `canonical.json`, `receipts_canon1.json` and `hotswap_canon1.json` and the generator of
  the first. `receipts.json` and `hotswap.json` keep the cases built from what canon/1 wrote, as refusals.
- A Rust acknowledgment sequence beyond plus or minus 2^53 minus 1 is refused with a `CanonicalError`, as
  Python raises `EncodingError`, in `canon`, `sign_ack`, `verify_ack` and `AckReceiver::on_ack`; none panics.

**Artifacts that were canon/1 and were not re-signed.** `prismpath-hw/demo/flows/*.ppt.manifest.{json,sig}`,
`prismpath-hw/demo-display/switch_nav.ppt.manifest.{json,sig}` and the three copies in
`prismpath-hw/hyst-cert/evidence/` are pack manifests signed under canon/1 by a demo authority key whose
private half is not kept, and the evidence copies are named by an anchored `SHA256SUMS`; they are historic
records, no product code reads them, and `prismpath-hw/hyst-cert/VERIFY.md` says how to check them.
`prismpath/comparisons/results/prismpath/evidence/A8/receipt_root.json` is a recorded result of a comparison
harness run, signed the same way. `prismpath/flows/wazuh_triage_decomposed.lock` was re-written as a canon/2 lock.

**What remains.** Not hashed or signed, so not moved: a durable run checkpoint (its state may hold floats that a
resume must see unchanged), the flow authority's version floor file, the sink's JSONL records, the receipt
stream's binary wire frames, and the comparison harnesses that model other systems.

### 3.2 The encoding layer, proved (formal/Core/Canon2.lean, Canon2Proofs.lean, 2026-11-10)

The Lean development has a canon/2 writer beside the reader, and the two are proved inverse. The writer,
`Core.writeBytes`, spells a value with no whitespace, the members of every object in the order of the UTF-16
code units of their keys, strings as raw UTF-8 with only `"`, `\` and the control characters escaped (`\b \t
\n \f \r`, otherwise lowercase `\u00xx`), and integers in decimal with no leading zero and a minus sign only
before a nonzero magnitude, as the writers of the other four implementations do. It is total; its domain,
the canonical values, is decided by `Core.canon`: no object holds a key twice, every integer lies within plus
or minus 2^53 minus 1, nesting is at most 128 deep, and in every object the keys strictly increase in UTF-16
code unit order. A Lean string holds Unicode scalar values only, so no value holds a lone surrogate by its
type. The strict reader, `Core.readCanonical`, reads a byte string with `Core.readBytes` and accepts it
exactly when it is the writer's spelling of the value read, and otherwise refuses it with the reader's own
cause or `not-canonical` (`DocErr.notCanonical`, a cause `readBytes` never returns). It is the core's one
reader: `Core.verdictBytes` reads the image and the reading with it, and the oracle reads with nothing else.
`Core.canonicalize` is the writer's step for text a person wrote. The theorems, in words:

1. **What the reader returns** (`readChars_doc`, `readBytes_doc`). Every value the reader returns holds no
   key twice in any object, only integers within the exact range, and nests at most 128 deep.
2. **Round trip** (`read_write`, `readChars_wr`). For every canonical value, the reader reads the writer's
   bytes back to that value. More generally, every value the reader could return, spelled with its members
   in the order given, reads back to itself.
3. **The canonical form of an accepted document** (`canonical_form`, `read_write_doc`,
   `same_value_same_spelling`). For every byte string the reader accepts, the writer's bytes of its value are
   a canonical document that reads back to the value's normal form (the same members, every object's in key
   order), and writing that normal form gives the same bytes again; two accepted documents whose values have
   the same members, in any order, have byte identical canonical spellings.
4. **One spelling per value** (`write_injective`, `readCanonical_unique`). The writer is injective on
   canonical values, and two byte strings the strict reader accepts with the same value are byte identical.
5. **Canonicity** (`readCanonical_iff`, `write_readCanonical`, `readCanonical_write`). The strict reader
   returns a value exactly when the value is canonical and the bytes are the writer's bytes of it: the
   accepted documents are exactly the canonical spellings, and for every one of them writing what was read
   gives back the input.
6. **Refusal** (`readCanonical_refuses`, `readCanonical_cause`). Every byte string that is not the canonical
   spelling of a canonical value is refused by the strict reader, with the reader's cause when it is not a
   document and `not-canonical` when it is a document spelled otherwise.
7. **The reader alone is not canonical** (`reader_not_canonical`). `Core.readBytes`, the reader this section
   defines and every implementation shares, accepts `[ ]`, `{"b":null,"a":null}` and a string with a needless
   `\u` escape, none of them a canonical spelling; the strict reader refuses all three.

8. **The core reads strictly** (`noncanonical_image_refused`, `noncanonical_reading_refused`,
   `unreadable_bytes_refused`, `verdictBytes_canonical`, `route_canonical`, `decided_reading_unique`). An
   image that reads but is not its canonical spelling refuses every reading with `policy:not-canonical`;
   under an accepted image, a reading that reads but is not its canonical spelling is refused with
   `reading:not-canonical`, so a respelling of a reading that routes does not route; a reading that is not a
   document is refused with its reader rule as before; on canonical bytes the decision is `Core.verdict` on
   the values; a route is given only when the image and the reading are each the writer's bytes of a
   canonical value; and two reading byte strings the strict reader accepts with the same value are the same
   bytes and get the same verdict.
9. **The canonicalize path** (`canonicalize_readCanonical`, `canonicalize_canonical`, `canonicalize_error_iff`,
   `canonicalize_idem`). What `canonicalize` writes for any text the reader reads is accepted by the strict
   reader, as the normal form of the value read; it is the identity on canonical bytes; it refuses exactly
   what the reader refuses, with the same cause, and never for the spelling; and it is idempotent.

Item 7 is why the readers were made strict. When these proofs were first written, every reader (the spec's
and all five implementations') accepted any legal spelling and the strict reader was proved but unused; the
eight rules refuse what is not a canon/2 document and none of them refuses whitespace, member order or an
escape, as RFC 8785 canonicalizes any JSON text. The owner decided (2026-11-10) that every hashed or signed
document and every reading must arrive as its exact canonical bytes, so the core now decides with
`readCanonical` (item 8) and every implementation's reader refuses what it refuses, with the same cause.
`verdict_text_perm`, which says two readings whose members are a permutation of each other get the same
verdict, still holds of the values `readChars` returns; under the strict reader at most one spelling of a
reading is accepted at all (`decided_reading_unique`).

The writer, the strict reader, `canonicalize`, `Core.verdictBytes` and `Core.verdict` depend on `propext` only
(the decimal digits are well founded recursion whose decreasing proof is `Nat.div_lt_self`, not `omega`, whose
proof terms carry `Quot.sound`); the theorems depend on at most the standard three.
`lake exe canon2-oracle` is the compiled strict reader, writer and canonicalize path (`formal/Core/Canon2Main.lean`), and
`formal/diff/canon2_diff.py` holds the Python, Rust, JavaScript and Go readers and writers to it
(`docs/research/verified-core-summary.md`, section 3).

## 4. The checks of a policy

After the image reads, the core decodes and checks it in this order; the first failure is the refusal.

1. **Shape and fragment** (section 2): the keys of the image and of each rule, the format tag, each
   definition a string, each condition and constant well formed, each name allowed, each condition no
   deeper than 50. Rules are decoded in order and a condition depth first, left to right.
2. **Definitions** (section 2.5), in code point order of the names.
3. **Lowering and rules 1 to 5** of SPEC.md section 4.5, rule by rule in order, atom by atom left to
   right (`apply_definitions`, `field_definitions.py:506-517`; `lower_expression`,
   `field_definitions.py:335-386`; `_atom_problem`, `field_definitions.py:432-467`):
   - a field an atom reads must be defined (rule 2): `image:field-index-oob` (code 76);
   - `None` only under `==` or `!=` (`ordered`), only on a field that allows absence
     (`absence-refused`), never in a list (`in-list`) (rule 5): `policy:none`;
   - kinds (rule 3): a `bool` field only by truthiness or `==`/`!=` with a boolean, a `category` field
     only by truthiness, `==`/`!=` with a string, or membership in strings, an `int` or `fixed` field
     only with numbers: otherwise `policy:kind-mismatch`;
   - on an `int` field every constant is an integer literal inside `[min, max]`
     (`policy:threshold`, `constant-range`); a decimal literal is a float, `image:unknown-type`;
   - on a `fixed` field every numeric constant is in the field's unit and is lowered to
     `value × scale`; it must be a whole number of units (`off-grid`) and lie in `[min, max]`
     (`out-of-range`), both `policy:threshold`; an integer literal `n` lowers to `n × scale`
     (SPEC.md 4.5, "`error_rate >= 1` means 1.0");
   - on a `fixed` field the rounding mode carries only its operators (rule 4,
     `field_definitions.py:71-75`): `floor` carries `>=` and `<`, `ceiling` carries `>` and `<=`,
     `exact` carries every comparison, membership and truthiness: otherwise `policy:rounding`.
4. **Rule 6**: every field that allows absence is tested with `== None` or `!= None` by some rule,
   checked in code point order: `policy:absence-untested`.

A policy that passes is *checked*: its definitions, and its rules with every constant a canonical
literal (an integer, a boolean, a string, or `None`).

**One cause per refused policy (D7, resolved in step 3).** The order above is normative, not a property
of the oracle: a policy with several problems is refused for the first, in every implementation, with
the field and the reason the oracle names. Within one atom the order is the field name, then the
operator, then the constant (`decodeCond`); a rule's depth is checked after its whole condition decodes;
and an atom's check against its definition runs as `checkCmp`, `checkMem` and `checkTruthy` run: `None`
first (an ordering, then a refused absence, then a `None` in a list), a decimal on a `bool` or `category`
field before its kind, on a `fixed` field a numeric constant under an operator its rounding does not
carry before its value, then each member's value in order (`int` range, a decimal on an `int` field,
off grid, out of range) and only then the rounding of a membership or a truthiness test. The Lean
semantics enumerates every problem in this order (`policyProblems`, `formal/Core/Order.lean`) and
proves the refusal it computes is the head of that list (section 7). The Python reference
(`field_definitions.core_problems`, called by `apply_definitions`) and the Rust port (`core_problems`,
called by its `apply_definitions`) enumerate the same list phase by phase: they decode every rule first,
then parse every definition in code point order, then check every decoded atom against its parsed
definition, then rule 6, so the first problem is the refusal (`FieldDefinitionError.cause`, `.field` and
`.reason`; Rust `Graph.field_error_cause`, `field_error_field`, `field_error_reason`), and the whole list,
one problem per atom, stays for diagnostics (`FieldDefinitionError.problems`, `Graph.field_error_causes`).
Only then do they lower the conditions' text. The engine's counters stay outside the core (section 1): the
reference and the port route on them, so an atom that reads one is not checked, and a policy the oracle
refuses for reading one is a scope difference. The frozen field definition vectors hold seven such
policies (`d7_*` in `field_definitions.json`), and the Rust replay checks the port's whole list against
the reference's.

## 5. Refusals and their causes

Every input that is not routed gets exactly one of these refusals, and every one is a registered row of
`prismpath/kernel/causes.py` (append only; rows 89 to 100 were appended for the core in step 2, the
policy refusals in the `envelope` class beside the pack verifier's structural refusals, the two reading
refusals in the `routing` class). The Lean semantics spells each refusal with its code and name
(`Refusal.code`, `Refusal.cause`, `formal/Core/Eval.lean`), and the theorem `refusal_registered` proves
every pair is a row of the registry, which `gen_causes_rs.py` generates into `formal/Core/Causes.lean`
beside the Rust table; so the oracle never prints a refusal without a code. The Python reference
carries the cause on every refusal (`FieldDefinitionError.cause`, `.code`, `.field`, `.reason`, and
`.problems`, each a `Problem` with its own cause), the Rust port on the graph (`Graph.field_error_cause`,
`field_error_field`, `field_error_reason`, `field_error_causes`), and the frozen field definition vectors
record the cause of every refused policy and of every problem in order, which the Rust replay checks.

| refusal | cause | code | when |
|---|---|---|---|
| image unreadable | `policy:unreadable` | 89 | section 3, on the image |
| image not its canonical spelling | `policy:not-canonical` | 101 | section 3, on an image that reads |
| reading not its canonical spelling | `reading:not-canonical` | 102 | section 3, on a reading that reads |
| image shape | `policy:shape` | 90 | section 2, the image is not the core's syntax |
| operator outside Level M | `image:unknown-op` | 74 | `causes.py:74`, an atom's operator outside the fragment |
| value type outside Level M | `image:unknown-type` | 75 | `causes.py:75` |
| name or depth outside Level M | `policy:not-level-m` | 91 | section 2.2, 2.4 |
| malformed definition | `policy:definition` | 92 | section 2.5 |
| undefined field | `image:field-index-oob` | 76 | `causes.py:76`, an atom names a field the policy does not declare |
| engine counter read | `policy:engine-counter` | 93 | section 1 |
| kind mismatch | `policy:kind-mismatch` | 94 | rule 3 |
| rounding mode | `policy:rounding` | 95 | rule 4 |
| threshold | `policy:threshold` | 96 | lowering and ranges |
| `None` misused | `policy:none` | 97 | rule 5 |
| absence untested | `policy:absence-untested` | 98 | rule 6 |
| reading unreadable | `reading:unreadable` | 99 | section 3, on the reading |
| reading not an object | `reading:not-object` | 100 | section 6 |
| value refused at the boundary | `route:contract-violation` | 37 | `causes.py:48`, the reading violates the declared definitions; the field and `missing`, `wrong_type` or `out_of_range` |
| no rule holds | `route:no-matching-edge` | 32 | `causes.py:43`, refused for admission |

A policy refusal refuses every reading with the same refusal. The image refusals 74 to 76 keep their
pack verifier names: the operator, value type and field index of a table image are the same three
facts about an atom.

## 6. Evaluation

For a checked policy and a reading that reads:

1. **Object.** The reading must be an object; any other document is `reading:not-object`.
2. **Boundary.** Every defined field, in code point order of the names, is checked against its
   definition (`accept_canonical`, `field_definitions.py:283-304`, in the composition of
   `gen_field_definitions._boundary_refusal`, `prismpath/portable/gen_field_definitions.py:152-158`):
   a missing key or `null` is the absent value, accepted only if the definition allows absence, else
   `missing`; a `bool` field takes a boolean, a `category` field a string, an `int` or `fixed` field an
   integer in `[min, max]` (else `out_of_range`); every other value is `wrong_type`. The first failure
   is `route:contract-violation` with the field and the reason. Keys the policy does not define are
   ignored. Since canon/2 has no float, the reference's `fractional` and `binary_float` reasons cannot
   arise.
3. **Conditions** (SPEC.md 4.2 on canonical values): `truthy` holds on a present value that is a
   non-zero integer, `true`, or a non-empty string; `== None` holds exactly on absence and `!= None`
   exactly on presence; on an absent field `!= k` and `not in` hold and every other atom fails; on a
   present value equality is by kind and value, ordering is defined on integers only, membership is
   equality with some member; `and` and `or` read every operand.
4. **First match** (SPEC.md section 3, step 1): the verdict is `route t` for the target `t` of the
   first rule whose condition holds; when none holds, `route:no-matching-edge`.

### 6.1 The system boundary and the policy check (D4, resolved)

Which fields a reading must hold canonically depends on who is checking (owner decision, 2026-11-10).
The two checks have distinct names and both are part of the core:

- **The system boundary** validates the soundness of the *system*: every field the policy defines, in
  code point order, is the reading's contract, whether or not a rule reads it. It is the boundary of
  step 2 above and the one the verdict applies; the frozen field definition vectors replay it.
  Lean `systemBoundary` (`formal/Core/Eval.lean`), Python `field_definitions.system_boundary`, Rust
  `field_definitions::system_boundary`.
- **The policy check** validates the soundness of a *policy*: only the defined fields some rule reads
  (the *routed* fields, `rulesFields` and `Checked.routedDefs` in Lean, `routed_fields` in Python and
  Rust), in code point order. It is what SPEC.md section 4.5 means by a canonical reading ("every
  defined field the flow routes on") and what the Facet quantizer checks for the fields it partitions
  (`prismpath/telemetry/quantizer.py:150-160`); it belongs to policy validation and lint, and it never
  produces a verdict. Lean `policyCheck`, Python `field_definitions.policy_check`, Rust
  `field_definitions::policy_check`.

How they relate is proved in `formal/Core/Boundary.lean`: a reading the system boundary accepts passes
the policy check (`policyCheck_of_systemBoundary`), so a reading the policy check refuses the system
boundary refuses too (`systemBoundary_of_policyCheck`) and the system boundary is at least as strict on
every reading; a policy check refusal names a routed field (`policyCheck_refuses_routed`); on a policy
that routes on every field it defines the two are the same function (`policyCheck_eq_systemBoundary`);
and the route of a reading the system boundary accepts depends only on the values of the routed fields
(`route_depends_on_routed`), which is why the policy check is the right check of a policy and the
system boundary the stricter contract of the system. The oracle's batch mode prints the policy check
beside every verdict, and the differential holds both legs to it (section 8).

## 7. The theorems

Proven in `formal/Core`, with no `sorry` and only Lean's standard axioms (`FQ/Axioms.lean` prints the
audit at every build). The evaluator itself, `Core.verdict`, depends only on `propext`: nothing it
computes goes through `Classical.choice`, which is why the core decodes UTF-8 itself.

**Termination.** `verdict_total`: every image and reading has a verdict; `verdict` and everything it
calls are defined by structural recursion, with no `partial` definition, so this is the kernel's own
guarantee. `matchSteps_le`: routing a reading evaluates at most as many atoms as the policy has, a
bound fixed when the policy is signed.

**No fail open.** `policy_refusal_refuses_all` and `unreadable_image_refused`: an image that does not
read, decode or check refuses every reading with its refusal. `unreadable_reading_refused` and
`boundary_refusal`: under an accepted policy a reading that does not read or that the boundary refuses
is refused. `route_sound`: a route is produced only when the image read and checked, the reading read
as an object and every definition accepted its value, and the route is the target of the first rule
whose condition holds, every earlier one failing. `route_is_a_target`: a route is always a rule's
target.

**Refusal completeness.** `verdict_cases`: every pair of inputs falls in exactly one of six cases,
policy refusal, reading unreadable, reading not an object, boundary refusal, no rule holds, route, each
characterized by the stage that produced it and carrying a refusal of the closed type `Refusal`
(section 5). `policy_refusal_iff`: a policy refusal appears exactly when the policy fails.
`verdict_route_or_refuse`: the verdicts are a closed set. Together with totality: no input yields an
exception, a crash or an undefined result.

**Determinism.** `verdict_perm`, `decideReading_perm` and `verdict_text_perm`: the verdict on a reading
depends on its members and not on their order (the reader guarantees distinct keys, `readChars_wf`).
`evalC_congr`: a condition's truth depends only on the canonical values of the fields.

**The bridge to FQ** (`Core/Bridge.lean`). `evalC_toX` and `firstMatch_eq_routeX`: the core's
evaluation is FQ's `evalX` and `routeX` (formal/FQ/Absence.lean) on the translated policy.
`boundary_canonical`: a reading the core's boundary accepts is canonical in FQ's sense for the
partitions of any policy the core accepts. `accepted_quantization_preserves`: so two readings the core
accepts with the same Facet quantization get the same verdict (from `FQ.absence_preservation`), and
`core_reconstruct_route`: the decoded reading routes as the reading (from `FQ.reconstructX_route`).
`scaled_correct` and `lowered_threshold_preserves`: a decimal threshold the core lowers on a `fixed`
field decides on the canonical integer of any rational source value as the authored decimal decides on
the source value (from `FQ.Conversion.convert_preserves`).

**The two checks of a reading** (`Core/Boundary.lean`, step 2, section 6.1).
`policyCheck_of_systemBoundary`: a reading the system boundary accepts passes the policy check.
`systemBoundary_of_policyCheck`: a reading the policy check refuses the system boundary refuses, so the
system boundary is at least as strict on every reading. `policyCheck_refuses_routed`: a policy check
refusal names a defined field some rule reads, with the definition's own reason.
`policyCheck_eq_systemBoundary`: on a policy that routes on every field it defines, the two checks are
the same function. `route_depends_on_routed`: two readings the system boundary accepts that hold the
same values on the routed fields get the same verdict (from `evalC_congr_on` and
`firstMatch_congr_on`, a condition's truth depends only on the fields it reads).

**Every refusal carries a registered code** (`Core/Codes.lean`, step 2, section 5).
`refusal_registered`: the (code, name) of every refusal, of every one of the thirteen policy refusals
and the four reading refusals, is a row of the registry generated from `prismpath/kernel/causes.py`
(`Core/Causes.lean`). `refusal_code_ne_zero`: no refusal carries 0, the code of a clean decision.
`registry_codes_distinct` and `refusal_name_of_code`: the registry gives each code one name, so a code
alone names the cause. `verdict_refusal_registered`: whatever the inputs, a refused verdict carries a
registered nonzero code. The proofs are `decide` over the generated list, so a spelling that drifts from
the registry, or a registry regenerated without a row the core uses, fails the build.

**One cause per refused policy** (`Core/Order.lean`, step 3, section 4). `policyProblems` lists every
problem of a policy image in the order of section 4: the document, the image's shape and its
definitions as text, each rule's decoding refusal rule by rule, each definition's refusal in code point
order, each atom's lowering refusal rule by rule and atom by atom, and rule 6. `loadPolicy_first_problem`:
the refusal `loadPolicy` computes is the head of that list, and `policy_cause_is_first`,
`policy_accepted_iff_no_problem` and `verdict_policy_cause` state it as an equivalence, for acceptance
and in verdict terms. `lowerCond_first_atom`: lowering one condition refuses for its first atom the
field's definition refuses, depth first and left to right, and passes exactly when every atom passes.
So the cause of a refused policy is one function of the image, the oracle's, and an implementation that
names the head of the same list names the same cause.

**The engine counter exclusion** (`Core/Scope.lean`, step 4, section 11). `counterRefusal_iff`: the check
a run uses to exclude a case, `counterRefusal`, holds exactly when `loadPolicy` refuses the image with
`engineCounter`. `counter_excluded_refused`: then every reading's verdict is that refusal, so an excluded
case hides no route and no other refusal.

**Evidence and the semantics** (`Core/Evidence.lean`, step 4, section 11). The file models a run (its cases,
image signatures, exclusions, receipts, manifest and root statement) and its verifier, `verifyRun`: the
verifier of section 11 with `--sample all` and both keys pinned, its checks written as one boolean
function, with the cryptography as parameters (`Crypto`: the hash, the canon/2 bytes of a receipt, the
Merkle root, signature verification and the two signed messages) and the receipt's decision as
`record`, the oracle's spelling (`spellRefusal`) with an empty field or reason left out, as the producers
write it. `verified_receipt_is_verdict`: every receipt of a run `verifyRun` accepts carries the hashes of an
image and a reading of a case of the run and records `Core.verdict` on them. `receipt_is_verdict_of_hashes`:
it records `Core.verdict` on any image and reading bytes with those hashes that collide with no document
of the run. `verified_run_complete`: every reading of every case the run does not exclude has its receipt.
`verified_refusal_registered`: a recorded refusal carries the code and cause of the verdict's refusal, a
nonzero registry row. `verified_excluded_counter`: a case excluded as `engine-counter` refuses every
reading with it. `evidence_sound` gathers them: if the pinned instance key's signatures are unforgeable,
its holder signed the root statement; a list of as many receipts under that Merkle root that exhibits no
hash collision is exactly the run's receipts; and every receipt records `Core.verdict` on every image and
reading with its hashes that exhibits no collision. The cryptographic assumptions are explicit hypotheses,
each stated for the objects at hand and never for all inputs (no hash onto a finite set is injective):
`Unforgeable` (Ed25519 under the pinned key), `NoTreeCollision` and `NoCollision` (SHA-256, in the Merkle
tree, over the canon/2 writer and on the documents). No `sorry`: what is not proven is a hypothesis of the
theorem that needs it.

**A shipped image's invariants** (`Core/Population.lean`). The first theorems about one image rather than
every image: the governed population's admission and evaluation images
(`integrations/governed_population/policy/*.core.json`), whose bytes `gen_policy.py` generates into
`Core/PopulationImage.lean` and holds equal to the files by its `--check`. `admission_loads` and
`evaluation_loads`: the kernel reads the bytes with `readCanonical` and `loadPolicy` (by `decide +kernel`)
and gets the written-out checked policies the proofs compute with. Every invariant is then stated of
`verdictBytes` on the shipped bytes and any reading: `stop_always_allowed` (a stop by the operator or the
controller is allowed whatever else the reading holds, once it passes the boundary),
`replicate_allowed_only_within`, `evolve_allowed_only_with_canary`, `protect_never_allowed`,
`restart_of_stopped_never_allowed`, `allow_fails_closed` and its corollaries, `admission_targets_registered`
and `canary_passed_iff`. They are about the reading the controller forms; the controller is outside them.

**Not proven, stated as plainly.** That any implementation computes `verdict`: Python, Rust and the
other targets are *conformant* to the oracle by differential testing (section 8), not proven. The
order of the image's `fields` members does not change a verdict, because definitions are read in
sorted order, but the uniqueness of that sort is not yet a theorem. The FQ bridge theorems take FQ's
partitions as FQ defines them; the quantizer's code is held to those by FQ's own bridge vectors. That
the reference and the port compute the head of `policyProblems`: they are held to it by the
differential and the frozen vectors (D7, section 9), not by proof. The canon/2 readers of Python
and Rust are held to the Lean reader by the frozen vectors and the differential, not by proof. That
`core_evidence.verify` and its Rust twin compute `verifyRun`, and that the ported checks of an image
(`core_policy.load_policy`, Rust `oracle_policy`) compute `loadPolicy`, are held by the tamper tests and by
the scope check against the oracle on every image of the large run, not by proof; and the replay trusts
that the `core-oracle` binary computes `Core.verdict`, which rests on the Lean compiler, the C compiler
and the hardware.

## 8. The oracle and the differential harness

**The oracle.** `lake exe core-oracle POLICY [READING ...]` (built by `lake build` in `formal/`)
prints one JSON line for the policy, `{"policy":"accepted"}` or `{"policy":"refused","cause":...,
"code":...}`, then one line per reading, `{"verdict":"route","target":...}` or
`{"verdict":"refuse","cause":...,"code":...,"field":...,"reason":...}` with `field` and `reason` only
where the refusal has them; every refusal carries its registered code (section 5). `--batch` reads
framed cases (`case <id> <n>` then `n + 1` documents, each as its byte length and its bytes) and prints
one line per case, each reading's verdict with its policy check beside it (`"policy_check"`, section
6.1) when the policy is accepted and the reading is an object. Every printed value is computed by
`Core.verdict`; `formal/Core/Main.lean` only frames and spells.

**The harness.** `formal/diff/core_diff.py` generates random images and readings, well formed and
malformed, biased toward boundaries (ranges at plus or minus 2^53 minus 1 and at 2^31, scales from 1
to 10^9 and invalid ones, on and off grid decimals, decimals at the digit and exponent bounds, empty
and duplicate lists, conditions at depth 25 and 49 to 53 as `not` chains and as `and` and `or` nested
on the left, the right and alternately, absence, wrong types, Python's whitespace and U+FEFF in
definitions, strings with escapes and astral characters, floats, `-0`, wide integers, duplicate keys,
deep nesting, invalid UTF-8, malformed and truncated images). The reference and the ports read flows,
so the harness renders each well formed image to the flow text it means, with semantics preserving
surface variation (orientation, grouping, tuples, chains); an image without a faithful rendering is
compared on the oracle alone. Each case runs through the oracle and seven legs, each an adapter around
the implementation's own functions:

| leg | implementation | composition | documents |
|---|---|---|---|
| `python` | the reference | `parser.parse`, `field_definitions.system_boundary` and `policy_check`, `engine.first_deterministic` | canon/2 (`kernel/canon2.py`) |
| `rust` | `prismpath-rs` | the same, `prismpath-rs/examples/core_diff.rs` | canon/2 (`canon2.rs`) |
| `js` | `prismpath/portable/prismpath.mjs` | `parse` (which checks the policy in the core's order and lowers exactly, in BigInt), `systemBoundary`, `firstDeterministic`, `policyCheck`, `formal/diff/core_diff_js.mjs` | canon/2 (`canon2Read`) |
| `go` | `prismpath-go` | `Parse` (the same, in `math/big`), `SystemBoundary`, `IsDeterministic` and `EvalCondition`, `PolicyCheck`, `prismpath-go/cmd/core_diff` | canon/2 (`Canon2Read`) |
| `c-interp` | `prismpath-hw/interp.c` | host: the reference checks the policy, reads, applies the system boundary; `ppt_compile.py` compiles and encodes registers; the interpreter picks the edge (`formal/diff/ppt_batch.c`) | canon/2 on the host |
| `c-hdr` | `prismpath-hw/ppt_eval.h`, the embedded evaluator the FPGA's C twin and the firmwares include | the same | canon/2 on the host |
| `ebpf` | `prismpath-ebpf/ppt_eval_bpf.h`, the evaluator every XDP program there includes, on its userspace path | the same host and compiler; the loader's parser (`ppt_image.c`, `parse_image_buf`, whose limits are the C interpreter's) admits the table, which is written into the maps as `ppt_maps.c` writes them, and the evaluator's own text runs over a shim of its array maps and `bpf_loop` (`formal/diff/ebpf_batch.c`) | canon/2 on the host |

Each difference is classified: `agree`; a scope difference (the inferred path and engine counters,
section 1); `target-limit` (D6: the compiler or the register encoder refuses a value outside 32 bits, interp.c's
64 deep stack would overflow, or the eBPF loader refuses a table past a map capacity, past 32 fields or past the same depth of 64, which no table of the large run does); or a
finding, which is minimised to a small reproducer of the same kind. A policy both sides refuse agrees
only when the leg names the oracle's cause and, where the oracle's refusal names a field or a reason,
the same field and reason (`finding:cause` otherwise, D7); a policy the oracle refuses for reading an
engine counter is the scope difference of section 1. Every refusal of the five legs that speak the
registry must carry its registered code (`finding:uncoded` otherwise), and the first tier legs' policy
checks must equal the oracle's (`finding:policy-check`).

**Commands.** `python formal/diff/core_diff.py --cases 100000 --seed 1 --report out.json` is the large
run (all seven legs by default; `--legs` picks some). `prismpath/tests/test_core_diff.py` is the seeded
CI sized run (5,000 cases, seed 7, every leg whose toolchain is present, a few seconds): it fails on any
finding (section 9 records none since step 3), on any reading level, policy check or policy cause
disagreement, on any uncoded refusal and on any crash, and it replays the seven policies of D7's
regression set through every leg. The oracle comes from `lake build` in `formal/`; the Rust leg is the
example `prismpath-rs/examples/core_diff.rs`, built on demand; the Go, C and eBPF adapters are compiled
into a private temporary directory per run.

**The large run, `core-ebpf`** (100,000 cases, seed 1, 419,651 readings, the generator of `core-js-go`, so every
row but the eBPF row is that run's). The eBPF leg carries what the C interpreter carries, so it no longer
refuses a table the interpreter runs, and its row is the interpreter's row:

| leg | agree | scope | excluded | other | findings |
|---|---|---|---|---|---|
| ebpf | 146,673 | 10,265 inferred, 372 engine counter | 3,181 | target-limit 3,527 at compile, 2,070 on a reading | 0 |

The 86 readings that `core-js-go` counted as outside the eBPF subset are the 86 that now agree (146,587
to 146,673), and no `target-limit` row is the eBPF loader's any more; the other six legs read as before,
no finding on any of the seven.

**The large run, `canon2-strict`** (100,000 cases, seed 1, 420,399 readings; the generator now sends
documents as their canonical bytes and 8 percent of images and readings respelled, so the oracle's counts
differ from the runs below). Every leg reads with its strict reader; the oracle refused 32,591 readings for
an image that was not canonical (`policy:not-canonical`) and 4,020 readings that were not
(`reading:not-canonical`), and every leg named the same cause on each:

| leg | agree | scope | excluded | other | findings |
|---|---|---|---|---|---|
| python | 159,800 | 9,370 inferred, 307 engine counter | 2,083 | | 0 |
| rust | 159,800 | 9,370, 307 | 2,083 | | 0 |
| js | 159,800 | 9,370, 307 | 2,083 | | 0 |
| go | 159,800 | 9,370, 307 | 2,083 | | 0 |
| c-interp | 144,945 | 9,370, 307 | 2,083 | target-limit 3,113 at compile, 1,883 on a reading | 0 |
| c-hdr | 144,945 | 9,370, 307 | 2,083 | target-limit 3,113, 1,883 | 0 |
| ebpf | 144,945 | 9,370, 307 | 2,083 | target-limit 3,113, 1,883 | 0 |

**The large run, `core-js-go`** (100,000 cases, seed 1, 419,651 readings, the same generator as step 3, so the
oracle's counts are the same). The JavaScript and Go kernels decide the core (D5), so their rows have the
shape of the reference's and the port's, and the refusing kernel and reader gap classes no longer exist:

| leg | agree | scope | excluded | other | findings |
|---|---|---|---|---|---|
| python | 163,379 | 10,265 inferred, 372 engine counter | 3,181 | | 0 |
| rust | 163,379 | 10,265, 372 | 3,181 | | 0 |
| js | 163,379 | 10,265, 372 | 3,181 | | 0 |
| go | 163,379 | 10,265, 372 | 3,181 | | 0 |
| c-interp | 146,673 | 10,265, 372 | 3,181 | target-limit 3,527 at compile, 2,070 on a reading | 0 |
| c-hdr | 146,673 | 10,265, 372 | 3,181 | target-limit 3,527, 2,070 | 0 |
| ebpf | 146,587 | 10,265, 372 | 3,181 | target-limit 3,527, 2,070, and 86 readings of tables outside the eBPF subset | 0 |

Every refusal of the JavaScript and Go legs carries its registered code and the oracle's cause, field and
reason, their policy checks equal the oracle's on every reading, and the 22,035 policies they refused as a
refusing kernel in step 3 now route every reading as the oracle does.

**The large run, step 3** (100,000 cases, seed 1, 419,651 readings, the step 2 generator, so the
oracle's counts are step 2's below). Per leg, case level policy rows and reading rows together:

| leg | agree | scope | excluded | other | findings |
|---|---|---|---|---|---|
| python | 163,379 | 10,265 inferred, 372 engine counter | 3,181 | | 0 |
| rust | 163,379 | 10,265, 372 | 3,181 | | 0 |
| js | 60,492 | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 276 float, 160 integer range, 154 negative zero, 33 depth, 26 duplicate key, 17 lone surrogate | 0 |
| go | 60,511 | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 257 float, 160, 154, 33, 26, 17 | 0 |
| c-interp | 146,673 | 10,265, 372 | 3,181 | target-limit 3,527 at compile, 2,070 on a reading | 0 |
| c-hdr | 146,673 | 10,265, 372 | 3,181 | target-limit 3,527, 2,070 | 0 |
| ebpf | 146,587 | 10,265, 372 | 3,181 | target-limit 3,527, 2,070, and 86 readings of tables outside the eBPF subset | 0 |

Step 4 reran it (same seed and generator): every count above is unchanged, with no finding on any leg.
No finding of any kind on any leg: the policy rows step 2 counted as D7 (9,758 for Python, 9,839 for
Rust) now agree, each with the
oracle's cause, field and reason, and the engine counter scope grew from 171 to 372 by the policies
whose first problem is reading a counter, which step 2 counted as D7. On every table the eBPF loader
admits, every register encodable reading routes on the in-kernel evaluator's text as the oracle routes it.

**The large run, step 2** (100,000 cases, seed 1, 419,651 readings). The oracle accepted 24,041 policies
and refused 75,959; it routed 30,380 readings and refused 13,741 with `route:no-matching-edge`, 40,892
with `route:contract-violation`, 15,846 as unreadable and 379 as not an object, the rest with their
policy's refusal; on 18,568 readings the system boundary refused a defined field no rule reads, which
the policy check passed (D4, section 6.1). Per leg (case level policy rows and reading rows together):

| leg | agree | cause-order (D7) | policy-cause (D7) | scope | excluded | other |
|---|---|---|---|---|---|---|
| python | 153,822 | 6,843 | 2,915 | 10,265 inferred, 171 engine counter | 3,181 | none |
| rust | 153,741 | 6,270 | 3,569 | 10,265, 171 | 3,181 | none |
| js | 60,492 | | | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 276 float, 160 integer range, 154 negative zero, 33 depth, 26 duplicate key, 17 lone surrogate |
| go | 60,511 | | | 10,265 inferred | 12,902 | 22,035 refusing-kernel; reader gaps 257 float, 160, 154, 33, 26, 17 |
| c-interp | 137,116 | 6,843 | 2,915 (the host's) | 10,265, 171 | 3,181 | target-limit 3,527 at compile, 2,070 on a reading |
| c-hdr | 137,116 | 6,843 | 2,915 (the host's) | 10,265, 171 | 3,181 | target-limit 3,527, 2,070 |

Excluded are the 3,181 images with no flow rendering, all refused by the oracle (for the second tier
legs also the images that do not read, which they have no reader for). No reading level disagreement,
no policy check disagreement, no uncoded refusal and no crash on any leg: on every policy a leg accepts
and the oracle accepts, every reading's route or refusal, with its field and reason, is the oracle's,
and on every policy the table compiled, every register encodable reading routes on both C evaluators
as the oracle routes it. The only findings are D7's, every one a policy both sides refuse.

**The large run, step 1** (for comparison; 100,000 cases, seed 1, 420,486 readings, the step 1
generator). Against the Python reference: 142,795 agreements; reader gaps 3,217 float, 3,561 duplicate
key, 8,490 integer range, 2,624 negative zero, 156 depth; 931 findings, every one D1. Against the Rust
port: 139,412 agreements; reader gaps 3,061 float, 3,434 duplicate key, 8,002 integer range, 2,551
negative zero; 1,569 findings, 1,182 of them D3 and 387 D1 and D2.

## 9. Where the implementations disagree on the slice

Each row is a disagreement the harness or a direct probe shows, with the side this specification
takes. Step 1 recorded D1 to D6; step 2 fixes D1, D2 and D3 (each with regression cases in the frozen
field definition vectors and in the harness's generator), resolves D4 (section 6.1), extends the
harness to the D5 and D6 legs, and records D7; step 3 resolves D7 and runs the eBPF leg of D6.

**D1. The depth bound is not applied to a defined flow (Python).** SPEC.md 4.1 makes a predicate
nested beyond 50 invalid and `check_predicate` refuses it (`predicates.py:169`), but a defined flow
never runs that check: `apply_definitions` classifies with `level_m.is_level_m`, which parses with
`expr_ast` (`predicates.py:249-263`) and has no depth bound. So the reference accepts the policy. At
depth 51 it then evaluates the condition; from depth 52 the evaluator's own bound (`predicates.py:225`)
raises at run time, `first_deterministic` treats the edge as non matching (`engine.py:73-77`), and a
later rule routes. Reproducer: `fields {"x": "int"}`, rule 1 `hit` when `not`×50 applied to
`x >= 3` (depth 52), rule 2 `miss` always, reading `{"x": 5}`: the reference routes `miss`, where the
author's first rule says `hit`. **Specification:** the policy is refused at load (`policy:not-level-m`,
`depth`), at every depth above 50. **Fixed in step 2:** `field_definitions.policy_problems` and
`fragment_problems` apply the reference's own static measure (`predicates._depth`) to every
deterministic condition of a defined flow (`_depth_problem`), so the policy is refused at load with
`policy:not-level-m`. Regressions: the vectors `depth_fifty_one_not_chain`, `depth_fifty_two_not_chain`
(refused) and `depth_fifty_not_chain` (accepted).

**D2. Rust bounds depth by a different measure (Rust).** The Rust predicate parser counts recursion
levels of its own grammar (`prismpath-rs/src/condition.rs:392-505`, `MAX_DEPTH` 50), not the
reference's static depth. A `not` chain is refused from depth 52, a nested `and` from depth 53; at
depth 51 Rust accepts and evaluates, and a nested `and` at depth 52 is accepted and silently never
matches, as in D1. Python and Rust therefore disagree with each other on conditions at depth 52.
Reproducer: as D1 with `not`×50 (Rust refuses, Python routes `miss`), and with an `and` nested to depth
52 (both accept and route `miss`). **Specification:** refuse above 50 by the measure of section 2.4.
**Fixed in step 2.** The direct probe showed the measure differed the other way too: an `and` nested on
the right inside parentheses cost the Rust parser two levels per level, so the port refused a right
nested condition far below 50 that the reference accepts. Now the parser's `depth` counts only the
nesting that is evaluation depth (a `not`, a later operand of `and` or `or`, a comparison's right side),
never a bracket, so its guard fires only where the evaluator (`ev_node`, the reference's `_ev`) refuses
anyway; brackets have their own bound of 200, Python's tokenizer's; and the static bound of SPEC.md 4.1
is the reference's measure, `condition::static_depth`, applied by `check_predicate` and by the policy
rules of a defined flow (`policy:not-level-m`). Regressions: the vectors `depth_fifty_nested_right` and
`depth_fifty_nested_left` (accepted), `depth_fifty_one_nested_right` and `depth_fifty_two_nested_left`
(refused); the harness's generator writes `and` and `or` nested on the left, the right and alternately
from depth 25 to 53.

**D3. Definition whitespace (Rust).** The reference splits a definition with `str.split()`
(`field_definitions.py:140`) and the front matter value is stripped with `str.strip()`
(`parser.py:108`), both of which treat U+001C to U+001F as whitespace; the Rust twin uses
`split_whitespace` (`prismpath-rs/src/field_definitions.rs:137`), which does not. Reproducer: the
definition `int\u001fmin=0` (or `int\u001f`): the reference accepts an `int` field, Rust refuses
`unknown kind "int\u{1f}min=0"`. **Specification:** the reference's whitespace (section 2.5); Rust is
wrong. U+001C to U+001E also end a line in the reference's `splitlines`, so they cannot reach a
definition through the flow text at all. **Fixed in step 2:** `condition::is_py_ws` is now exactly
Python's `str.isspace` (it also wrongly counted U+FEFF, which JavaScript's trim strips and Python's
does not), a definition is split with `condition::py_split`, and the front matter keys and values are
stripped with `py_trim` as the reference strips them, not with JavaScript's trim. Regressions: the
vectors `definition_split_on_python_whitespace` (U+001F, U+3000, U+2000, accepted) and
`definition_with_a_byte_order_mark` (refused); the generator's separators include the rest of
Python's whitespace set and U+FEFF.

**D4. Which fields the boundary checks (reference, two paths). Resolved in step 2 (section 6.1).** SPEC.md 4.5 calls a reading canonical
when every defined field *the flow routes on* is canonical, and the Facet quantizer checks only the
fields it partitions (`prismpath/telemetry/quantizer.py:150-160`), while the conformance composition
that both Python and Rust replay checks every defined field (`gen_field_definitions.py:152-158`,
`prismpath-rs/tests/test_field_definitions.rs`). They differ on a policy that defines a field it never
reads. **Resolution (owner, 2026-11-10):** both are right, for different checkers. The core's runtime
boundary is the *system boundary* (every defined field, as the corpus freezes); the SPEC prose and the
quantizer describe the *policy check* (the routed fields). Section 6.1 defines both, the three
implementations carry both, and the Lean theorems state that the system boundary is at least as strict
and that only routed fields can change a route.

**D5. The second tier kernels (JavaScript, Go). Resolved on `core-js-go`.** Both refused every flow that
defined its fields (`prismpath/portable/prismpath.mjs`, `prismpath-go/parser.go`), as SPEC.md 4.5 requires of
a kernel that does not implement field definitions, so on the core they agreed only on refusals.
**Specification:** conformant by refusal until the owner chose otherwise; step 2 recorded them as refusing
kernels. **Owner decision (2026-11-10): both take the same treatment as the Python reference and the Rust
port and decide the core.** They now implement section 4.5 and the core's checks, each in its own kernel
and with its own conformance replay: a canon/2 reader and writer (`canon2Read`, `canon2Write`; `Canon2Read`,
`Canon2Write`), the definition grammar with Python's whitespace, exact decimal lowering on the source spans
of the predicate text (BigInt in JavaScript, `math/big` in Go, 28 digits and an exponent of 30 as in
the reference), the policy problems in the order of section 4 with the registered causes 89 to 100 and the
field and reason the oracle names (`FieldDefinitionError` in both), the system boundary and the policy check
(section 6.1) and first match routing. A refused flow has every edge disabled and the engine refuses it.
Two evaluator corrections came with it, both matching the reference and the Rust port (D2): a bracket does not
count as predicate depth and more than 200 open brackets refuse (JavaScript), and `and` and `or` are n-ary
nodes whose operands are siblings, so a long `a and b and c ...` is one level and not as many as it has
operands (Go); Go also reads `\xNN` in a string as the code point and not the byte, and both read the front
matter with Python's whitespace (JavaScript's trim strips U+FEFF, which Python does not). The frozen vectors
replay in both (`canon2.json` 73 of 73, `field_definitions.json` 156 of 156), and the 80 flows of
`flows.json` that carry engine options stay skipped, since the type gate, the transcript bound and the run
id are options of the flow engine and outside the core; none of them defines a field. The step 2 text below records why
it was not done then.
**Step 2: recorded as refusing kernels.** Implementing section 4.5 in them is not contained: each would need the definition grammar,
exact decimal lowering on the source spans of the predicate text (the JavaScript kernel in BigInt), the
six policy rules with their causes, the system boundary and the policy check, and a canon/2 reader, a
port of about the size of `prismpath-rs/src/field_definitions.rs` and `canon2.rs` in each language, with
its own conformance replay. Both are legs of the harness now (adapters `formal/diff/core_diff_js.mjs`,
`prismpath-go/cmd/core_diff`): on the large run of step 3 they refused all 22,035 defined flows the oracle accepts,
agreed on every flow without definitions, and differed otherwise only by reader gaps, documents canon/2
refuses and their runtime's JSON reads; the run of `core-js-go` in section 8 shows neither.

**D6. The table targets (C, FPGA, eBPF).** Constants and registers are signed 32 bit
(`int-out-of-i32`, SPEC.md 4.3), so a checked policy with a constant outside that range compiles to no
table. This is a declared target limit, not a disagreement; the table adapter (step 2) must report it as
a refusal of the compiler, never a different route. **Step 2: confirmed.** The C legs compile every
checked policy with `prismpath-hw/ppt_compile.py` and run its readings through `interp.c` and
`ppt_eval.h`; 3,527 checked policies of the large run hold a constant outside 32 bits and are refused by
the compiler (`int-out-of-i32`), and 2,070 readings of compiled policies hold a value the 32 bit
registers cannot carry and are refused by the register encoder (`encode_scalar`, the same reason);
neither is ever a route. Every other reading routes as the oracle routes it. The target limit is not a
registered cause of the core: it is the compiler's refusal, and stays outside the core's closed set.
**Step 3: the eBPF target is a leg.** Loading an XDP program and running it with `BPF_PROG_TEST_RUN`
needs CAP_BPF, and this host has unprivileged BPF disabled and the work runs without privileges, so the
leg takes the eBPF target's userspace path: the in-kernel evaluator's own text
(`prismpath-ebpf/ppt_eval_bpf.h`, the `eval_atom`, `eval_prog` and `evaluate` of every XDP program
there) compiled natively against a shim of its array maps, `bpf_map_lookup_elem` and `bpf_loop` with the
kernel's semantics, behind the loader's own parser. It routes every reading of every table the loader
admits as the oracle does; the loader's declared subset then (an operand stack of 4, 64 edges per node, 64
words per edge, 32 fields, `check_evaluator_limits`) refused 86 readings' tables of the large run, a
refusal and never a route. What the leg does not exercise is the kernel's verifier and JIT, which the
kernel certification in CI (`ebpf_kernel`) covers.

**Step 4 (`core-ebpf`): the subset gap closed.** The 86 were the same two table features and no others:
edge programs of 65 to about 113 words, from `in` lists of more than 32 members and long chains of `and`
and `or` (397 of the large run's tables), and operand stacks of 5 to 25, from right nested parentheses
(122 tables). `interp.c` runs both (its stack is 64 deep
and a program has no length bound), the evaluator did not, so they were the eBPF target's own limit and
not the table's. The evaluator now carries them: `STACK_MAX` is 64, the operand stack is one `__u64` whose
bit `i` is slot `i`, so `st_get` and `st_put` are a shift by a masked amount instead of a `switch` of one
arm a slot (a depth of 64 would have been 64 arms an access, and the verifier explores arms), and
`MAX_PROG_PER_EDGE` and `MAX_EDGES_PER_NODE` sit at the map capacities, 4,096 words and 1,024 edges,
which cost the verifier nothing because both loops are `bpf_loop` callbacks verified once and cost a packet
only what its own table holds. The object's `prog_word_cb` shrank from 423 to 332 instructions. Past
the interpreter's own depth of 64 the loader still refuses the table, as `interp.c` exits on it, and a
table past a map capacity or 32 fields is refused at load with the other `MAX_*` bounds, a registered
refusal of the target at the point the table is built and never a route; source predicates cannot reach
either (they nest at most 50 deep, about 25 stack slots). Neither the 100,000 case run nor the 5,000 case
CI run holds a table of that kind, so `target-limit:subset` is zero on both and is kept as a class,
so that a table past a capacity would still be counted and never routed. The verifier's acceptance is the kernel job's
and cannot be checked here: `prismpath-ebpf/verifier_budget.py` reads each built object and holds it to
the limits the repository already models (combined stack within 512 bytes with each frame rounded to 32,
no cycle in the evaluator's control flow outside `bpf_loop`, the evaluator's three functions reached
through `bpf_loop`), `cert_corpus.py --boundary` writes 35 records of the evaluator's bounds that the
`ebpf_kernel` job loads and replays in kernel (stack 25, 63 and 64, programs of 33, 2,000 and 4,000 words, a
node of 200 edges), and the same tables run natively through this leg's driver in
`prismpath/tests/test_ebpf_evaluator_bounds.py`.

**The 32 bit limit stays a refusal on every target, the eBPF one included.** The eBPF evaluator could carry
64 bit values (its registers and atoms are `__s32` structs the compiler and the loader share, and the
BPF registers are 64 bits wide), and widening them was considered and not done: the table image is one
format with one set of readers, `ppt_compile.py`, `interp.c`, `ppt_eval.h`, the FPGA's tables, the
loader, the signed policy hash and the conformance corpus, so a 64 bit atom on one target would be
another table format and another differential for the others, and the FPGA registers and the C
firmware's `int32_t` could not follow. A policy with a constant or a reading outside 32 bits is
therefore refused at compile time by the shared compiler for every table target alike (the 3,527 and
2,070 of the large run), never routed differently on one of them.

**D7. Which cause names a policy with several problems (Python, Rust). Resolved in step 3.** Found when
step 2 made every leg report its cause. Both sides refused the same policies and every refusal carried a
registered code, but on a policy with at least two problems the reference and the port met them in their
own phases, the Level M classifier judging a whole condition before its atoms, the lowering of a
condition's decimals running before its atoms were checked, and a malformed definition stopping the
definitions before any atom was read, so they could name another problem than the oracle's first
(31 kinds for Python, 37 for Rust in step 2's large run). Reproducer: `fields {"x": "int"}`, one rule
`["and", ["cmp", "x", "==", ["num", "9007199254740992"]], ["cmp", "x", "==", ["num", "2.5"]]]`: the oracle
names `policy:threshold` (`constant-range`, the first atom), the reference named `image:unknown-type` (the
classifier saw the float in the second atom first). **Resolution (the bulletproof one):** the order of
section 4 is normative and every implementation names its first problem. The reference's
`apply_definitions` and the port's now run `core_problems`, which decodes every rule in the core's
abstract syntax (`decode_condition`), parses the definitions in code point order, checks each decoded atom
in Lean's order and then rule 6, and only then lowers the text; the refusal is the first problem, with
the oracle's field and reason, and the whole list stays for diagnostics. Lean proves the core's refusal
is the head of the same order (`loadPolicy_first_problem`, section 7). The harness compares cause, field
and reason and counts any difference as a finding; on the large run of section 8 there is none on any
leg, the Python and Rust problem lists are equal case for case, and seven `d7_*` vectors in
`field_definitions.json` and the CI run's D7 set hold the cases above and the other phase crossings
(decoding before a definition, a later rule's decoding before an earlier rule's lowering, an earlier atom
before a later threshold, a membership's range before its rounding, definitions in code point order, a
lowering problem before rule 6). Policies the oracle refuses for reading an engine counter are the scope
difference of section 1, not D7: the reference does not refuse a counter, so it names the policy's next
problem.

**Reader gaps (closed).** Step 1 counted floats, `-0`, wide integers, duplicate keys and deep nesting
as reader gaps: the implementations read documents with canon/1, which accepts them. canon/2 is now
the reader of both first tier legs (section 3), so these documents are refused with the oracle's rule and a
difference on them is a finding; the step 2 runs show none. The two second tier legs kept theirs (their
runtimes' JSON, which also accepts a lone surrogate escape) until `core-js-go`, which gave them canon/2
readers: every leg now reads canon/2 and the harness no longer has the class.

## 10. Next

Step 2 adopted canon/2 for the core's documents (section 3) and wrote down the migration of the rest
(section 3.1), registered every core refusal (section 5), resolved D4 into the system boundary and the
policy check (section 6.1), fixed D1 to D3, ran the JavaScript, Go and C legs (D5, D6), and proved the
new claims (section 7). Step 3 (this branch) resolved D7 with a theorem and with the reference and the
port checking in the core's order (sections 4, 7 and 9), made a differential run evidence in its own
right (section 11), and ran the eBPF table target as a leg on its userspace path (D6). Owner decisions
settled since: the JavaScript and Go kernels implement section 4.5 and decide the core (D5,
`core-js-go`). Left open: when the canon/2 migration of section 3.1 starts; the Rust predicate parser's
reading of `-(5)` at evaluation (the core's decoder now reads it as Python's syntax tree does, and the
lowering refuses it on a fixed field in both); whether the eBPF leg should also run in kernel where CI has
the privileges. Step 4 made a run's root statement canon/2 (section 11), proved what a verified run says
about `Core.verdict` (section 7), wrote the summary for a reviewer (`docs/research/verified-core-summary.md`),
and narrowed a run's engine counter exclusion to the policies the oracle refuses for it
(section 11).

## 11. A differential run as evidence

A differential run says that on these inputs an implementation decided these things, and that the
oracle decides them alike. Step 3 makes that a claim a reader can check without trusting the
implementation, the harness or whoever ran it. A run is a directory, written by
`formal/diff/core_evidence.py produce` (the Python reference decides) or by
`prismpath-hotswap-rs/examples/core_evidence.rs produce` (the Rust port decides), from the same inputs:

| file | what it holds |
|---|---|
| `cases.jsonl` | the inputs, one canon/2 line per case: the image's and every reading's bytes in hex, and the image's canonical rendering as flow text (what the reference and the port read; `prismpath.kernel.core_render`), or null for an image with none |
| `images.jsonl` | one image attestation per case, `prismpath.core-image/1`: the case, the image's SHA-256, the authority key's id, and an Ed25519 signature over the domain prefix `prismpath.core-image/1\0` followed by the image's canon/2 bytes |
| `receipts.jsonl` | one receipt per decision, `prismpath.core-receipt/1`, a canon/2 line: its position `idx`, the case and the reading's index, the image's SHA-256, the reading's SHA-256, the decider (`python` or `rust`), and the decision, `route` with its target or `refuse` with the registered cause, its nonzero `cause_code` and the field and reason where the refusal has them |
| `receipts.roots.jsonl` | one root statement, `prismpath.core-run-root/2`, a canon/2 line signed with the instance key over the domain prefix `prismpath.core-run-root/2\0` followed by the canon/2 bytes of every member but `sig`: the log `core-run`, the RFC 6962 Merkle root of the receipts' SHA-256 leaves (the tree of `ledger_ots`, below) and their count, the signer's clock `time_us` (an integer count of microseconds since the epoch), the instance key's id and public half, and `policy`, the SHA-256 of `run.json` |
| `run.json` | the manifest, `prismpath.core-run/1`: the decider, the counts, the excluded cases with their reasons, the SHA-256 of `cases.jsonl` and `images.jsonl`, and the two keys' ids |
| `authority.pub`, `instance.pub` | the two public keys, raw 32 bytes |

A receipt is not signed by itself: the root statement attests every receipt at once, and each receipt is a
leaf under the root it signs.

**The tree (step 5).** The receipts' tree is RFC 6962's (section 2.1, the Certificate Transparency tree),
the one every PrismPath ledger builds (`prismpath.ledgers.ledger_ots`, `prismpath_rs::merkle`, the eBPF
`merkle.h`): a leaf, here a receipt line's SHA-256, is hashed into the tree as SHA-256(0x00 || leaf); an
inner node is SHA-256(0x01 || left || right); a tree over n ≥ 2 leaves splits at k, the largest power of two
below n, the root of the first k leaves on the left and of the rest on the right; one leaf's root is its leaf
hash; nothing is duplicated. The tree before it, Bitcoin's (no prefixes, the last node of an odd layer paired
with itself), gave [a, b, c] and [a, b, c, c] one root, so a root alone did not fix how many receipts were
under it and only the statement's leaf count told the two apart, and a leaf could be presented as a node.
With the prefixes and the split, two nonempty lists with one root are one list, of any lengths, unless
SHA-256 collides: `Core/Merkle.lean` proves it over the hash as a parameter (`mth_injective`) and that the
retired tree collides for every hash (`retired_collides`). The scheme is carried by the format:
`prismpath.core-run-root/2` (and `prismpath-root-statement/3` for audit logs and epoch chains) states an
RFC 6962 root, and a `prismpath.core-run-root/1` statement, a root of the retired tree, is refused by both
verifiers by name ("whose root is of the retired Merkle tree"), never checked under the new one. Every run
written before step 5 is refused that way and has to be produced again. The known answer vectors are RFC
6962's own (the Certificate Transparency reference implementations' eight inputs, roots of the first one to
eight; `prismpath/tests/test_merkle_rfc6962.py` and `prismpath-rs/src/merkle.rs`).

**The stored flow is the image's rendering (step 5).** The authority signs the image, and the reference
kernel decides from the flow, so a producer holding the instance key could store a flow that is not the
image's and receipt its decisions with every hash and signature intact, the replay through the reference
agreeing because it reads the same edited flow. The renderer is therefore part of the package
(`prismpath.kernel.core_render`; the differential imports it, `render(doc, rng)`, and varies the spelling with
its random source): with no random source it writes the image's canonical rendering, every choice in its
plainest spelling, a function of the image alone. A run stores that rendering (`core_evidence.write_cases`),
the producers refuse cases whose flow is not it, and both verifiers refuse a run in which any case's flow is
not the canonical rendering of its signed image, or is null for an image that renders, or names a flow for
one that does not. The Rust twin carries a port of the canonical rendering (`core_evidence render --from
CASES` prints it), held equal to the Python on every image of the CI run and of 3,000 more. The authority key, which says which policy may run, signs the images, and
the instance key, which attests what was recorded, signs the root statement; they are never the same key
(`root_statement.check_separation`), and both are test keys, generated per run by the repository's own
code (`swap keygen`'s `policy_pack.keygen` and `ledger keygen`'s `root_statement.keygen` in Python, the
hot swap crate's `keygen` in Rust), the run holding only their public halves.

A case outside the core (section 1) is excluded with its reason, decided from the image alone, in this
order: an image the oracle refuses for reading an engine counter (`engine-counter`), one that reads but has
no flow rendering (`unrenderable`), and one that defines no field yet routes on a condition, which the
reference takes by its inferred path (`inferred-path`). So every receipted decision is a decision of the
core and must be the oracle's.

**The engine counter exclusion is the oracle's own (step 4).** Step 3 excluded every image whose conditions
mention `visits` or `error_count`, which also excluded images the oracle refuses for an earlier problem
(a malformed definition, an undefined field, a threshold before the counter): decisions of the core, left
out. Step 4 excludes an image exactly when the oracle refuses it with `policy:engine-counter`, decided by
the oracle's own check of the image, Lean's `counterRefusal` (`formal/Core/Scope.lean`: `loadPolicy` on the
image's bytes fails with `engineCounter`), ported line for line to the producers so that producing a run
needs no oracle: `prismpath.kernel.core_policy` (`load_policy`, `refuses_for_counter`; `formal/diff/core_policy.py` is the same module) and the Rust example's
`oracle_policy` module. Each port computes the whole of `loadPolicy`, accepted or the refusal's cause,
code, field and reason, in the order of section 4, and `core_evidence.py scope-check --from CASES --rust
LINES` holds both to the oracle on every image (`core_evidence policy --from CASES` prints the Rust
port's). Lean proves the exclusion hides nothing (`counter_excluded_refused`: such an image refuses every
reading with `policy:engine-counter`), and an image that mentions a counter but is refused for an earlier
problem is receipted with the oracle's refusal, which the replay checks.

**The verifier** (`core_evidence.py verify RUN`, and `core_evidence verify RUN` in Rust; `--sample N` or
`all`, `--pin-authority PUB --pin-instance PUB`) checks, and refuses the run at the first failure: the
two keys against the pins and against `run.json`, and that they differ; the root statement through
`verify_root_statement` (one line, read by canon/2 and in its canonical spelling, not a retired
`prismpath.core-run-root/1`, exactly the members of `prismpath.core-run-root/2` with integers where the format has them, the run's instance key, the
signature under it over the domain prefix and the body, the Merkle root of every receipt and their count)
and that its `policy` binds this `run.json`; that `cases.jsonl` and
`images.jsonl` are the files `run.json` names; that every case's stored flow is its image's canonical
rendering; every image attestation's signature under the authority key
over its image's bytes; that the excluded cases are exactly those the image says are outside the core;
that the receipts are, in order, one per reading of every other case, each in its canonical canon/2
spelling, binding that case's image and reading by hash, naming the run's decider, and a route with a
target or a refusal with a registered nonzero code; and it replays the sampled receipts through the
oracle (`core-oracle --batch`, the image and the reading of each), every decision required to be the
oracle's with its cause, code, field and reason. A receipt resigned under the right instance key with a
false decision passes the signature checks and fails the replay, which is why the replay is part of the
verifier and not an extra. Every check but the replay is the package's (`prismpath.ledgers.core_evidence`),
and the shipped command `prismpath evidence verify RUN` (the same flags) replays through the Python
reference kernel instead, since the oracle does not ship; the research test holds the two replays to each
other on every run and altered run above (`prismpath/tests/test_core_evidence.py`, marked `cross_language`).

**The round trip** (`prismpath/tests/test_core_evidence.py` at CI size, and the large run). On the 100,000
cases of seed 1, step 4: both ported checks name the oracle's verdict on the policy of every one of the
100,000 images (24,041 accepted, 1,310 refused for an engine counter, the rest refused with the oracle's
cause, code, field and reason); each producer writes 361,984 receipts and excludes 13,818 cases (1,310
engine counter, 9,327 inferred path, 3,181 unrenderable); the Python verifier checks the Rust run and the
Rust verifier the Python run, each with every receipt replayed, and every one of the 361,984 replayed
decisions agrees with the oracle on both; the two runs' receipts are the same bytes but for the decider.
The 1,310 are the 372 policies the differential counts as the engine counter scope (section 8) and 938
that define no field, which the differential counts as the inferred path. Step 3 wrote 352,564 receipts
and excluded 16,081 cases (7,505 mentioning an engine counter, 5,674 inferred path, 2,902 unrenderable):
step 4 receipts 9,420 more decisions, every one replayed and agreeing. The test also
alters each part of a run (a decision, a dropped receipt, a reading, an image signature, the manifest, a
key, the root statement's signature, its clock written as a float of seconds, a later clock, the
statement respelled with whitespace, a second statement), resigns a false receipt, puts an audit log's
root statement format in place of the run's, pins a foreign key, edits a flow and seals the run again
around it, and signs a `/1` statement over the retired tree's root, and both verifiers refuse each.

Lean states what a verified run shows about `Core.verdict` (`Core/Evidence.lean`, section 7):
`evidence_sound`, over a model of the run and of this verifier with every receipt replayed, the
cryptography as explicit hypotheses. What a verified run shows: the holder of the authority key published these images, the holder of the
instance key stated these receipts, the decisions are the oracle's on every replayed receipt, and the
Python and Rust verifiers agree on all of it. What it does not: when (the statement's time is the
signer's clock; anchoring its hash with `ledger anchor` adds a third party's time), that a sample stands
for the receipts it did not replay (replay `all` for that), or anything about the cases excluded as
outside the core.

**canon/2 end to end (step 4).** Every document of a run is canon/2: the cases, the image attestations,
the receipts, the manifest and, since step 4, the root statement. Step 3 signed the run's root with the
audit log's statement format, `prismpath-root-statement/1`, whose bytes were canon/1 compact and whose time
was an ISO 8601 string; step 4 gave the core run its own format, `prismpath.core-run-root/1`, with its own
domain prefix, integers and strings only and the time as `time_us`, an integer. It is written by
`core_evidence.make_root_statement` in Python and by the Rust example, each verifying the other's. The
audit log's and epoch chain's statements have since become `prismpath-root-statement/2` (section 3.1) and,
with the RFC 6962 tree, `prismpath-root-statement/3`, and the run's statement `prismpath.core-run-root/2`;
the run's verifier refuses a statement in any audit log format. The hash of the statement, what an
anchor would stamp, is the SHA-256 of its canon/2 line; `ledger anchor` is not yet taught this format.
