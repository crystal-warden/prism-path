# The C core of policy distribution

These files are the C side of `docs/design/spec-policy-distribution.md` for the `mesh` and `cfs` targets.
The same sources are compiled on the host for the tests and unchanged for the boards and the cFS app.
Nothing allocates, every bound is a constant in `pp_dist.h`, and the one dependency is Monocypher's
Ed25519, vendored in `prismpath-hw/mesh/main`.

| File | What it holds |
|---|---|
| `pp_canon2.h` | The canon/2 reader. It tells canonical bytes from canon/2 in another spelling and from bytes that are not canon/2, and then reads canonical bytes member by member |
| `pp_dist.h`, `pp_dist.c` | The sealed container, the envelope scanner, the trust store, the verifier (V2 to V11), the frame reassembly, the enforcement point machine with revocation applied, and the signed state record |
| `host_check.c` | A stdio harness the Python tests drive |

A revocation is applied as soon as it verifies. The PEP holds the latest list and no other, refuses a list that
drops a key the current one holds with `dist:trust-replay` (R6), keeps the floor a list raises for its own stream,
and lapses or drops a release that no longer stands (R5). A trust body is held to 16,384 bytes beside the kind's
640 byte table bound, and the signed size is checked against the right bound before any body is read (E6, V5).

The scanner reads the envelope's members in canonical order and checks of `meta` only that it is an
object nesting at most three levels that ends inside the envelope, as E9 allows a constrained target. The
signatures are checked before the scanner reads a byte (V3 before V4). The machine keeps what it must hold
durably in one `pp_durable` struct in parts (the anchor, the counter, the trust store, the floor, each release slot
and a pending intent named by release id and seq), and the caller's `persist` is told which parts changed and
writes each whole, so a state record writes its 12 byte counter and no more, and it reports every
transition in a state record signed by the instance key.

Section 21 is built for `mesh`. The install record, the rate counts and the held and staged statement of each install
kind are five more parts, each written to two media by `persist` and read back from the first copy that reads, the
record before the set it names (IS10). `pp_pep_ask` decides one request: the action floor first, which on this kind
only allows and is held narrow by one bounded postfix pass at staging (AF9), then the active release, the fallback
policy or the refusal of X3, with the basis and the policy hash of the set that decided (RC1). The ceiling is a list
of body hashes. The layout and the reading domain the PEP was built with are in its `pp_config`.

The controller key is built for `mesh` (K6, K7, H9, H16). The anchor may name one key in the controller role and
`fresh`. A controller key's signature never counts on an envelope. A `trust.controller` is a trust kind on `@trust`
that replaces the controller key, retires the one before and starts the epoch id again. `pp_pep_take_statement`
reads one controller statement of 102 or 126 bytes (`pp_statement_verify`, the twin of
`prismpath/distribution/statement.py`), takes its epoch id under the rules of H9 and sends no record. Where `fresh`
is set it keeps the latest fresh statement in its own part (`PP_PART_FRESH`), lapses a release or holds it at X1
once that statement runs out, and on a node with no clock takes its time floor from the first one of each start.
The epoch id lives in memory only. A frame of type 6 carries one statement.

`prismpath/tests/test_distribution_c.py` builds `host_check.c` with the host `cc` and
The `cfs` kind takes a `cfs.table`, the `PP_PolicyTable_t` bytes before `ImageSig` (4,692 bytes). Every release and
install slot is sized by `PP_TABLE_MAX`, which is the mesh node's 640 bytes unless a build sets it, so the firmware
keeps its RAM. The cFS app and the host check of the cfs kind build with `-DPP_TABLE_MAX=4692`, and a build whose
bound is below a kind's table has no row for that kind. A cfs PEP takes a table with another core image on the
signers' word (W2, IS12), asks a table floor whose rules allow or escalate, past its signed rate escalates with
`dist:floor-rate`, and holds each floor rule to AF9 on the table's own PPT image and rules. `pp_pep_commit_check`
answers what a commit would without changing anything, so the cFS app switches its table service first and commits
after (section 9.5). `pp_read_anchor` reads a `/1` or `/2` trust anchor. On cfs an escalation of the action floor is
opened with `pp_pep_escalated` under the hash of the receipt the caller wrote for it, at most eight at a time, each for
600 seconds and kept with the rate counts in both copies. An `operator.answer` signed by one operator key of the install
record, on a PEP whose install threshold is 2 or more, is applied once when it names the PEP's id, an open escalation
and the floor that made it, inside the floor's signed `answer_rate`, durably before the `answered` record (OP1 to OP4).
The answer and the request of its escalation, with the command the caller kept beside it (a cFS command's message id,
function code and size, which the core never reads), are then the caller's in `pep->answer`. An escalation kept in the
older layout, before the command was kept, reads with none, and the cFS app does not carry it out. An answer never raises the time
floor, and on `mesh` it is `dist:target-mismatch`.

`prismpath/tests/test_distribution_c.py` and `test_distribution_c_cfs.py` build `host_check.c` with the host `cc` and
`-Wall -Wextra -Werror -fsanitize=address,undefined`. It replays every corpus case on the `mesh` kind,
runs the machine step for step beside the Python one (`prismpath/distribution/pep.py` on a modelled mesh
node) and requires the same signed state records byte for byte, and runs the frame reassembly frame for
frame beside `prismpath/distribution/frames.py` on streams from fixed seeds. A fixed seed fuzz holds the
scanner to the Python reader. The test skips, naming the reason, when there is no C compiler.

To build the harness by hand:

```
cc -std=c11 -Wall -Wextra -Werror -I prismpath-hw/dist -I prismpath-hw/mesh/main -o host_check \
   prismpath-hw/dist/host_check.c prismpath-hw/dist/pp_dist.c \
   prismpath-hw/mesh/main/monocypher.c prismpath-hw/mesh/main/monocypher-ed25519.c
```

`PPT_DEV_BUILD` sets bit 6 of every state record's status (D3). The `mesh` and `cfs` targets have no
escape hatch in any build.
