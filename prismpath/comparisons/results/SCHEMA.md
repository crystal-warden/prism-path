# Result file contract (frozen at pre-registration)

Every measurement in the layer comparison is one JSON file under `results/<system>/`, and
`matrix.py` reads nothing else. No cell of the matrix is ever typed by hand.

## File name

`results/<system>/<dimension>__<policy>__<scenario>.json`

- `<system>` is one of the registered system ids (`prismpath`, `opa`, `cedar`, `cerbos`,
  `openfga`, `openlane`) or a combination id `<system>+glue` for a combination test.
- `<dimension>` is `A1`..`A8` or `B1`..`B5`.
- `<policy>` and `<scenario>` are the corpus ids the result exercised. Dimensions graded without
  a scenario (B4, B5, documentation rows) use `policy = "none"` and `scenario = "matrix-row"`.

## Fields (all required unless marked optional)

| field | type | meaning |
|---|---|---|
| `system` | string | system id, matching the directory |
| `system_version` | string | exact installed version or commit of the comparator |
| `dimension` | string | `A1`..`A8`, `B1`..`B5` |
| `policy` | string | corpus policy id or `none` |
| `scenario` | string | corpus scenario id or `matrix-row` |
| `expected` | string or null | the corpus expected outcome for this scenario, copied verbatim, null for matrix rows |
| `observed` | string | what the system actually returned, in the neutral outcome vocabulary, or `error`, `undefined`, `not-expressible` |
| `match` | bool | `observed == expected` (false when expected is null) |
| `grade` | string | `NATIVE`, `WITH-WORK`, or `NOT` |
| `idiomatic` | bool | the translation used the system's documented idiom; false when the translator was unsure |
| `glue` | object or null | required when grade is `WITH-WORK`: `{ "description": str, "components": [str], "loc": int, "hours": number }` |
| `evidence_path` | string | repo relative path to the artifact that reproduces this row (translated policy, runner log, capture) |
| `harness_commit` | string | short git sha of the harness that produced the row |
| `run_at` | string | ISO 8601 UTC timestamp |
| `notes` | string | free text, uncertainty stated here |
| `measurements` | object, optional | numeric readings for A5 and A7: `{ "bytes_on_wire": int, "latency_ns": {"min","median","p95","max","n"} }` |

## Aggregation rule (pre-registered, `matrix.py` implements exactly this)

- A matrix cell is one `(system, dimension)`.
- The cell grade is the **minimum** over that cell's result files under the order
  `NOT < WITH-WORK < NATIVE`. One `NOT` scenario makes the cell `NOT`. The cell also reports the
  count of each grade and the count of `match == false`.
- A cell with zero result files is `UNTESTED`. `UNTESTED` is rendered, never hidden.
- A cell whose files disagree on `expected` for the same scenario, or carry a `grade` outside the
  three values, or a `WITH-WORK` without `glue`, is a **validation error** and `matrix.py` exits
  nonzero. A broken result file never becomes a cell.
- Combination systems (`<system>+glue`) get their own columns. They count as "practical
  combinations" for the distinct-layer test below.

## Distinct-layer verdict (pre-registered, computed, never typed)

For each Group A dimension: `DISTINCT` iff the `prismpath` cell is `NATIVE` and every other
tested column, combinations included, is `NOT`. `NOT-DISTINCT` iff the `prismpath` cell is
`NATIVE` and at least one other column is `NATIVE` or `WITH-WORK`. `OPEN` iff any comparator
column is `UNTESTED` or the `prismpath` cell itself is not `NATIVE`. Group B dimensions get a
`LOSES` / `HOLDS` / `OPEN` marker by the mirror rule: `LOSES` iff a comparator is `NATIVE` where
prismpath is `WITH-WORK` or `NOT`, or a comparator is `WITH-WORK` where prismpath is `NOT`; `OPEN` iff
the prismpath cell or any comparator is `UNTESTED` and the row is not already `LOSES`; `HOLDS` otherwise.

## Outputs

`matrix.py` writes `MATRIX.md` (rows = dimensions, columns = systems, cell = grade with counts
and the evidence paths listed beneath the table) and `matrix.json` (the same data, machine
readable, including the verdict per dimension and a `generated_from` list of every result file
consumed with its sha256).
