# Routing tests for `coding.md`

Run with `python -m prismpath.cli test prismpath/flows/coding.md`. Each row asserts which edge a node
takes for a given outcome — the deterministic rows need no model; the `debug` rows exercise the
embedding tier. A PM can read and extend this table; CI asserts it; a past mis-route becomes a row.

| node      | outcome                                        | fields                    | expect     |
|-----------|------------------------------------------------|---------------------------|------------|
| run_tests | all tests passed                               | tests_pass=true           | done       |
| run_tests | three tests still fail                         | tests_pass=false          | debug      |
| run_tests | still failing after many attempts              | tests_pass=false; visits=4 | give_up    |
| debug     | the fix is obvious — a one-line typo, edit and retry | | write_code |
| debug     | this is unsolvable without a spec change we can't make |         | give_up    |
