# Routing tests — `prismpath test fanout_review.md` (deterministic rows, no model needed)
# The child's own decisions are asserted in review_one.tests.md (`prismpath test review_one.md`).

| node   | outcome                             | fields      | expect            |
|--------|-------------------------------------|-------------|-------------------|
| gather | six files changed in the PR         | files=true  | dispatch          |
| gather | the diff is empty                   | files=false | nothing_to_review |
