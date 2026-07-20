# Routing tests — `prismpath test pr_review.md` (deterministic rows, no model needed)

| node            | outcome                              | fields        | expect          |
|-----------------|--------------------------------------|---------------|-----------------|
| lint            | formatter and linter both clean      | clean=true    | run_ci          |
| lint            | two lint errors in the new module    | clean=false   | request_changes |
| run_ci          | full suite green, build ok           | ci_pass=true  | human_review    |
| run_ci          | three tests fail on the new branch   | ci_pass=false | request_changes |
| request_changes | author pushed a revised commit       | revised=true  | lint            |
