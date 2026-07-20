---
name: build_PrismPath
start: plan
---

## plan
Lay out the work for hardening and extending PrismPath: the deliverables are a comprehensive
pytest suite (parser, predicates, router, engine), a CLI, new example flows, and a README.
-> implement: when always

## implement
Write or revise the next deliverable file for the PrismPath framework, keeping it consistent with
the files already written and fixing any error reported from the last test run.
-> run_tests: when not more_files
-> implement: when more_files

## run_tests
Run the produced pytest suite over the new PrismPath tests in a subprocess and report pass/fail.
-> document: when tests_pass
-> give_up: when visits > 4
-> debug: when not tests_pass

## debug
Read the failing test output and judge whether the fix is clear enough to edit the code and
retry, or whether the failure is environmental or the task is genuinely blocked.
-> implement: the fix is clear, edit the code and try the tests again
-> give_up: the failure is environmental or the task is unsolvable

## document
Write the README that ties the framework, CLI, tests, and example flows together.
-> done: when always

## done
All deliverables are produced and the test suite passes. The build is complete.

## give_up
Too many failed iterations or an unrecoverable failure. Stop and report.
