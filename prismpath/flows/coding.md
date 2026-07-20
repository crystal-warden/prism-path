---
name: coding
start: write_code
---

## write_code
Write or revise the Python function so it satisfies the task and passes the tests.
-> run_tests: when always

## run_tests
Run the hidden test suite against the current code.
-> done: when tests_pass
-> give_up: when visits > 3
-> debug: when not tests_pass

## debug
Look at the failing test output and judge whether the fix is clear or the task is unsolvable.
-> write_code: the fix is clear, edit the code and try again
-> give_up: the problem is unsolvable or out of scope

## done
All tests pass — the task is complete.

## give_up
Too many failed attempts, or the task is unsolvable. Stop.
