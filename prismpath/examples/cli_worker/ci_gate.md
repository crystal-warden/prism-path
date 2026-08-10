---
name: ci_gate
start: gate
---

## gate
Read the build report and decide whether to ship.
-> ship:         when passed and coverage >= 80
-> low_coverage: when passed
-> triage:       else
-> error_hold:   on error

## ship
Tag and release.

## low_coverage
Tests pass but coverage is short; ask for more tests before release.

## triage
Tests failed; assign the failures to an owner.

## error_hold
The report could not be parsed; hold for a human.
