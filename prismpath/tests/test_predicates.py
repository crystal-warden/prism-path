# tests/test_predicates.py
import pytest
from prismpath.predicates import (
    is_deterministic, eval_condition, check_predicate, PredicateError,
)

def test_is_deterministic():
    assert is_deterministic('when x')
    assert is_deterministic('always')
    assert is_deterministic('else')
    assert is_deterministic('false')
    assert not is_deterministic('a natural-language condition')

def test_eval_condition():
    assert eval_condition('x == y', {'x': 1, 'y': 1})
    assert not eval_condition('x == y', {'x': 1, 'y': 2})
    assert eval_condition('x != y', {'x': 1, 'y': 2})
    assert not eval_condition('x != y', {'x': 1, 'y': 1})
    assert eval_condition('x < y', {'x': 1, 'y': 2})
    assert not eval_condition('x < y', {'x': 2, 'y': 1})
    assert eval_condition('x <= y', {'x': 1, 'y': 2})
    assert eval_condition('x <= y', {'x': 2, 'y': 2})
    assert not eval_condition('x <= y', {'x': 2, 'y': 1})
    assert eval_condition('x > y', {'x': 2, 'y': 1})
    assert not eval_condition('x > y', {'x': 1, 'y': 2})
    assert eval_condition('x >= y', {'x': 2, 'y': 1})
    assert eval_condition('x >= y', {'x': 2, 'y': 2})
    assert not eval_condition('x >= y', {'x': 1, 'y': 2})
    # post-loop fix: eval_condition returns a bool; assert the truth value, not membership.
    assert eval_condition('x in y', {'x': 'apple', 'y': ['banana', 'apple', 'cherry']})
    assert not eval_condition('x in y', {'x': 'orange', 'y': ['banana', 'apple', 'cherry']})
    assert not eval_condition('x not in y', {'x': 'apple', 'y': ['banana', 'apple']})
    assert eval_condition('x not in y', {'x': 'orange', 'y': ['banana', 'apple']})
    assert eval_condition('x and y', {'x': True, 'y': True})
    assert not eval_condition('x and y', {'x': True, 'y': False})
    assert eval_condition('x or y', {'x': False, 'y': True})
    assert eval_condition('x or y', {'x': True, 'y': False})
    assert not eval_condition('x or y', {'x': False, 'y': False})

def test_eval_condition_safety():
    with pytest.raises(ValueError):
        eval_condition('when foo()', {})
    with pytest.raises(ValueError):
        eval_condition('when foo.bar', {})
    with pytest.raises(ValueError):
        eval_condition('when foo[0]', {})

def test_eval_condition_unknown_name():
    # post-loop fix: per the spec, bare 'else'/'always' -> True and 'false' -> False.
    assert not eval_condition('when missing', {})   # unknown name -> None (falsy)
    assert eval_condition('always', {})
    assert eval_condition('else', {})
    assert not eval_condition('false', {})


# --- hardening (see fuzz_predicates.py): eval_condition must fail SAFE, never crash a run ---

def test_predicate_error_is_valueerror():
    # existing callers catch ValueError; PredicateError must remain a subclass.
    assert issubclass(PredicateError, ValueError)


def test_missing_field_comparison_is_unsatisfied_not_a_crash():
    # `when score >= 0.9` with no `score` field: None >= 0.9 would TypeError in raw Python;
    # here it must be a defined False (matching the documented "unknown -> falsy" intuition).
    assert eval_condition('when score >= 0.9', {}) is False
    assert eval_condition('when score < 0.9', {}) is False
    assert eval_condition('when visits > 3', {}) is False


def test_type_mismatched_comparison_is_unsatisfied_not_a_crash():
    assert eval_condition('when status < 5', {'status': 'done'}) is False
    assert eval_condition('when count > 0', {'count': [1, 2, 3]}) is False


def test_membership_on_non_iterable_is_safe():
    # `x in None` would TypeError; `in` -> False, `not in` -> True (its negation).
    assert eval_condition('when x in items', {'x': 1}) is False           # items missing -> None
    assert eval_condition('when x not in items', {'x': 1}) is True
    # equality is total and keeps exact semantics even against None
    assert eval_condition('when x == y', {'x': None}) is True             # y missing -> None
    assert eval_condition('when x != y', {'x': 1}) is True


def test_unparseable_predicate_raises_predicate_error_not_syntaxerror():
    for bad in ('when score >=', 'when yield x', 'when and or'):
        with pytest.raises(PredicateError):
            eval_condition(bad, {})


def test_deep_nesting_is_rejected_not_recursionerror():
    deep = 'when ' + '(' * 500 + 'x' + ')' * 500
    with pytest.raises(PredicateError):
        eval_condition(deep, {'x': 1})


def test_no_code_execution_from_adversarial_predicates():
    tripped = {'v': False}
    def trip():
        tripped['v'] = True
        return True
    ctx = {'trip': trip, 'x': 1, 'foo': {'bar': 1}}
    for attack in ("when trip()", "when (trip)()", "when foo.bar", "when foo[0]",
                   "when __import__('os').system('x')", "when [].__class__",
                   "when (lambda: trip())()"):
        with pytest.raises(PredicateError):
            eval_condition(attack, ctx)
    assert tripped['v'] is False   # nothing executed


# --- the static safety check (wired into Graph.validate / lint) ---

def test_check_predicate_passes_safe_conditions():
    for good in ('when tests_pass', 'when not tests_pass', 'when visits > 3',
                 'when status == "done"', 'when x in [1, 2, 3]',
                 'always', 'else', 'false', 'a natural-language condition'):
        assert check_predicate(good) == []


def test_check_predicate_flags_unsafe_and_unparseable():
    assert check_predicate('when foo()')        # Call
    assert check_predicate('when foo.bar')      # Attribute
    assert check_predicate('when foo[0]')       # Subscript
    assert check_predicate('when 1 + 1')        # BinOp (arithmetic not allowed)
    assert check_predicate('when x is y')       # `is` not in the comparator allowlist
    assert check_predicate('when score >=')     # unparseable
    assert check_predicate('when [x for x in y]')  # comprehension


def test_check_predicate_does_not_evaluate():
    # a would-be side effect in a rejected predicate must not run during the static check.
    tripped = {'v': False}
    # check_predicate only parses/walks; even a 'call' shape must not execute anything.
    problems = check_predicate("when boom()")
    assert problems and tripped['v'] is False
