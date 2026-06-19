from __future__ import annotations

from pesentinel.core.verdict import bayes_pia


def test_bayes_textbook_example() -> None:
    """The textbook example from Ch.15 §6.3:
    P(I)=0.00002, P(A|I)=0.8, P(A|~I)=0.0001 -> P(I|A) ~ 0.14"""
    result = bayes_pia(0.00002, 0.8, 0.0001)
    assert 0.13 < result < 0.15


def test_bayes_exercise_15_15() -> None:
    """Exercise 15.15: 10M records, 10 attacks/day, 20 records/attack,
    true-alarm=0.6, false-alarm=0.0005.
    P(I) = 10*20 / 10_000_000 = 0.00002
    P(I|A) = P(I)*0.6 / (P(I)*0.6 + P(~I)*0.0005)"""
    p_i = 10 * 20 / 10_000_000
    result = bayes_pia(p_i, 0.6, 0.0005)
    # Should be a small fraction
    assert 0.01 < result < 0.03


def test_bayes_zero_prior() -> None:
    assert bayes_pia(0.0, 0.9, 0.001) == 0.0


def test_bayes_perfect_detection() -> None:
    result = bayes_pia(0.5, 1.0, 0.0)
    assert result == 1.0


def test_bayes_no_false_alarms() -> None:
    result = bayes_pia(0.01, 0.9, 0.0)
    assert result == 1.0
