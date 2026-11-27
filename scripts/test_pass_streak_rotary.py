"""Tests for PassStreakRotary."""
from scripts.pass_streak_rotary import PassStreakRotary


def test_pass_streak_rotary():
    r = PassStreakRotary(capacity=2)
    r.record(False)
    r.record(True)
    r.record(True)
    assert r.pass_rate() == 1.0
