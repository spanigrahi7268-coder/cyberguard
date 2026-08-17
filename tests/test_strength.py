"""
test_strength.py
Unit tests for cyberguard.strength module.
Run with: python -m pytest tests/
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cyberguard.strength import (
    calculate_entropy,
    rule_based_score,
    classify_strength,
    analyze_password,
    _has_sequential_chars,
    _has_excessive_repeats,
)


def test_entropy_empty_password():
    assert calculate_entropy("") == 0.0


def test_entropy_increases_with_length():
    short = calculate_entropy("Abc123")
    longer = calculate_entropy("Abc123Def456")
    assert longer > short


def test_entropy_increases_with_char_variety():
    letters_only = calculate_entropy("abcdefgh")
    mixed = calculate_entropy("aB3!defg")
    assert mixed > letters_only


def test_rule_based_score_weak_password():
    rules = rule_based_score("password")
    assert rules["no_common_password"] is False
    assert rules["length_strong (>=12)"] is False


def test_rule_based_score_strong_password():
    rules = rule_based_score("Tr0ub4dor&3xyz!")
    assert rules["has_uppercase"] is True
    assert rules["has_lowercase"] is True
    assert rules["has_digit"] is True
    assert rules["has_special_char"] is True
    assert rules["no_common_password"] is True


def test_sequential_chars_detected():
    assert _has_sequential_chars("abc123") is True
    assert _has_sequential_chars("xk9q2z") is False


def test_excessive_repeats_detected():
    assert _has_excessive_repeats("aaa123") is True
    assert _has_excessive_repeats("ab12ab") is False


def test_classify_strength_boundaries():
    assert classify_strength(10) == "Very Weak"
    assert classify_strength(30) == "Weak"
    assert classify_strength(45) == "Reasonable"
    assert classify_strength(70) == "Strong"
    assert classify_strength(150) == "Very Strong"


def test_analyze_password_structure():
    report = analyze_password("Str0ng!Pass123")
    assert "entropy_bits" in report
    assert "strength_label" in report
    assert "rule_details" in report
    assert report["password_length"] == len("Str0ng!Pass123")
