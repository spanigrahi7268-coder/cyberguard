"""
strength.py
Password strength analysis using entropy calculation and rule-based checks.
"""

import math
import re
import string

# A small sample of extremely common passwords for offline blacklist checking.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "login", "iloveyou",
    "password1", "1234567", "sunshine", "princess", "football",
}


def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits using pool-size method:
    entropy = length * log2(pool_size)
    """
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[%s]" % re.escape(string.punctuation), password):
        pool_size += len(string.punctuation)
    if re.search(r"\s", password):
        pool_size += 1

    if pool_size == 0 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def rule_based_score(password: str) -> dict:
    """
    Checks password against common security rules.
    Returns a dict with pass/fail status of each rule.
    """
    return {
        "length_ok (>=8)": len(password) >= 8,
        "length_strong (>=12)": len(password) >= 12,
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special_char": bool(re.search(r"[%s]" % re.escape(string.punctuation), password)),
        "no_common_password": password.lower() not in COMMON_PASSWORDS,
        "no_sequential_chars": not _has_sequential_chars(password),
        "no_repeated_chars": not _has_excessive_repeats(password),
    }


def _has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detects sequences like 'abc', '123', 'xyz'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        if len(chunk) < run_length:
            continue
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def _has_excessive_repeats(password: str, max_repeat: int = 3) -> bool:
    """Detects characters repeated max_repeat or more times consecutively."""
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count >= max_repeat:
                return True
        else:
            count = 1
    return False


def classify_strength(entropy: float) -> str:
    """Classifies password strength based on entropy (bits)."""
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"


def analyze_password(password: str) -> dict:
    """Full analysis combining entropy, rules and classification."""
    entropy = calculate_entropy(password)
    rules = rule_based_score(password)
    passed = sum(1 for v in rules.values() if v)
    total = len(rules)

    # Entropy alone can be misleading for well-known common passwords
    # (e.g. "password" scores decent entropy but is trivially guessable
    # via dictionary attack). Force a "Very Weak" label in that case.
    if not rules["no_common_password"]:
        strength_label = "Very Weak"
    else:
        strength_label = classify_strength(entropy)

    return {
        "password_length": len(password),
        "entropy_bits": entropy,
        "strength_label": strength_label,
        "rules_passed": f"{passed}/{total}",
        "rule_details": rules,
    }
