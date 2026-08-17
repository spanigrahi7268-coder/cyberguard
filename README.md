# 🛡️ CyberGuard — Password Strength & Data Breach Checker

A lightweight, dependency-free **cybersecurity mini-project** in Python that analyzes password strength using entropy calculation + rule-based heuristics, and checks whether a password has been exposed in a known data breach — **without ever sending the actual password over the network**.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📖 Overview

Weak and reused passwords remain one of the leading causes of account compromise. CyberGuard is a small, self-contained tool that demonstrates core defensive-security concepts:

- **Entropy-based strength scoring** (information theory: `bits = length × log2(pool_size)`)
- **Rule-based heuristics** (length, character variety, common-password blacklist, sequential/repeated character detection)
- **Breach intelligence** via the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) Pwned Passwords API, using the **k-Anonymity model** so the real password/hash is never transmitted in full.

This project is built for learning and portfolio purposes and only performs **defensive / analysis** functions — it does not crack, brute-force, or attack any system.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔢 Entropy Calculation | Estimates bits of entropy based on character pool size and length |
| ✅ Rule-Based Checks | 9 security rules (length, uppercase/lowercase/digit/symbol, common password, sequences, repeats) |
| 🌐 Breach Check | Queries HIBP's Pwned Passwords API safely using k-Anonymity (only first 5 hash chars sent) |
| 🖥️ CLI Tool | Simple command-line interface with hidden password input |
| 📊 JSON Output | Machine-readable report for integration into other tools |
| 🧪 Unit Tested | Core logic covered by unit tests |

---

## 🔐 How the Breach Check Stays Private

1. The password is hashed locally using **SHA-1**.
2. Only the **first 5 characters** of the hash are sent to the HIBP API.
3. HIBP returns *all* hash suffixes that share that 5-character prefix (usually 100s–1000s of entries).
4. The full match is done **locally** on your machine.

This means the real password — and even its full hash — **never leaves your computer**. This is the same technique used by browser built-in breach-check features.

```
Password → SHA-1 Hash → Send first 5 chars → Receive suffix list → Match locally
```

---

## 📂 Project Structure

```
cyberguard/
├── cyberguard/
│   ├── __init__.py
│   ├── strength.py       # Entropy + rule-based strength analysis
│   ├── breach_check.py   # HIBP k-Anonymity breach lookup
│   └── cli.py            # Command-line interface
├── tests/
│   └── test_strength.py  # Unit tests
├── requirements.txt
├── LICENSE
├── .gitignore
└── README.md
```

---

## 🚀 Installation

```bash
git clone https://github.com/spanigrahi7268-coder/cyberguard.git

```

No external packages are required to run the core tool — it only uses the Python standard library.

---

## 🧑‍💻 Usage

### Interactive (recommended — hides your typed password)
```bash
python -m cyberguard.cli
```

### Pass password directly (visible in shell history — use for testing only)
```bash
python -m cyberguard.cli -p "MySecretPass123!"
```

### Skip the online breach check (fully offline)
```bash
python -m cyberguard.cli -p "MySecretPass123!" --no-breach-check
```

### Get JSON output
```bash
python -m cyberguard.cli -p "MySecretPass123!" --json
```

### Sample Output
```
===== CyberGuard Password Report =====
Length          : 16
Entropy (bits)  : 95.27
Strength        : Strong
Rules Passed    : 8/9

--- Rule Breakdown ---
  [PASS] length_ok (>=8)
  [PASS] length_strong (>=12)
  [PASS] has_lowercase
  [PASS] has_uppercase
  [PASS] has_digit
  [PASS] has_special_char
  [PASS] no_common_password
  [FAIL] no_sequential_chars
  [PASS] no_repeated_chars

--- Breach Check (Have I Been Pwned) ---
  Good news: This password was not found in known breaches.
========================================
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.8+
- **Libraries used:** `hashlib`, `urllib`, `argparse`, `getpass`, `re`, `math` (all standard library)
- **External API:** [HaveIBeenPwned Pwned Passwords API v3](https://haveibeenpwned.com/API/v3#PwnedPasswords)

---

## 🗺️ Future Improvements

- [ ] Web UI (Flask/FastAPI) version
- [ ] Password generator with configurable policy
- [ ] Bulk CSV password audit mode for organizations
- [ ] Integration with `zxcvbn` for more realistic crack-time estimates

---

## ⚠️ Disclaimer

This tool is for **educational and defensive security purposes only**. It does not store, log, or transmit full plaintext passwords to any third party. Always follow your organization's security policy before using any password-analysis tool on production credentials.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

Built as a cybersecurity mini-project. Contributions and suggestions welcome via Issues / Pull Requests.
