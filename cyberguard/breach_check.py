"""
breach_check.py
Checks whether a password has appeared in known data breaches using the
Have I Been Pwned (HIBP) Pwned Passwords API.

Privacy note: This uses the k-Anonymity model. The full password (or its
full hash) is NEVER sent over the network. Only the first 5 characters of
the SHA-1 hash are sent to the API, and the matching is done locally on the
returned suffix list. This means HIBP never sees the actual password.

API docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
import urllib.request
import urllib.error


HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"


def _sha1_hash(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_breach(password: str, timeout: int = 5) -> dict:
    """
    Checks if a password appears in known breaches.

    Returns a dict:
        {
            "breached": bool,
            "times_seen": int,
            "error": str or None
        }
    """
    sha1_hash = _sha1_hash(password)
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = HIBP_API_URL.format(prefix)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CyberGuard-Password-Checker"}
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        return {"breached": None, "times_seen": 0, "error": str(exc)}

    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"breached": True, "times_seen": int(count), "error": None}

    return {"breached": False, "times_seen": 0, "error": None}
