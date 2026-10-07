"""
Password Security Checker
-------------------------
Scores a password's strength and checks whether it has appeared in a known
data breach, without ever sending the password over the internet.

Breach check (k-anonymity):
    1. Hash the password with SHA-1.
    2. Send only the first 5 characters of the hash to the
       Have I Been Pwned "Pwned Passwords" API.
    3. The API returns every leaked hash that starts with those 5 characters.
    4. We look for the rest of our hash in that list on our own machine.
    The service never sees the password or even its full hash.

Usage:
    python password_checker.py            # prompts for a password (hidden input)
    python password_checker.py --offline  # skip the breach check
"""

import argparse
import getpass
import hashlib
import math
import string
import urllib.request

HIBP_URL = "https://api.pwnedpasswords.com/range/"

# A short sample of the most common leaked passwords. A real deployment
# would load a larger list such as the top 100k from SecLists.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "login", "dragon", "football", "iloveyou",
    "master", "sunshine", "princess", "qwerty123", "1q2w3e4r", "000000",
    "passw0rd", "trustno1", "baseball", "superman", "hello123", "shadow",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def character_pool(password):
    """How many possible characters an attacker must try per position."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        pool += 33
    return pool


def entropy_bits(password):
    """Rough brute-force entropy: length * log2(pool size)."""
    pool = character_pool(password)
    return round(len(password) * math.log2(pool), 1) if pool else 0.0


def has_sequence(password, length=4):
    """True if the password contains a run like 'abcd', '4321', or 'qwer'."""
    lowered = password.lower()
    sources = KEYBOARD_ROWS + [string.ascii_lowercase]
    for src in sources:
        for i in range(len(src) - length + 1):
            chunk = src[i:i + length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_repeats(password, run=3):
    """True if any character repeats `run` times in a row, like 'aaa'."""
    return any(password[i] * run == password[i:i + run] for i in range(len(password) - run + 1))


def analyze(password):
    """Return (score 0-100, rating, list of findings)."""
    findings = []
    score = 0

    length = len(password)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 15
        findings.append("Use at least 12 characters.")
    else:
        findings.append("Too short: under 8 characters can be brute-forced quickly.")

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    score += classes * 10
    if classes < 3:
        findings.append("Mix uppercase, lowercase, numbers, and symbols.")

    bits = entropy_bits(password)
    if bits >= 60:
        score += 20
    elif bits >= 40:
        score += 10

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        findings.append("This is one of the most common passwords. Attackers try it first.")
    if has_sequence(password):
        score -= 15
        findings.append("Contains a predictable sequence (like 'abcd' or 'qwer').")
    if has_repeats(password):
        score -= 10
        findings.append("Contains repeated characters (like 'aaa').")

    score = max(0, min(100, score))
    if score >= 80:
        rating = "Strong"
    elif score >= 55:
        rating = "Moderate"
    else:
        rating = "Weak"
    return score, rating, findings


def sha1_prefix_suffix(password):
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_response(body, suffix):
    """Find our hash suffix in the API's 'SUFFIX:COUNT' lines. Return breach count."""
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip())
    return 0


def breach_count(password, fetch=None):
    """
    Return how many times this password appears in known breaches.
    `fetch` can be swapped out in tests so they don't need the internet.
    """
    prefix, suffix = sha1_prefix_suffix(password)
    if fetch is None:
        def fetch(p):
            req = urllib.request.Request(HIBP_URL + p, headers={"User-Agent": "password-security-checker"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode("utf-8")
    return parse_range_response(fetch(prefix), suffix)


def main():
    parser = argparse.ArgumentParser(description="Check password strength and breach exposure.")
    parser.add_argument("--offline", action="store_true", help="skip the Have I Been Pwned check")
    args = parser.parse_args()

    password = getpass.getpass("Password to check (input hidden): ")
    if not password:
        print("No password entered.")
        return

    score, rating, findings = analyze(password)
    print(f"\nStrength : {rating} ({score}/100)")
    print(f"Length   : {len(password)} characters")
    print(f"Entropy  : ~{entropy_bits(password)} bits")
    for f in findings:
        print(f"  - {f}")

    if not args.offline:
        try:
            count = breach_count(password)
        except OSError as err:
            print(f"\nBreach check skipped (network error: {err})")
        else:
            if count:
                print(f"\nFOUND IN BREACHES: seen {count:,} times. Do not use this password.")
            else:
                print("\nNot found in known breaches.")


if __name__ == "__main__":
    main()
