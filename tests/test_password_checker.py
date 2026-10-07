import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from password_checker import (
    analyze, breach_count, entropy_bits, has_repeats, has_sequence,
    parse_range_response, sha1_prefix_suffix,
)


def test_common_password_scores_zero():
    score, rating, findings = analyze("password")
    assert score == 0
    assert rating == "Weak"


def test_long_mixed_password_is_strong():
    score, rating, _ = analyze("Tr0ub4dor&Horse-Battery!")
    assert rating == "Strong"


def test_short_password_flagged():
    _, _, findings = analyze("Ab1!")
    assert any("short" in f.lower() for f in findings)


def test_sequence_detection():
    assert has_sequence("myqwertpass")
    assert has_sequence("xx4321xx")
    assert not has_sequence("k9#Lm2@p")


def test_repeat_detection():
    assert has_repeats("heyyyy")
    assert not has_repeats("hey")


def test_entropy_grows_with_variety():
    assert entropy_bits("aaaaaaaa") < entropy_bits("aA1!aA1!")


def test_sha1_split():
    prefix, suffix = sha1_prefix_suffix("password")
    full = hashlib.sha1(b"password").hexdigest().upper()
    assert prefix + suffix == full
    assert len(prefix) == 5


def test_only_prefix_is_sent():
    sent = []
    def fake_fetch(prefix):
        sent.append(prefix)
        return ""
    breach_count("hunter2", fetch=fake_fetch)
    assert len(sent) == 1 and len(sent[0]) == 5


def test_breach_found_in_fake_response():
    _, suffix = sha1_prefix_suffix("password")
    fake_body = f"0000000000000000000000000000000000A:3\n{suffix}:9545824\n"
    assert breach_count("password", fetch=lambda p: fake_body) == 9545824


def test_parse_range_no_match():
    assert parse_range_response("ABC:1\nDEF:2", "XYZ") == 0
