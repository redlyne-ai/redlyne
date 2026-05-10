"""
Fixture: using `random` module for security-sensitive token generation.

CWE-330: Use of Insufficiently Random Values.
The random module is a Mersenne Twister — predictable from a few outputs.
For tokens, session IDs, or anything an attacker could observe, use
`secrets` (CSPRNG) instead.

Engine should detect RANDOM-001 and rewrite to secrets.SystemRandom().
"""
import random


def generate_token():
    return random.randint(100000, 999999)
