"""
Fixture: hashing a password with SHA-1.

CWE-327: Use of a Broken or Risky Cryptographic Algorithm.
SHA-1 is broken for collision resistance and not designed as a password hash
anyway. Engine should detect SHA1-001 and rewrite to sha512 (and ideally
the human will replace with a real password-hashing function like bcrypt).
"""
import hashlib


def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
