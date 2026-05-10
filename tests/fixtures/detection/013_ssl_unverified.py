"""
Fixture: ssl._create_unverified_context disables certificate verification.

CWE-295: Improper Certificate Validation. Anything connecting through this
context is wide open to MITM. Engine should rewrite to
ssl.create_default_context() which validates by default.
"""
import ssl


def make_context():
    return ssl._create_unverified_context()
