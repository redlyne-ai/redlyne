"""
Fixture: requests.get with verify=False.

CWE-295: disabling TLS certificate verification opens the channel to MITM.
Engine should rewrite to verify=True. (If the target genuinely uses a
self-signed cert, the right fix is to pass the CA bundle path, not to
disable verification.)
"""
import requests


def fetch():
    return requests.get("https://example.com/api", verify=False)
