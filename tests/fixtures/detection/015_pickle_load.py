"""
Fixture: pickle.loads on untrusted bytes.

CWE-502: Insecure Deserialization. pickle is a remote-code-execution
primitive when fed attacker-controlled bytes. For untrusted input use
json (or schema-validated msgpack). Engine should rewrite to json.loads.
"""
import pickle


def load(blob):
    return pickle.loads(blob)
