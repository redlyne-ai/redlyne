"""
Fixture: yaml.dump emits Python-specific tags by default.

CWE-502 family: writing arbitrary Python objects via yaml.dump means a
downstream yaml.load (without SafeLoader) can deserialize and execute
them. Use yaml.safe_dump for round-trippable, language-agnostic YAML.
"""
import yaml


def serialize(data):
    return yaml.dump(data)
