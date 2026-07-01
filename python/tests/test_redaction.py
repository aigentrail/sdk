"""Standalone tests for client-side PII redaction.

Loads otel_exporter.py directly so it runs without the SDK's OTel/pydantic deps
(OTel is imported lazily, so the module loads on stdlib alone). Runnable as
`python tests/test_redaction.py` or via pytest.
"""

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "otel_exporter", os.path.join(_HERE, "..", "gentrail", "otel_exporter.py")
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
redact_pii = _mod.redact_pii
_luhn_valid = _mod._luhn_valid
GovernanceTracer = _mod.GovernanceTracer


def test_redact_pii():
    cases = {
        "reach me at jane.doe@example.com please": "reach me at [EMAIL] please",
        "SSN 123-45-6789 on file": "SSN [SSN] on file",
        "key AKIAIOSFODNN7EXAMPLE leaked": "key [AWS_KEY] leaked",
        "card 4111111111111111 charged": "card [CREDIT_CARD] charged",
        "card 4111 1111 1111 1111 charged": "card [CREDIT_CARD] charged",
        "amex 378282246310005 ok": "amex [CREDIT_CARD] ok",
        "a@b.com and 123-45-6789": "[EMAIL] and [SSN]",
        "just a normal sentence with 42 items": "just a normal sentence with 42 items",
        "": "",
    }
    for raw, want in cases.items():
        got = redact_pii(raw)
        assert got == want, f"redact_pii({raw!r}) = {got!r}, want {want!r}"


def test_redact_leaves_non_luhn():
    # A 16-digit number that fails Luhn is not a card and must survive.
    for s in [
        "order 4111111111111112 shipped",
        "ref 1234567890123456 pending",
        "phone 555-123-4567",
        "id 12345",
    ]:
        assert redact_pii(s) == s, f"redacted a non-card: {s!r} -> {redact_pii(s)!r}"


def test_luhn_valid():
    for s in ["4111111111111111", "4111 1111 1111 1111", "378282246310005", "5500005555555559"]:
        assert _luhn_valid(s), f"luhn should accept {s!r}"
    for s in ["4111111111111112", "1234567890123456", "12345", "", "not a number"]:
        assert not _luhn_valid(s), f"luhn should reject {s!r}"


class _FakeSpan:
    def __init__(self):
        self.attrs = {}

    def set_attribute(self, key, value):
        self.attrs[key] = value


class _FakeTracer:
    def __init__(self):
        self.span = _FakeSpan()

    def start_span(self, name):
        return self.span


def test_start_invocation_redacts_input_when_enabled():
    span = GovernanceTracer(_FakeTracer(), None, redact=True).start_invocation(
        "agent", "Agent", "journal-1", "contact jane@acme.com now"
    )
    assert span.attrs["input.value"] == "contact [EMAIL] now"


def test_start_invocation_keeps_raw_when_disabled():
    span = GovernanceTracer(_FakeTracer(), None, redact=False).start_invocation(
        "agent", "Agent", "journal-1", "contact jane@acme.com now"
    )
    assert span.attrs["input.value"] == "contact jane@acme.com now"


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _fn()
            print(f"ok  {_name}")
    print("PII REDACTION TESTS PASSED")
