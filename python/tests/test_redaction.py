"""Client-side PII redaction, checked against the corpus shared with the Gentrail
server detector and the Go SDK (spec/pii_conformance.json).

Registers a stub `gentrail` package so the stdlib-only modules load without the
SDK's pydantic/OTel deps. Runnable as `python tests/test_redaction.py` or via pytest.
"""

import json
import os
import random
import re
import sys
import time
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.abspath(os.path.join(_HERE, "..", "gentrail"))
if "gentrail" not in sys.modules:
    _pkg = types.ModuleType("gentrail")
    _pkg.__path__ = [_PKG_DIR]
    sys.modules["gentrail"] = _pkg

from gentrail import otel_exporter as _otel  # noqa: E402
from gentrail import pii as _pii  # noqa: E402

redact_pii = _otel.redact_pii
GovernanceTracer = _otel.GovernanceTracer


def test_redact_pii():
    cases = {
        "reach me at jane.doe@example.com please": "reach me at [EMAIL] please",
        "SSN 123-45-6789 on file": "SSN [SSN] on file",
        "SSN 123456789 on file": "SSN [SSN] on file",
        "key AKIAZ4QXN7P2LRT5WVKB leaked": "key [AWS_KEY] leaked",
        "card 4111111111111111 charged": "card [CREDIT_CARD] charged",
        "card 4111 1111 1111 1111 charged": "card [CREDIT_CARD] charged",
        "amex 378282246310005 ok": "amex [CREDIT_CARD] ok",
        "pay DE89370400440532013000 today": "pay [IBAN] today",
        "phone 555-123-4567": "phone [PHONE]",
        "token ghp_R8x2mQ9vL4kT7nB1cZ5wY3pH6jD0fG2sA9eK": "token [SECRET]",
        '{"email":"a@b.co","ssn":"111-22-3333"}': '{"email":"[EMAIL]","ssn":"[SSN]"}',
        "a@b.com and 123-45-6789": "[EMAIL] and [SSN]",
        "just a normal sentence with 42 items": "just a normal sentence with 42 items",
        "": "",
    }
    for raw, want in cases.items():
        got = redact_pii(raw)
        assert got == want, f"redact_pii({raw!r}) = {got!r}, want {want!r}"


def test_redact_leaves_look_alikes():
    for s in [
        "order 4111111111111112 shipped",
        "ref 1234567890123456 pending",
        "ref 555-123-4567",
        "id 12345",
        "icon@2x.png",
        "api_key = $API_KEY",
        "key AKIAIOSFODNN7EXAMPLE",
    ]:
        assert redact_pii(s) == s, f"redacted a look-alike: {s!r} -> {redact_pii(s)!r}"


_PLACEHOLDER_RE = re.compile(r"\[(AWS_KEY|CREDIT_CARD|EMAIL|IBAN|PHONE|SECRET|SSN)\]")


def test_redaction_conforms_to_gentrail_corpus():
    with open(os.path.join(_HERE, "..", "..", "spec", "pii_conformance.json"), encoding="utf-8") as f:
        corpus = json.load(f)
    assert tuple(corpus["classes"]) == _pii.PII_CLASSES, f"corpus classes {corpus['classes']} vs SDK {_pii.PII_CLASSES}"
    assert corpus["cases"], "corpus has no cases"
    failures = []
    for case in corpus["cases"]:
        found = set()
        for field in case["fields"]:
            redacted = redact_pii(field)
            if not case["want"] and redacted != field:
                failures.append(f"{case['name']}: {field!r} -> {redacted!r}, want unchanged")
            found.update(_PLACEHOLDER_RE.findall(redacted))
        if sorted(found) != case["want"]:
            failures.append(f"{case['name']}: placeholders {sorted(found)}, want {case['want']}")
    assert not failures, "\n".join(failures)


def test_redaction_leaves_nothing_detectable():
    for field in [
        "0@0.AA+000000000000000",
        "0@0.AA+00000000+00000000+00000000+00000000",
        "ssn 123-45-6789 and a@b.com 4111111111111111",
        "phone 555-123-4567 api_key = \"q8Zr4TmN2vX7pL1kW9sB\"",
    ]:
        redacted = redact_pii(field)
        leftover = _pii.pii_findings(redacted)
        assert not leftover, f"redact_pii({field!r}) = {redacted!r} still has {leftover}"


def test_randomized_fields_redact_to_a_fixpoint():
    rng = random.Random(20260923)
    alphabet = "0123456789 -+().@AKIAZ_ssnphoneapi_key=\"[]\n" + chr(0x2011) + chr(0xFF11) + chr(0x200B)
    for _ in range(3000):
        field = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        for finding in _pii.pii_findings(field):
            assert 0 <= finding.start < finding.end <= len(field), f"{finding} outside {field!r}"
        redacted = redact_pii(field)
        leftover = _pii.pii_findings(redacted)
        assert not leftover, f"redact_pii({field!r}) = {redacted!r} still has {leftover}"


def test_secret_scan_is_linear_time_on_adversarial_input():
    fillers = ["0", "a", "a.", "a-", "a ", "aA0"]
    started = time.perf_counter()
    for rule in _pii._secret_rules().rules:
        keyword = rule.keywords[0]
        for filler in fillers:
            run = filler * (100_000 // len(filler))
            for text in (keyword + " = " + run, keyword + run, run + keyword):
                for _ in rule.regex.finditer(text):
                    pass
    elapsed = time.perf_counter() - started
    assert elapsed < 10, f"adversarial sweep took {elapsed:.1f}s; a backtracking engine is back"


def test_redacting_a_megabyte_of_digits_is_fast():
    field = "cohere api_key = " + "0" * 1_000_000
    started = time.perf_counter()
    redact_pii(field)
    elapsed = time.perf_counter() - started
    assert elapsed < 2, f"redact_pii on 1 MB took {elapsed:.2f}s"


def test_vendored_secret_rules_compile():
    rule_set = _pii._secret_rules()
    assert len(rule_set.rules) >= 200, f"compiled {len(rule_set.rules)} rules"
    assert rule_set.global_allowlist.regexes, "global allowlist has no regexes"


def test_vendored_iban_registry_loads():
    lengths = _pii._iban_length_by_country()
    assert len(lengths) >= 80
    assert lengths["DE"] == 22 and lengths["NO"] == 15


def test_luhn_valid():
    for s in ["4111111111111111", "4111 1111 1111 1111", "378282246310005", "5500005555555559"]:
        assert _pii._luhn_valid(s), f"luhn should accept {s!r}"
    for s in ["4111111111111112", "1234567890123456", "12345", "", "not a number"]:
        assert not _pii._luhn_valid(s), f"luhn should reject {s!r}"


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
