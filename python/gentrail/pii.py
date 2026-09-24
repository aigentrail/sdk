"""Client-side PII redaction, a port of Gentrail's server detector.

Findings replace their span with a typed placeholder ([EMAIL], [SSN], ...) so
the raw value never leaves the process while the data class stays visible to
governance. tests/pii_conformance.json is the corpus shared with the server and
the Go SDK; the vendored rule data lives in gentrail/pii_data.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

PII_CLASSES = ("AWS_KEY", "CREDIT_CARD", "EMAIL", "IBAN", "PHONE", "SECRET", "SSN")

_REDACTION_PASSES_MAX = 4


@dataclass(frozen=True)
class PIIFinding:
    pii_class: str
    start: int
    end: int
    detector: str


@dataclass(frozen=True)
class _NormalizedText:
    text: str
    lower: str
    origin_of_index: Sequence[int]
    numeric_spans: Tuple[Tuple[int, int], ...]

    def finding(self, pii_class: str, start: int, end: int, detector: str) -> PIIFinding:
        assert 0 <= start < end <= len(self.text), "pii span outside normalized text"
        original_start = self.origin_of_index[start]
        last_origin_in_span = self.origin_of_index[end - 1]
        original_end = self.origin_of_index[end]
        next_index = end + 1
        while original_end <= last_origin_in_span:
            original_end = self.origin_of_index[next_index]
            next_index += 1
        return PIIFinding(pii_class, original_start, original_end, detector)

    def digit_at(self, i: int) -> bool:
        return 0 <= i < len(self.text) and "0" <= self.text[i] <= "9"

    def alphanumeric_at(self, i: int) -> bool:
        if i < 0 or i >= len(self.text):
            return False
        c = self.lower[i]
        return "0" <= c <= "9" or "a" <= c <= "z"

    def context_before(self, start: int, words: Sequence[str]) -> bool:
        window = self.lower[max(0, start - 40) : start]
        return any(word in window for word in words)


def redact_pii(field: str) -> str:
    """Replace every PII finding in field with its placeholder, repeating until
    nothing changes: replacing one value can expose a neighbour that was
    previously glued to it."""
    redacted = field
    for _ in range(_REDACTION_PASSES_MAX):
        next_redacted = _redact_pii_once(redacted)
        if next_redacted == redacted:
            return redacted
        redacted = next_redacted
    return redacted


def _redact_pii_once(field: str) -> str:
    findings = sorted(pii_findings(field), key=lambda f: (f.start, -f.end))
    if not findings:
        return field
    parts: List[str] = []
    written = 0
    for finding in findings:
        if finding.start < written:
            written = max(written, finding.end)
            continue
        parts.append(field[written : finding.start])
        parts.append("[" + finding.pii_class + "]")
        written = finding.end
    parts.append(field[written:])
    return "".join(parts)


def pii_findings(field: str) -> List[PIIFinding]:
    if not field:
        return []
    text = _normalize(field)
    findings: List[PIIFinding] = []
    for detect in _DETECTORS:
        findings.extend(detect(text))
    for finding in findings:
        assert 0 <= finding.start < finding.end <= len(field), "pii finding outside its field"
    return findings


def _normalize(original: str) -> _NormalizedText:
    if original.isascii():
        spans = tuple(_numeric_spans(original))
        return _NormalizedText(original, original.lower(), range(len(original) + 1), spans)
    parts: List[str] = []
    origin: List[int] = []
    copied_to = 0
    for m in _NON_ASCII_RE.finditer(original):
        parts.append(original[copied_to : m.start()])
        origin.extend(range(copied_to, m.start()))
        for index in range(m.start(), m.end()):
            folded = _fold_char(original[index])
            parts.append(folded)
            origin.extend([index] * len(folded))
        copied_to = m.end()
    parts.append(original[copied_to:])
    origin.extend(range(copied_to, len(original)))
    origin.append(len(original))
    text = "".join(parts)
    assert len(origin) == len(text) + 1, "pii normalization lost its offset map"
    lower = text.translate(_ASCII_UPPER_TO_LOWER)
    return _NormalizedText(text, lower, tuple(origin), tuple(_numeric_spans(text)))


_ASCII_UPPER_TO_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]+")
_DROPPED_CHARS = frozenset(chr(c) for c in (0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
_DASH_CHARS = frozenset(chr(c) for c in (*range(0x2010, 0x2016), 0x2212, 0xFE58, 0xFE63, 0xFF0D))


def _fold_char(char: str) -> str:
    if char in _DROPPED_CHARS:
        return ""
    if char in _DASH_CHARS:
        return "-"
    if unicodedata.category(char) == "Zs":
        return " "
    return unicodedata.normalize("NFKC", char)


_NUMERIC_SPAN_RE = re.compile(r"[+(]?\d(?:[ .()\-]{0,2}\d)*", re.ASCII)
_NUMERIC_SPAN_DIGITS_MIN = 8


def _numeric_spans(text: str) -> List[Tuple[int, int]]:
    return [
        m.span()
        for m in _NUMERIC_SPAN_RE.finditer(text)
        if sum(1 for c in m.group() if "0" <= c <= "9") >= _NUMERIC_SPAN_DIGITS_MIN
    ]


def _find_all_in_spans(pattern: "re.Pattern[str]", text: str, spans: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    matches: List[Tuple[int, int]] = []
    for span_start, span_end in spans:
        for m in pattern.finditer(text, span_start, span_end):
            matches.append((m.start(), m.end()))
    return matches


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.ASCII)
_FILE_EXTENSIONS_THAT_ARE_NOT_TLDS = frozenset(
    "bmp css csv gif htm html ico jpeg jpg js json jsx md pdf png py svg tif tiff toml ts tsx txt webp xml yaml yml".split()
)


def _email_findings(text: _NormalizedText) -> List[PIIFinding]:
    findings = []
    for start, end in _find_all_in_spans(_EMAIL_RE, text.lower, _email_spans(text.lower)):
        top_level_domain = text.lower[text.lower.rindex(".", start, end) + 1 : end]
        if top_level_domain in _FILE_EXTENSIONS_THAT_ARE_NOT_TLDS:
            continue
        findings.append(text.finding("EMAIL", start, end, "email"))
    return findings


def _is_email_char(c: str) -> bool:
    return "a" <= c <= "z" or "0" <= c <= "9" or c in "._%+-"


def _email_spans(lower: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    span_end = 0
    at = lower.find("@")
    while at >= 0:
        if at >= span_end:
            start = at
            while start > 0 and _is_email_char(lower[start - 1]):
                start -= 1
            span_end = at + 1
            while span_end < len(lower) and _is_email_char(lower[span_end]):
                span_end += 1
            spans.append((start, span_end))
        at = lower.find("@", at + 1)
    return spans


_SSN_DASHED_RE = re.compile(r"\d{3}-\d{2}-\d{4}", re.ASCII)
_SSN_UNDELIMITED_RE = re.compile(r"\d{3} \d{2} \d{4}|\d{9}", re.ASCII)
_SSN_CONTEXT_WORDS = ("ssn", "social security", "ss#", "ss #")


def _ssn_findings(text: _NormalizedText) -> List[PIIFinding]:
    findings = []
    for start, end in _find_all_in_spans(_SSN_DASHED_RE, text.text, text.numeric_spans):
        if _isolated_token(text, start, end) and _valid_ssn(text.text[start:end].replace("-", "")):
            findings.append(text.finding("SSN", start, end, "ssn_dashed"))
    for start, end in _find_all_in_spans(_SSN_UNDELIMITED_RE, text.text, text.numeric_spans):
        if not _isolated_token(text, start, end) or not text.context_before(start, _SSN_CONTEXT_WORDS):
            continue
        if _valid_ssn(text.text[start:end].replace(" ", "")):
            findings.append(text.finding("SSN", start, end, "ssn_with_context"))
    return findings


def _isolated_token(text: _NormalizedText, start: int, end: int) -> bool:
    before, after = start - 1, end
    if text.alphanumeric_at(before) or text.alphanumeric_at(after):
        return False
    dash_before = before >= 0 and text.text[before] == "-"
    dash_after = after < len(text.text) and text.text[after] == "-"
    return not dash_before and not dash_after


def _valid_ssn(digits: str) -> bool:
    assert len(digits) == 9, "valid_ssn needs exactly nine digits"
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


_DIGIT_RUN_RE = re.compile(r"\d(?:[ -]?\d)*", re.ASCII)


def _credit_card_findings(text: _NormalizedText) -> List[PIIFinding]:
    findings = []
    for run_start, run_end in _find_all_in_spans(_DIGIT_RUN_RE, text.text, text.numeric_spans):
        groups = _digit_groups(text.text, run_start, run_end)
        first = 0
        while first < len(groups):
            last = _longest_card_span(text.text, groups, first)
            if last is None:
                first += 1
                continue
            findings.append(text.finding("CREDIT_CARD", groups[first][0], groups[last][1], "credit_card_luhn"))
            first = last + 1
    return findings


def _digit_groups(text: str, start: int, end: int) -> List[Tuple[int, int]]:
    groups: List[Tuple[int, int]] = []
    group_start = start
    for i in range(start, end):
        if text[i] in " -":
            groups.append((group_start, i))
            group_start = i + 1
    groups.append((group_start, end))
    return groups


def _longest_card_span(text: str, groups: Sequence[Tuple[int, int]], first: int) -> Optional[int]:
    card_digits_min, card_digits_max = 13, 19
    digits = ""
    last: Optional[int] = None
    for i in range(first, len(groups)):
        digits += text[groups[i][0] : groups[i][1]]
        if len(digits) > card_digits_max:
            break
        if len(digits) >= card_digits_min and _valid_card_number(digits):
            last = i
    return last


def _valid_card_number(digits: str) -> bool:
    if not "2" <= digits[0] <= "6":
        return False
    if digits.count(digits[0]) == len(digits):
        return False
    return _luhn_valid(digits)


def _luhn_valid(s: str) -> bool:
    digits = [ord(c) - 48 for c in s if "0" <= c <= "9"]
    if not 13 <= len(digits) <= 19:
        return False
    total, double = 0, False
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


@lru_cache(maxsize=1)
def _iban_length_by_country() -> Dict[str, int]:
    registry = json.loads(_read_data("iban_registry.json"))
    lengths = registry["length_by_country"]
    assert lengths, "iban registry has no countries"
    for country, length in lengths.items():
        assert len(country) == 2 and 15 <= length <= 34, f"implausible iban entry {country} {length}"
    return lengths


def _iban_findings(text: _NormalizedText) -> List[PIIFinding]:
    findings = []
    lengths = _iban_length_by_country()
    for start in _iban_candidate_starts(text.text):
        length = lengths.get(text.text[start : start + 2])
        if length is None or text.alphanumeric_at(start - 1):
            continue
        compact, end = _collect_iban(text.text, start, length)
        if len(compact) != length or text.alphanumeric_at(end) or not _iban_checksum_valid(compact):
            continue
        findings.append(text.finding("IBAN", start, end, "iban_mod97"))
    return findings


_IBAN_CANDIDATE_RE = re.compile(r"(?=[A-Z]{2}\d{2})", re.ASCII)


def _iban_candidate_starts(text: str) -> List[int]:
    return [m.start() for m in _IBAN_CANDIDATE_RE.finditer(text)]


def _collect_iban(text: str, start: int, length: int) -> Tuple[str, int]:
    compact: List[str] = []
    end = start
    i = start
    while i < len(text) and len(compact) < length:
        c = text[i]
        if "0" <= c <= "9" or "A" <= c <= "Z":
            compact.append(c)
            end = i + 1
        elif c != " " or i == start or text[i - 1] == " ":
            break
        i += 1
    return "".join(compact), end


def _iban_checksum_valid(compact: str) -> bool:
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for c in rearranged:
        if "0" <= c <= "9":
            remainder = (remainder * 10 + ord(c) - 48) % 97
        elif "A" <= c <= "Z":
            remainder = (remainder * 100 + ord(c) - 55) % 97
        else:
            return False
    return remainder == 1


_PHONE_INTERNATIONAL_RE = re.compile(r"\+\d[\d ().-]{6,22}\d", re.ASCII)
_PHONE_NATIONAL_RE = re.compile(r"\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}", re.ASCII)
_PHONE_CONTEXT_WORDS = ("phone", "tel", "call", "mobile", "cell", "fax", "sms", "whatsapp", "text me", "contact")


def _phone_findings(text: _NormalizedText) -> List[PIIFinding]:
    findings = []
    for start, end in _find_all_in_spans(_PHONE_INTERNATIONAL_RE, text.text, text.numeric_spans):
        digit_count = sum("0" <= c <= "9" for c in text.text[start:end])
        if text.alphanumeric_at(start - 1) or text.digit_at(end) or not 8 <= digit_count <= 15:
            continue
        findings.append(text.finding("PHONE", start, end, "phone_international"))
    for start, end in _find_all_in_spans(_PHONE_NATIONAL_RE, text.text, text.numeric_spans):
        if _isolated_token(text, start, end) and text.context_before(start, _PHONE_CONTEXT_WORDS):
            findings.append(text.finding("PHONE", start, end, "phone_national_with_context"))
    return findings


@dataclass(frozen=True)
class _SecretAllowlist:
    target: str
    regexes: Tuple["re.Pattern[str]", ...]
    stopwords: Tuple[str, ...]

    def allows(self, targets: Dict[str, str]) -> bool:
        if any(regex.search(targets[self.target]) for regex in self.regexes):
            return True
        lower_secret = targets["secret"].lower()
        return any(stopword in lower_secret for stopword in self.stopwords)


@dataclass(frozen=True)
class _SecretRule:
    rule_id: str
    pii_class: str
    regex: "re.Pattern[str]"
    secret_group: int
    entropy_min: float
    keywords: Tuple[str, ...]
    allowlists: Tuple[_SecretAllowlist, ...]


@dataclass(frozen=True)
class _SecretRuleSet:
    rules: Tuple[_SecretRule, ...]
    global_allowlist: _SecretAllowlist
    unique_keywords: Tuple[str, ...]


def go_regex_to_python(pattern: str) -> str:
    """Translate RE2 syntax gitleaks uses that Python's re rejects: mid-pattern
    flag directives such as (?i) scope to the rest of their group in RE2 but
    must lead the whole expression in Python, and \\z is spelled \\Z."""
    out: List[str] = []
    open_directives: List[List[str]] = [[]]
    i, in_class = 0, False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            escaped = pattern[i : i + 2]
            out.append("\\Z" if escaped == "\\z" else escaped)
            i += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
            out.append("\\[" if char == "[" else char)
            i += 1
            continue
        if char == "[":
            in_class = True
            out.append(char)
            if pattern[i + 1 : i + 2] == "^":
                out.append("^")
                i += 1
            if pattern[i + 1 : i + 2] == "]":
                out.append("]")
                i += 1
            i += 1
            continue
        directive = re.match(r"\(\?([a-zA-Z]*(?:-[a-zA-Z]+)?)\)", pattern[i:])
        if directive and i > 0:
            flags = directive.group(1)
            out.append("(?" + flags + ":")
            open_directives[-1].append(flags)
            i += directive.end()
            continue
        if char == "(":
            open_directives.append([])
        elif char == ")":
            out.append(")" * len(open_directives.pop()))
        elif char == "|" and open_directives[-1]:
            out.append(")" * len(open_directives[-1]))
            out.append("|")
            out.extend("(?" + flags + ":" for flags in open_directives[-1])
            i += 1
            continue
        out.append(char)
        i += 1
    out.append(")" * len(open_directives[-1]))
    return "".join(out)


def _compile_secret_allowlist(source: Dict[str, object]) -> _SecretAllowlist:
    target = source.get("regex_target") or "secret"
    assert target in ("secret", "match", "line"), f"unknown regex target {target!r}"
    return _SecretAllowlist(
        target=str(target),
        regexes=tuple(re.compile(go_regex_to_python(p), re.ASCII) for p in source.get("regexes") or ()),
        stopwords=tuple(source.get("stopwords") or ()),
    )


@lru_cache(maxsize=1)
def _secret_rules() -> _SecretRuleSet:
    source = json.loads(_read_data("gitleaks_rules.json"))
    assert source["rules"], "vendored gitleaks rules are empty"
    rules = []
    unique_keywords: Dict[str, None] = {}
    for rule in source["rules"]:
        assert rule["keywords"], f"rule {rule['id']} has no keywords to prefilter on"
        regex = re.compile(go_regex_to_python(rule["regex"]), re.ASCII)
        assert rule["secret_group"] <= regex.groups, f"rule {rule['id']} secret group out of range"
        pii_class = "AWS_KEY" if rule["id"] == "aws-access-token" else "SECRET"
        allowlists = tuple(_compile_secret_allowlist(a) for a in rule["allowlists"])
        rules.append(
            _SecretRule(rule["id"], pii_class, regex, rule["secret_group"], rule["entropy"], tuple(rule["keywords"]), allowlists)
        )
        for keyword in rule["keywords"]:
            assert keyword, f"rule {rule['id']} has an empty keyword"
            unique_keywords[keyword] = None
    global_allowlist = _compile_secret_allowlist(source.get("global_allowlist") or {})
    return _SecretRuleSet(tuple(rules), global_allowlist, tuple(unique_keywords))


def _present_keywords(lower: str, keywords: Sequence[str]) -> frozenset:
    return frozenset(keyword for keyword in keywords if keyword in lower)


def _secret_findings(text: _NormalizedText) -> List[PIIFinding]:
    rule_set = _secret_rules()
    present = _present_keywords(text.lower, rule_set.unique_keywords)
    if not present:
        return []
    findings = []
    for rule in rule_set.rules:
        if not any(keyword in present for keyword in rule.keywords):
            continue
        for m in rule.regex.finditer(text.text):
            start, end = _secret_span(m, rule.secret_group)
            if start >= end or _secret_rejected(text.text, m, start, end, rule, rule_set.global_allowlist):
                continue
            findings.append(text.finding(rule.pii_class, start, end, "gitleaks:" + rule.rule_id))
    return findings


def _secret_span(m: "re.Match[str]", secret_group: int) -> Tuple[int, int]:
    if secret_group > 0:
        return m.span(secret_group)
    for group in range(1, (m.re.groups or 0) + 1):
        start, end = m.span(group)
        if start >= 0 and end > start:
            return start, end
    return m.span(0)


def _secret_rejected(text: str, m: "re.Match[str]", start: int, end: int, rule: _SecretRule, global_allowlist: _SecretAllowlist) -> bool:
    secret = text[start:end]
    if rule.entropy_min > 0 and _shannon_entropy(secret) <= rule.entropy_min:
        return True
    line_start = text.rfind("\n", 0, m.start()) + 1
    line_end = text.find("\n", m.end())
    targets = {
        "secret": secret,
        "match": m.group(0),
        "line": text[line_start : line_end if line_end >= 0 else len(text)],
    }
    return global_allowlist.allows(targets) or any(a.allows(targets) for a in rule.allowlists)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s.encode("utf-8"))
    entropy = 0.0
    for char in set(s):
        frequency = s.count(char) / length
        entropy -= frequency * math.log2(frequency)
    return entropy


def _read_data(name: str) -> str:
    return (Path(__file__).parent / "pii_data" / name).read_text(encoding="utf-8")


_DETECTORS: Tuple[Callable[[_NormalizedText], List[PIIFinding]], ...] = (
    _email_findings,
    _ssn_findings,
    _credit_card_findings,
    _iban_findings,
    _phone_findings,
    _secret_findings,
)
