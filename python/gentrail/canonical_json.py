"""RFC 8785 (JCS) canonical JSON, so a sealed journal hashes identically in
every Gentrail SDK: keys sorted by UTF-16 code units, no insignificant
whitespace, minimal string escaping, and ECMAScript number formatting."""

from __future__ import annotations

import math
from typing import Any

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _ecmascript_number(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"canonical JSON object keys must be strings, got {type(key).__name__}")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_canonical_string(key) + ":" + canonical_json(value[key]) for key in keys) + "}"
    raise TypeError(f"{type(value).__name__} is not canonical JSON")


def _canonical_string(s: str) -> str:
    out = ['"']
    for char in s:
        escaped = _SHORT_ESCAPES.get(char)
        if escaped is not None:
            out.append(escaped)
        elif char < " ":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _ecmascript_number(f: float) -> str:
    if math.isnan(f) or math.isinf(f):
        raise ValueError("canonical JSON has no NaN or Infinity")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    mantissa, _, exponent = repr(abs(f)).partition("e")
    integer_part, _, fraction_part = mantissa.partition(".")
    digits = integer_part + fraction_part
    point = len(integer_part) + (int(exponent) if exponent else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    return sign + _place_decimal_point(digits, point)


def _place_decimal_point(digits: str, point: int) -> str:
    count = len(digits)
    if count <= point <= 21:
        return digits + "0" * (point - count)
    if 0 < point <= 21:
        return digits[:point] + "." + digits[point:]
    if -6 < point <= 0:
        return "0." + "0" * -point + digits
    exponent = point - 1
    mantissa = digits[0] + ("." + digits[1:] if count > 1 else "")
    return mantissa + "e" + ("+" if exponent > 0 else "-") + str(abs(exponent))
