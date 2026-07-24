"""Strict JSON decoding for security-sensitive protocol boundaries."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from typing import Any


MAX_INTEGER_DIGITS = 128


def strict_json_loads(value: str | bytes | bytearray) -> Any:
    """Decode JSON without duplicate keys, non-finite values, or huge integers."""

    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
        parse_int=_bounded_int,
    )


def require_exact_keys(value: dict[str, object], expected: Iterable[str]) -> None:
    """Reject missing or unknown object members at a protocol boundary."""

    if set(value) != set(expected):
        raise ValueError("JSON object fields do not match the protocol schema")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, item in pairs:
        if key in output:
            raise ValueError("duplicate JSON object key")
        output[key] = item
    return output


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _bounded_int(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds the safety limit")
    return int(value)


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number is not permitted")
    return result
