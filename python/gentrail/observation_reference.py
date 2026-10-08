from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .canonical_json import canonical_json

ARGUMENTS_SIZE_BYTES_MAX = 2 * 1024 * 1024
DECISION_OUTCOMES = frozenset({"verified", "request_conflict", "unavailable"})


@dataclass(frozen=True)
class DecisionReference:
    request_id: str
    invocation_id: str
    proposal_hash: str
    arguments_hash: str

    def validate(self) -> None:
        for identity in (self.request_id, self.invocation_id):
            if (
                not isinstance(identity, str)
                or not identity.strip()
                or len(identity.encode()) > 256
            ):
                raise ValueError("invalid decision reference identity")
        for digest in (self.proposal_hash, self.arguments_hash):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise ValueError("invalid decision reference digest")


def arguments_hash(arguments: str) -> str:
    if len(arguments.encode()) > ARGUMENTS_SIZE_BYTES_MAX:
        raise ValueError("observation arguments exceed size limit")
    decoded = json.loads(arguments or "{}", parse_int=float)
    if decoded is None:
        decoded = {}
    if not isinstance(decoded, dict):
        raise ValueError("observation arguments must be a JSON object")
    return hashlib.sha256(canonical_json(decoded).encode()).hexdigest()


def checked_reference(value: Any, request: dict[str, Any]) -> DecisionReference | None:
    if not isinstance(value, dict):
        return None
    try:
        reference = DecisionReference(
            **{key: value.get(key) for key in DecisionReference.__annotations__}
        )
        reference.validate()
        if reference.request_id != request[
            "request_id"
        ] or reference.invocation_id != request.get("invocation_id", ""):
            return None
        if reference.arguments_hash != arguments_hash(
            json.dumps(request.get("tool_args"))
        ):
            return None
        return reference
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def observation_attributes(
    reference: DecisionReference | None, arguments: str
) -> dict[str, str]:
    if reference is None:
        return {}
    if not isinstance(reference, DecisionReference):
        raise TypeError("invalid decision reference")
    reference.validate()
    return {
        "aigentrail.decision.request_id": reference.request_id,
        "aigentrail.decision.invocation_id": reference.invocation_id,
        "aigentrail.decision.proposal_hash": reference.proposal_hash,
        "aigentrail.decision.arguments_hash": arguments_hash(arguments),
    }
