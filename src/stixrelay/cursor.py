from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any

from .errors import ValidationError

# A cursor token is `v1.<payload>.<signature>` where both segments are unpadded
# URL-safe base64. The payload remembers everything a continuation needs (the
# collection, the filters, the page size, the snapshot boundary, and the keyset
# position); the signature is HMAC-SHA256 of the payload segment keyed by a
# per-database secret, so a cursor can neither be forged nor edited off-service.
VERSION = "v1"
FIELDS = {"v", "c", "t", "a", "l", "s", "p"}

INVALID = "next is not a cursor issued by this service"


def _decode_segment(segment: str) -> bytes:
    return base64.b64decode(
        (segment + "=" * (-len(segment) % 4)).encode(), altchars=b"-_", validate=True
    )


def encode_cursor(payload: dict[str, Any], secret: bytes) -> str:
    body = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{VERSION}.{body}.{token}"


def decode_cursor(token: Any, secret: bytes) -> dict[str, Any]:
    if not isinstance(token, str):
        raise ValidationError(INVALID)
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != VERSION or not parts[1] or not parts[2]:
        raise ValidationError(INVALID)
    body = parts[1]
    try:
        signature = _decode_segment(parts[2])
        payload = json.loads(_decode_segment(body))
    except (binascii.Error, ValueError):
        raise ValidationError(INVALID) from None
    expected = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise ValidationError(INVALID)
    if not _well_formed(payload):
        raise ValidationError(INVALID)
    return payload


def _well_formed(payload: Any) -> bool:
    if not isinstance(payload, dict) or set(payload) != FIELDS:
        return False
    if payload["v"] != 1 or not isinstance(payload["c"], str):
        return False
    if payload["t"] is not None and (
        not isinstance(payload["t"], list)
        or any(not isinstance(item, str) for item in payload["t"])
    ):
        return False
    if payload["a"] is not None and not isinstance(payload["a"], str):
        return False
    if (
        not isinstance(payload["l"], int)
        or isinstance(payload["l"], bool)
        or not 1 <= payload["l"] <= 200
    ):
        return False
    if (
        not isinstance(payload["s"], int)
        or isinstance(payload["s"], bool)
        or payload["s"] < 0
    ):
        return False
    position = payload["p"]
    return (
        isinstance(position, list)
        and len(position) == 2
        and all(isinstance(item, str) for item in position)
    )
