from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from .errors import ValidationError

_SCHEME = "v1"


def encode(secret: bytes, snapshot_id: int, offset: int, collection_id: str) -> str:
    """Build an opaque, URL-safe cursor for the next page of a snapshot."""
    payload = json.dumps(
        {"s": snapshot_id, "o": offset, "c": collection_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    body = _b64encode(payload)
    signature = _b64encode(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{_SCHEME}.{body}.{signature}"


def decode(secret: bytes, token: Any, collection_id: str) -> tuple[int, int]:
    """Return ``(snapshot_id, offset)`` from a cursor produced for this collection."""
    if not isinstance(token, str):
        raise ValidationError("next is not a valid cursor for this service")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _SCHEME:
        raise ValidationError("next is not a valid cursor for this service")
    _, body, signature = parts
    expected = _b64encode(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise ValidationError("next cursor was modified or was not issued by this service")
    try:
        payload = json.loads(_b64decode(body))
    except (ValueError, json.JSONDecodeError) as error:
        raise ValidationError("next is not a valid cursor for this service") from error
    if not isinstance(payload, dict) or set(payload) != {"s", "o", "c"}:
        raise ValidationError("next is not a valid cursor for this service")
    snapshot_id, offset, cursor_collection = payload["s"], payload["o"], payload["c"]
    if not isinstance(snapshot_id, int) or isinstance(snapshot_id, bool):
        raise ValidationError("next is not a valid cursor for this service")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValidationError("next is not a valid cursor for this service")
    if not isinstance(cursor_collection, str):
        raise ValidationError("next is not a valid cursor for this service")
    if cursor_collection != collection_id:
        raise ValidationError("next cursor does not belong to this collection")
    return snapshot_id, offset


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
