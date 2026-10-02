from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .cursor import decode_cursor, encode_cursor
from .errors import ConflictError, NotFoundError, ValidationError
from .model import (
    MEDIA_TYPE,
    OBJECT_TYPES,
    SPEC_VERSION,
    StixObject,
    canonical_timestamp,
    identifier_type,
    timestamp_value,
)
from .store import Store

COLLECTION_PROPERTIES = ("id", "title", "description", "can_read", "can_write")

# `limit` is a decimal integer between 1 and 200; anything else is rejected.
LIMIT_VALUE = re.compile(r"[0-9]+")
MAX_LIMIT = 200


@dataclass(frozen=True)
class Result:
    """A stored value plus the HTTP status the first creation used."""

    payload: dict[str, Any]
    status: int

    def to_json(self) -> dict[str, Any]:
        return self.payload


def _object_result(document: dict[str, Any], collection_id: str, added_at: str, status: int) -> Result:
    payload = {
        "collection_id": collection_id,
        "added_at": added_at,
        "version": document["modified"],
        "spec_version": SPEC_VERSION,
        "object": document,
    }
    return Result(payload, status)


class StixRelay:
    """STIX 2.1 object library with a TAXII 2.1 collection subset."""

    def __init__(self, database: str):
        self.store = Store(database)

    # ------------------------------------------------------------------ helpers

    def _idempotent(self, key: str | None, operation: str, action: Callable[[], Result]) -> Result:
        if not key:
            raise ValidationError("Idempotency-Key header is required")
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT operation, response, status FROM idempotency WHERE key = ?", (key,)
            ).fetchone()
            if existing:
                if existing["operation"] != operation:
                    raise ConflictError("idempotency key was already used for another operation")
                return Result(self.store.decode(existing["response"]), existing["status"])
            result = action()
            connection.execute(
                "INSERT INTO idempotency(key, operation, response, status) VALUES (?, ?, ?, ?)",
                (key, operation, self.store.encode(result.payload), result.status),
            )
            return result

    def _identity(self, raw: Any) -> tuple[str, ...]:
        if not isinstance(raw, list) or not raw or any(not isinstance(item, str) for item in raw):
            raise ValidationError("type must be a comma separated list of STIX object types")
        requested: list[str] = []
        for item in raw:
            for name in item.split(","):
                name = name.strip()
                if not name:
                    raise ValidationError("type must not contain an empty value")
                if name not in OBJECT_TYPES:
                    raise ValidationError(
                        f"type must be one of {', '.join(OBJECT_TYPES)}; got {name}"
                    )
                if name not in requested:
                    requested.append(name)
        return tuple(requested)

    def _added_after(self, raw: Any) -> str | None:
        if raw is None:
            return None
        if not isinstance(raw, list) or len(raw) != 1:
            raise ValidationError("added_after must be supplied exactly once")
        value = raw[0].replace(" ", "T", 1) if " " in raw[0] else raw[0]
        return canonical_timestamp(value, "added_after")

    def _limit(self, raw: Any) -> int | None:
        if raw is None:
            return None
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], str):
            raise ValidationError("limit must be supplied exactly once")
        if LIMIT_VALUE.fullmatch(raw[0]) is None:
            raise ValidationError("limit must be a decimal integer between 1 and 200")
        limit = int(raw[0])
        if not 1 <= limit <= MAX_LIMIT:
            raise ValidationError("limit must be a decimal integer between 1 and 200")
        return limit

    def _cursor_state(self, raw: Any, collection_id: str) -> dict[str, Any]:
        if not isinstance(raw, list) or len(raw) != 1:
            raise ValidationError("next must be supplied exactly once")
        state = decode_cursor(raw[0], self.store.cursor_secret)
        if state["c"] != collection_id:
            raise ValidationError("next does not belong to this collection")
        return state

    def _require_collection(self, collection_id: str) -> dict[str, Any]:
        row = self.store.connection.execute(
            "SELECT document FROM collections WHERE id = ?", (collection_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"collection {collection_id} was not found")
        return self.store.decode(row["document"])

    def _require_references(self, collection_id: str, stix_object: StixObject) -> None:
        """Every relationship endpoint must already exist in the same collection."""
        for reference in stix_object.references():
            row = self.store.connection.execute(
                "SELECT version FROM objects WHERE collection_id = ? AND object_id = ?"
                " ORDER BY version DESC LIMIT 1",
                (collection_id, reference),
            ).fetchone()
            if not row:
                raise ValidationError(
                    f"relationship references unknown {identifier_type(reference)} {reference}"
                    f" in collection {collection_id}"
                )

    # ------------------------------------------------------------------- public

    def create_collection(self, raw: Any, key: str | None) -> Result:
        if not isinstance(raw, dict):
            raise ValidationError("collection body must be a JSON object")
        unknown = sorted(set(raw) - set(COLLECTION_PROPERTIES))
        if unknown:
            raise ValidationError(f"collection has unsupported properties: {', '.join(unknown)}")
        collection_id = raw.get("id")
        if not isinstance(collection_id, str) or not collection_id:
            raise ValidationError("collection id must be a non-empty string")
        title = raw.get("title")
        if not isinstance(title, str) or not title:
            raise ValidationError("collection title must be a non-empty string")
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise ValidationError("collection description must be a string")
        for name in ("can_read", "can_write"):
            if name in raw and not isinstance(raw[name], bool):
                raise ValidationError(f"collection {name} must be a boolean")
        document = {
            "id": collection_id,
            "title": title,
            "description": description,
            "can_read": raw.get("can_read", True),
            "can_write": raw.get("can_write", True),
            "media_type": MEDIA_TYPE,
        }

        def create() -> Result:
            try:
                self.store.connection.execute(
                    "INSERT INTO collections(id, document) VALUES (?, ?)",
                    (collection_id, self.store.encode(document)),
                )
            except Exception as error:
                if "UNIQUE constraint" in str(error):
                    raise ConflictError(f"collection {collection_id} already exists") from error
                raise
            return Result(document, 201)

        return self._idempotent(key, f"create-collection:{collection_id}", create)

    def get_collection(self, collection_id: str) -> dict[str, Any]:
        return self._require_collection(collection_id)

    def list_collections(self) -> list[dict[str, Any]]:
        rows = self.store.connection.execute(
            "SELECT document FROM collections ORDER BY id"
        ).fetchall()
        return [self.store.decode(row["document"]) for row in rows]

    def add_object(
        self, collection_id: str, raw: Any, key: str | None, added_at: str | None = None
    ) -> Result:
        if not isinstance(raw, dict):
            raise ValidationError("object body must be a JSON object")
        if "added_at" in raw:
            if not isinstance(raw["added_at"], str):
                raise ValidationError("added_at must be a UTC timestamp string")
            if added_at is None:
                added_at = raw["added_at"]
            raw = {name: value for name, value in raw.items() if name != "added_at"}
        stix_object = StixObject.parse(raw)
        stamp = (
            canonical_timestamp(added_at, "added_at")
            if added_at is not None
            else self.store.now()
        )

        def create() -> Result:
            self._require_collection(collection_id)
            self._require_references(collection_id, stix_object)
            row = self.store.connection.execute(
                "SELECT version FROM objects WHERE collection_id = ? AND object_id = ?"
                " ORDER BY version DESC LIMIT 1",
                (collection_id, stix_object.id),
            ).fetchone()
            if row:
                if row["version"] == stix_object.modified:
                    raise ConflictError(
                        f"version {stix_object.modified} of {stix_object.id} already exists"
                    )
                if timestamp_value(stix_object.modified) < timestamp_value(row["version"]):
                    raise ConflictError(
                        f"version {stix_object.modified} of {stix_object.id} is older than the"
                        f" stored version {row['version']}"
                    )
            self.store.connection.execute(
                "INSERT INTO objects(collection_id, object_id, version, type, added_at, document)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    collection_id,
                    stix_object.id,
                    stix_object.version_key(),
                    stix_object.type,
                    stamp,
                    self.store.encode(stix_object.document()),
                ),
            )
            return _object_result(stix_object.document(), collection_id, stamp, 201)

        return self._idempotent(key, f"add-object:{collection_id}:{stix_object.id}", create)

    def list_objects(
        self,
        collection_id: str,
        type_filter: Any = None,
        added_after: Any = None,
        limit: Any = None,
        cursor: Any = None,
    ) -> Result:
        self._require_collection(collection_id)
        if cursor is not None and (
            type_filter is not None or added_after is not None or limit is not None
        ):
            raise ValidationError(
                "next must not be combined with type, added_after, or limit"
            )
        requested = self._identity(type_filter) if type_filter is not None else None
        cutoff = self._added_after(added_after)
        page_size = self._limit(limit)

        if page_size is None and cursor is None:
            return self._list_all(collection_id, requested, cutoff)

        position: tuple[str, str] | None = None
        if cursor is not None:
            # A continuation reuses the filters, page size, and snapshot boundary
            # remembered in the cursor instead of taking them from the query string.
            state = self._cursor_state(cursor, collection_id)
            requested = tuple(state["t"]) if state["t"] is not None else None
            cutoff = state["a"]
            page_size = state["l"]
            snapshot = state["s"]
            position = (state["p"][0], state["p"][1])
        else:
            # The snapshot boundary is the highest insertion sequence visible right now:
            # objects and revisions stored after this point never join this round.
            snapshot = self.store.connection.execute(
                "SELECT COALESCE(MAX(rowid), 0) AS seq FROM objects WHERE collection_id = ?",
                (collection_id,),
            ).fetchone()["seq"]

        sql = (
            "SELECT document, added_at, object_id FROM ("
            "  SELECT object_id, document, added_at, type,"
            "         ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY version DESC) AS rank"
            "  FROM objects WHERE collection_id = ? AND rowid <= ?"
            ") WHERE rank = 1"
        )
        parameters: list[Any] = [collection_id, snapshot]
        if requested is not None:
            placeholders = ", ".join("?" for _ in requested)
            sql += f" AND type IN ({placeholders})"
            parameters.extend(requested)
        if cutoff is not None:
            sql += " AND added_at > ?"
            parameters.append(cutoff)
        if position is not None:
            sql += " AND (added_at > ? OR (added_at = ? AND object_id > ?))"
            parameters.extend((position[0], position[0], position[1]))
        sql += " ORDER BY added_at, object_id LIMIT ?"
        parameters.append(page_size + 1)
        rows = self.store.connection.execute(sql, parameters).fetchall()

        page = rows[:page_size]
        more = len(rows) > page_size
        payload: dict[str, Any] = {
            "objects": [self.store.decode(row["document"]) for row in page],
            "more": more,
        }
        if more:
            last = page[-1]
            payload["next"] = encode_cursor(
                {
                    "v": 1,
                    "c": collection_id,
                    "t": list(requested) if requested is not None else None,
                    "a": cutoff,
                    "l": page_size,
                    "s": snapshot,
                    "p": [last["added_at"], last["object_id"]],
                },
                self.store.cursor_secret,
            )
        if requested is not None:
            payload["type"] = list(requested)
        return Result(payload, 200)

    def _list_all(
        self, collection_id: str, requested: tuple[str, ...] | None, cutoff: str | None
    ) -> Result:
        sql = (
            "SELECT document, added_at FROM ("
            "  SELECT document, added_at, type,"
            "         ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY version DESC) AS rank"
            "  FROM objects WHERE collection_id = ?"
            ") WHERE rank = 1"
        )
        parameters: list[Any] = [collection_id]
        if requested is not None:
            placeholders = ", ".join("?" for _ in requested)
            sql += f" AND type IN ({placeholders})"
            parameters.extend(requested)
        sql += " ORDER BY added_at, json_extract(document, '$.id')"
        rows = self.store.connection.execute(sql, parameters).fetchall()

        objects: list[dict[str, Any]] = []
        for row in rows:
            if cutoff is not None and timestamp_value(row["added_at"]) <= timestamp_value(cutoff):
                continue
            objects.append(self.store.decode(row["document"]))
        payload: dict[str, Any] = {"objects": objects, "more": False}
        if requested is not None:
            payload["type"] = list(requested)
        return Result(payload, 200)

    def object_versions(self, collection_id: str, object_id: str) -> Result:
        self._require_collection(collection_id)
        if not isinstance(object_id, str) or not object_id:
            raise ValidationError("objectId must be a non-empty STIX identifier")
        rows = self.store.connection.execute(
            "SELECT version, added_at FROM objects WHERE collection_id = ? AND object_id = ?"
            " ORDER BY version",
            (collection_id, object_id),
        ).fetchall()
        if not rows:
            raise NotFoundError(f"object {object_id} was not found in collection {collection_id}")
        versions = [row["version"] for row in rows]
        payload = {
            "id": object_id,
            "versions": versions,
            "earliest": [versions[0]],
            "latest": [versions[-1]],
            "added_at": [row["added_at"] for row in rows],
        }
        return Result(payload, 200)
