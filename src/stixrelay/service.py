from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

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
        self, collection_id: str, type_filter: Any = None, added_after: Any = None
    ) -> Result:
        self._require_collection(collection_id)
        requested = self._identity(type_filter) if type_filter is not None else None
        cutoff = self._added_after(added_after)

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
