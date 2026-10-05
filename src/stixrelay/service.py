from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Callable

from . import cursor
from .errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from .model import (
    MEDIA_TYPE,
    OBJECT_TYPES,
    SPEC_VERSION,
    StixObject,
    canonical_timestamp,
    identifier_type,
    parse_pattern,
    timestamp_value,
)
from .store import Store

COLLECTION_PROPERTIES = ("id", "title", "description", "can_read", "can_write")

NDJSON_MEDIA_TYPE = "application/x-ndjson"
EXPORT_FORMATS = ("stix", "ndjson")
EXPORT_VERSIONS = ("current", "all")
EXPORT_QUERY_PARAMETERS = ("type", "added_after", "format", "versions")

MATCHES_PROPERTIES = ("observations", "include_revoked")


@dataclass(frozen=True)
class Result:
    """A stored value plus the HTTP status the first creation used."""

    payload: dict[str, Any]
    status: int

    def to_json(self) -> dict[str, Any]:
        return self.payload


@dataclass(frozen=True)
class Export:
    """A rendered collection export: media type plus the already encoded body."""

    media_type: str
    body: bytes
    status: int = 200


def _object_result(document: dict[str, Any], collection_id: str, added_at: str, status: int) -> Result:
    payload = {
        "collection_id": collection_id,
        "added_at": added_at,
        "version": document["modified"],
        "spec_version": SPEC_VERSION,
        "object": document,
    }
    return Result(payload, status)


# The lifecycle fields are the only ones a revocation version is allowed to change.
_REVOCATION_LIFETIME_FIELDS = ("modified", "revoked")


def _revocation_mismatch(current: dict[str, Any], replacement: dict[str, Any]) -> list[str]:
    """Properties a revocation version adds, drops, or changes besides the lifecycle fields."""
    mismatched: list[str] = []
    for key in sorted(set(current) | set(replacement)):
        if key in _REVOCATION_LIFETIME_FIELDS:
            continue
        if key not in current or key not in replacement or current[key] != replacement[key]:
            mismatched.append(key)
    return mismatched


def _observation_kind(value: Any) -> str:
    """The JSON basic type of an observed or pattern literal value.

    A boolean is its own basic type and is never treated as a number, even
    though Python models ``bool`` as a subclass of ``int``.
    """
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _observation_match(actual: Any, operator: str, expected: Any) -> bool:
    """Whether one observed value satisfies one pattern comparison."""
    if operator in ("=", "!="):
        # Equality compares by value only when both sides share a JSON basic
        # type; a type mismatch is no match, for `!=` just as for `=`.
        if _observation_kind(actual) != _observation_kind(expected):
            return False
        return actual == expected if operator == "=" else actual != expected
    # The ordering operators compare numbers only; anything else is no match.
    if _observation_kind(actual) != "number" or _observation_kind(expected) != "number":
        return False
    if operator == "<":
        return actual < expected
    if operator == ">":
        return actual > expected
    if operator == "<=":
        return actual <= expected
    return actual >= expected


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
        if not isinstance(raw, list) or len(raw) != 1:
            raise ValidationError("limit must be supplied exactly once")
        value = raw[0]
        if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
            raise ValidationError("limit must be a decimal integer between 1 and 200")
        page_size = int(value)
        if not 1 <= page_size <= 200:
            raise ValidationError("limit must be a decimal integer between 1 and 200")
        return page_size

    def _collection_document(self, collection_id: str) -> dict[str, Any] | None:
        row = self.store.connection.execute(
            "SELECT document FROM collections WHERE id = ?", (collection_id,)
        ).fetchone()
        return self.store.decode(row["document"]) if row else None

    def _require_readable(self, collection_id: str) -> dict[str, Any]:
        """Missing and unreadable collections are indistinguishable: both 404."""
        document = self._collection_document(collection_id)
        if document is None or not document.get("can_read", True):
            raise NotFoundError("collection access is denied")
        return document

    def _require_writable(self, collection_id: str) -> dict[str, Any]:
        document = self._require_readable(collection_id)
        if not document.get("can_write", True):
            raise ForbiddenError("collection is not writable")
        return document

    def _require_references(self, collection_id: str, stix_object: StixObject) -> None:
        """Every referenced object must already exist in the same collection."""
        for reference in stix_object.references():
            row = self.store.connection.execute(
                "SELECT version FROM objects WHERE collection_id = ? AND object_id = ?"
                " ORDER BY version DESC LIMIT 1",
                (collection_id, reference),
            ).fetchone()
            if not row:
                raise ValidationError(
                    f"{stix_object.type} references unknown {identifier_type(reference)}"
                    f" {reference} in collection {collection_id}"
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
        return self._require_readable(collection_id)

    def list_collections(self) -> list[dict[str, Any]]:
        rows = self.store.connection.execute(
            "SELECT document FROM collections ORDER BY id"
        ).fetchall()
        return [
            document
            for document in (self.store.decode(row["document"]) for row in rows)
            if document.get("can_read", True)
        ]

    def add_object(
        self, collection_id: str, raw: Any, key: str | None, added_at: str | None = None
    ) -> Result:
        # Access is decided before any validation, idempotency, or versioning work
        # so a denied request consumes nothing and reveals nothing.
        self._require_writable(collection_id)
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
            row = self.store.connection.execute(
                "SELECT version, document FROM objects WHERE collection_id = ? AND object_id = ?"
                " ORDER BY version DESC LIMIT 1",
                (collection_id, stix_object.id),
            ).fetchone()
            current_document: dict[str, Any] | None = None
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
                current_document = self.store.decode(row["document"])
                if current_document.get("revoked", False):
                    # A revoked object is terminal in its collection: any later write
                    # is a conflict, even one that flips revoked back or matches exactly.
                    raise ConflictError(
                        f"{stix_object.id} is revoked and accepts no further versions"
                    )
            self._require_references(collection_id, stix_object)
            if current_document is not None and stix_object.revoked:
                mismatched = _revocation_mismatch(current_document, stix_object.document())
                if mismatched:
                    raise ValidationError(
                        "a revocation version must keep every property and value of the current"
                        " version except modified and revoked; changed: " + ", ".join(mismatched)
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
        *,
        limit: Any = None,
        next_token: Any = None,
    ) -> Result:
        self._require_readable(collection_id)
        token = self._next_token(next_token)
        if token is not None:
            if type_filter is not None or added_after is not None or limit is not None:
                raise ValidationError("next must be supplied without type, added_after, or limit")
            return self._continue_snapshot(collection_id, token)

        requested = self._identity(type_filter) if type_filter is not None else None
        cutoff = self._added_after(added_after)
        page_size = self._limit(limit)
        documents = self._current_documents(
            self.store.connection, collection_id, requested, cutoff
        )

        if page_size is None:
            payload: dict[str, Any] = {"objects": documents, "more": False}
            if requested is not None:
                payload["type"] = list(requested)
            return Result(payload, 200)
        return self._start_snapshot(collection_id, requested, page_size, documents)

    def _next_token(self, raw: Any) -> str | None:
        if raw is None:
            return None
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], str):
            raise ValidationError("next is not a valid cursor for this service")
        return raw[0]

    def _current_documents(
        self,
        connection: Any,
        collection_id: str,
        requested: tuple[str, ...] | None,
        cutoff: str | None,
    ) -> list[dict[str, Any]]:
        """Latest readable revision of every object, in the stable listing order."""
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
        rows = connection.execute(sql, parameters).fetchall()

        documents: list[dict[str, Any]] = []
        for row in rows:
            if cutoff is not None and timestamp_value(row["added_at"]) <= timestamp_value(cutoff):
                continue
            documents.append(self.store.decode(row["document"]))
        return documents

    def _start_snapshot(
        self,
        collection_id: str,
        requested: tuple[str, ...] | None,
        page_size: int,
        documents: list[dict[str, Any]],
    ) -> Result:
        """Freeze the current result set so later writes stay out of this round."""
        type_echo = self.store.encode(list(requested)) if requested is not None else None
        with self.store.transaction() as connection:
            snapshot_id = connection.execute(
                "INSERT INTO snapshots(collection_id, created_at, limit_value, type_filter)"
                " VALUES (?, ?, ?, ?)",
                (collection_id, self.store.now(), page_size, type_echo),
            ).lastrowid
            connection.executemany(
                "INSERT INTO snapshot_entries(snapshot_id, position, document) VALUES (?, ?, ?)",
                [
                    (snapshot_id, position, self.store.encode(document))
                    for position, document in enumerate(documents)
                ],
            )
            total = len(documents)
            rows = connection.execute(
                "SELECT document FROM snapshot_entries WHERE snapshot_id = ?"
                " ORDER BY position LIMIT ?",
                (snapshot_id, page_size),
            ).fetchall()
        return self._page_result(snapshot_id, collection_id, type_echo, 0, rows, total)

    def _continue_snapshot(self, collection_id: str, token: str) -> Result:
        snapshot_id, offset = cursor.decode(self.store.cursor_secret, token, collection_id)
        snapshot = self.store.connection.execute(
            "SELECT id, collection_id, limit_value, type_filter FROM snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()
        if snapshot is None or snapshot["collection_id"] != collection_id:
            raise ValidationError("next is not a valid cursor for this service")
        total = self.store.connection.execute(
            "SELECT COUNT(*) AS count FROM snapshot_entries WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()["count"]
        if offset >= total:
            raise ValidationError("next cursor has no remaining pages")
        rows = self.store.connection.execute(
            "SELECT document FROM snapshot_entries WHERE snapshot_id = ?"
            " ORDER BY position LIMIT ? OFFSET ?",
            (snapshot_id, snapshot["limit_value"], offset),
        ).fetchall()
        return self._page_result(
            snapshot_id,
            snapshot["collection_id"],
            snapshot["type_filter"],
            offset,
            rows,
            total,
        )

    def _page_result(
        self,
        snapshot_id: int,
        collection_id: str,
        type_filter: str | None,
        offset: int,
        rows: list[Any],
        total: int,
    ) -> Result:
        objects = [self.store.decode(row["document"]) for row in rows]
        next_offset = offset + len(objects)
        more = next_offset < total
        payload: dict[str, Any] = {"objects": objects, "more": more}
        if type_filter is not None:
            payload["type"] = self.store.decode(type_filter)
        if more:
            payload["next"] = cursor.encode(
                self.store.cursor_secret, snapshot_id, next_offset, collection_id
            )
        return Result(payload, 200)

    def object_versions(self, collection_id: str, object_id: str) -> Result:
        self._require_readable(collection_id)
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

    # ----------------------------------------------------------------- matches

    def match_indicators(self, collection_id: str, raw: Any) -> dict[str, Any]:
        """Current-version indicator matches for a set of observed values.

        Read only: the access check runs before any body validation, and the
        evaluation creates no version, cursor, snapshot, or idempotency
        record and never modifies the database.
        """
        self._require_readable(collection_id)
        if not isinstance(raw, dict):
            raise ValidationError("matches body must be a JSON object")
        unknown = sorted(set(raw) - set(MATCHES_PROPERTIES))
        if unknown:
            raise ValidationError(
                f"matches has unsupported properties: {', '.join(unknown)}"
            )
        if "observations" not in raw:
            raise ValidationError("matches requires the observations property")
        observations = raw["observations"]
        if not isinstance(observations, dict) or not observations:
            raise ValidationError("observations must be a non-empty JSON object")
        for path, value in observations.items():
            if not isinstance(path, str) or not path:
                raise ValidationError("observation keys must be non-empty strings")
            if isinstance(value, (bool, str)):
                continue
            if isinstance(value, int):
                continue
            if isinstance(value, float) and math.isfinite(value):
                continue
            raise ValidationError(
                "observation values must be strings, finite numbers, or booleans"
            )
        include_revoked = raw.get("include_revoked", False)
        if not isinstance(include_revoked, bool):
            raise ValidationError("include_revoked must be a boolean")

        documents = self._current_documents(
            self.store.connection, collection_id, ("indicator",), None
        )
        matches: list[dict[str, Any]] = []
        for document in documents:
            if document.get("revoked", False) and not include_revoked:
                continue
            parsed = parse_pattern(document["pattern"])
            if parsed is None:
                continue
            path, operator, expected = parsed
            if path not in observations:
                continue
            if _observation_match(observations[path], operator, expected):
                matches.append(
                    {
                        "id": document["id"],
                        "modified": document["modified"],
                        "pattern": document["pattern"],
                    }
                )
        matches.sort(key=lambda item: item["id"])
        return {"matches": matches, "count": len(matches)}

    # ------------------------------------------------------------------ export

    def export_collection(
        self,
        collection_id: str,
        query: Any,
    ) -> Export:
        # Access is decided before touching any parameter, exactly like the other
        # collection reads, so a bad query never reveals whether a collection exists.
        self._require_readable(collection_id)
        if not isinstance(query, dict):
            raise ValidationError("query parameters must be a mapping")
        extra = sorted(set(query) - set(EXPORT_QUERY_PARAMETERS))
        if extra:
            raise ValidationError(f"unsupported query parameters: {', '.join(extra)}")
        export_format = self._choice(query, "format", EXPORT_FORMATS, "stix")
        version_mode = self._choice(query, "versions", EXPORT_VERSIONS, "current")
        requested = self._identity(query.get("type")) if query.get("type") is not None else None
        cutoff = self._added_after(query.get("added_after"))

        if version_mode == "current":
            documents = self._current_documents(
                self.store.connection, collection_id, requested, cutoff
            )
        else:
            documents = self._all_version_documents(collection_id, requested, cutoff)

        if export_format == "ndjson":
            body = b"".join(
                (json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                for document in documents
            )
            return Export(NDJSON_MEDIA_TYPE, body)
        body = json.dumps(
            {"type": "bundle", "objects": documents},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        return Export(MEDIA_TYPE, body)

    @staticmethod
    def _choice(query: dict[str, Any], name: str, allowed: tuple[str, ...], default: str) -> str:
        raw = query.get(name)
        if raw is None:
            return default
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], str):
            raise ValidationError(f"{name} must be supplied exactly once")
        value = raw[0]
        if value not in allowed:
            raise ValidationError(f"{name} must be one of {', '.join(allowed)}; got {value}")
        return value

    def _all_version_documents(
        self,
        collection_id: str,
        requested: tuple[str, ...] | None,
        cutoff: str | None,
    ) -> list[dict[str, Any]]:
        """Every stored revision matching the filter, in export order.

        Each version is filtered by its own ``added_at`` (strictly half-open) and
        ordered by ``added_at``, object id, then ``modified``.
        """
        sql = "SELECT document, added_at FROM objects WHERE collection_id = ?"
        parameters: list[Any] = [collection_id]
        if requested is not None:
            placeholders = ", ".join("?" for _ in requested)
            sql += f" AND type IN ({placeholders})"
            parameters.extend(requested)
        sql += " ORDER BY added_at, object_id, version"
        rows = self.store.connection.execute(sql, parameters).fetchall()

        documents: list[dict[str, Any]] = []
        for row in rows:
            if cutoff is not None and timestamp_value(row["added_at"]) <= timestamp_value(cutoff):
                continue
            documents.append(self.store.decode(row["document"]))
        return documents
