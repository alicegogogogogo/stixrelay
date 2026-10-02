from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import ValidationError

# Object types this release can store, and the STIX id prefix each one uses.
OBJECT_TYPES = ("identity", "indicator", "malware", "relationship", "report")
ID_PREFIX = {
    "identity": "identity",
    "indicator": "indicator",
    "malware": "malware",
    "relationship": "relationship",
    "report": "report",
}

# A report may only point at these object types through `object_refs`.
REPORT_REF_TYPES = ("identity", "indicator", "malware", "relationship")

# Character classes are written as explicit alternations: a literal hyphen inside a
# bracket expression is easy to mis-read (and can leak unexpected characters into
# the class), so every class below lists its characters one by one.
_LOWER = r"(?:[a-z])"
_TYPE_CHAR = r"(?:[a-z]|[0-9]|[-])"
# Property paths and patterns are case sensitive in STIX, so uppercase letters and
# quoted property segments (for example `hashes.'SHA-256'`) are accepted here.
_PROPERTY_CHAR = r"(?:[A-Za-z]|[0-9]|[_.'\-]|[ ])"
_HEX = r"(?:[0-9a-f])"
_COMPARISON = r"(?:=|!=|<=|>=|<|>)"
_VALUE = r"(?:'[^']*'|[-]?[0-9]+(?:\.[0-9]+)?|true|false)"
_OBJECT_PATH = r"(?:[A-Za-z]|[0-9]|[_.'\-])+"

STIX_ID = re.compile(
    _LOWER + _TYPE_CHAR + r"*--" + _HEX + r"{8}-" + _HEX + r"{4}-4" + _HEX + r"{3}-"
    r"(?:[89ab])" + _HEX + r"{3}-" + _HEX + r"{12}"
)
TIMESTAMP = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z")
RELATIONSHIP_TYPE = re.compile(_LOWER + r"(?:[a-z]|[0-9]|[_]|[-])*")
# A single-comparison STIX pattern such as [file:hashes.'SHA-256' = 'abc'].
PATTERN = re.compile(
    r"\[" + _OBJECT_PATH + r":" + _PROPERTY_CHAR + r"*[A-Za-z0-9_']" + r"\s*"
    + _COMPARISON + r"\s*" + _VALUE + r"\]"
)

# Properties every STIX object in this release may carry, with their JSON type.
COMMON_PROPERTIES: dict[str, str] = {
    "type": "string",
    "spec_version": "string",
    "id": "string",
    "created": "timestamp",
    "modified": "timestamp",
    "created_by_ref": "reference",
    "revoked": "boolean",
    "labels": "string_array",
    "confidence": "confidence",
    "lang": "string",
    "external_references": "external_references",
}

TYPE_PROPERTIES: dict[str, dict[str, str]] = {
    "identity": {
        "name": "string",
        "description": "string",
        "identity_class": "string",
        "sectors": "string_array",
        "contact_information": "string",
        "roles": "string_array",
    },
    "indicator": {
        "name": "string",
        "description": "string",
        "pattern": "pattern",
        "pattern_type": "string",
        "pattern_version": "string",
        "valid_from": "timestamp",
        "valid_until": "timestamp",
        "indicator_types": "string_array",
        "kill_chain_phases": "kill_chain_phases",
    },
    "malware": {
        "name": "string",
        "description": "string",
        "is_family": "boolean",
        "malware_types": "string_array",
        "aliases": "string_array",
        "first_seen": "timestamp",
        "last_seen": "timestamp",
        "kill_chain_phases": "kill_chain_phases",
    },
    "relationship": {
        "relationship_type": "relationship_type",
        "description": "string",
        "source_ref": "reference",
        "target_ref": "reference",
        "start_time": "timestamp",
        "stop_time": "timestamp",
    },
    "report": {
        "name": "string",
        "description": "string",
        "published": "timestamp",
        "report_types": "string_array",
        "object_refs": "report_refs",
    },
}

REQUIRED_PROPERTIES: dict[str, tuple[str, ...]] = {
    "identity": ("name",),
    "indicator": ("name", "pattern", "valid_from"),
    "malware": ("name", "is_family"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "report": ("name", "published", "object_refs"),
}

MEDIA_TYPE = "application/stix+json;version=2.1"
SPEC_VERSION = "2.1"

# Keys accepted inside one entry of `external_references`.
EXTERNAL_REFERENCE_PROPERTIES = ("source_name", "description", "url", "external_id")


def canonical_timestamp(value: Any, field: str) -> str:
    """Return `value` as a canonical UTC STIX timestamp with microsecond precision."""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a UTC timestamp string")
    match = TIMESTAMP.match(value)
    if match is None:
        raise ValidationError(f"{field} must look like 2024-01-02T03:04:05.000000Z")
    fraction = (match.group(7) or "").ljust(6, "0")
    try:
        datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6)),
            int(fraction),
            tzinfo=timezone.utc,
        )
    except ValueError as error:
        raise ValidationError(f"{field} is not a valid calendar timestamp") from error
    return (
        f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
        f"T{match.group(4)}:{match.group(5)}:{match.group(6)}.{fraction}Z"
    )


def timestamp_value(value: str) -> datetime:
    """Parse a canonical timestamp produced by :func:`canonical_timestamp`."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or STIX_ID.fullmatch(value) is None:
        raise ValidationError(
            f"{field} must be a STIX identifier of the form <type>--<uuid> "
            "with a lowercase UUIDv4"
        )
    return value


def identifier_type(value: str) -> str:
    return value.split("--", 1)[0]


def _validate_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _validate_string_array(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array of non-empty strings")
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValidationError(f"{field} must be a non-empty array of non-empty strings")
    return list(value)


def _validate_boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be a boolean")
    return value


def _validate_confidence(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        raise ValidationError(f"{field} must be an integer between 0 and 100")
    return value


def _validate_external_references(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array of objects")
    references: list[dict[str, str]] = []
    for index, entry in enumerate(value):
        location = f"{field}[{index}]"
        if not isinstance(entry, dict):
            raise ValidationError(f"{location} must be an object")
        unknown = sorted(set(entry) - set(EXTERNAL_REFERENCE_PROPERTIES))
        if unknown:
            raise ValidationError(f"{location} has unsupported properties: {', '.join(unknown)}")
        if "source_name" not in entry:
            raise ValidationError(f"{location} must contain source_name")
        normalized: dict[str, str] = {}
        for key, item in entry.items():
            normalized[key] = _validate_string(item, f"{location}.{key}")
        references.append(normalized)
    return references


def _validate_kill_chain_phases(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array of objects")
    phases: list[dict[str, str]] = []
    for index, entry in enumerate(value):
        location = f"{field}[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"kill_chain_name", "phase_name"}:
            raise ValidationError(
                f"{location} must contain exactly kill_chain_name and phase_name"
            )
        phases.append(
            {
                "kill_chain_name": _validate_string(entry["kill_chain_name"], f"{location}.kill_chain_name"),
                "phase_name": _validate_string(entry["phase_name"], f"{location}.phase_name"),
            }
        )
    return phases


def _validate_pattern(value: Any, field: str) -> str:
    text = _validate_string(value, field)
    if PATTERN.fullmatch(text) is None:
        raise ValidationError(
            f"{field} must be a STIX pattern of the form "
            "[object-type:property = 'value'] using one of =, !=, <, >, <=, >="
        )
    return text


def _validate_relationship_type(value: Any, field: str) -> str:
    text = _validate_string(value, field)
    if RELATIONSHIP_TYPE.fullmatch(text) is None:
        raise ValidationError(f"{field} must be a snake_case relationship type")
    return text


def _validate_report_refs(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array of STIX identifiers")
    references: list[str] = []
    for index, item in enumerate(value):
        location = f"{field}[{index}]"
        reference = validate_identifier(item, location)
        target_type = identifier_type(reference)
        if target_type not in REPORT_REF_TYPES:
            raise ValidationError(
                f"{location} must reference one of {', '.join(REPORT_REF_TYPES)};"
                f" got {target_type}"
            )
        if reference in references:
            raise ValidationError(f"{field} must not contain the duplicate reference {reference}")
        references.append(reference)
    return references


def _validate_property(value: Any, kind: str, field: str) -> Any:
    if kind == "string":
        return _validate_string(value, field)
    if kind == "timestamp":
        return canonical_timestamp(value, field)
    if kind == "boolean":
        return _validate_boolean(value, field)
    if kind == "confidence":
        return _validate_confidence(value, field)
    if kind == "string_array":
        return _validate_string_array(value, field)
    if kind == "reference":
        return validate_identifier(value, field)
    if kind == "pattern":
        return _validate_pattern(value, field)
    if kind == "relationship_type":
        return _validate_relationship_type(value, field)
    if kind == "report_refs":
        return _validate_report_refs(value, field)
    if kind == "external_references":
        return _validate_external_references(value, field)
    if kind == "kill_chain_phases":
        return _validate_kill_chain_phases(value, field)
    raise ValidationError(f"{field} is not a supported property")


def _validate_link(identifier: str, field: str, type_name: str) -> None:
    if identifier_type(identifier) != type_name:
        raise ValidationError(
            f"{field} must reference a {type_name} object, got {identifier_type(identifier)}"
        )


# Relationship endpoints this release accepts: an indicator points at the identity
# that published the intelligence, which mirrors how `indicates` is used in the wild.
RELATIONSHIP_LINKS = (("source_ref", "indicator"), ("target_ref", "identity"))


@dataclass(frozen=True)
class StixObject:
    """One validated STIX 2.1 object ready to be stored in a collection."""

    type: str
    id: str
    created: str
    modified: str
    properties: dict[str, Any]

    @classmethod
    def parse(cls, raw: Any) -> "StixObject":
        if not isinstance(raw, dict):
            raise ValidationError("STIX object body must be a JSON object")
        type_name = raw.get("type")
        if type_name not in OBJECT_TYPES:
            raise ValidationError(
                "type must be one of " + ", ".join(OBJECT_TYPES)
            )
        allowed = set(COMMON_PROPERTIES) | set(TYPE_PROPERTIES[type_name])
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ValidationError(
                f"{type_name} has unsupported properties: {', '.join(unknown)}"
            )
        if raw.get("spec_version", SPEC_VERSION) != SPEC_VERSION:
            raise ValidationError("spec_version must be 2.1")

        if not isinstance(raw.get("id"), str):
            raise ValidationError("id is required")
        identifier = validate_identifier(raw["id"], "id")
        if identifier_type(identifier) != ID_PREFIX[type_name]:
            raise ValidationError(
                f"id {identifier} does not match type {type_name}; "
                f"expected the {ID_PREFIX[type_name]}--<uuid> form"
            )

        for name in ("created", "modified"):
            if name not in raw:
                raise ValidationError(f"{name} is required")
        created = canonical_timestamp(raw["created"], "created")
        modified = canonical_timestamp(raw["modified"], "modified")
        if timestamp_value(modified) < timestamp_value(created):
            raise ValidationError("modified must not be earlier than created")

        properties: dict[str, Any] = {"type": type_name, "id": identifier, "spec_version": SPEC_VERSION}
        for name, kind in COMMON_PROPERTIES.items():
            if name in ("type", "id", "created", "modified"):
                continue
            if name in raw:
                properties[name] = _validate_property(raw[name], kind, name)
        for name, kind in TYPE_PROPERTIES[type_name].items():
            if name in raw:
                properties[name] = _validate_property(raw[name], kind, name)

        for name in REQUIRED_PROPERTIES[type_name]:
            if name not in raw:
                raise ValidationError(f"{type_name} requires the {name} property")

        if type_name == "indicator":
            if properties.get("pattern_type", "stix") != "stix":
                raise ValidationError("only pattern_type stix is supported")
            properties["pattern_type"] = "stix"
        if type_name == "relationship":
            cls._validate_relationship(properties)
        return cls(type_name, identifier, created, modified, properties)

    @staticmethod
    def _validate_relationship(properties: dict[str, Any]) -> None:
        source = properties["source_ref"]
        target = properties["target_ref"]
        if source == target:
            raise ValidationError("source_ref and target_ref must differ")
        _validate_link(source, *RELATIONSHIP_LINKS[0])
        _validate_link(target, *RELATIONSHIP_LINKS[1])
        if "start_time" in properties and "stop_time" in properties:
            if timestamp_value(properties["stop_time"]) < timestamp_value(properties["start_time"]):
                raise ValidationError("stop_time must not be earlier than start_time")

    def document(self) -> dict[str, Any]:
        document = dict(self.properties)
        document["created"] = self.created
        document["modified"] = self.modified
        return document

    def references(self) -> tuple[str, ...]:
        if self.type == "relationship":
            return (self.properties["source_ref"], self.properties["target_ref"])
        if self.type == "report":
            return tuple(self.properties["object_refs"])
        return ()

    def version_key(self) -> str:
        """The TAXII version identifier of this revision."""
        return self.modified
