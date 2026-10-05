import json
import tempfile
import unittest
from pathlib import Path

from stixrelay.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from stixrelay.model import MEDIA_TYPE
from stixrelay.service import NDJSON_MEDIA_TYPE, StixRelay

IDENTITY_ID = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
INDICATOR_ID = "indicator--a2f4b7d8-2c7e-4a4b-9d0e-6f6a1c9d3f21"
MALWARE_ID = "malware--3c9d1e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
RELATIONSHIP_ID = "relationship--b6a1e2c3-1f2a-4b3c-8d4e-5f6a7b8c9d0e"
REPORT_ID = "report--c7d8e9f0-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
REPORT2_ID = "report--d8e9f012-3b4c-4d5e-9f50-6a7b8c9d0e1f"
NOTE_ID = "note--9fb2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
NOTE2_ID = "note--a0c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"

CREATED = "2024-01-01T00:00:00Z"
REPORT_PUBLISHED = "2024-03-01T00:00:00Z"


def identity(*, modified: str = CREATED, name: str = "Example Org") -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": modified,
        "name": name,
        "identity_class": "organization",
    }


def indicator(*, modified: str = CREATED, pattern: str = "[file:hashes.'SHA-256' = 'aa']") -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": INDICATOR_ID,
        "created": CREATED,
        "modified": modified,
        "name": "Bad hash",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": CREATED,
    }


def malware(*, modified: str = CREATED) -> dict:
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": MALWARE_ID,
        "created": CREATED,
        "modified": modified,
        "name": "Loader",
        "is_family": True,
        "malware_types": ["trojan"],
    }


def relationship(*, modified: str = CREATED) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": modified,
        "relationship_type": "indicates",
        "source_ref": INDICATOR_ID,
        "target_ref": IDENTITY_ID,
    }


def report(
    *,
    modified: str = CREATED,
    object_refs: list[str] | None = None,
    published: str = REPORT_PUBLISHED,
    report_id: str = REPORT_ID,
) -> dict:
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": CREATED,
        "modified": modified,
        "name": "Monthly report",
        "description": "What happened this month",
        "published": published,
        "report_types": ["threat-report"],
        "object_refs": [INDICATOR_ID, IDENTITY_ID] if object_refs is None else object_refs,
    }


def revoked(payload: dict) -> dict:
    body = dict(payload)
    body["revoked"] = True
    return body


def note(
    *,
    modified: str = CREATED,
    content: str = "Analyst comment",
    object_refs: list[str] | None = None,
    note_id: str = NOTE_ID,
    abstract: str | object = None,
    authors: list[str] | object = None,
) -> dict:
    payload = {
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created": CREATED,
        "modified": modified,
        "content": content,
        "object_refs": [INDICATOR_ID] if object_refs is None else object_refs,
    }
    if abstract is not None:
        payload["abstract"] = abstract
    if authors is not None:
        payload["authors"] = authors
    return payload


class StixRelayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.service = StixRelay(str(Path(self.directory.name) / "test.db"))
        self.service.create_collection({"id": "feed", "title": "Primary feed"}, "c1")

    def tearDown(self):
        self.directory.cleanup()

    def add(self, payload: dict, key: str, added_at: str = "2024-01-02T00:00:00Z"):
        return self.service.add_object("feed", dict(payload, added_at=added_at), key).to_json()

    def add_status(self, payload: dict, key: str, added_at: str = "2024-01-02T00:00:00Z") -> int:
        return self.service.add_object(
            "feed", dict(payload, added_at=added_at), key
        ).status

    def test_collection_is_created_once_and_conflicts_on_duplicate(self):
        document = self.service.get_collection("feed")
        self.assertEqual("Primary feed", document["title"])
        self.assertEqual("application/stix+json;version=2.1", document["media_type"])
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.service.create_collection({"id": "feed", "title": "Other"}, "c2")

    def test_object_round_trip_preserves_every_property(self):
        stored = self.add(indicator(), "k1")
        self.assertEqual("feed", stored["collection_id"])
        self.assertEqual("2024-01-02T00:00:00.000000Z", stored["added_at"])
        self.assertEqual("2024-01-01T00:00:00.000000Z", stored["version"])
        self.assertEqual("[file:hashes.'SHA-256' = 'aa']", stored["object"]["pattern"])
        self.assertEqual("stix", stored["object"]["pattern_type"])
        self.assertEqual(
            [stored["object"]], self.service.list_objects("feed").to_json()["objects"]
        )

    def test_timestamps_are_normalised_to_microsecond_utc(self):
        self.add(identity(), "k1")
        document = self.service.list_objects("feed").to_json()["objects"][0]
        self.assertEqual("2024-01-01T00:00:00.000000Z", document["created"])
        self.assertEqual("2024-01-01T00:00:00.000000Z", document["modified"])

    def test_unknown_property_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "unsupported properties: whatever"):
            self.add(dict(identity(), whatever=1), "k1")

    def test_unknown_type_is_rejected(self):
        payload = dict(identity(), type="campaign")
        with self.assertRaisesRegex(ValidationError, "type must be one of"):
            self.add(payload, "k1")

    def test_id_prefix_must_match_type(self):
        payload = dict(identity(), id=INDICATOR_ID)
        with self.assertRaisesRegex(ValidationError, "does not match type identity"):
            self.add(payload, "k1")

    def test_malformed_identifiers_are_rejected(self):
        for identifier in (
            "identity--f431f809-377b-15e0-aa1c-6a4751cae5ff",
            "identity--F431F809-377b-45e0-aa1c-6a4751cae5ff",
            "identity-f431f809-377b-45e0-aa1c-6a4751cae5ff",
        ):
            with self.assertRaisesRegex(ValidationError, "must be a STIX identifier"):
                self.add(dict(identity(), id=identifier), f"k-{identifier}")

    def test_required_properties_are_enforced_per_type(self):
        with self.assertRaisesRegex(ValidationError, "identity requires the name property"):
            self.add({key: value for key, value in identity().items() if key != "name"}, "k1")
        with self.assertRaisesRegex(ValidationError, "malware requires the is_family property"):
            self.add({key: value for key, value in malware().items() if key != "is_family"}, "k2")
        with self.assertRaisesRegex(ValidationError, "indicator requires the pattern property"):
            self.add({key: value for key, value in indicator().items() if key != "pattern"}, "k3")

    def test_property_types_are_enforced(self):
        with self.assertRaisesRegex(ValidationError, "is_family must be a boolean"):
            self.add(dict(malware(), is_family="yes"), "k1")
        with self.assertRaisesRegex(ValidationError, "labels must be a non-empty array"):
            self.add(dict(identity(), labels=[]), "k2")
        with self.assertRaisesRegex(ValidationError, "confidence must be an integer"):
            self.add(dict(identity(), confidence=101), "k3")
        with self.assertRaisesRegex(ValidationError, "external_references\\[0\\] must contain source_name"):
            self.add(dict(identity(), external_references=[{"url": "https://x"}]), "k4")
        with self.assertRaisesRegex(ValidationError, "kill_chain_phases\\[0\\] must contain exactly"):
            self.add(dict(malware(), kill_chain_phases=[{"kill_chain_name": "x"}]), "k5")

    def test_patterns_are_validated(self):
        with self.assertRaisesRegex(ValidationError, "must be a STIX pattern"):
            self.add(indicator(pattern="file:name = 'x'"), "k1")
        with self.assertRaisesRegex(ValidationError, "must be a STIX pattern"):
            self.add(indicator(pattern="[file:name = x]"), "k2")
        with self.assertRaisesRegex(ValidationError, "only pattern_type stix"):
            self.add(dict(indicator(), pattern_type="snort"), "k3")

    def test_spec_version_must_be_2_1(self):
        with self.assertRaisesRegex(ValidationError, "spec_version must be 2.1"):
            self.add(dict(identity(), spec_version="2.0"), "k1")

    def test_modified_cannot_precede_created(self):
        payload = dict(identity(), created="2024-05-05T00:00:00Z", modified=CREATED)
        with self.assertRaisesRegex(ValidationError, "modified must not be earlier than created"):
            self.add(payload, "k1")

    def test_relationship_endpoints_must_exist(self):
        with self.assertRaisesRegex(ValidationError, "unknown indicator"):
            self.add(relationship(), "k1")

    def test_relationship_endpoint_types_are_fixed(self):
        with self.assertRaisesRegex(ValidationError, "source_ref must reference a indicator"):
            self.add(dict(relationship(), source_ref=IDENTITY_ID, target_ref=INDICATOR_ID), "k1")

    def test_relationship_is_stored_once_both_endpoints_exist(self):
        self.add(indicator(), "k1")
        self.add(identity(), "k2")
        stored = self.add(relationship(), "k3")
        self.assertEqual("indicates", stored["object"]["relationship_type"])
        listed = self.service.list_objects("feed", ["relationship"]).to_json()
        self.assertEqual([stored["object"]], listed["objects"])
        self.assertEqual(["relationship"], listed["type"])

    def test_duplicate_relationship_is_rejected(self):
        self.add(indicator(), "k1")
        self.add(identity(), "k2")
        self.add(relationship(), "k3")
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(relationship(), "k4")

    def test_new_version_is_appended_and_old_version_is_read_only(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(
            identity(modified="2024-02-01T00:00:00Z", name="Renamed Org"),
            "k2",
            added_at="2024-02-02T00:00:00Z",
        )
        versions = self.service.object_versions("feed", IDENTITY_ID).to_json()
        self.assertEqual(
            ["2024-01-01T00:00:00.000000Z", "2024-02-01T00:00:00.000000Z"], versions["versions"]
        )
        self.assertEqual(["2024-01-01T00:00:00.000000Z"], versions["earliest"])
        self.assertEqual(["2024-02-01T00:00:00.000000Z"], versions["latest"])
        document = self.service.list_objects("feed").to_json()["objects"][0]
        self.assertEqual("Renamed Org", document["name"])
        self.assertEqual("2024-02-01T00:00:00.000000Z", document["modified"])

    def test_version_must_advance(self):
        self.add(identity(modified="2024-02-01T00:00:00Z"), "k1")
        with self.assertRaisesRegex(ConflictError, "is older than the stored version"):
            self.add(identity(), "k2")

    def test_identical_version_is_a_conflict(self):
        self.add(identity(), "k1")
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(identity(), "k2")

    def test_versions_are_monotonic_and_unique(self):
        stamps = ["2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", "2024-01-03T00:00:00Z"]
        for index, stamp in enumerate(stamps):
            self.add(identity(modified=stamp), f"k{index}")
        versions = self.service.object_versions("feed", IDENTITY_ID).to_json()["versions"]
        self.assertEqual(sorted(versions), versions)
        self.assertEqual(len(set(versions)), len(versions))
        self.assertEqual(3, len(versions))

    def test_unknown_object_versions_are_not_found(self):
        with self.assertRaisesRegex(NotFoundError, "was not found in collection"):
            self.service.object_versions("feed", MALWARE_ID)

    # ---------------------------------------------------------------- revocation

    def test_revoked_is_optional_and_not_emitted_when_omitted(self):
        stored = self.add(identity(), "k1")
        self.assertNotIn("revoked", stored["object"])
        listed = self.service.list_objects("feed").to_json()["objects"][0]
        self.assertNotIn("revoked", listed)

    def test_explicit_revoked_false_is_stored_as_false(self):
        stored = self.add(dict(identity(), revoked=False), "k1")
        self.assertIs(stored["object"]["revoked"], False)
        self.assertIs(
            self.service.list_objects("feed").to_json()["objects"][0]["revoked"], False
        )

    def test_a_first_version_may_be_born_revoked_for_historical_import(self):
        stored = self.add(revoked(identity()), "k1")
        self.assertIs(stored["object"]["revoked"], True)
        self.assertEqual(1, len(self.service.list_objects("feed").to_json()["objects"]))
        with self.assertRaisesRegex(ConflictError, "is revoked"):
            self.add(identity(modified="2024-02-01T00:00:00Z"), "k2")

    def test_revoked_must_be_a_boolean(self):
        with self.assertRaisesRegex(ValidationError, "revoked must be a boolean"):
            self.add(dict(identity(), revoked="yes"), "k1")

    def test_a_later_revocation_version_is_stored(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        result = self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "k2",
            added_at="2024-02-02T00:00:00Z",
        )
        self.assertIs(result["object"]["revoked"], True)
        self.assertEqual("2024-02-01T00:00:00.000000Z", result["version"])
        self.assertEqual("2024-02-02T00:00:00.000000Z", result["added_at"])
        current = self.service.list_objects("feed").to_json()["objects"][0]
        self.assertIs(current["revoked"], True)
        self.assertEqual("2024-02-01T00:00:00.000000Z", current["modified"])

    def test_revocation_version_is_listed_in_versions_latest_and_added_at(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "k2",
            added_at="2024-02-02T00:00:00Z",
        )
        versions = self.service.object_versions("feed", IDENTITY_ID).to_json()
        self.assertEqual(
            [
                "2024-01-01T00:00:00.000000Z",
                "2024-02-01T00:00:00.000000Z",
            ],
            versions["versions"],
        )
        self.assertEqual(["2024-02-01T00:00:00.000000Z"], versions["latest"])
        self.assertEqual(
            ["2024-01-02T00:00:00.000000Z", "2024-02-02T00:00:00.000000Z"],
            versions["added_at"],
        )

    def test_a_revocation_version_must_match_the_current_version_except_lifecycle_fields(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        cases = (
            (dict(name="Renamed Org"), "name"),
            (dict(identity_class="government"), "identity_class"),
            (dict(description="new"), "description"),
            (dict(confidence=50), "confidence"),
        )
        for index, (overrides, field) in enumerate(cases):
            payload = revoked(dict(identity(modified="2024-03-01T00:00:00Z"), **overrides))
            with self.assertRaisesRegex(ValidationError, field):
                self.add(payload, f"rev-bad-{index}")
        # Nothing was written: only the original version remains and the object is live.
        versions = self.service.object_versions("feed", IDENTITY_ID).to_json()
        self.assertEqual(["2024-01-01T00:00:00.000000Z"], versions["versions"])
        self.assertNotIn(
            "revoked", self.service.list_objects("feed").to_json()["objects"][0]
        )

    def test_a_revocation_version_must_carry_a_later_modified(self):
        self.add(dict(identity(), revoked=False), "k1")
        # Same modified with revoked=true still follows the identical-version conflict.
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(revoked(identity()), "k2")

    def test_a_normal_new_version_still_applies_before_revocation(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(
            identity(modified="2024-02-01T00:00:00Z", name="Renamed Org"),
            "k2",
            added_at="2024-02-02T00:00:00Z",
        )
        result = self.add(
            revoked(identity(modified="2024-03-01T00:00:00Z", name="Renamed Org")),
            "k3",
            added_at="2024-03-02T00:00:00Z",
        )
        self.assertIs(result["object"]["revoked"], True)
        self.assertEqual("Renamed Org", result["object"]["name"])

    def test_once_revoked_any_later_write_is_a_conflict(self):
        self.add(identity(), "k1")
        self.add(revoked(identity(modified="2024-02-01T00:00:00Z")), "k2")
        later = identity(modified="2024-03-01T00:00:00Z")
        attempts = (
            later,
            dict(later, revoked=False),
            {key: value for key, value in revoked(later).items() if key != "revoked"},
            dict(revoked(later), name="Something else"),
        )
        for index, payload in enumerate(attempts):
            with self.assertRaisesRegex(ConflictError, "is revoked"):
                self.add(payload, f"after-{index}")
        self.assertEqual(
            2, len(self.service.object_versions("feed", IDENTITY_ID).to_json()["versions"])
        )

    def test_same_or_earlier_modified_after_revocation_keeps_existing_conflict_wording(self):
        self.add(identity(), "k1")
        self.add(revoked(identity(modified="2024-02-01T00:00:00Z")), "k2")
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(revoked(identity(modified="2024-02-01T00:00:00Z")), "k3")
        with self.assertRaisesRegex(ConflictError, "is older than the stored version"):
            self.add(revoked(identity(modified="2024-01-01T00:00:00Z")), "k4")

    def test_a_rejected_revocation_or_later_write_consumes_no_idempotency_key(self):
        self.add(identity(), "k1")
        with self.assertRaises(ValidationError):
            self.add(
                revoked(identity(modified="2024-02-01T00:00:00Z", name="Changed")),
                "rev-key",
            )
        # The same key now succeeds with a conforming revocation.
        stored = self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")), "rev-key"
        )
        self.assertIs(stored["object"]["revoked"], True)
        with self.assertRaises(ConflictError):
            self.add(identity(modified="2024-03-01T00:00:00Z"), "late-key")
        # The rejected post-revocation write did not consume its key either.
        with self.assertRaisesRegex(ConflictError, "is revoked"):
            self.add(identity(modified="2024-03-01T00:00:00Z"), "late-key")

    def test_revoked_object_still_appears_in_listings_and_half_open_deltas(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "k2",
            added_at="2024-02-02T00:00:00Z",
        )
        listed = self.service.list_objects("feed").to_json()["objects"]
        self.assertEqual([IDENTITY_ID], [item["id"] for item in listed])
        self.assertIs(listed[0]["revoked"], True)
        # Strictly half-open: the revocation added exactly at the cutoff is excluded.
        self.assertEqual(
            [],
            self.service.list_objects("feed", None, ["2024-02-02T00:00:00Z"]).to_json()["objects"],
        )
        delta = self.service.list_objects("feed", None, ["2024-02-01T00:00:00Z"]).to_json()
        self.assertEqual([IDENTITY_ID], [item["id"] for item in delta["objects"]])
        self.assertIs(delta["objects"][0]["revoked"], True)

    def test_a_revocation_mid_pagination_stays_out_of_the_open_snapshot(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(malware(), "k2", added_at="2024-01-03T00:00:00Z")
        first = self.service.list_objects("feed", limit=["1"]).to_json()
        self.assertEqual(1, len(first["objects"]))
        self.assertNotIn("revoked", first["objects"][0])
        # The identity is revoked after page one established the snapshot.
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "k3",
            added_at="2024-02-02T00:00:00Z",
        )
        second = self.service.list_objects("feed", next_token=[first["next"]]).to_json()
        self.assertEqual([MALWARE_ID], [item["id"] for item in second["objects"]])
        self.assertFalse(second["more"])
        # A new round started from page one snapshots the revoked current state.
        fresh = self.service.list_objects("feed", limit=["10"]).to_json()
        identity_doc = next(item for item in fresh["objects"] if item["id"] == IDENTITY_ID)
        self.assertIs(identity_doc["revoked"], True)

    def test_revoked_objects_remain_valid_references(self):
        self.add(indicator(), "k1")
        self.add(identity(), "k2")
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "k3",
            added_at="2024-02-02T00:00:00Z",
        )
        # A revoked endpoint still satisfies relationship/report reference integrity.
        self.assertEqual(
            201, self.add_status(relationship(), "k4", added_at="2024-02-03T00:00:00Z")
        )
        self.assertEqual(
            201,
            self.add_status(
                report(modified="2024-03-01T00:00:00Z", object_refs=[INDICATOR_ID, IDENTITY_ID]),
                "k5",
                added_at="2024-03-02T00:00:00Z",
            ),
        )

    def test_revoking_a_referenced_object_does_not_cascade(self):
        self.add(indicator(), "k1")
        self.add(identity(), "k2")
        self.add(relationship(), "k3", added_at="2024-01-05T00:00:00Z")
        self.add(
            report(modified="2024-03-01T00:00:00Z", object_refs=[INDICATOR_ID, IDENTITY_ID]),
            "k4",
            added_at="2024-03-02T00:00:00Z",
        )
        self.add(
            revoked(indicator(modified="2024-02-01T00:00:00Z")),
            "k5",
            added_at="2024-02-03T00:00:00Z",
        )
        listed = self.service.list_objects("feed").to_json()["objects"]
        ids = {item["id"] for item in listed}
        self.assertIn(RELATIONSHIP_ID, ids)
        self.assertIn(REPORT_ID, ids)
        relationship_doc = next(item for item in listed if item["id"] == RELATIONSHIP_ID)
        self.assertNotIn("revoked", relationship_doc)

    def test_idempotent_replay_after_revocation_returns_the_first_response(self):
        first = self.add(identity(), "same", added_at="2024-01-02T00:00:00Z")
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "rev",
            added_at="2024-02-02T00:00:00Z",
        )
        replayed = self.add(identity(), "same", added_at="2024-01-02T00:00:00Z")
        self.assertEqual(first, replayed)
        self.assertNotIn("revoked", replayed["object"])

    def test_added_after_is_strictly_half_open(self):
        self.add(indicator(), "k1", added_at="2024-01-02T00:00:00Z")
        # The object arrives exactly at the cutoff, so a half-open delta excludes it.
        self.assertEqual(
            [], self.service.list_objects("feed", None, ["2024-01-02T00:00:00Z"]).to_json()["objects"]
        )
        self.assertEqual(
            [],
            self.service.list_objects("feed", None, ["2024-01-02T00:00:00.000001Z"]).to_json()["objects"],
        )
        later = self.service.list_objects("feed", None, ["2024-01-01T23:59:59Z"]).to_json()
        self.assertEqual(1, len(later["objects"]))
        self.assertFalse(later["more"])

    def test_delta_reports_objects_received_after_the_cutoff(self):
        self.add(indicator(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(identity(), "k2", added_at="2024-03-02T00:00:00Z")
        objects = self.service.list_objects("feed", None, ["2024-02-01T00:00:00Z"]).to_json()["objects"]
        self.assertEqual([IDENTITY_ID], [document["id"] for document in objects])

    def test_delta_reports_a_new_version_of_an_old_object(self):
        self.add(identity(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(
            identity(modified="2024-02-01T00:00:00Z"),
            "k2",
            added_at="2024-03-02T00:00:00Z",
        )
        objects = self.service.list_objects("feed", None, ["2024-02-01T00:00:00Z"]).to_json()["objects"]
        self.assertEqual(1, len(objects))
        self.assertEqual("2024-02-01T00:00:00.000000Z", objects[0]["modified"])

    def test_type_filter_returns_only_current_versions(self):
        self.add(indicator(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(malware(), "k2", added_at="2024-01-03T00:00:00Z")
        listed = self.service.list_objects("feed", ["indicator", "malware"]).to_json()
        self.assertEqual(
            [INDICATOR_ID, MALWARE_ID], [document["id"] for document in listed["objects"]]
        )
        self.assertEqual(["indicator", "malware"], listed["type"])

    def test_unknown_type_filter_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "type must be one of"):
            self.service.list_objects("feed", ["campaign"])

    def test_listing_is_deterministic(self):
        self.add(indicator(), "k1", added_at="2024-01-02T00:00:00Z")
        self.add(identity(), "k2", added_at="2024-01-02T00:00:00Z")
        self.add(malware(), "k3", added_at="2024-01-02T00:00:00Z")
        first = self.service.list_objects("feed").to_json()["objects"]
        second = self.service.list_objects("feed").to_json()["objects"]
        self.assertEqual(first, second)
        self.assertEqual([IDENTITY_ID, INDICATOR_ID, MALWARE_ID], [item["id"] for item in first])

    def test_unknown_collection_is_not_found(self):
        with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
            self.service.list_objects("missing")
        with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
            self.service.add_object("missing", identity(), "k1")

    # ------------------------------------------------------------------ reports

    def _seed_report_targets(self):
        self.add(indicator(), "rep-ind", added_at="2024-01-02T00:00:00Z")
        self.add(identity(), "rep-ide", added_at="2024-01-03T00:00:00Z")

    def test_report_references_must_already_exist_in_the_collection(self):
        with self.assertRaisesRegex(ValidationError, "report references unknown indicator"):
            self.add(report(), "k1")
        with self.assertRaises(NotFoundError):
            self.service.object_versions("feed", REPORT_ID)
        self.assertEqual([], self.service.list_objects("feed", ["report"]).to_json()["objects"])

    def test_report_is_stored_once_every_reference_exists(self):
        self._seed_report_targets()
        self.add(malware(), "rep-mal", added_at="2024-01-04T00:00:00Z")
        self.add(relationship(), "rep-rel", added_at="2024-01-05T00:00:00Z")
        stored = self.add(
            report(object_refs=[RELATIONSHIP_ID, MALWARE_ID, INDICATOR_ID, IDENTITY_ID]),
            "rep-1",
            added_at="2024-01-06T00:00:00Z",
        )
        document = stored["object"]
        self.assertEqual("report", document["type"])
        self.assertEqual(REPORT_ID, document["id"])
        self.assertEqual("Monthly report", document["name"])
        self.assertEqual("What happened this month", document["description"])
        self.assertEqual("2024-03-01T00:00:00.000000Z", document["published"])
        self.assertEqual(["threat-report"], document["report_types"])
        self.assertEqual(
            [RELATIONSHIP_ID, MALWARE_ID, INDICATOR_ID, IDENTITY_ID], document["object_refs"]
        )
        self.assertEqual("2024-01-06T00:00:00.000000Z", stored["added_at"])
        listed = self.service.list_objects("feed", ["report"]).to_json()
        self.assertEqual([document], listed["objects"])
        self.assertEqual(["report"], listed["type"])

    def test_report_optional_properties_are_absent_when_omitted(self):
        self._seed_report_targets()
        minimal = {
            key: value
            for key, value in report().items()
            if key not in ("description", "report_types")
        }
        stored = self.add(minimal, "rep-min")
        self.assertNotIn("description", stored["object"])
        self.assertNotIn("report_types", stored["object"])

    def test_report_rejecting_an_unknown_target_persists_nothing(self):
        self._seed_report_targets()
        with self.assertRaisesRegex(ValidationError, "report references unknown malware"):
            self.add(report(object_refs=[IDENTITY_ID, MALWARE_ID]), "rep-bad")
        self.assertEqual([], self.service.list_objects("feed", ["report"]).to_json()["objects"])
        with self.assertRaises(NotFoundError):
            self.service.object_versions("feed", REPORT_ID)
        # The rolled back write did not consume the idempotency key.
        self.add(malware(), "rep-mal", added_at="2024-01-04T00:00:00Z")
        stored = self.service.add_object(
            "feed",
            dict(report(object_refs=[IDENTITY_ID, MALWARE_ID]), added_at="2024-01-06T00:00:00Z"),
            "rep-bad",
        )
        self.assertEqual(201, stored.status)

    def test_report_reference_to_another_collection_is_unknown(self):
        self._seed_report_targets()
        self.service.create_collection({"id": "other", "title": "Other feed"}, "co")
        self.service.add_object("other", dict(malware(), added_at="2024-01-04T00:00:00Z"), "ko")
        with self.assertRaisesRegex(ValidationError, "report references unknown malware"):
            self.add(report(object_refs=[MALWARE_ID]), "rep-cross")

    def test_report_object_refs_must_be_non_empty_unique_and_supported(self):
        self._seed_report_targets()
        cases = (
            ([], "non-empty array of STIX identifiers"),
            (IDENTITY_ID, "non-empty array of STIX identifiers"),
            ([IDENTITY_ID, IDENTITY_ID], "duplicate reference"),
            ([1], "must be a STIX identifier"),
            ([""], "must be a STIX identifier"),
            (["identity--not-a-uuid"], "must be a STIX identifier"),
            (["identity--f431f809-377b-15e0-aa1c-6a4751cae5ff"], "must be a STIX identifier"),
            (["campaign--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"], "must reference one of"),
            ([REPORT_ID], "must reference one of"),
            (["report--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"], "must reference one of"),
        )
        for index, (refs, message) in enumerate(cases):
            with self.assertRaisesRegex(ValidationError, message):
                self.add(report(report_id=REPORT2_ID, object_refs=refs), f"rep-ref-{index}")
        self.assertEqual([], self.service.list_objects("feed", ["report"]).to_json()["objects"])

    def test_report_required_properties_are_enforced(self):
        self._seed_report_targets()
        for field in ("name", "published", "object_refs"):
            with self.assertRaisesRegex(ValidationError, f"report requires the {field} property"):
                self.add(
                    {key: value for key, value in report().items() if key != field},
                    f"rep-req-{field}",
                )

    def test_report_property_types_are_enforced(self):
        self._seed_report_targets()
        bad = (
            (dict(published="2024-03-01"), "published must look like"),
            (dict(published=20240301), "published must be a UTC timestamp string"),
            (dict(report_types=[]), "report_types must be a non-empty array"),
            (dict(report_types=[""]), "report_types must be a non-empty array"),
            (dict(report_types="threat-report"), "report_types must be a non-empty array"),
            (dict(name=""), "name must be a non-empty string"),
            (dict(whatever=1), "unsupported properties: whatever"),
        )
        for index, (overrides, message) in enumerate(bad):
            with self.assertRaisesRegex(ValidationError, message):
                self.add(dict(report(), **overrides), f"rep-type-{index}")

    def test_report_versions_can_add_and_remove_references(self):
        self._seed_report_targets()
        self.add(malware(), "rep-mal", added_at="2024-01-04T00:00:00Z")
        self.add(
            report(modified="2024-03-01T00:00:00Z", object_refs=[INDICATOR_ID, IDENTITY_ID]),
            "rep-v1",
            added_at="2024-03-02T00:00:00Z",
        )
        self.add(
            report(modified="2024-04-01T00:00:00Z", object_refs=[INDICATOR_ID]),
            "rep-v2",
            added_at="2024-04-02T00:00:00Z",
        )
        current = self.service.list_objects("feed", ["report"]).to_json()["objects"][0]
        self.assertEqual("2024-04-01T00:00:00.000000Z", current["modified"])
        self.assertEqual([INDICATOR_ID], current["object_refs"])

        # A reference removed in one revision can come back in a later one.
        self.add(
            report(
                modified="2024-05-01T00:00:00Z",
                object_refs=[INDICATOR_ID, IDENTITY_ID, MALWARE_ID],
            ),
            "rep-v3",
            added_at="2024-05-02T00:00:00Z",
        )
        versions = self.service.object_versions("feed", REPORT_ID).to_json()
        self.assertEqual(
            [
                "2024-03-01T00:00:00.000000Z",
                "2024-04-01T00:00:00.000000Z",
                "2024-05-01T00:00:00.000000Z",
            ],
            versions["versions"],
        )
        current = self.service.list_objects("feed", ["report"]).to_json()["objects"][0]
        self.assertEqual(
            [INDICATOR_ID, IDENTITY_ID, MALWARE_ID], current["object_refs"]
        )

    def test_report_revision_referencing_an_unknown_target_leaves_current_intact(self):
        self._seed_report_targets()
        self.add(report(modified="2024-03-01T00:00:00Z"), "rep-v1")
        with self.assertRaisesRegex(ValidationError, "report references unknown malware"):
            self.add(
                report(modified="2024-04-01T00:00:00Z", object_refs=[MALWARE_ID]), "rep-v2"
            )
        current = self.service.list_objects("feed", ["report"]).to_json()["objects"][0]
        self.assertEqual("2024-03-01T00:00:00.000000Z", current["modified"])
        self.assertEqual(
            1, len(self.service.object_versions("feed", REPORT_ID).to_json()["versions"])
        )

    def test_report_version_conflicts_and_idempotency_follow_existing_rules(self):
        self._seed_report_targets()
        first = self.add(
            report(modified="2024-03-01T00:00:00Z", object_refs=[IDENTITY_ID]),
            "rep-key",
            added_at="2024-03-02T00:00:00Z",
        )
        repeated = self.add(
            report(modified="2024-03-01T00:00:00Z", object_refs=[IDENTITY_ID]),
            "rep-key",
            added_at="2024-03-02T00:00:00Z",
        )
        self.assertEqual(first, repeated)
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(report(modified="2024-03-01T00:00:00Z"), "rep-dup")
        with self.assertRaisesRegex(ConflictError, "older than the stored version"):
            self.add(report(modified="2024-02-01T00:00:00Z"), "rep-old")
        self.assertEqual(
            1, len(self.service.object_versions("feed", REPORT_ID).to_json()["versions"])
        )

    def test_report_uses_the_delta_version_and_type_filter(self):
        self.add(indicator(), "rep-ind", added_at="2024-01-02T00:00:00Z")
        self.add(identity(), "rep-ide", added_at="2024-01-03T00:00:00Z")
        self.add(
            report(modified="2024-03-01T00:00:00Z"),
            "rep-v1",
            added_at="2024-03-02T00:00:00Z",
        )
        self.assertEqual(
            [],
            self.service.list_objects(
                "feed", ["report"], ["2024-03-02T00:00:00Z"]
            ).to_json()["objects"],
        )
        delta = self.service.list_objects(
            "feed", ["report"], ["2024-03-01T23:59:59Z"]
        ).to_json()
        self.assertEqual([REPORT_ID], [item["id"] for item in delta["objects"]])
        self.assertEqual(["report"], delta["type"])

        self.add(
            report(modified="2024-04-01T00:00:00Z", object_refs=[INDICATOR_ID]),
            "rep-v2",
            added_at="2024-04-02T00:00:00Z",
        )
        delta = self.service.list_objects(
            "feed", None, ["2024-04-01T00:00:00Z"]
        ).to_json()["objects"]
        self.assertEqual([REPORT_ID], [item["id"] for item in delta])
        self.assertEqual([INDICATOR_ID], delta[0]["object_refs"])

    def test_report_on_an_unwritable_collection_is_forbidden(self):
        self.service.create_collection(
            {"id": "restricted", "title": "Restricted", "can_write": False}, "cr"
        )
        with self.assertRaisesRegex(ForbiddenError, "collection is not writable"):
            self.service.add_object("restricted", report(), "k1")
        stored = self.service.add_object(
            "feed", dict(indicator(), added_at="2024-01-02T00:00:00Z"), "k1"
        )
        self.assertEqual(201, stored.status)

    # ------------------------------------------------------------------- notes

    def _seed_note_targets(self):
        self.add(indicator(), "note-ind", added_at="2024-01-02T00:00:00Z")
        self.add(identity(), "note-ide", added_at="2024-01-03T00:00:00Z")

    def test_note_round_trip_preserves_every_property(self):
        self._seed_note_targets()
        payload = note(
            abstract="Short summary",
            authors=["alice", "bob"],
            object_refs=[INDICATOR_ID, IDENTITY_ID],
        )
        stored = self.add(payload, "note-1", added_at="2024-01-06T00:00:00Z")
        document = stored["object"]
        self.assertEqual("note", document["type"])
        self.assertEqual(NOTE_ID, document["id"])
        self.assertEqual("2.1", document["spec_version"])
        self.assertEqual("Analyst comment", document["content"])
        self.assertEqual("Short summary", document["abstract"])
        self.assertEqual(["alice", "bob"], document["authors"])
        self.assertEqual([INDICATOR_ID, IDENTITY_ID], document["object_refs"])
        self.assertEqual("2024-01-06T00:00:00.000000Z", stored["added_at"])
        self.assertEqual("2024-01-01T00:00:00.000000Z", stored["version"])
        self.assertNotIn("revoked", document)
        listed = self.service.list_objects("feed", ["note"]).to_json()
        self.assertEqual([document], listed["objects"])
        self.assertEqual(["note"], listed["type"])

    def test_note_optional_properties_are_absent_when_omitted(self):
        self._seed_note_targets()
        stored = self.add(note(), "note-min")
        self.assertNotIn("abstract", stored["object"])
        self.assertNotIn("authors", stored["object"])

    def test_note_required_properties_are_enforced(self):
        self._seed_note_targets()
        for field in ("content", "object_refs"):
            with self.assertRaisesRegex(ValidationError, f"note requires the {field} property"):
                self.add(
                    {key: value for key, value in note().items() if key != field},
                    f"note-req-{field}",
                )

    def test_note_unknown_property_is_rejected(self):
        self._seed_note_targets()
        with self.assertRaisesRegex(ValidationError, "unsupported properties: whatever"):
            self.add(dict(note(), whatever=1), "note-unknown")

    def test_note_id_prefix_must_match_type(self):
        self._seed_note_targets()
        with self.assertRaisesRegex(ValidationError, "does not match type note"):
            self.add(dict(note(), id=REPORT_ID), "note-prefix")

    def test_note_identifier_must_be_lowercase_uuidv4(self):
        self._seed_note_targets()
        for identifier in (
            "note--9FB2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
            "note--9fb2c3d4-e5f6-1a7b-8c9d-0e1f2a3b4c5d",
            "note-9fb2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        ):
            with self.assertRaisesRegex(ValidationError, "must be a STIX identifier"):
                self.add(dict(note(), id=identifier), f"note-id-{identifier}")

    def test_note_scalar_property_types_are_enforced(self):
        self._seed_note_targets()
        bad = (
            (dict(content=""), "content must be a non-empty string"),
            (dict(content=5), "content must be a non-empty string"),
            (dict(abstract=""), "abstract must be a non-empty string"),
            (dict(abstract=7), "abstract must be a non-empty string"),
            (dict(authors=[]), "authors must be a non-empty array"),
            (dict(authors="alice"), "authors must be a non-empty array"),
            (dict(authors=["alice", ""]), "authors must be a non-empty array"),
            (dict(authors=["alice", 3]), "authors must be a non-empty array"),
        )
        for index, (overrides, message) in enumerate(bad):
            with self.assertRaisesRegex(ValidationError, message):
                self.add(dict(note(note_id=NOTE2_ID), **overrides), f"note-type-{index}")

    def test_note_object_refs_must_be_non_empty_unique_and_supported(self):
        self._seed_note_targets()
        cases = (
            ([], "non-empty array of STIX identifiers"),
            (IDENTITY_ID, "non-empty array of STIX identifiers"),
            ([INDICATOR_ID, INDICATOR_ID], "duplicate reference"),
            ([1], "must be a STIX identifier"),
            ([""], "must be a STIX identifier"),
            (["note--not-a-uuid"], "must be a STIX identifier"),
            (["note--9fb2c3d4-e5f6-1a7b-8c9d-0e1f2a3b4c5d"], "must be a STIX identifier"),
            (["campaign--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"], "must reference one of"),
        )
        for index, (refs, message) in enumerate(cases):
            with self.assertRaisesRegex(ValidationError, message):
                self.add(note(note_id=NOTE2_ID, object_refs=refs), f"note-ref-{index}")
        self.assertEqual([], self.service.list_objects("feed", ["note"]).to_json()["objects"])

    def test_note_cannot_reference_itself(self):
        self._seed_note_targets()
        with self.assertRaisesRegex(ValidationError, "must not reference the note itself"):
            self.add(note(object_refs=[INDICATOR_ID, NOTE_ID]), "note-self")
        with self.assertRaises(NotFoundError):
            self.service.object_versions("feed", NOTE_ID)

    def test_note_references_must_already_exist_in_the_collection(self):
        self.add(indicator(), "note-ind")
        with self.assertRaisesRegex(ValidationError, "note references unknown identity"):
            self.add(note(object_refs=[INDICATOR_ID, IDENTITY_ID]), "note-missing")
        with self.assertRaises(NotFoundError):
            self.service.object_versions("feed", NOTE_ID)
        self.assertEqual([], self.service.list_objects("feed", ["note"]).to_json()["objects"])

    def test_note_reference_to_another_collection_is_unknown(self):
        self._seed_note_targets()
        self.service.create_collection({"id": "other", "title": "Other feed"}, "co")
        self.service.add_object("other", dict(malware(), added_at="2024-01-04T00:00:00Z"), "ko")
        with self.assertRaisesRegex(ValidationError, "note references unknown malware"):
            self.add(note(object_refs=[MALWARE_ID]), "note-cross")

    def test_note_may_reference_every_supported_type_including_another_note(self):
        self._seed_note_targets()
        self.add(malware(), "note-mal", added_at="2024-01-04T00:00:00Z")
        self.add(relationship(), "note-rel", added_at="2024-01-05T00:00:00Z")
        self.add(
            report(modified="2024-03-01T00:00:00Z"),
            "note-rep",
            added_at="2024-03-02T00:00:00Z",
        )
        first = self.add(
            note(note_id=NOTE_ID, object_refs=[INDICATOR_ID, IDENTITY_ID, MALWARE_ID]),
            "note-1",
            added_at="2024-03-03T00:00:00Z",
        )
        self.assertEqual(NOTE_ID, first["object"]["id"])
        # A second note annotates the relationship, the report, and the first note.
        second = self.add(
            note(
                note_id=NOTE2_ID,
                object_refs=[RELATIONSHIP_ID, REPORT_ID, NOTE_ID],
            ),
            "note-2",
            added_at="2024-03-04T00:00:00Z",
        )
        self.assertEqual(NOTE2_ID, second["object"]["id"])
        self.assertEqual(
            [RELATIONSHIP_ID, REPORT_ID, NOTE_ID], second["object"]["object_refs"]
        )

    def test_note_accepts_a_revoked_target(self):
        self._seed_note_targets()
        self.add(
            revoked(identity(modified="2024-02-01T00:00:00Z")),
            "note-rev",
            added_at="2024-02-02T00:00:00Z",
        )
        self.assertEqual(
            201,
            self.add_status(
                note(object_refs=[IDENTITY_ID]), "note-on-revoked",
                added_at="2024-02-03T00:00:00Z",
            ),
        )

    def test_note_versions_append_and_revisions_can_change_fields_and_refs(self):
        self._seed_note_targets()
        self.add(malware(), "note-mal", added_at="2024-01-04T00:00:00Z")
        self.add(
            note(
                modified="2024-03-01T00:00:00Z",
                content="First take",
                object_refs=[INDICATOR_ID, IDENTITY_ID],
            ),
            "note-v1",
            added_at="2024-03-02T00:00:00Z",
        )
        self.add(
            note(
                modified="2024-04-01T00:00:00Z",
                content="Revised take",
                abstract="Summary",
                authors=["alice"],
                object_refs=[INDICATOR_ID, MALWARE_ID],
            ),
            "note-v2",
            added_at="2024-04-02T00:00:00Z",
        )
        current = self.service.list_objects("feed", ["note"]).to_json()["objects"][0]
        self.assertEqual("2024-04-01T00:00:00.000000Z", current["modified"])
        self.assertEqual("Revised take", current["content"])
        self.assertEqual("Summary", current["abstract"])
        self.assertEqual(["alice"], current["authors"])
        self.assertEqual([INDICATOR_ID, MALWARE_ID], current["object_refs"])
        versions = self.service.object_versions("feed", NOTE_ID).to_json()
        self.assertEqual(
            ["2024-03-01T00:00:00.000000Z", "2024-04-01T00:00:00.000000Z"],
            versions["versions"],
        )

    def test_note_revision_referencing_an_unknown_target_leaves_current_intact(self):
        self._seed_note_targets()
        self.add(note(modified="2024-03-01T00:00:00Z"), "note-v1")
        with self.assertRaisesRegex(ValidationError, "note references unknown malware"):
            self.add(
                note(modified="2024-04-01T00:00:00Z", object_refs=[MALWARE_ID]),
                "note-v2",
            )
        current = self.service.list_objects("feed", ["note"]).to_json()["objects"][0]
        self.assertEqual("2024-03-01T00:00:00.000000Z", current["modified"])
        self.assertEqual([INDICATOR_ID], current["object_refs"])
        self.assertEqual(
            1, len(self.service.object_versions("feed", NOTE_ID).to_json()["versions"])
        )
        # The rolled back revision did not consume its idempotency key.
        self.add(malware(), "note-mal", added_at="2024-01-04T00:00:00Z")
        stored = self.service.add_object(
            "feed",
            dict(
                note(modified="2024-04-01T00:00:00Z", object_refs=[MALWARE_ID]),
                added_at="2024-04-02T00:00:00Z",
            ),
            "note-v2",
        )
        self.assertEqual(201, stored.status)

    def test_note_version_conflicts_follow_existing_rules(self):
        self._seed_note_targets()
        self.add(note(modified="2024-03-01T00:00:00Z"), "note-key")
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.add(note(modified="2024-03-01T00:00:00Z"), "note-dup")
        with self.assertRaisesRegex(ConflictError, "older than the stored version"):
            self.add(note(modified="2024-02-01T00:00:00Z"), "note-old")

    def test_note_revocation_lifecycle(self):
        self._seed_note_targets()
        self.add(
            note(
                modified="2024-03-01T00:00:00Z",
                abstract="Keep",
                authors=["alice"],
            ),
            "note-v1",
            added_at="2024-03-02T00:00:00Z",
        )
        # A revocation that also edits content or refs is a 400.
        bad = note(
            modified="2024-04-01T00:00:00Z",
            content="Changed",
            abstract="Keep",
            authors=["alice"],
        )
        with self.assertRaisesRegex(ValidationError, "content"):
            self.add(revoked(bad), "note-rev-bad")
        good = note(
            modified="2024-04-01T00:00:00Z",
            abstract="Keep",
            authors=["alice"],
        )
        result = self.add(
            revoked(good), "note-rev-ok", added_at="2024-04-02T00:00:00Z"
        )
        self.assertIs(result["object"]["revoked"], True)
        versions = self.service.object_versions("feed", NOTE_ID).to_json()
        self.assertEqual(
            ["2024-03-01T00:00:00.000000Z", "2024-04-01T00:00:00.000000Z"],
            versions["versions"],
        )
        # Any write after revocation is a conflict.
        with self.assertRaisesRegex(ConflictError, "is revoked"):
            self.add(note(modified="2024-05-01T00:00:00Z"), "note-after")
        # The revoked note still references a live object and stays listed.
        listed = self.service.list_objects("feed", ["note"]).to_json()["objects"]
        self.assertEqual([NOTE_ID], [item["id"] for item in listed])
        self.assertIs(listed[0]["revoked"], True)

    def test_note_participates_in_type_filter_order_and_deltas(self):
        self._seed_note_targets()
        self.add(
            note(modified="2024-03-01T00:00:00Z"),
            "order-note",
            added_at="2024-03-02T00:00:00Z",
        )
        combined = self.service.list_objects(
            "feed", ["note", "indicator"]
        ).to_json()
        self.assertEqual(["note", "indicator"], combined["type"])
        self.assertEqual(
            [INDICATOR_ID, NOTE_ID], [item["id"] for item in combined["objects"]]
        )
        # Strictly half-open delta: the note added exactly at the cutoff is excluded.
        self.assertEqual(
            [],
            self.service.list_objects(
                "feed", ["note"], ["2024-03-02T00:00:00Z"]
            ).to_json()["objects"],
        )
        delta = self.service.list_objects(
            "feed", None, ["2024-03-01T23:59:59Z"]
        ).to_json()
        self.assertEqual([NOTE_ID], [item["id"] for item in delta["objects"]])

    def test_note_pagination_echoes_type_and_freezes_snapshot(self):
        self._seed_note_targets()
        for index, stamp in enumerate(
            ("2024-03-02T00:00:00Z", "2024-03-03T00:00:00Z"), start=1
        ):
            self.add(
                note(
                    note_id=(NOTE_ID if index == 1 else NOTE2_ID),
                    modified=stamp,
                ),
                f"note-page-{index}",
                added_at=stamp,
            )
        first = self.service.list_objects("feed", ["note"], limit=["1"]).to_json()
        self.assertEqual(["note"], first["type"])
        self.assertEqual([NOTE_ID], [item["id"] for item in first["objects"]])
        self.assertTrue(first["more"])
        # A late note revision stays out of the open snapshot.
        self.add(
            note(
                note_id=NOTE_ID,
                modified="2024-05-01T00:00:00Z",
                content="Late edit",
            ),
            "note-late",
            added_at="2024-05-02T00:00:00Z",
        )
        second = self.service.list_objects(
            "feed", next_token=[first["next"]]
        ).to_json()
        self.assertEqual(["note"], second["type"])
        self.assertEqual([NOTE2_ID], [item["id"] for item in second["objects"]])
        self.assertFalse(second["more"])
        fresh = self.service.list_objects("feed", ["note"], limit=["10"]).to_json()
        self.assertEqual(
            ["Analyst comment", "Late edit"],
            [item["content"] for item in fresh["objects"]],
        )

    def test_note_idempotent_replay_returns_the_first_response(self):
        self._seed_note_targets()
        payload = dict(
            note(modified="2024-03-01T00:00:00Z"), added_at="2024-03-02T00:00:00Z"
        )
        first = self.service.add_object("feed", payload, "same").to_json()
        repeated = self.service.add_object("feed", payload, "same").to_json()
        self.assertEqual(first, repeated)

    def test_report_can_reference_an_existing_note(self):
        self._seed_note_targets()
        self.add(
            note(modified="2024-03-01T00:00:00Z"),
            "rep-note",
            added_at="2024-03-02T00:00:00Z",
        )
        stored = self.add(
            report(
                modified="2024-04-01T00:00:00Z",
                object_refs=[INDICATOR_ID, NOTE_ID],
            ),
            "rep-with-note",
            added_at="2024-04-02T00:00:00Z",
        )
        self.assertEqual("report", stored["object"]["type"])
        self.assertEqual([INDICATOR_ID, NOTE_ID], stored["object"]["object_refs"])

    def test_report_reference_to_an_unknown_note_is_rejected(self):
        self._seed_note_targets()
        with self.assertRaisesRegex(ValidationError, "report references unknown note"):
            self.add(
                report(
                    modified="2024-04-01T00:00:00Z",
                    object_refs=[INDICATOR_ID, NOTE_ID],
                ),
                "rep-note-missing",
            )
        self.assertEqual([], self.service.list_objects("feed", ["report"]).to_json()["objects"])

    def test_report_note_reference_keeps_duplicate_and_self_rules(self):
        self._seed_note_targets()
        self.add(note(), "rep-note-dup")
        with self.assertRaisesRegex(ValidationError, "duplicate reference"):
            self.add(report(object_refs=[NOTE_ID, NOTE_ID]), "rep-note-dup-ref")
        # A report still cannot point at itself, even though notes are now allowed.
        with self.assertRaisesRegex(ValidationError, "must reference one of"):
            self.add(report(object_refs=[REPORT_ID]), "rep-self")

    def test_note_on_an_unwritable_collection_is_forbidden(self):
        self.service.create_collection(
            {"id": "restricted", "title": "Restricted", "can_write": False}, "cn"
        )
        with self.assertRaisesRegex(ForbiddenError, "collection is not writable"):
            self.service.add_object("restricted", note(), "k1")

    # ------------------------------------------------------------------ access

    def _restricted_collection(self, **flags):
        self.service.create_collection(
            {"id": "restricted", "title": "Restricted", **flags}, "cr"
        )

    def test_listing_hides_unreadable_collections(self):
        self._restricted_collection(can_read=False)
        self.service.create_collection({"id": "alpha", "title": "Alpha"}, "ca")
        listed = self.service.list_collections()
        self.assertEqual(["alpha", "feed"], [item["id"] for item in listed])

    def test_unreadable_collection_is_indistinguishable_from_missing(self):
        self._restricted_collection(can_read=False)
        for call in (
            lambda: self.service.get_collection("restricted"),
            lambda: self.service.list_objects("restricted"),
            lambda: self.service.object_versions("restricted", IDENTITY_ID),
            lambda: self.service.add_object("restricted", identity(), "k1"),
        ):
            with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
                call()

    def test_read_only_collection_rejects_writes_with_forbidden(self):
        self._restricted_collection(can_write=False)
        self.assertEqual("Restricted", self.service.get_collection("restricted")["title"])
        with self.assertRaisesRegex(ForbiddenError, "collection is not writable"):
            self.service.add_object("restricted", identity(), "k1")

    def test_denied_writes_do_not_consume_the_idempotency_key(self):
        self._restricted_collection(can_write=False)
        with self.assertRaises(ForbiddenError):
            self.service.add_object("restricted", identity(), "reuse")
        stored = self.service.add_object(
            "feed", dict(identity(), added_at="2024-01-02T00:00:00Z"), "reuse"
        )
        self.assertEqual(201, stored.status)

    def test_unreadable_collection_does_not_start_or_continue_a_snapshot(self):
        self._restricted_collection(can_read=True, can_write=True)
        self.service.add_object(
            "restricted", dict(identity(), added_at="2024-01-02T00:00:00Z"), "k1"
        )
        token = self.service.list_objects("restricted", limit=["1"]).to_json()
        self.assertFalse(token["more"])
        self.service.store.connection.execute(
            "UPDATE collections SET document = ? WHERE id = ?",
            (
                self.service.store.encode(
                    {
                        "id": "restricted",
                        "title": "Restricted",
                        "description": "",
                        "can_read": False,
                        "can_write": False,
                        "media_type": "application/stix+json;version=2.1",
                    }
                ),
                "restricted",
            ),
        )
        with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
            self.service.list_objects("restricted", limit=["1"])

    def test_idempotent_create_returns_the_first_result(self):
        first = self.service.add_object("feed", dict(indicator(), added_at="2024-01-02T00:00:00Z"), "same")
        repeated = self.service.add_object("feed", dict(indicator(), added_at="2024-01-02T00:00:00Z"), "same")
        self.assertEqual(first.payload, repeated.payload)
        self.assertEqual(201, repeated.status)
        self.assertEqual(1, len(self.service.list_objects("feed").to_json()["objects"]))

    def test_idempotency_key_cannot_be_reused_for_another_operation(self):
        self.service.create_collection({"id": "other", "title": "Other"}, "shared")
        with self.assertRaises(ConflictError):
            self.service.create_collection({"id": "third", "title": "Third"}, "shared")

    def test_idempotency_key_is_required(self):
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key header is required"):
            self.service.add_object("feed", identity(), None)

    def test_collection_validation(self):
        with self.assertRaisesRegex(ValidationError, "unsupported properties"):
            self.service.create_collection({"id": "x", "title": "X", "extra": 1}, "k1")
        with self.assertRaisesRegex(ValidationError, "title must be a non-empty string"):
            self.service.create_collection({"id": "x", "title": ""}, "k2")
        with self.assertRaisesRegex(ValidationError, "can_write must be a boolean"):
            self.service.create_collection({"id": "x", "title": "X", "can_write": "yes"}, "k3")

    def test_state_survives_a_restart(self):
        path = str(Path(self.directory.name) / "restart.db")
        first = StixRelay(path)
        first.create_collection({"id": "feed", "title": "Primary feed"}, "c1")
        first.add_object("feed", dict(identity(), added_at="2024-01-02T00:00:00Z"), "k1")
        reopened = StixRelay(path)
        self.assertEqual(
            [IDENTITY_ID], [item["id"] for item in reopened.list_objects("feed").to_json()["objects"]]
        )

    # --------------------------------------------------------------- pagination

    PAGE_INDICATOR_IDS = (
        "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f01",
        "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f02",
        "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f03",
        "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f04",
        "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f05",
    )

    def _paged_indicator(self, number: int, **overrides) -> dict:
        payload = indicator()
        payload["id"] = self.PAGE_INDICATOR_IDS[number - 1]
        payload["name"] = f"Indicator {number}"
        payload.update(overrides)
        return payload

    def _seed_indicators(self, count: int, *, key_prefix: str = "ind"):
        for number in range(1, count + 1):
            self.add(
                self._paged_indicator(number),
                f"{key_prefix}-{number}",
                added_at=f"2024-02-{number:02d}T00:00:00Z",
            )

    def test_legacy_listing_without_limit_is_unchanged(self):
        self._seed_indicators(3)
        page = self.service.list_objects("feed", ["indicator"], ["2024-01-01T00:00:00Z"]).to_json()
        self.assertEqual(3, len(page["objects"]))
        self.assertFalse(page["more"])
        self.assertNotIn("next", page)
        self.assertEqual(["indicator"], page["type"])

    def test_limit_paginates_in_stable_order(self):
        self._seed_indicators(5)
        first = self.service.list_objects("feed", limit=["2"]).to_json()
        self.assertEqual(
            [1, 2], [int(item["name"].rsplit(" ", 1)[1]) for item in first["objects"]]
        )
        self.assertTrue(first["more"])
        self.assertIn("next", first)

        seen = [item["id"] for item in first["objects"]]
        token = first["next"]
        for expected_size, more in ((2, True), (1, False)):
            page = self.service.list_objects("feed", next_token=[token]).to_json()
            self.assertEqual(expected_size, len(page["objects"]))
            self.assertEqual(more, page["more"])
            seen.extend(item["id"] for item in page["objects"])
            token = page.get("next")
        self.assertEqual(5, len(seen))
        self.assertEqual(len(set(seen)), len(seen))
        self.assertIsNone(token)

    def test_limit_equal_to_total_has_no_next(self):
        self._seed_indicators(2)
        page = self.service.list_objects("feed", limit=["2"]).to_json()
        self.assertEqual(2, len(page["objects"]))
        self.assertFalse(page["more"])
        self.assertNotIn("next", page)

    def test_type_and_added_after_are_remembered_by_the_cursor(self):
        self._seed_indicators(3)
        self.add(identity(), "identity-page", added_at="2024-02-05T00:00:00Z")
        first = self.service.list_objects(
            "feed", ["indicator"], ["2024-02-01T00:00:00Z"], limit=["1"]
        ).to_json()
        self.assertEqual(["indicator"], first["type"])
        # The cutoff excludes indicator 1 (added 2024-02-01, equal to cutoff).
        self.assertEqual("Indicator 2", first["objects"][0]["name"])
        second = self.service.list_objects("feed", next_token=[first["next"]]).to_json()
        self.assertEqual(["indicator"], second["type"])
        self.assertEqual("Indicator 3", second["objects"][0]["name"])
        self.assertFalse(second["more"])

    def test_cursor_replays_its_snapshot_not_the_first_page(self):
        self._seed_indicators(3)
        first = self.service.list_objects("feed", limit=["2"]).to_json()
        second = self.service.list_objects("feed", next_token=[first["next"]]).to_json()
        replayed = self.service.list_objects("feed", next_token=[first["next"]]).to_json()
        self.assertEqual(second["objects"], replayed["objects"])
        self.assertEqual(second.get("next"), replayed.get("next"))

    def test_new_objects_and_revisions_stay_out_of_an_open_snapshot(self):
        self._seed_indicators(2)
        first = self.service.list_objects("feed", limit=["1"]).to_json()
        # A revision and a brand new object arrive after the snapshot began.
        self.add(
            self._paged_indicator(1, modified="2024-05-01T00:00:00Z", name="Indicator 1 v2"),
            "ind-1-v2",
            added_at="2024-05-02T00:00:00Z",
        )
        self.add(
            self._paged_indicator(3),
            "ind-late-3",
            added_at="2024-05-03T00:00:00Z",
        )
        second = self.service.list_objects("feed", next_token=[first["next"]]).to_json()
        self.assertEqual(1, len(second["objects"]))
        self.assertFalse(second["more"])
        self.assertEqual("Indicator 2", second["objects"][0]["name"])
        fresh = self.service.list_objects("feed", limit=["10"]).to_json()
        self.assertEqual(
            ["Indicator 2", "Indicator 1 v2", "Indicator 3"],
            [item["name"] for item in fresh["objects"]],
        )

    def test_snapshot_survives_a_restart(self):
        path = str(Path(self.directory.name) / "paged.db")
        service = StixRelay(path)
        service.create_collection({"id": "feed", "title": "Primary feed"}, "c1")
        service.add_object("feed", dict(indicator(), added_at="2024-01-02T00:00:00Z"), "k1")
        service.add_object(
            "feed",
            dict(indicator(), id=self.PAGE_INDICATOR_IDS[1], added_at="2024-01-03T00:00:00Z"),
            "k2",
        )
        first = service.list_objects("feed", limit=["1"]).to_json()
        reopened = StixRelay(path)
        page = reopened.list_objects("feed", next_token=[first["next"]]).to_json()
        self.assertEqual(1, len(page["objects"]))
        self.assertFalse(page["more"])

    def test_limit_validation(self):
        for value in ("0", "201", "01", "-1", "1.0", "abc", "1 ", ""):
            with self.assertRaisesRegex(ValidationError, "limit must be a decimal integer"):
                self.service.list_objects("feed", limit=[value])
        with self.assertRaisesRegex(ValidationError, "limit must be supplied exactly once"):
            self.service.list_objects("feed", limit=["1", "2"])

    def test_next_cannot_mix_with_other_parameters(self):
        with self.assertRaisesRegex(ValidationError, "without type, added_after, or limit"):
            self.service.list_objects("feed", ["indicator"], next_token=["x"])
        with self.assertRaisesRegex(ValidationError, "without type, added_after, or limit"):
            self.service.list_objects("feed", None, ["2024-01-01T00:00:00Z"], next_token=["x"])
        with self.assertRaisesRegex(ValidationError, "without type, added_after, or limit"):
            self.service.list_objects("feed", limit=["1"], next_token=["x"])

    def test_next_must_be_supplied_once(self):
        with self.assertRaisesRegex(ValidationError, "not a valid cursor"):
            self.service.list_objects("feed", next_token=["a", "b"])

    def test_tampered_or_foreign_cursors_are_rejected(self):
        self._seed_indicators(2)
        token = self.service.list_objects("feed", limit=["1"]).to_json()["next"]
        with self.assertRaisesRegex(ValidationError, "not a valid cursor"):
            self.service.list_objects("feed", next_token=["garbage"])
        flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaisesRegex(ValidationError, "modified or was not issued"):
            self.service.list_objects("feed", next_token=[flipped])
        self.service.create_collection({"id": "other", "title": "Other"}, "co")
        with self.assertRaisesRegex(ValidationError, "does not belong to this collection"):
            self.service.list_objects("other", next_token=[token])
        with self.assertRaisesRegex(ValidationError, "not a valid cursor"):
            self.service.list_objects("feed", next_token=[None])

    def test_cursor_signed_by_another_service_is_rejected(self):
        self._seed_indicators(2)
        other = StixRelay(str(Path(self.directory.name) / "other-secret.db"))
        from stixrelay import cursor as cursor_module
        token = cursor_module.encode(other.store.cursor_secret, 1, 1, "feed")
        with self.assertRaisesRegex(ValidationError, "modified or was not issued"):
            self.service.list_objects("feed", next_token=[token])

    # ------------------------------------------------------------------ export

    @staticmethod
    def _query(**parameters: str) -> dict:
        return {name: [value] for name, value in parameters.items()}

    def _seed_export_history(self):
        # identity v1 arrives first; indicator v1 arrives second; identity v2
        # (a normal revision) arrives third; the identity revocation arrives last.
        self.add(identity(), "exp-i1", added_at="2024-01-02T00:00:00Z")
        self.add(indicator(), "exp-n1", added_at="2024-01-03T00:00:00Z")
        self.add(
            identity(modified="2024-02-01T00:00:00Z", name="Renamed Org"),
            "exp-i2",
            added_at="2024-02-02T00:00:00Z",
        )
        self.add(
            revoked(identity(modified="2024-03-01T00:00:00Z", name="Renamed Org")),
            "exp-i3",
            added_at="2024-03-02T00:00:00Z",
        )

    def test_export_defaults_to_a_stix_bundle_of_current_documents(self):
        self._seed_export_history()
        export = self.service.export_collection("feed", {})
        self.assertEqual(200, export.status)
        self.assertEqual(MEDIA_TYPE, export.media_type)
        bundle = json.loads(export.body)
        self.assertEqual(["type", "objects"], list(bundle))
        self.assertEqual("bundle", bundle["type"])
        # Only current versions: the indicator, then the revoked identity current.
        self.assertEqual(
            [(INDICATOR_ID, "2024-01-01T00:00:00.000000Z", None),
             (IDENTITY_ID, "2024-03-01T00:00:00.000000Z", True)],
            [
                (document["id"], document["modified"], document.get("revoked"))
                for document in bundle["objects"]
            ],
        )
        for document in bundle["objects"]:
            self.assertNotIn("added_at", document)
            self.assertNotIn("collection_id", document)
            self.assertNotIn("version", document)

    def test_export_current_matches_the_unpaginated_object_read(self):
        self._seed_export_history()
        export = self.service.export_collection(
            "feed", self._query(type="identity", added_after="2024-01-01T00:00:00Z")
        )
        bundle = json.loads(export.body)
        listed = self.service.list_objects(
            "feed", ["identity"], ["2024-01-01T00:00:00Z"]
        ).to_json()["objects"]
        self.assertEqual(listed, bundle["objects"])

    def test_export_ndjson_emits_one_object_per_line_ending_in_newline(self):
        self._seed_export_history()
        export = self.service.export_collection(
            "feed", self._query(format="ndjson")
        )
        self.assertEqual(NDJSON_MEDIA_TYPE, export.media_type)
        text = export.body.decode()
        self.assertTrue(text.endswith("\n"))
        lines = text.split("\n")
        self.assertEqual("", lines[-1])
        documents = [json.loads(line) for line in lines[:-1]]
        self.assertEqual(2, len(documents))
        self.assertEqual([INDICATOR_ID, IDENTITY_ID], [item["id"] for item in documents])

    def test_export_empty_stix_has_empty_objects_and_ndjson_is_zero_bytes(self):
        stix = self.service.export_collection("feed", {})
        self.assertEqual(MEDIA_TYPE, stix.media_type)
        self.assertEqual({"type": "bundle", "objects": []}, json.loads(stix.body))
        ndjson = self.service.export_collection("feed", self._query(format="ndjson"))
        self.assertEqual(NDJSON_MEDIA_TYPE, ndjson.media_type)
        self.assertEqual(b"", ndjson.body)

    def test_export_versions_all_keeps_every_revision_in_export_order(self):
        self._seed_export_history()
        export = self.service.export_collection(
            "feed", self._query(versions="all")
        )
        documents = json.loads(export.body)["objects"]
        self.assertEqual(
            [
                (IDENTITY_ID, "2024-01-01T00:00:00.000000Z"),
                (INDICATOR_ID, "2024-01-01T00:00:00.000000Z"),
                (IDENTITY_ID, "2024-02-01T00:00:00.000000Z"),
                (IDENTITY_ID, "2024-03-01T00:00:00.000000Z"),
            ],
            [(document["id"], document["modified"]) for document in documents],
        )
        # The pre-revocation history survives alongside the revoked current version.
        self.assertNotIn("revoked", documents[0])
        self.assertNotIn("revoked", documents[2])
        self.assertIs(documents[3]["revoked"], True)

    def test_export_versions_all_sorts_same_added_at_by_id_then_modified(self):
        # Two different objects and two versions of one id, all received at once.
        self.add(indicator(), "exp-order-n", added_at="2024-01-02T00:00:00Z")
        self.add(identity(modified="2024-01-01T00:00:00Z"), "exp-order-i1",
                 added_at="2024-01-02T00:00:00Z")
        self.add(identity(modified="2024-02-01T00:00:00Z", name="Renamed Org"),
                 "exp-order-i2", added_at="2024-01-02T00:00:00Z")
        documents = json.loads(
            self.service.export_collection(
                "feed", self._query(versions="all")
            ).body
        )["objects"]
        self.assertEqual(
            [
                (IDENTITY_ID, "2024-01-01T00:00:00.000000Z"),
                (IDENTITY_ID, "2024-02-01T00:00:00.000000Z"),
                (INDICATOR_ID, "2024-01-01T00:00:00.000000Z"),
            ],
            [(document["id"], document["modified"]) for document in documents],
        )

    def test_export_versions_all_applies_added_after_to_each_version(self):
        self._seed_export_history()
        documents = json.loads(
            self.service.export_collection(
                "feed",
                self._query(versions="all", added_after="2024-02-02T00:00:00Z"),
            ).body
        )["objects"]
        # The version received exactly at the cutoff is excluded; only the
        # revocation, received strictly later, remains of the identity's history.
        self.assertEqual(
            [(IDENTITY_ID, "2024-03-01T00:00:00.000000Z")],
            [(document["id"], document["modified"]) for document in documents],
        )

    def test_export_type_filter_applies_to_both_version_modes(self):
        self._seed_export_history()
        for mode in ("current", "all"):
            documents = json.loads(
                self.service.export_collection(
                    "feed", self._query(versions=mode, type="indicator")
                ).body
            )["objects"]
            self.assertEqual(
                [INDICATOR_ID], [document["id"] for document in documents], mode
            )

    def test_export_formats_share_one_object_set_and_order(self):
        self._seed_export_history()
        for mode in ("current", "all"):
            stix = json.loads(
                self.service.export_collection(
                    "feed", self._query(versions=mode)
                ).body
            )["objects"]
            ndjson = [
                json.loads(line)
                for line in self.service.export_collection(
                    "feed", self._query(versions=mode, format="ndjson")
                ).body.decode().splitlines()
            ]
            self.assertEqual(stix, ndjson, mode)

    def test_export_query_validation(self):
        self._seed_export_history()
        cases = (
            {"format": ["xml"]},
            {"format": ["stix", "ndjson"]},
            {"versions": ["latest"]},
            {"versions": ["current", "all"]},
            {"type": ["campaign"]},
            {"added_after": ["not-a-timestamp"]},
            {"limit": ["1"]},
            {"next": ["token"]},
            {"unknown": ["1"]},
        )
        for query in cases:
            with self.assertRaisesRegex(ValidationError, "validation|must|unsupported"):
                self.service.export_collection("feed", query)

    def test_export_denied_or_missing_collection_is_not_found_even_with_bad_query(self):
        self.service.create_collection(
            {"id": "restricted", "title": "Restricted", "can_read": False}, "cr"
        )
        # The bad format must not turn into a 400 that proves the collection exists.
        for collection_id in ("restricted", "missing"):
            with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
                self.service.export_collection(
                    collection_id, {"format": ["xml"], "unknown": ["1"]}
                )

    def test_export_creates_no_snapshots_versions_or_idempotency_records(self):
        self._seed_export_history()
        snapshot_count = self.service.store.connection.execute(
            "SELECT COUNT(*) AS count FROM snapshots"
        ).fetchone()["count"]
        idempotency_count = self.service.store.connection.execute(
            "SELECT COUNT(*) AS count FROM idempotency"
        ).fetchone()["count"]
        for query in ({}, {"format": ["ndjson"]}, {"versions": ["all"]}):
            self.service.export_collection("feed", query)
        self.assertEqual(
            snapshot_count,
            self.service.store.connection.execute(
                "SELECT COUNT(*) AS count FROM snapshots"
            ).fetchone()["count"],
        )
        self.assertEqual(
            idempotency_count,
            self.service.store.connection.execute(
                "SELECT COUNT(*) AS count FROM idempotency"
            ).fetchone()["count"],
        )
        # Objects and their version history read exactly as before the exports.
        self.assertEqual(
            4,
            self.service.store.connection.execute(
                "SELECT COUNT(*) AS count FROM objects"
            ).fetchone()["count"],
        )


INDICATOR2_ID = "indicator--1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"


def indicator2(*, modified: str = CREATED, pattern: str = "[file:size > 100]") -> dict:
    return dict(indicator(modified=modified, pattern=pattern), id=INDICATOR2_ID)


class MatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.service = StixRelay(str(Path(self.directory.name) / "test.db"))
        self.service.create_collection({"id": "feed", "title": "Primary feed"}, "c1")

    def tearDown(self):
        self.directory.cleanup()

    def add(self, payload: dict, key: str, added_at: str = "2024-01-02T00:00:00Z"):
        return self.service.add_object("feed", dict(payload, added_at=added_at), key).to_json()

    def match(self, body: dict, collection_id: str = "feed") -> dict:
        return self.service.match_indicators(collection_id, body)

    def test_equality_match_returns_id_modified_and_pattern(self):
        self.add(indicator(), "k1")
        result = self.match({"observations": {"file:hashes.'SHA-256'": "aa"}})
        self.assertEqual(1, result["count"])
        self.assertEqual(
            [
                {
                    "id": INDICATOR_ID,
                    "modified": "2024-01-01T00:00:00.000000Z",
                    "pattern": "[file:hashes.'SHA-256' = 'aa']",
                }
            ],
            result["matches"],
        )

    def test_no_match_returns_empty_result(self):
        self.add(indicator(), "k1")
        for observations in (
            {"file:hashes.'SHA-256'": "bb"},
            {"file:hashes.'MD5'": "aa"},
            {"file:hashes.'sha-256'": "aa"},
            {"other": "aa"},
        ):
            result = self.match({"observations": observations})
            self.assertEqual({"matches": [], "count": 0}, result)

    def test_path_matching_is_exact_in_case_and_quoting(self):
        self.add(indicator(pattern="[file:hashes.'SHA-256'='aa']"), "k1")
        result = self.match({"observations": {"file:hashes.'SHA-256'": "aa"}})
        self.assertEqual(1, result["count"])
        result = self.match({"observations": {"file:hashes.SHA-256": "aa"}})
        self.assertEqual(0, result["count"])

    def test_whitespace_around_operator_is_not_part_of_the_path(self):
        self.add(indicator(pattern="[file:name   =   'x']"), "k1")
        result = self.match({"observations": {"file:name": "x"}})
        self.assertEqual(1, result["count"])
        result = self.match({"observations": {"file:name   ": "x"}})
        self.assertEqual(0, result["count"])

    def test_not_equal_and_numeric_ordering_operators(self):
        self.add(indicator(pattern="[file:name != 'x']"), "k1")
        self.add(indicator2(), "k2")
        result = self.match({"observations": {"file:name": "y", "file:size": 150}})
        self.assertEqual([INDICATOR2_ID, INDICATOR_ID], [m["id"] for m in result["matches"]])
        result = self.match({"observations": {"file:name": "x", "file:size": 100}})
        self.assertEqual([], result["matches"])
        for index, (pattern, hit, miss) in enumerate((
            ("[file:size < 100]", 50, 100),
            ("[file:size <= 100]", 100, 101),
            ("[file:size >= 100]", 100, 99),
        )):
            service = StixRelay(str(Path(self.directory.name) / f"ops{index}.db"))
            service.create_collection({"id": "ops", "title": "Ops"}, "c2")
            service.add_object(
                "ops", dict(indicator(pattern=pattern), added_at="2024-01-02T00:00:00Z"), "k"
            )
            self.assertEqual(
                1, service.match_indicators("ops", {"observations": {"file:size": hit}})["count"]
            )
            self.assertEqual(
                0, service.match_indicators("ops", {"observations": {"file:size": miss}})["count"]
            )

    def test_numbers_compare_by_value_across_int_and_float(self):
        self.add(indicator(pattern="[file:size = 100]"), "k1")
        self.assertEqual(1, self.match({"observations": {"file:size": 100.0}})["count"])

    def test_type_mismatch_never_matches_and_boolean_is_not_a_number(self):
        self.add(indicator(pattern="[file:size = 1]"), "k1")
        self.add(indicator2(pattern="[file:flag = true]"), "k2")
        # 1 is a number, True is a boolean: neither equality fires across kinds.
        result = self.match({"observations": {"file:size": True, "file:flag": 1}})
        self.assertEqual(0, result["count"])
        # Ordering operators only apply to numbers.
        result = self.match({"observations": {"file:size": "2"}})
        self.assertEqual(0, result["count"])

    def test_ordering_operators_do_not_apply_to_strings(self):
        self.add(indicator(pattern="[file:name < 'b']"), "k1")
        self.assertEqual(0, self.match({"observations": {"file:name": "a"}})["count"])

    def test_not_equal_requires_the_same_json_type(self):
        self.add(indicator(pattern="[file:name != 'x']"), "k1")
        self.assertEqual(0, self.match({"observations": {"file:name": 5}})["count"])

    def test_only_indicators_are_matched(self):
        self.add(identity(), "k1")
        self.assertEqual(
            {"matches": [], "count": 0}, self.match({"observations": {"file:name": "x"}})
        )

    def test_only_the_current_version_is_checked(self):
        self.add(indicator(pattern="[file:name = 'x']"), "k1")
        self.add(indicator(modified="2024-02-01T00:00:00Z", pattern="[file:name = 'y']"), "k2")
        result = self.match({"observations": {"file:name": "x"}})
        self.assertEqual(0, result["count"])
        result = self.match({"observations": {"file:name": "y"}})
        self.assertEqual("2024-02-01T00:00:00.000000Z", result["matches"][0]["modified"])

    def test_revoked_indicators_are_skipped_unless_requested(self):
        self.add(indicator(), "k1")
        self.add(revoked(indicator(modified="2024-02-01T00:00:00Z")), "k2")
        observations = {"observations": {"file:hashes.'SHA-256'": "aa"}}
        self.assertEqual(0, self.match(observations)["count"])
        result = self.match(dict(observations, include_revoked=True))
        self.assertEqual(1, result["count"])
        self.assertEqual(INDICATOR_ID, result["matches"][0]["id"])

    def test_matches_are_sorted_by_id_and_listed_once(self):
        self.add(indicator(pattern="[file:name = 'x']"), "k1")
        self.add(indicator2(pattern="[file:name = 'x']"), "k2")
        result = self.match({"observations": {"file:name": "x"}})
        self.assertEqual(2, result["count"])
        self.assertEqual([INDICATOR2_ID, INDICATOR_ID], [m["id"] for m in result["matches"]])

    def test_missing_or_unreadable_collection_is_not_found_before_body_validation(self):
        self.service.create_collection(
            {"id": "restricted", "title": "Restricted", "can_read": False}, "cr"
        )
        for collection_id in ("restricted", "missing"):
            for body in ({"observations": {"file:name": "x"}}, [], {"unknown": 1}):
                with self.assertRaisesRegex(NotFoundError, "collection access is denied"):
                    self.service.match_indicators(collection_id, body)

    def test_body_validation(self):
        cases = (
            [],
            {},
            {"observations": None},
            {"observations": {}},
            {"observations": []},
            {"observations": {"": "x"}},
            {"observations": {"file:name": None}},
            {"observations": {"file:name": ["x"]}},
            {"observations": {"file:name": {"nested": 1}}},
            {"observations": {"file:name": float("nan")}},
            {"observations": {"file:name": float("inf")}},
            {"observations": {"file:name": "x"}, "include_revoked": "yes"},
            {"observations": {"file:name": "x"}, "unknown": 1},
        )
        for body in cases:
            with self.assertRaisesRegex(ValidationError, "."):
                self.match(body)

    def test_matching_creates_no_versions_cursors_snapshots_or_idempotency_records(self):
        self.add(indicator(), "k1")
        counts = {}
        for table in ("objects", "snapshots", "snapshot_entries", "idempotency"):
            counts[table] = self.service.store.connection.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()["count"]
        self.match({"observations": {"file:hashes.'SHA-256'": "aa"}})
        self.match({"observations": {"file:hashes.'SHA-256'": "bb"}, "include_revoked": True})
        for table, count in counts.items():
            self.assertEqual(
                count,
                self.service.store.connection.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()["count"],
            )


if __name__ == "__main__":
    unittest.main()
