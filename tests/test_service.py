import tempfile
import unittest
from pathlib import Path

from stixrelay.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from stixrelay.service import StixRelay

IDENTITY_ID = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
INDICATOR_ID = "indicator--a2f4b7d8-2c7e-4a4b-9d0e-6f6a1c9d3f21"
MALWARE_ID = "malware--3c9d1e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
RELATIONSHIP_ID = "relationship--b6a1e2c3-1f2a-4b3c-8d4e-5f6a7b8c9d0e"

CREATED = "2024-01-01T00:00:00Z"


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


class StixRelayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.service = StixRelay(str(Path(self.directory.name) / "test.db"))
        self.service.create_collection({"id": "feed", "title": "Primary feed"}, "c1")

    def tearDown(self):
        self.directory.cleanup()

    def add(self, payload: dict, key: str, added_at: str = "2024-01-02T00:00:00Z"):
        return self.service.add_object("feed", dict(payload, added_at=added_at), key).to_json()

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


if __name__ == "__main__":
    unittest.main()
