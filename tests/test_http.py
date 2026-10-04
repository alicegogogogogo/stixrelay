import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stixrelay.server import Handler
from stixrelay.service import StixRelay
from test_service import (
    IDENTITY_ID,
    INDICATOR_ID,
    MALWARE_ID,
    NOTE_ID,
    REPORT_ID,
    identity,
    indicator,
    malware,
    note,
    report,
)

IDENTITY_ADDED_AT = "2024-01-02T00:00:00Z"
IDENTITY_VERSION = "2024-01-01T00:00:00.000000Z"


class HttpTests(unittest.TestCase):
    """The HTTP surface exposes the same rules as the service object."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        Handler.service = StixRelay(str(Path(cls.directory.name) / "http.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.directory.cleanup()

    def request(self, method: str, path: str, body: dict | None = None, key: str | None = None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if key:
            request.add_header("Idempotency-Key", key)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_health(self):
        status, body = self.request("GET", "/health")
        self.assertEqual(200, status)
        self.assertEqual({"status": "ok", "product": "stixrelay"}, body)

    def test_collection_and_object_flow(self):
        status, body = self.request(
            "POST", "/taxii2/collections", {"id": "f1", "title": "Feed one"}, "h1"
        )
        self.assertEqual(201, status)
        self.assertEqual("f1", body["id"])
        status, body = self.request("GET", "/taxii2/collections/f1")
        self.assertEqual(200, status)
        self.assertEqual("Feed one", body["title"])

        status, body = self.request(
            "POST",
            "/taxii2/collections/f1/objects/",
            dict(identity(), added_at=IDENTITY_ADDED_AT),
            "h2",
        )
        self.assertEqual(201, status)
        self.assertEqual(IDENTITY_ID, body["object"]["id"])
        self.assertEqual("2024-01-02T00:00:00.000000Z", body["added_at"])
        self.assertEqual(IDENTITY_VERSION, body["version"])

        status, body = self.request("GET", "/taxii2/collections/f1/objects/?type=identity")
        self.assertEqual(200, status)
        self.assertEqual([IDENTITY_ID], [item["id"] for item in body["objects"]])
        self.assertEqual(["identity"], body["type"])

        status, body = self.request(
            "GET", "/taxii2/collections/f1/objects/?added_after=2024-01-02T00:00:00Z"
        )
        self.assertEqual(200, status)
        self.assertEqual([], body["objects"])

        status, body = self.request(
            "GET", f"/taxii2/collections/f1/objects/{IDENTITY_ID}/versions/"
        )
        self.assertEqual(200, status)
        self.assertEqual([IDENTITY_VERSION], body["versions"])
        self.assertEqual([IDENTITY_VERSION], body["latest"])

    def test_repeated_object_post_returns_the_first_result(self):
        self.request("POST", "/taxii2/collections", {"id": "f2", "title": "Feed two"}, "h3")
        payload = dict(indicator(), added_at="2024-01-05T00:00:00Z")
        first = self.request("POST", "/taxii2/collections/f2/objects/", payload, "h4")
        repeated = self.request("POST", "/taxii2/collections/f2/objects/", payload, "h4")
        self.assertEqual(201, first[0])
        self.assertEqual(201, repeated[0])
        self.assertEqual(first[1], repeated[1])

    def test_errors_use_the_documented_shape(self):
        self.request("POST", "/taxii2/collections", {"id": "f3", "title": "Feed three"}, "h5")
        status, body = self.request(
            "POST", "/taxii2/collections/f3/objects/", dict(identity(), id=MALWARE_ID), "h6"
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])
        self.assertIn("does not match type", body["error"]["message"])

        status, body = self.request("GET", "/taxii2/collections/nope/objects/")
        self.assertEqual(404, status)
        self.assertEqual("not_found", body["error"]["code"])

        status, body = self.request("GET", "/nope")
        self.assertEqual(404, status)
        self.assertEqual("not_found", body["error"]["code"])

        status, body = self.request("GET", "/taxii2/collections/f3/objects/?unknown=1")
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

        status, body = self.request(
            "POST", "/taxii2/collections/f3/objects/", dict(malware(), added_at="bad"), "h7"
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

    def test_objects_path_without_a_trailing_slash_is_accepted(self):
        self.request("POST", "/taxii2/collections", {"id": "f4", "title": "Feed four"}, "h8")
        status, body = self.request(
            "POST",
            "/taxii2/collections/f4/objects",
            dict(malware(), added_at="2024-01-06T00:00:00Z"),
            "h9",
        )
        self.assertEqual(201, status)
        self.assertEqual(MALWARE_ID, body["object"]["id"])
        status, body = self.request("GET", "/taxii2/collections/f4/objects?type=malware")
        self.assertEqual(200, status)
        self.assertEqual([MALWARE_ID], [item["id"] for item in body["objects"]])

    def test_collection_access_boundary(self):
        self.request(
            "POST",
            "/taxii2/collections",
            {"id": "hidden", "title": "Hidden", "can_read": False},
            "ha1",
        )
        self.request(
            "POST",
            "/taxii2/collections",
            {"id": "readonly", "title": "Read only", "can_write": False},
            "ha2",
        )

        status, body = self.request("GET", "/taxii2/collections")
        self.assertEqual(200, status)
        self.assertNotIn("hidden", [item["id"] for item in body["collections"]])
        self.assertIn("readonly", [item["id"] for item in body["collections"]])

        for path in (
            "/taxii2/collections/hidden",
            "/taxii2/collections/hidden/objects/",
            f"/taxii2/collections/hidden/objects/{IDENTITY_ID}/versions/",
        ):
            status, body = self.request("GET", path)
            self.assertEqual(404, status, path)
            self.assertEqual(
                {"error": {"code": "not_found", "message": "collection access is denied"}},
                body,
                path,
            )

        status, body = self.request(
            "POST",
            "/taxii2/collections/hidden/objects/",
            dict(identity(), added_at=IDENTITY_ADDED_AT),
            "ha3",
        )
        self.assertEqual(404, status)
        self.assertEqual("collection access is denied", body["error"]["message"])

        status, body = self.request(
            "POST",
            "/taxii2/collections/readonly/objects/",
            dict(identity(), added_at=IDENTITY_ADDED_AT),
            "ha4",
        )
        self.assertEqual(403, status)
        self.assertEqual(
            {"error": {"code": "forbidden", "message": "collection is not writable"}}, body
        )

        # The denied write consumed nothing: the same key works on a writable collection.
        self.request(
            "POST", "/taxii2/collections", {"id": "writable", "title": "Writable"}, "ha5"
        )
        status, body = self.request(
            "POST",
            "/taxii2/collections/writable/objects/",
            dict(identity(), added_at=IDENTITY_ADDED_AT),
            "ha4",
        )
        self.assertEqual(201, status)

    def test_content_type_must_be_json(self):
        request = urllib.request.Request(
            self.base + "/taxii2/collections", data=b"{}", method="POST"
        )
        request.add_header("Content-Type", "text/plain")
        request.add_header("Idempotency-Key", "h10")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read())
                status = response.status
        except urllib.error.HTTPError as error:
            try:
                status = error.code
                body = json.loads(error.read())
            finally:
                error.close()
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

    def test_pagination_walks_every_page_and_freezes_the_snapshot(self):
        self.request("POST", "/taxii2/collections", {"id": "p1", "title": "Paged"}, "p0")
        for number, object_id in enumerate(
            (
                "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f01",
                "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f02",
                "indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f03",
            ),
            start=1,
        ):
            payload = dict(indicator(), id=object_id, name=f"Paged {number}")
            payload["added_at"] = f"2024-04-{number:02d}T00:00:00Z"
            status, _ = self.request(
                "POST", "/taxii2/collections/p1/objects/", payload, f"p{number}"
            )
            self.assertEqual(201, status)

        status, first = self.request(
            "GET", "/taxii2/collections/p1/objects/?type=indicator&limit=2"
        )
        self.assertEqual(200, status)
        self.assertEqual(["Paged 1", "Paged 2"], [item["name"] for item in first["objects"]])
        self.assertTrue(first["more"])
        self.assertEqual(["indicator"], first["type"])
        self.assertIn("next", first)

        # An object arriving mid-walk does not enter the open snapshot.
        late = dict(
            indicator(),
            id="indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f04",
            name="Paged 4",
            added_at="2024-05-01T00:00:00Z",
        )
        self.request("POST", "/taxii2/collections/p1/objects/", late, "p4")

        status, second = self.request(
            "GET", f"/taxii2/collections/p1/objects/?next={first['next']}"
        )
        self.assertEqual(200, status)
        self.assertEqual(["Paged 3"], [item["name"] for item in second["objects"]])
        self.assertFalse(second["more"])
        self.assertNotIn("next", second)
        self.assertEqual(["indicator"], second["type"])

        # Replaying the same cursor repeats the remaining page, not the first.
        status, replayed = self.request(
            "GET", f"/taxii2/collections/p1/objects/?next={first['next']}"
        )
        self.assertEqual(second["objects"], replayed["objects"])

        # Restarting from page one sees the late object.
        status, restarted = self.request(
            "GET", "/taxii2/collections/p1/objects/?limit=10"
        )
        self.assertEqual(4, len(restarted["objects"]))
        self.assertFalse(restarted["more"])

    def test_legacy_objects_call_has_no_pagination_fields(self):
        self.request("POST", "/taxii2/collections", {"id": "p2", "title": "Legacy"}, "pl0")
        payload = dict(malware(), added_at="2024-06-01T00:00:00Z")
        self.request("POST", "/taxii2/collections/p2/objects/", payload, "pl1")
        status, body = self.request("GET", "/taxii2/collections/p2/objects/")
        self.assertEqual(200, status)
        self.assertEqual(1, len(body["objects"]))
        self.assertFalse(body["more"])
        self.assertNotIn("next", body)
        self.assertNotIn("type", body)

    def test_limit_validation_errors(self):
        self.request("POST", "/taxii2/collections", {"id": "pv", "title": "Limit"}, "pv0")
        for value in ("0", "201", "01", "-1", "1.5", "abc", "%201", "1%20"):
            status, body = self.request(
                "GET", f"/taxii2/collections/pv/objects/?limit={value}"
            )
            self.assertEqual(400, status, value)
            self.assertEqual("validation_error", body["error"]["code"], value)
        status, body = self.request(
            "GET", "/taxii2/collections/pv/objects/?limit=1&limit=2"
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

    def test_next_validation_errors(self):
        self.request("POST", "/taxii2/collections", {"id": "p3", "title": "Cursors"}, "pc0")
        self.request(
            "POST",
            "/taxii2/collections/p3/objects/",
            dict(malware(), added_at="2024-07-01T00:00:00Z"),
            "pc1",
        )
        self.request(
            "POST",
            "/taxii2/collections/p3/objects/",
            dict(
                indicator(),
                id="indicator--a2f4b7d8-2c7e-4a4b-9d0e-0f6a1c9d3f09",
                added_at="2024-07-02T00:00:00Z",
            ),
            "pc2",
        )
        _, first = self.request("GET", "/taxii2/collections/p3/objects/?limit=1")
        token = first["next"]
        flipped = token[:-1] + ("B" if token[-1] == "A" else "A")

        for query, label in (
            (f"next={token}&type=malware", "with type"),
            (f"next={token}&added_after=2024-01-01T00:00:00Z", "with added_after"),
            (f"next={token}&limit=1", "with limit"),
            ("next=not-a-real-cursor", "malformed"),
            (f"next={flipped}", "tampered"),
        ):
            status, body = self.request("GET", f"/taxii2/collections/p3/objects/?{query}")
            self.assertEqual(400, status, label)
            self.assertEqual("validation_error", body["error"]["code"], label)

        status, body = self.request("GET", f"/taxii2/collections/p3/objects/?next={token}&next={token}")
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

        self.request("POST", "/taxii2/collections", {"id": "p4", "title": "Other"}, "pc3")
        status, body = self.request("GET", f"/taxii2/collections/p4/objects/?next={token}")
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

    def test_unknown_query_parameter_is_still_rejected(self):
        self.request("POST", "/taxii2/collections", {"id": "p5", "title": "Unknowns"}, "pu0")
        status, body = self.request(
            "GET", "/taxii2/collections/p5/objects/?limit=1&cursor=x"
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])

    def test_pagination_keeps_not_found_semantics(self):
        status, body = self.request("GET", "/taxii2/collections/missing/objects/?limit=1")
        self.assertEqual(404, status)
        self.assertEqual("not_found", body["error"]["code"])

    # ----------------------------------------------------------------- reports

    def test_report_flow_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "r1", "title": "Reports"}, "r0")

        # A report before its references exist is a validation error.
        status, body = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(report(), added_at="2024-02-03T00:00:00Z"),
            "r1-bad",
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])
        self.assertIn("references unknown", body["error"]["message"])

        status, _ = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(indicator(), added_at="2024-02-01T00:00:00Z"),
            "r1-ind",
        )
        self.assertEqual(201, status)
        status, _ = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(identity(), added_at="2024-02-02T00:00:00Z"),
            "r1-ide",
        )
        self.assertEqual(201, status)

        # Same key, now with both references present, succeeds: the failed write
        # consumed neither the object nor the idempotency key.
        status, first = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(report(), added_at="2024-02-03T00:00:00Z"),
            "r1-bad",
        )
        self.assertEqual(201, status)
        self.assertEqual(REPORT_ID, first["object"]["id"])
        self.assertEqual("2024-03-01T00:00:00.000000Z", first["object"]["published"])
        self.assertEqual([INDICATOR_ID, IDENTITY_ID], first["object"]["object_refs"])

        status, repeated = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(report(), added_at="2024-02-03T00:00:00Z"),
            "r1-bad",
        )
        self.assertEqual(201, status)
        self.assertEqual(first, repeated)

        status, body = self.request(
            "GET", "/taxii2/collections/r1/objects/?type=report"
        )
        self.assertEqual(200, status)
        self.assertEqual([REPORT_ID], [item["id"] for item in body["objects"]])
        self.assertEqual(["report"], body["type"])

        status, body = self.request(
            "GET",
            f"/taxii2/collections/r1/objects/{REPORT_ID}/versions/",
        )
        self.assertEqual(200, status)
        self.assertEqual(["2024-01-01T00:00:00.000000Z"], body["versions"])

        # A revision drops one reference and must still validate against current set.
        status, body = self.request(
            "POST",
            "/taxii2/collections/r1/objects/",
            dict(
                report(
                    modified="2024-04-01T00:00:00Z", object_refs=[INDICATOR_ID]
                ),
                added_at="2024-04-02T00:00:00Z",
            ),
            "r1-v2",
        )
        self.assertEqual(201, status)
        self.assertEqual([INDICATOR_ID], body["object"]["object_refs"])

        status, body = self.request(
            "GET", "/taxii2/collections/r1/objects/?added_after=2024-04-01T00:00:00Z"
        )
        self.assertEqual(200, status)
        self.assertEqual([REPORT_ID], [item["id"] for item in body["objects"]])

    def test_report_validation_errors_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "r2", "title": "Reports 2"}, "rr0")
        self.request(
            "POST",
            "/taxii2/collections/r2/objects/",
            dict(identity(), added_at="2024-02-01T00:00:00Z"),
            "rr-ide",
        )
        cases = (
            dict(object_refs=[]),
            dict(object_refs=[IDENTITY_ID, IDENTITY_ID]),
            dict(object_refs=["report--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"]),
            dict(object_refs=["campaign--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"]),
            dict(object_refs=["identity--nope"]),
            dict(published="March 1st"),
            dict(report_types=[]),
            dict(extra=1),
        )
        for index, overrides in enumerate(cases):
            status, body = self.request(
                "POST",
                "/taxii2/collections/r2/objects/",
                dict(report(report_id="report--d000000%d-0000-4000-8000-00000000000%d" % (index, index)), **overrides),
                f"rr-bad-{index}",
            )
            self.assertEqual(400, status, overrides)
            self.assertEqual("validation_error", body["error"]["code"], overrides)

    def test_report_pagination_echoes_type_and_freezes_snapshot(self):
        self.request("POST", "/taxii2/collections", {"id": "r3", "title": "Reports 3"}, "rp0")
        self.request(
            "POST",
            "/taxii2/collections/r3/objects/",
            dict(identity(), added_at="2024-02-01T00:00:00Z"),
            "rp-ide",
        )
        self.request(
            "POST",
            "/taxii2/collections/r3/objects/",
            dict(indicator(), added_at="2024-02-02T00:00:00Z"),
            "rp-ind",
        )
        reports = (
            ("report--e1000001-0000-4000-8000-000000000001", "2024-03-01T00:00:00Z"),
            ("report--e1000002-0000-4000-8000-000000000002", "2024-03-02T00:00:00Z"),
        )
        for index, (report_id, added) in enumerate(reports, start=1):
            status, _ = self.request(
                "POST",
                "/taxii2/collections/r3/objects/",
                dict(
                    report(report_id=report_id, modified=added),
                    added_at=added,
                ),
                f"rp-{index}",
            )
            self.assertEqual(201, status)

        status, first = self.request(
            "GET", "/taxii2/collections/r3/objects/?type=report&limit=1"
        )
        self.assertEqual(200, status)
        self.assertEqual(["report"], first["type"])
        self.assertEqual(1, len(first["objects"]))
        self.assertTrue(first["more"])

        # A late revision stays out of the open snapshot.
        self.request(
            "POST",
            "/taxii2/collections/r3/objects/",
            dict(
                report(report_id=reports[0][0], modified="2024-05-01T00:00:00Z"),
                added_at="2024-05-02T00:00:00Z",
            ),
            "rp-late",
        )
        status, second = self.request(
            "GET", f"/taxii2/collections/r3/objects/?next={first['next']}"
        )
        self.assertEqual(200, status)
        self.assertEqual(["report"], second["type"])
        self.assertEqual([reports[1][0]], [item["id"] for item in second["objects"]])
        self.assertFalse(second["more"])


    # ------------------------------------------------------------------ notes

    def test_note_flow_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "n1", "title": "Notes"}, "n0")

        # A note before its reference exists is a validation error.
        status, body = self.request(
            "POST",
            "/taxii2/collections/n1/objects/",
            dict(note(), added_at="2024-02-03T00:00:00Z"),
            "n1-bad",
        )
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])
        self.assertIn("references unknown", body["error"]["message"])

        status, _ = self.request(
            "POST",
            "/taxii2/collections/n1/objects/",
            dict(indicator(), added_at="2024-02-01T00:00:00Z"),
            "n1-ind",
        )
        self.assertEqual(201, status)

        # The rejected key now succeeds.
        status, first = self.request(
            "POST",
            "/taxii2/collections/n1/objects/",
            dict(
                note(
                    abstract="Heads up",
                    authors=["alice"],
                    object_refs=[INDICATOR_ID],
                ),
                added_at="2024-02-03T00:00:00Z",
            ),
            "n1-bad",
        )
        self.assertEqual(201, status)
        self.assertEqual(NOTE_ID, first["object"]["id"])
        self.assertEqual("Analyst comment", first["object"]["content"])
        self.assertEqual("Heads up", first["object"]["abstract"])
        self.assertEqual(["alice"], first["object"]["authors"])
        self.assertEqual([INDICATOR_ID], first["object"]["object_refs"])
        self.assertEqual("2024-02-03T00:00:00.000000Z", first["added_at"])

        # Idempotent replay returns the first response.
        status, repeated = self.request(
            "POST",
            "/taxii2/collections/n1/objects/",
            dict(
                note(
                    abstract="Heads up",
                    authors=["alice"],
                    object_refs=[INDICATOR_ID],
                ),
                added_at="2024-02-03T00:00:00Z",
            ),
            "n1-bad",
        )
        self.assertEqual(201, status)
        self.assertEqual(first, repeated)

        status, body = self.request(
            "GET", "/taxii2/collections/n1/objects/?type=note"
        )
        self.assertEqual(200, status)
        self.assertEqual([NOTE_ID], [item["id"] for item in body["objects"]])
        self.assertEqual(["note"], body["type"])

        status, body = self.request(
            "GET", f"/taxii2/collections/n1/objects/{NOTE_ID}/versions/"
        )
        self.assertEqual(200, status)
        self.assertEqual(["2024-01-01T00:00:00.000000Z"], body["versions"])

        # A revision changes the content and drops the abstract; refs re-checked.
        status, body = self.request(
            "POST",
            "/taxii2/collections/n1/objects/",
            dict(
                note(
                    modified="2024-04-01T00:00:00Z",
                    authors=["alice"],
                    object_refs=[INDICATOR_ID],
                ),
                added_at="2024-04-02T00:00:00Z",
            ),
            "n1-v2",
        )
        self.assertEqual(201, status)
        self.assertEqual("Analyst comment", body["object"]["content"])
        self.assertNotIn("abstract", body["object"])

        status, body = self.request(
            "GET", "/taxii2/collections/n1/objects/?added_after=2024-04-01T00:00:00Z"
        )
        self.assertEqual(200, status)
        self.assertEqual([NOTE_ID], [item["id"] for item in body["objects"]])

    def test_note_validation_errors_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "n2", "title": "Notes 2"}, "nn0")
        self.request(
            "POST",
            "/taxii2/collections/n2/objects/",
            dict(indicator(), added_at="2024-02-01T00:00:00Z"),
            "nn-ind",
        )
        cases = (
            dict(content=""),
            dict(object_refs=[]),
            dict(object_refs=[INDICATOR_ID, INDICATOR_ID]),
            dict(object_refs=[NOTE_ID]),
            dict(object_refs=["campaign--a1a1a1a1-1a1a-4a1a-8a1a-1a1a1a1a1a1a"]),
            dict(object_refs=["note--nope"]),
            dict(authors=[]),
            dict(authors=[""]),
            dict(authors="alice"),
            dict(abstract=""),
            dict(extra=1),
        )
        for index, overrides in enumerate(cases):
            status, body = self.request(
                "POST",
                "/taxii2/collections/n2/objects/",
                dict(
                    note(note_id="note--d100000%d-0000-4000-8000-00000000000%d" % (index, index)),
                    **overrides,
                ),
                f"nn-bad-{index}",
            )
            self.assertEqual(400, status, overrides)
            self.assertEqual("validation_error", body["error"]["code"], overrides)

    def test_note_revocation_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "n3", "title": "Notes 3"}, "nr0")
        self.request(
            "POST",
            "/taxii2/collections/n3/objects/",
            dict(indicator(), added_at="2024-02-01T00:00:00Z"),
            "nr-ind",
        )
        self.request(
            "POST",
            "/taxii2/collections/n3/objects/",
            dict(note(), added_at="2024-02-03T00:00:00Z"),
            "nr1",
        )
        good = dict(
            note(modified="2024-03-01T00:00:00Z"),
            revoked=True,
            added_at="2024-03-02T00:00:00Z",
        )
        status, body = self.request("POST", "/taxii2/collections/n3/objects/", good, "nr2")
        self.assertEqual(201, status)
        self.assertIs(body["object"]["revoked"], True)

        follow_up = dict(
            note(modified="2024-04-01T00:00:00Z"),
            added_at="2024-04-02T00:00:00Z",
        )
        status, body = self.request(
            "POST", "/taxii2/collections/n3/objects/", follow_up, "nr3"
        )
        self.assertEqual(409, status)
        self.assertEqual("conflict", body["error"]["code"])

    def test_report_can_reference_a_note_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "n4", "title": "Notes 4"}, "nq0")
        self.request(
            "POST",
            "/taxii2/collections/n4/objects/",
            dict(indicator(), added_at="2024-02-01T00:00:00Z"),
            "nq-ind",
        )
        self.request(
            "POST",
            "/taxii2/collections/n4/objects/",
            dict(
                note(modified="2024-03-01T00:00:00Z"),
                added_at="2024-03-02T00:00:00Z",
            ),
            "nq-note",
        )
        status, body = self.request(
            "POST",
            "/taxii2/collections/n4/objects/",
            dict(
                report(
                    modified="2024-04-01T00:00:00Z",
                    object_refs=[INDICATOR_ID, NOTE_ID],
                ),
                added_at="2024-04-02T00:00:00Z",
            ),
            "nq-report",
        )
        self.assertEqual(201, status)
        self.assertEqual([INDICATOR_ID, NOTE_ID], body["object"]["object_refs"])

    # -------------------------------------------------------------- revocation

    def test_revocation_lifecycle_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "rv", "title": "Revocations"}, "rv0")
        base = dict(identity(), added_at="2024-01-02T00:00:00Z")
        status, first = self.request("POST", "/taxii2/collections/rv/objects/", base, "rv1")
        self.assertEqual(201, status)
        self.assertNotIn("revoked", first["object"])

        # A revocation that also changes another property is a 400 and writes nothing.
        bad = dict(
            identity(modified="2024-02-01T00:00:00Z", name="Changed"),
            revoked=True,
            added_at="2024-02-02T00:00:00Z",
        )
        status, body = self.request("POST", "/taxii2/collections/rv/objects/", bad, "rv-bad")
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"]["code"])
        self.assertIn("name", body["error"]["message"])

        # The rejected key is reusable for the conforming revocation.
        good = dict(
            identity(modified="2024-02-01T00:00:00Z"),
            revoked=True,
            added_at="2024-02-02T00:00:00Z",
        )
        status, body = self.request("POST", "/taxii2/collections/rv/objects/", good, "rv-bad")
        self.assertEqual(201, status)
        self.assertIs(body["object"]["revoked"], True)
        self.assertEqual("2024-02-01T00:00:00.000000Z", body["version"])

        # The revoked object stays visible and is not hidden from listings.
        status, body = self.request("GET", "/taxii2/collections/rv/objects/")
        self.assertEqual(200, status)
        self.assertEqual([IDENTITY_ID], [item["id"] for item in body["objects"]])
        self.assertIs(body["objects"][0]["revoked"], True)

        status, body = self.request(
            "GET", f"/taxii2/collections/rv/objects/{IDENTITY_ID}/versions/"
        )
        self.assertEqual(200, status)
        self.assertEqual(
            ["2024-01-01T00:00:00.000000Z", "2024-02-01T00:00:00.000000Z"],
            body["versions"],
        )
        self.assertEqual(["2024-02-01T00:00:00.000000Z"], body["latest"])

        # Any later write is a 409 conflict, including one that un-revokes.
        for index, payload in enumerate(
            (
                dict(identity(modified="2024-03-01T00:00:00Z")),
                dict(identity(modified="2024-03-01T00:00:00Z"), revoked=False),
                dict(identity(modified="2024-03-01T00:00:00Z"), revoked=True, name="X"),
            )
        ):
            payload["added_at"] = "2024-03-02T00:00:00Z"
            status, error_body = self.request(
                "POST", "/taxii2/collections/rv/objects/", payload, f"rv-after-{index}"
            )
            self.assertEqual(409, status)
            self.assertEqual("conflict", error_body["error"]["code"])

        # Replaying the original successful key still returns the first response.
        status, replayed = self.request("POST", "/taxii2/collections/rv/objects/", base, "rv1")
        self.assertEqual(201, status)
        self.assertEqual(first, replayed)

    def test_a_first_version_may_be_born_revoked_over_http(self):
        self.request("POST", "/taxii2/collections", {"id": "rv2", "title": "Imported"}, "rv20")
        payload = dict(identity(), revoked=True, added_at="2024-01-02T00:00:00Z")
        status, body = self.request("POST", "/taxii2/collections/rv2/objects/", payload, "rv21")
        self.assertEqual(201, status)
        self.assertIs(body["object"]["revoked"], True)
        follow_up = dict(identity(modified="2024-02-01T00:00:00Z"), added_at="2024-02-02T00:00:00Z")
        status, body = self.request(
            "POST", "/taxii2/collections/rv2/objects/", follow_up, "rv22"
        )
        self.assertEqual(409, status)
        self.assertEqual("conflict", body["error"]["code"])


if __name__ == "__main__":
    unittest.main()
