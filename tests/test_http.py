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
from test_service import IDENTITY_ID, MALWARE_ID, identity, indicator, malware

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


if __name__ == "__main__":
    unittest.main()
