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


if __name__ == "__main__":
    unittest.main()
