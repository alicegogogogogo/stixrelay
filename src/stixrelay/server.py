from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import NotFoundError, StixRelayError, ValidationError
from .service import StixRelay


class Handler(BaseHTTPRequestHandler):
    service: StixRelay

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Any:
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ValidationError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1_000_000:
                raise ValueError
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("request body must be valid JSON") from error

    def _dispatch(self) -> tuple[int, Any]:
        split = urlsplit(self.path)
        parts = [unquote(part) for part in split.path.split("/") if part]
        query = parse_qs(split.query, keep_blank_values=True)
        extra = sorted(set(query) - {"type", "added_after", "limit", "next"})
        if extra:
            raise ValidationError(f"unsupported query parameters: {', '.join(extra)}")

        if parts == ["health"]:
            if self.command != "GET":
                raise NotFoundError("route was not found")
            return 200, {"status": "ok", "product": "stixrelay"}
        if parts == ["taxii2", "collections"]:
            if self.command == "GET":
                return 200, {"collections": self.service.list_collections()}
            if self.command == "POST":
                body = self._body()
                result = self.service.create_collection(body, self.headers.get("Idempotency-Key"))
                return result.status, result.to_json()
        if len(parts) == 3 and parts[:2] == ["taxii2", "collections"] and self.command == "GET":
            return 200, self.service.get_collection(parts[2])
        if len(parts) == 4 and parts[:2] == ["taxii2", "collections"] and parts[3] == "objects":
            collection_id = parts[2]
            if self.command == "GET":
                result = self.service.list_objects(
                    collection_id,
                    query.get("type"),
                    query.get("added_after"),
                    query.get("limit"),
                    query.get("next"),
                )
                return result.status, result.to_json()
            if self.command == "POST":
                body = self._body()
                added_at = body.get("added_at") if isinstance(body, dict) else None
                result = self.service.add_object(
                    collection_id,
                    body,
                    self.headers.get("Idempotency-Key"),
                    added_at,
                )
                return result.status, result.to_json()
        if (
            len(parts) == 6
            and parts[:2] == ["taxii2", "collections"]
            and parts[3] == "objects"
            and parts[5] == "versions"
            and self.command == "GET"
        ):
            result = self.service.object_versions(parts[2], parts[4])
            return result.status, result.to_json()
        raise NotFoundError("route was not found")

    def _handle(self) -> None:
        try:
            status, response = self._dispatch()
            self._json(status, response)
        except StixRelayError as error:
            self._json(error.status, {"error": {"code": error.code, "message": str(error)}})
        except Exception:
            self._json(500, {"error": {"code": "internal_error", "message": "internal server error"}})

    do_GET = _handle
    do_POST = _handle


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the StixRelay HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="stixrelay.db")
    arguments = parser.parse_args()
    Handler.service = StixRelay(arguments.database)
    server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)
    print(f"StixRelay listening on http://{arguments.host}:{arguments.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
