# StixRelay

StixRelay is a small STIX 2.1 object library with a TAXII 2.1 collection subset on
top of it. It stores threat-intelligence objects in SQLite, validates them against
the subset of STIX described below, keeps every revision of an object, and serves
current state and `added_after` deltas over a TAXII-shaped HTTP API.

The initial release intentionally supports a compact public contract:

- six object types: `identity`, `indicator`, `malware`, `relationship`, `report`,
  and `note`;
- every object is validated against a fixed property allowlist plus a required set
  that depends on its type, and its `id` must match its `type`;
- a `relationship` can only be stored once both endpoints already exist in the
  same collection;
- a `report` can only be stored when every entry of `object_refs` already exists
  as the current version of an `identity`, `indicator`, `malware`,
  `relationship`, or `note` object in the same collection;
- a `note` can only be stored when every entry of `object_refs` already exists
  as the current version of any supported object — including another `note`,
  but never the note itself — in the same collection;
- revisions are append only: a newer `modified` timestamp adds a version, the
  `modified` timestamp is the TAXII version identifier, and versions never regress;
- deltas use `added_after` as a **strictly half-open** interval over the time the
  server received a version;
- duplicate commands with the same idempotency key return the original result.

## Requirements

- Python 3.11 or newer
- no third-party runtime dependencies

## Run the service

```bash
PYTHONPATH=src python -m stixrelay.server --host 127.0.0.1 --port 8080 --database stixrelay.db
```

The process prints `StixRelay listening on http://127.0.0.1:8080` after it has
bound the port.

## Data model

### Collections

A collection contains exactly `id`, `title`, `description`, `can_read`, and
`can_write`; the stored document adds the fixed `media_type` of this release.
`description` defaults to `""`, and `can_read`/`can_write` default to `true`.
The flags are enforced on the server: a collection with `can_read: false` is
invisible — it is absent from the collection list, and every direct read or
write against it (collection, objects, versions) fails with the same
`not_found` as a collection that does not exist, so its existence is never
revealed. A readable collection with `can_write: false` rejects object POSTs
with `forbidden`. Access is checked before validation, idempotency, versioning,
and cursor handling, so a denied request stores nothing and does not consume
its idempotency key.

```json
{
  "id": "feed",
  "title": "Primary feed",
  "description": "",
  "can_read": true,
  "can_write": true,
  "media_type": "application/stix+json;version=2.1"
}
```

### Objects

Every object carries these common properties: `type`, `spec_version`, `id`,
`created`, `modified`, `created_by_ref`, `revoked`, `labels`, `confidence`,
`lang`, `external_references`. Type specific properties and requirements:

| type | required | optional |
| --- | --- | --- |
| `identity` | `name` | `description`, `identity_class`, `sectors`, `contact_information`, `roles` |
| `indicator` | `name`, `pattern`, `valid_from` | `description`, `pattern_type`, `pattern_version`, `valid_until`, `indicator_types`, `kill_chain_phases` |
| `malware` | `name`, `is_family` | `description`, `malware_types`, `aliases`, `first_seen`, `last_seen`, `kill_chain_phases` |
| `relationship` | `relationship_type`, `source_ref`, `target_ref` | `description`, `start_time`, `stop_time` |
| `report` | `name`, `published`, `object_refs` | `description`, `report_types` |
| `note` | `content`, `object_refs` | `abstract`, `authors` |

Property rules:

- `id` must be `<type>--<uuid>` where `<uuid>` is a lowercase RFC 4122 version 4
  UUID, and `<type>` must equal the object's `type`;
- `spec_version`, when present, must be `2.1`;
- `created` and `modified` are required UTC timestamps of the form
  `2024-01-02T03:04:05.000000Z` (a missing fractional part expands to six digits),
  and `modified` must not be earlier than `created`;
- `labels`, `sectors`, `indicator_types`, `malware_types`, `aliases`, and `roles`
  are non-empty arrays of non-empty strings; `confidence` is an integer between 0
  and 100; `external_references` is a non-empty array of objects containing
  `source_name` and optionally `description`, `url`, `external_id`;
  `kill_chain_phases` is a non-empty array of objects containing exactly
  `kill_chain_name` and `phase_name`;
- `pattern_type` must be `stix` (the default). `pattern` must be a
  single-comparison STIX pattern such as `[file:hashes.'SHA-256' = 'aa']`: an
  object path, a colon, a property path (quoted segments are allowed), one of
  `=`, `!=`, `<`, `>`, `<=`, `>=`, and a quoted string, number, or boolean value;
- `relationship_type` is a snake_case name such as `indicates` or `targets-x_1`;
- a `relationship` fixes the endpoint types of this release: `source_ref` must
  reference an `indicator` and `target_ref` must reference an `identity`. Both
  endpoints must already exist in the same collection, which is what makes the
  reference integrity check meaningful. If both `start_time` and `stop_time` are
  given, `start_time` must not be later;
- a `report` requires `published` (a UTC timestamp in the same format as
  `created`/`modified`) and `object_refs`: a non-empty array of STIX identifiers
  whose type prefix is `identity`, `indicator`, `malware`, `relationship`, or
  `note`. Entries must be well formed, must not repeat, and must not point at the
  report itself (a `report--` identifier is rejected). The optional `report_types`
  is a non-empty array of non-empty strings. At write time every entry must
  resolve to the current version of an object in the **same** collection; an
  unknown, cross-collection, duplicated, or self reference — together with an
  empty array — is a `validation_error` and the whole submission is rejected. A
  later report version may add or remove entries freely; each submission is
  checked against the objects current in the collection at that moment;
- a `note` requires `content` (a non-empty string) and `object_refs`: a non-empty
  array of STIX identifiers whose type prefix is any supported type, `note`
  included. The optional `abstract` is a non-empty string when present, and
  `authors` is a non-empty array of non-empty strings. Entries of `object_refs`
  must be well formed, must not repeat, and must not point at the note itself.
  Existence is checked exactly like a `report`: every entry must resolve to the
  current version of an object in the same collection at write time — a revoked
  target still counts as existing — and any unknown, cross-collection,
  duplicated, or self reference rejects the whole submission with a
  `validation_error` that stores no version and consumes no idempotency key.

Any property outside the allowlist for the object's type is rejected.

### Versions

The `modified` timestamp **is** the TAXII version identifier of a revision.

- posting an object whose `modified` is greater than the stored version appends a
  new revision; older revisions stay readable and are never modified;
- posting the same `modified` again is a `conflict`, even when the body differs;
- posting a `modified` earlier than the stored version is a `conflict`, so the
  version sequence of an object only grows;
- `GET /objects/` and delta listings report the newest revision of each object;
  `GET /objects/{objectId}/versions/` reports every revision.

### Revocation

`revoked` is the object lifecycle flag, not an ordinary editable property.

- the first version may omit `revoked`, set it explicitly to `false`, or set it to
  `true` when importing intelligence that is already revoked. An omitted flag is
  treated as `false` by lifecycle checks and is not added to the response;
- while the current version is not revoked, a normal new version follows the usual
  validation and monotonicity rules and may change any property;
- posting a later `modified` with `revoked` changing from `false` (or omitted) to
  `true` creates a **revocation version**. After normalisation every property and
  value except `modified` and `revoked` must be identical to the current version;
  otherwise the response is `400 validation_error` and no version is written;
- a successful revocation returns the usual `201` write response with
  `object.revoked` set to `true` and `version` equal to the normalised `modified`;
- a revocation version becomes the current version: it is never hidden, it appears
  in unpaginated and paginated object listings, enters strictly half-open
  `added_after` deltas at its own `added_at`, and is listed in `versions`,
  `latest`, and `added_at`. Historical versions stay untouched;
- a pagination snapshot keeps the revocation state it started with: a revocation
  received after the first paged request never enters that round's later pages;
- revocation never cascades: relationships, reports, and notes keep working, and
  a revoked object still counts as an existing object of the collection in the
  relationship, report, and note reference integrity checks;
- once the current version is revoked, **any** later write to that id in the
  collection is a `409 conflict` — a later `modified`, flipping `revoked` back to
  `false`, omitting `revoked`, or changing other properties alike. Writes with the
  same or an earlier `modified` keep their existing `conflict` semantics.

A rejected revocation or a write rejected after revocation adds no version and
does not consume its idempotency key. Replaying a key whose first write succeeded
still returns that first response, even when the object has since been revoked.

### `added_at`

`added_at` is when the server received a version, with microsecond precision. It is
independent of the STIX `modified` timestamp, which describes when the producer
changed the object. A POST body may set it explicitly to make delta behaviour
reproducible in tests; when it is absent the server uses its own clock.

## HTTP API

All bodies are JSON and must be sent with `Content-Type: application/json`.
Unknown fields, unsupported query parameters, and unknown routes are rejected.
TAXII object paths are accepted with or without their trailing slash.

State-changing POST requests require an `Idempotency-Key` header. Replaying a key
returns the first result and the status of the first request; reusing a key for a
different operation is a `conflict`.

### Health

```http
GET /health
```

Returns `{"status":"ok","product":"stixrelay"}`.

### Collections

```http
POST /taxii2/collections
Idempotency-Key: collection-1

{"id":"feed","title":"Primary feed"}
```

Returns HTTP 201 with the stored collection; creating an existing id is a
`conflict`.

```http
GET /taxii2/collections
GET /taxii2/collections/feed
```

The first returns `{"collections":[...]}` sorted by `id`, limited to collections
with `can_read: true`; the second returns one collection. An unknown or
unreadable collection is `not_found` with the message
`collection access is denied`.

### Add an object

```http
POST /taxii2/collections/feed/objects/
Idempotency-Key: indicator-1

{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a2f4b7d8-2c7e-4a4b-9d0e-6f6a1c9d3f21",
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "name": "Bad hash",
  "pattern": "[file:hashes.'SHA-256' = 'aa']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00Z",
  "added_at": "2024-01-02T00:00:00Z"
}
```

Returns HTTP 201 with the stored object plus its storage metadata:

```json
{
  "collection_id": "feed",
  "added_at": "2024-01-02T00:00:00.000000Z",
  "version": "2024-01-01T00:00:00.000000Z",
  "spec_version": "2.1",
  "object": {"type": "indicator", "...": "the validated object"}
}
```

`object` is the canonical form of the submission: `spec_version` is filled in,
timestamps are normalised, and `pattern_type` defaults to `stix`. A mismatched
`id` prefix, a missing required property, an unknown property, a `relationship`
whose endpoints do not exist, or a `report`/`note` whose `object_refs` do not
resolve in the same collection is a `validation_error`.

### Read objects

```http
GET /taxii2/collections/feed/objects/?type=indicator,malware&added_after=2024-01-01T00:00:00Z
```

The filter query parameters are optional and may appear at most once.

- `type` is a comma separated list of supported object types; only those types are
  returned and the applied list is echoed back in `type`;
- `added_after` is a UTC timestamp and the interval is **strictly half-open**: a
  version whose `added_at` equals the cutoff is excluded, and only versions with a
  greater `added_at` are returned. Omitting it returns every object;
- when an object received a new version after the cutoff, the delta returns that
  newest version;
- results are the newest revision of each object, sorted by `added_at` and then by
  object id, so the same query always returns the same order.

```json
{"objects":[{"type":"identity","id":"identity--...","...":"..."}],"more":false,"type":["identity"]}
```

A request without `limit` (and without `next`) is the legacy, un-paginated read: it
returns every matching current revision, `more` is always `false`, and no `next` is
present.

### Cursor pagination

Add `limit` to page through a large collection instead of receiving every object at
once:

```http
GET /taxii2/collections/feed/objects/?limit=100
```

`limit` is a decimal integer between `1` and `200` and may appear at most once. The
first request takes the normal read path, so `type` and `added_after` keep their
exact existing semantics.

- each response keeps `objects` and `more`; when a `type` filter was applied, the
  applied list is echoed in `type` on every page;
- while the current ordering has more rows, `more` is `true` and the response adds
  `next`, an opaque URL-safe cursor; on the last page `more` is `false` and `next`
  is absent;
- follow-up requests send **only** `next` — repeating `type`, `added_after`, or
  `limit` together with `next` is a `validation_error`. The server remembers the
  filter and page size from the first request:

```http
GET /taxii2/collections/feed/objects/?next=v1.AbCd...
```

- objects are ordered stably by `added_at` and then object id; each object appears
  at most once, showing only the newest revision readable in the pagination round;
- the first paged request establishes a **snapshot**. Objects and revisions
  received afterwards never enter that round's pages; they only become visible when
  a new round starts from page one. Replaying the same cursor re-reads the
  remaining pages of its own snapshot rather than restarting at the first page.

`limit` that is not a decimal integer, is below `1`, above `200`, or appears more
than once is a `validation_error`. `next` that is repeated, malformed, issued by
another service, modified, bound to another collection, or combined with `type`,
`added_after`, or `limit` is also a `validation_error`.

### Read object versions

```http
GET /taxii2/collections/feed/objects/identity--f431f809-377b-45e0-aa1c-6a4751cae5ff/versions/
```

Returns every revision of one object, oldest first:

```json
{
  "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "versions": ["2024-01-01T00:00:00.000000Z", "2024-02-01T00:00:00.000000Z"],
  "earliest": ["2024-01-01T00:00:00.000000Z"],
  "latest": ["2024-02-01T00:00:00.000000Z"],
  "added_at": ["2024-01-02T00:00:00.000000Z", "2024-02-02T00:00:00.000000Z"]
}
```

An object with no revision in that collection is `not_found`.

## Errors

Errors use this shape:

```json
{"error":{"code":"validation_error","message":"human readable detail"}}
```

Validation errors (unknown fields, unknown types, bad identifiers, bad patterns,
missing relationship endpoints, unresolvable report or note `object_refs`, a revocation
version that changes anything besides `modified` and `revoked`, bad
`added_after`, bad `limit` or `next`, unsupported query parameters) return 400. Writes to a read-only collection
return 403 (`forbidden`). Missing collections and objects — and any access to a
collection with `can_read: false` — return 404. Version conflicts, duplicate
collections, writes to an already revoked object, and idempotency key reuse
return 409.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

`tests/test_service.py` covers object validation, version monotonicity, half-open
deltas, and idempotency. `tests/test_http.py` drives the real
`ThreadingHTTPServer` on an ephemeral port, including the error shapes.
