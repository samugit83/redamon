# OpenAPI endpoint inventory

OpenAPI recon reads API descriptions and imports declared operations into the
target's graph. It does not need to call the operations or obtain successful
responses from them. Imported declarations are evidence of documentation, not
confirmation that an operation is deployed or accessible.

## Configuration

Enable **OpenAPI** in project recon settings. Automatic discovery checks a
bounded set of common specification/documentation paths on in-scope HTTP origins
and documentation URLs found during resource enumeration. Literal Swagger UI
`url`, `urls` and `configUrl` references and Redoc `spec-url` attributes are
followed. Common probes include `/api-docs` and `/api-docs/`. Swagger UI initializer
scripts containing a JSON literal under `swaggerDoc` or `spec` are also parsed.
Arbitrary JavaScript is not executed; use a direct source URL for
documentation that builds its configuration dynamically.

Under **OpenAPI sources**, add one or more JSON/YAML specification URLs. Static
Swagger UI/configuration URLs also work. Each entry has optional fetch headers,
an optional API server override and an enable switch. Sources are fetched on each
run. The UI/API assigns a stable source `id`; programmatic sources may supply one,
otherwise the URL is its identity fallback. Use distinct IDs for separate auth
contexts sharing a URL. Headers may authenticate the document download, for example
`Authorization: Bearer <token>`; these are not API-operation credentials.

Automatic discovery can use per-origin headers. Credentials stay on their exact
origin (scheme, host and port). Cross-origin redirects, documentation links and
external references are blocked; configure another source explicitly when
needed. Same-origin relative references are supported. Query values in source
URLs are omitted from graph provenance; a source hash distinguishes documents
selected by different queries.

Discovery paths are configurable per project in **OpenAPI > Discovery paths**
(`openapiDiscoveryPaths` / `OPENAPI_DISCOVERY_PATHS`). The list replaces the 12
built-in paths; Add path, Remove, and Restore defaults are available. Empty lists
disable common-path probes while preserving discovered links and configured sources.
Use origin-relative paths starting with `/`, without queries or fragments (up to
200 paths, 2048 characters each). Existing projects receive the default list when
the new database column is added.

## Target association

Scope follows the project's existing target settings:

- An empty subdomain list permits subdomains and does not include the apex.
- `.` includes the apex; by itself it still permits subdomain discovery.
- Actual prefixes select exact subdomains; add `.` to include the apex too.
- Enabled Rules of Engagement host/CIDR exclusions take precedence.
- IP mode permits configured IPs/CIDRs only.

The resolved API server controls graph placement, not the specification's host.
A specification on `docs.example.com` can declare operations on
`api.example.com`. Each imported operation connects through the appropriate
Domain/Subdomain and BaseURL. Servers outside scope are reported and skipped.
Specifications never expand project scope. Domain-batch runs use each stored,
approved group and its subdomain prefixes independently in full and partial recon.

OpenAPI 3 operation/path/root server precedence, relative servers and variable
defaults are supported. Swagger 2 uses schemes, host and basePath. The optional
server override replaces the effective server URL including its base path; it
must still be in scope. All eligible declared servers are imported.

## Parsing and coverage

Supported versions: Swagger 2.0, OpenAPI 3.0.x and 3.1.x, in JSON or YAML.
Unsupported versions generate diagnostics. Operations preserve their HTTP
method and path template, effective parameters/security and request/response
schemas as method-specific OpenAPI metadata. Recursive schemas retain reference
links. References support JSON Pointer fragments; unsupported anchors produce diagnostics.
YAML requires string mapping keys and JSON-compatible values. Callbacks/webhooks do not become ordinary inbound endpoint nodes.

Unresolved references and malformed operations are reported. A partially resolved
operation may be retained with its unresolved reference; consult diagnostics
before treating its request schema as complete. Discovery cannot guarantee that
every specification on a target is found, or that a specification is complete.

Defaults: 10-second request timeout, 50 specification documents, at most 500 HTTP
document requests. Each document is limited to 5 MiB, total downloads to 32 MiB,
and redirects to five hops. Output is capped at 10,000 operations, 1 MiB per
operation and 16 MiB of serialized operation metadata,
and reference traversal to a bounded depth/node count. Budget exhaustion is an
explicit incomplete-inventory diagnostic. Configured sources are processed before
automatic common-path probes.

The same stage runs in full recon and as **OpenAPI** partial recon. Configured
sources work even when HTTP probing found no live endpoints. Partial manual URL
inputs are discovery targets and cannot change project scope; configure direct
specification URLs under OpenAPI sources.

Partial recon is additive: matching declarations are updated; older declarations
absent from a newer document retain their previous provenance. Absence from a
specification does not establish removal of a deployed route. Full recon uses
its existing project graph reset behavior.

Full recon waits for graph persistence and records graph errors separately from
parsing, preserving the parsed inventory if the graph write fails.

## Verification

Run the Python gate through `./redamon.sh test unit` (Docker images, per-file
isolation). Focused coverage lives in `recon/tests/test_openapi_recon.py`,
`recon/tests/test_openapi_pipeline.py`, `recon/tests/test_openapi_settings.py`,
and `tests/test_openapi_graph.py`. Webapp configuration has adjacent Vitest tests.

Real HTTP streaming and Neo4j integration tests:
recon/tests/test_openapi_fetch_integration.py and tests/test_openapi_graph_integration.py.
