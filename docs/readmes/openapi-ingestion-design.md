# Target-scoped OpenAPI ingestion

Approved conversational design, 2026-09-10.

## Behavior

Recon discovers OpenAPI documents using bounded common-path probes and links in
crawl results or Swagger UI configuration. Users can configure source URLs,
optional fetch headers, and a server override. Both sources use the same parser.
Document retrieval credentials are origin-bound and never become API credentials.
Only resolved HTTP(S) operation URLs within configured target scope enter the
graph. A document never expands scope. Explicit source URLs may be hosted outside
target scope, but only their in-scope operations are imported. Redirects and
external references do not implicitly authorize additional document hosts.

Supported document versions are Swagger 2.0 and OpenAPI 3.0/3.1. JSON and YAML are
accepted. Unsupported versions, inaccessible sources and unresolved references
produce diagnostics, not an apparently successful empty inventory. Recursive
schemas remain references; fetching and expansion have explicit bounds.

Server resolution observes operation/path/root precedence, Swagger 2 host,
schemes and basePath, relative URLs and variable defaults. A configured override
replaces the effective server URL, including its base path. Multiple in-scope
servers are imported. API URL construction appends the operation path to the
server base path. The document location is provenance, not endpoint ownership.

Each operation preserves method, templated path, operationId, summary, tags,
effective parameters/security, requestBody and responses in method-specific
OpenAPI metadata. No operation is executed merely to import it. Callbacks and
webhooks are retained in source documents but are not inbound endpoint nodes.
Import records are declarations, not proof of deployed availability.

## Interfaces

Settings: OPENAPI_ENABLED=true, OPENAPI_AUTO_DISCOVER=true, OPENAPI_SOURCES=[],
OPENAPI_DISCOVERY_HEADERS=[] (entries {origin, headers}), OPENAPI_TIMEOUT=10,
OPENAPI_MAX_DOCUMENTS=50. Each source is
{id?: string, url, headers: string[], serverOverride?: string, enabled?: boolean}.
Camel-case equivalents are exposed in project configuration and Prisma.

run_openapi_recon(recon_data: dict, settings: dict) -> dict mutates/returns
recon_data with openapi = {operations: list, documents: list, diagnostics: list}.
Operations have {baseurl, path, method, source_url, source_id, document_hash,
operation_ref, operation: dict}. Document entries contain
{url, source_id, sha256, version, operation_count}. source_id hashes the configured source context and original candidate URL before
redirects. Configured contexts use source ID with source URL fallback; automatic
contexts use candidate URL. Header changes and row reordering preserve identity;
source_url omits query values to avoid exposing URL credentials.
Diagnostics contain {url, code, message}; never credential/header values.
run_openapi_recon_isolated returns only the openapi payload from a deep copy.

Graph entry update_graph_from_openapi(recon_data, user_id, project_id) consumes
this payload. It independently checks scope using the effective project scope
stored in openapi.scope, creates tenant-scoped Domain/Subdomain/BaseURL/Endpoint
associations, and stores method-specific declarations as JSON on Endpoint.
Endpoint natural identity remains baseurl/path/method/user_id/project_id.
Each declaration includes source URL, hash and operation reference; repeated
imports replace that source's declaration while preserving other tool evidence.
Domain receives a JSON summary of documents/diagnostics; raw spec bodies and
credentials are not graph fields. Raw schema material stays nested JSON rather
than flattening incompatible GET/POST parameters into the legacy shared model.

Full pipeline runs the stage after resource enumeration and before vulnerability
scanning, even if no live URL was found when configured sources exist. Partial
recon exposes OpenAPI with BaseURL inputs and invokes the same runner/writer.

## Scope contract

Scope derives from TARGET_DOMAIN, SUBDOMAIN_LIST, ROE_ENABLED,
ROE_EXCLUDED_HOSTS and IP-mode TARGET_IPS using existing configuration semantics.
SUBDOMAIN_LIST includes the apex only when it contains '.'. An empty list or
['.'] allows all subdomains; actual prefixes constrain imports to exact hosts.
An empty or invalid target fails closed. Exact subdomain selections constrain
imports; broad-domain mode allows suffix-boundary subdomains subject to excludes.
Root exclusion applies independently. Do not infer scope from document servers.

## Validation

Hermetic Docker tests cover version parsing, YAML, references/cycles, protected
documents, redirect header containment, server precedence/base paths, Swagger 2,
target suffix attacks and exclusions, operation metadata, graph tenant keys and
repeat imports, both pipeline entry paths and settings persistence. Run the
repository Docker unit gate and webapp checks, reporting missing images or
pre-existing failures separately. No real target data belongs in fixtures.

Partial imports are additive: declarations absent from newer documents retain
their previous provenance. Full recon uses its existing graph reset. Full recon
waits for graph persistence and reports graph errors separately from parsing.
