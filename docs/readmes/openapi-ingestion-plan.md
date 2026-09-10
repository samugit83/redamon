# OpenAPI Ingestion Implementation Plan

> For agentic workers: use superpowers:subagent-driven-development for independent
> tasks and review the combined change before completion.

**Goal:** Import every supported, in-scope OpenAPI operation from discovered or configured documents.

**Architecture:** Bounded fetch/discovery, version-aware parsing and scope resolution
feed a dedicated graph writer. Full and partial recon share this implementation.

**Tech Stack:** Python 3.11, requests, PyYAML, Neo4j, Prisma, React/TypeScript.

**Spec:** docs/readmes/openapi-ingestion-design.md

## Global constraints

- Swagger 2.0 and OpenAPI 3.0/3.1 only; explicit diagnostics for other versions.
- No live-operation requests during ingestion; no target-scope expansion.
- Tenant keys on all entity MERGEs; preserve existing tool data.
- Docker-only Python tests, per-file isolation; no real target fixtures.
- Preserve the unrelated staged deletion already present in the checkout.

## Task 1: Fetch, parse and resolve (root)

Files: recon/helpers/openapi/{fetch,parser}.py, graph_db/mixins/recon/openapi_scope.py,
recon/main_recon_modules/openapi_recon.py, recon/tests/test_openapi_recon.py.
Consumes settings and recon_data; produces the payload defined in the spec.

- [x] Add tests for a spec on docs.example.com declaring api.example.com/v2:
  `assert operation['baseurl'] == 'https://api.example.com'` and
  `assert operation['path'] == '/v2/users/{id}'`.
- [x] Run the test file in redamon-recon and confirm missing implementation.
- [x] Implement scope predicate, origin-bound document fetcher and bounded
  reference resolver, then Swagger UI/common-path source discovery.
- [x] Add mixed methods, Swagger 2, server overrides, recursive schemas,
  redirected credentials, protected-document and excluded-host cases.
- [x] Run the complete new test file in redamon-recon.

## Task 2: Configuration and workflow (frontend implementer)

Files: webapp/prisma/schema.prisma, ProjectForm sections/types/defaults/workflow,
webapp API project validators, preset schema/catalog, recon/project_settings.py,
recon_orchestrator tool allowlists where present.
Produces the exact settings names in the spec; partial tool identifier OpenAPI.

- [x] Add settings persistence and validation tests rejecting malformed sources.
- [x] Run relevant tests in the webapp Docker image.
- [x] Add defaults, fetch mapping, source/header controls and workflow wiring,
  following an existing BaseURL-consuming tool.
- [x] Ensure secrets are not embedded in generated presets or diagnostics.
- [x] Run Docker webapp type-check, lint and affected Vitest files.

## Task 3: Graph storage (graph implementer)

Files: graph_db/mixins/recon/openapi_mixin.py, recon_mixin.py,
tests/test_openapi_graph.py, docs/readmes/GRAPH.SCHEMA.md,
agentic/prompts/base.py and endpoint graph presentation as necessary.
Consumes openapi payload and scope contract; produces update_graph_from_openapi.

- [x] Add mock-session tests asserting all MERGE keys include tenant identity,
  only scoped hosts are imported and GET/POST declarations remain separate.
- [x] Run tests in redamon-agent before implementing.
- [x] Implement additive declaration storage and coherent target associations.
- [x] Document all graph properties and synchronize agent schema guidance.
- [x] Verify idempotence and preservation of other-source provenance.

## Task 4: Full/partial integration and acceptance (root)

Files: recon/main.py, partial_recon.py, partial_recon_modules/openapi_recon.py,
recon tests and user-facing README.

- [x] Add shared entry integration tests with mocked runner and graph writer.
- [x] Wire full runs after resource_enum, outside no-live-target skip branches;
  wire partial OpenAPI using graph-sourced BaseURLs and current project settings.
- [x] Run focused tests then ./redamon.sh test unit via Docker-capable bash.
- [ ] Apply Prisma additive schema when the stopped stack is started.
- [x] Run webapp checks and rebuild affected
  containers using repository build controls where the environment permits.
- [x] Review the combined diff for scope/credential leaks and unmet contracts.

## Execution record

Ruling: proceed from the approved conversational design without repeating design
approval; the user explicitly instructed execution. Work on feature/openapi-ingestion.
Docker access required sandbox escalation; Docker images are available.

Tasks 1-4 implemented and reviewed. Final focused Docker validation:
- Parser/discovery/scope: 43 passed.
- Full/partial pipeline: 3 passed; settings: 3 passed.
- Graph: 16 passed plus 18 subtests; real Neo4j integration: 1 passed.
- Real HTTP streaming/deadline integration: 1 passed.
- Graph composition/updated_at: 15 passed, 2 existing skips.
- Affected webapp files: 244 passed; phase map: 109 passed; workflow: 46 passed.
- Prisma validation and production webapp build passed.
- Webapp and agent images rebuilt successfully through compose_build.

The full repository gate was run but is not green. Remaining failures include
an existing agent prompt-size ceiling, unchanged supply-chain cache resync test,
missing AI lab compose fixture, existing Windows-sensitive shell/frontend tests,
and unrelated frontend test type errors. The eager-import RoE regression and new
graph updated_at failures found during implementation were fixed and verified;
frontend mappings collected mid-implementation also pass in the final focused run.
The existing Next 16 lint command fails because next lint is no longer accepted.

The application stack was stopped. No application services were started and no
Prisma db push was applied to its database. The existing webapp startup entrypoint
synchronizes the Prisma schema. Implementation is uncommitted on
feature/openapi-ingestion; the unrelated staged deletion remains untouched.