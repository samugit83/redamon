# OpenAPI endpoint inventory

OpenAPI / Swagger import is a resource-enumeration source. Its configuration,
security model, graph output, run conditions and verification are documented in
[README.RESOURCE_ENUM.md, "OpenAPI / Swagger Import"](README.RESOURCE_ENUM.md#openapi--swagger-import),
and the settings in the wiki's
[Project Settings Reference](https://github.com/samugit83/redamon/wiki/Project-Settings-Reference#openapi-import).

## Test case generation

`recon.helpers.openapi.testcases.generate_test_cases(operations, *, base_url=None,
categories=None, max_per_operation=12)` consumes the operation records returned by
`parser.parse_operations`. It generates plans only: no requests, graph writes or
project settings. Supported categories are `bola`, `bfla`, `auth_missing`,
`mass_assignment`, `input_validation` and `method_drift`, tagged with OWASP API
Top 10 2023 identifiers. Expectations describe checks for a future executor;
a generated case is not a vulnerability finding.

Request paths use `{{BASE_URL}}` unless the caller supplies `base_url`; inventory
server URLs are ignored. Credentials and cross-user identifiers remain placeholders.
`build_example(schema, components)` builds minimal structural JSON examples with
local reference/cycle protection and a maximum depth of 6; unsupported schemas
terminate as null. It is not a complete JSON Schema validator.

Cases sort by operation ID, method, path template, category and name before the
per-operation cap (default 12), then the complete list sorts by the same keys.
Use `categories` to focus a capped plan, or raise the cap for all generated
mutations. Undeclared methods are generated once per path using all its declared
methods, attached to its first sorted operation. Duplicate inventory records from
multiple servers produce one plan. Each `TestCase` exposes `to_dict()` and
`to_json()` with stable key order.
