"""The uniqueness key of every node label: the SINGLE declaration.

This is what a label IS - its identity, the tuple a MERGE dedupes on. It used
to be 45 hand-written CREATE CONSTRAINT strings in schema.py AND a label list
implied by the prompt prose, so adding a node type meant editing both and
forgetting either failed silently.

Now schema.py GENERATES its constraints from here (schema.build_constraints),
and schema_catalog re-exports it so the renderer and the completeness tests
read the same declaration rather than a second copy of it.

The constraint NAME is part of the declaration, not cosmetic: a same-name
`CREATE ... IF NOT EXISTS` against a database that still holds the old
constraint is a silent no-op, so renaming a key requires a new name plus a
DROP in DROP_LEGACY_CONSTRAINTS.

Every tenant-scoped key ends in user_id + project_id. That is the tenant
isolation boundary, not a convention: dropping them from a key would let two
projects collide on one node.
"""

KEY_CONSTRAINTS = [
    {
        "label": "Domain",
        "constraint": "domain_unique",
        "var": "d",
        "key_properties": [
            "name",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Subdomain",
        "constraint": "subdomain_unique",
        "var": "s",
        "key_properties": [
            "name",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "IP",
        "constraint": "ip_unique",
        "var": "i",
        "key_properties": [
            "address",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "BaseURL",
        "constraint": "baseurl_unique",
        "var": "u",
        "key_properties": [
            "url",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Port",
        "constraint": "port_unique",
        "var": "p",
        "key_properties": [
            "number",
            "protocol",
            "ip_address",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Service",
        "constraint": "service_unique",
        "var": "svc",
        "key_properties": [
            "name",
            "port_number",
            "ip_address",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Technology",
        "constraint": "technology_unique",
        "var": "t",
        "key_properties": [
            "name",
            "version",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Endpoint",
        "constraint": "endpoint_unique",
        "var": "e",
        "key_properties": [
            "path",
            "method",
            "baseurl",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Parameter",
        "constraint": "parameter_unique",
        "var": "p",
        "key_properties": [
            "name",
            "position",
            "endpoint_path",
            "baseurl",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Header",
        "constraint": "header_unique",
        "var": "h",
        "key_properties": [
            "name",
            "value",
            "baseurl",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "DNSRecord",
        "constraint": "dnsrecord_unique",
        "var": "dns",
        "key_properties": [
            "type",
            "value",
            "subdomain",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Certificate",
        "constraint": "certificate_key_unique",
        "var": "c",
        "key_properties": [
            "cert_key",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Traceroute",
        "constraint": "traceroute_unique",
        "var": "tr",
        "key_properties": [
            "target_ip",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "CVE",
        "constraint": "cve_unique",
        "var": "c",
        "key_properties": [
            "id"
        ]
    },
    {
        "label": "MitreData",
        "constraint": "mitredata_unique",
        "var": "m",
        "key_properties": [
            "id"
        ]
    },
    {
        "label": "Capec",
        "constraint": "capec_unique",
        "var": "cap",
        "key_properties": [
            "capec_id"
        ]
    },
    {
        "label": "Vulnerability",
        "constraint": "vulnerability_tenant_unique",
        "var": "v",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ExploitGvm",
        "constraint": "exploitgvm_tenant_unique",
        "var": "e",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "GithubHunt",
        "constraint": "githubhunt_tenant_unique",
        "var": "gh",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "GithubRepository",
        "constraint": "githubrepo_tenant_unique",
        "var": "gr",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "GithubPath",
        "constraint": "githubpath_tenant_unique",
        "var": "gp",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Package",
        "constraint": "package_unique",
        "var": "p",
        "key_properties": [
            "purl",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "SbomDocument",
        "constraint": "sbomdoc_tenant_unique",
        "var": "d",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MalPackageFinding",
        "constraint": "malpackagefinding_unique",
        "var": "mf",
        "key_properties": [
            "finding_id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "GithubSecret",
        "constraint": "githubsecret_tenant_unique",
        "var": "gs",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "GithubSensitiveFile",
        "constraint": "githubsensitivefile_tenant_unique",
        "var": "gsf",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerScan",
        "constraint": "multiscannerscan_unique",
        "var": "ts",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerRepository",
        "constraint": "multiscannerrepository_unique",
        "var": "tr",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerFinding",
        "constraint": "multiscannerfinding_unique",
        "var": "tf",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerImage",
        "constraint": "multiscannerimage_unique",
        "var": "ti",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerModel",
        "constraint": "multiscannermodel_unique",
        "var": "tm",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerBucket",
        "constraint": "multiscannerbucket_unique",
        "var": "tb",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "MultiscannerEndpoint",
        "constraint": "multiscannerendpoint_unique",
        "var": "te",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "JsReconFinding",
        "constraint": "jsreconfinding_tenant_unique",
        "var": "jf",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Secret",
        "constraint": "secret_tenant_unique",
        "var": "s",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ExternalDomain",
        "constraint": "externaldomain_unique",
        "var": "ed",
        "key_properties": [
            "domain",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ThreatPulse",
        "constraint": "threatpulse_unique",
        "var": "tp",
        "key_properties": [
            "pulse_id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "Malware",
        "constraint": "malware_unique",
        "var": "m",
        "key_properties": [
            "hash",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "AttackChain",
        "constraint": "attack_chain_id",
        "var": "ac",
        "key_properties": [
            "chain_id"
        ]
    },
    {
        "label": "ChainStep",
        "constraint": "chain_step_id",
        "var": "s",
        "key_properties": [
            "step_id"
        ]
    },
    {
        "label": "ChainFinding",
        "constraint": "chain_finding_id",
        "var": "f",
        "key_properties": [
            "finding_id"
        ]
    },
    {
        "label": "ChainDecision",
        "constraint": "chain_decision_id",
        "var": "d",
        "key_properties": [
            "decision_id"
        ]
    },
    {
        "label": "ChainFailure",
        "constraint": "chain_failure_id",
        "var": "fl",
        "key_properties": [
            "failure_id"
        ]
    },
    {
        "label": "KBChunk",
        "constraint": "kb_chunk_id",
        "var": "c",
        "key_properties": [
            "chunk_id"
        ]
    },
    {
        "label": "UserInput",
        "constraint": "userinput_tenant_unique",
        "var": "ui",
        "key_properties": [
            "id",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ADUser",
        "constraint": "aduser_tenant_unique",
        "var": "adu",
        "key_properties": [
            "object_identifier",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ADGroup",
        "constraint": "adgroup_tenant_unique",
        "var": "adg",
        "key_properties": [
            "object_identifier",
            "user_id",
            "project_id"
        ]
    },
    {
        "label": "ADComputer",
        "constraint": "adcomputer_tenant_unique",
        "var": "adc",
        "key_properties": [
            "object_identifier",
            "user_id",
            "project_id"
        ]
    }
]


LABELS_WITH_KEYS = {k["label"] for k in KEY_CONSTRAINTS}
