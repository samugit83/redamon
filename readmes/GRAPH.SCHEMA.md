# RedAmon Neo4j Graph Schema

## Overview

This document defines the Neo4j graph database schema for storing reconnaissance data.
The schema is designed to enable attack chain analysis by connecting all discovered assets,
services, technologies, and vulnerabilities in a navigable graph structure.

---

## 🎯 Design Principles

1. **Hierarchical Ownership**: All nodes trace back to a Domain with `user_id` and `project_id`
2. **Attack Surface Mapping**: Every potential entry point is modeled (ports, URLs, parameters)
3. **Technology-Vulnerability Linkage**: Technologies connect to known CVEs for risk assessment
4. **No Redundancy**: Information stored once, relationships handle connections
5. **Query Efficiency**: Optimized for path traversal (attack chains)
6. **Multi-Tenant Isolation**: Every node has `user_id` + `project_id` for tenant filtering

---

## 🏗️ Multi-Tenant AWS Scalability Strategy

This schema uses **Logical Partitioning with Composite Indexes** for multi-tenant isolation.
Every node type includes `user_id` and `project_id` properties with composite indexes.

### Why This Approach?

```
┌─────────────────────────────────────────────────────────────────┐
│                    Single Neo4j Database                        │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  User A     │  │  User B     │  │  User C     │  ...        │
│  │  Project 1  │  │  Project 1  │  │  Project 1  │             │
│  │  Project 2  │  │  Project 2  │  │  Project 2  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
│  Composite Constraints: (fields, user_id, project_id) IS UNIQUE │
│  Query Pattern: Always filter by tenant FIRST                   │
└─────────────────────────────────────────────────────────────────┘
```

### Query Pattern (CRITICAL)

All queries **MUST** start by filtering on `user_id` and `project_id` to leverage indexes:

```cypher
// ✅ CORRECT - Uses composite index, scans only tenant's data
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
-[:HAS_SUBDOMAIN]->(s:Subdomain)
-[:RESOLVES_TO]->(ip:IP)
-[:HAS_PORT]->(p:Port)
RETURN d, s, ip, p

// ❌ WRONG - Full graph scan, affects all tenants
MATCH (v:Vulnerability {severity: 'critical'})
RETURN v
```

### AWS Deployment Architecture

```
Node.js API (EKS/ECS Fargate)
        │
        ├── ElastiCache Redis ─── Query caching per tenant
        │
        └── Neo4j AuraDB / Neo4j on EC2
                │
                └── Composite indexes on (user_id, project_id)
```

### Scaling Path

| Phase | Users | Strategy | AWS Services |
|-------|-------|----------|--------------|
| MVP | 0-100 | Single DB + Indexes | ECS Fargate, Neo4j AuraDB |
| Growth | 100-1K | Read Replicas | EKS, AuraDB Professional |
| Scale | 1K+ | Sharded by User Pools | EKS Multi-AZ, Neo4j Cluster |

---

## 📊 Node Types

> ⚠️ **IMPORTANT**: All node types below implicitly include `user_id` and `project_id` properties
> for multi-tenant isolation, even if not shown in the examples. These are indexed with composite
> indexes for optimal query performance. See [Tenant Composite Indexes](#tenant-composite-indexes-critical-for-multi-tenant-query-performance).

### 1. Domain (Root Node)
The entry point for all queries. Contains project/user ownership.

```cypher
(:Domain {
    name: "vulnweb.com",                    // Root domain name (UNIQUE per tenant)
    user_id: "samgiam",                     // Owner/user identifier
    project_id: "first_test",               // Project identifier
    scan_timestamp: datetime,               // When scan was performed
    scan_type: "domain_discovery_port_scan_http_probe_vuln_scan",
    target: "testphp.vulnweb.com",          // Original target (may differ from root)
    filtered_mode: true,                    // Was SUBDOMAIN_LIST filter used?
    subdomain_filter: ["testphp."],         // Subdomain prefixes from SUBDOMAIN_LIST
    modules_executed: ["whois", "dns_resolution", "port_scan", "http_probe", "vuln_scan"],
    
    // Scan modes (from metadata)
    anonymous_mode: false,                   // Was Tor used?
    bruteforce_mode: false,                  // Was subdomain bruteforcing enabled?
    
    // WHOIS Information
    registrar: "Gandi SAS",
    registrar_url: "http://www.gandi.net",
    whois_server: "whois.gandi.net",
    creation_date: datetime,
    expiration_date: datetime,
    updated_date: datetime,
    dnssec: "unsigned",
    
    // Owner Information
    organization: "Invicti Security Limited",
    country: "MT",
    city: "REDACTED FOR PRIVACY",           // City (often redacted)
    state: null,                             // State/province
    address: "REDACTED FOR PRIVACY",         // Street address
    registrant_postal_code: "REDACTED FOR PRIVACY",
    
    // Contact Information (may be redacted)
    registrant_name: "REDACTED FOR PRIVACY",
    admin_name: "REDACTED FOR PRIVACY",
    admin_org: "REDACTED FOR PRIVACY",
    tech_name: "REDACTED FOR PRIVACY",
    tech_org: "REDACTED FOR PRIVACY",
    
    // Status
    status: ["clientTransferProhibited"],
    
    // WHOIS Contact Emails
    whois_emails: ["abuse@support.gandi.net", "...@contact.gandi.net"],
    
    // WHOIS extra fields
    domain_name: "VULNWEB.COM",              // Registered domain name (uppercase)
    referral_url: null,                      // Referral URL if any
    reseller: null,                          // Reseller if any
    
    // Name servers (moved from separate node)
    name_servers: ["NS-105-A.GANDI.NET", "NS-105-B.GANDI.NET", "NS-105-C.GANDI.NET"],

    // OSINT enrichment (set by VirusTotal and OTX)
    vt_enriched: true,
    vt_reputation: -5,                      // VirusTotal community reputation score
    vt_malicious_count: 2,                  // Number of malicious engine detections
    vt_suspicious_count: 1,                 // Suspicious engine detections
    vt_harmless_count: 60,                  // Harmless engine detections
    vt_undetected_count: 10,                // Undetected (no verdict) engine count
    vt_categories: "{\"Forcepoint ThreatSeeker\": \"malicious\"}",  // JSON-serialised categories dict
    vt_registrar: "MarkMonitor Inc.",       // Registrar from VirusTotal
    vt_tags: ["malware", "phishing"],       // VirusTotal threat/category tags
    vt_community_malicious: 5,             // Community malicious votes (distinct from engine count)
    vt_community_harmless: 120,            // Community harmless votes
    vt_last_analysis_date: 1704067200,     // Unix timestamp of last VirusTotal scan
    vt_jarm: "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4",  // JARM TLS fingerprint
    vt_popularity_alexa: 15234,            // Alexa popularity rank
    vt_popularity_umbrella: 8901,          // Cisco Umbrella rank
    otx_pulse_count: 3,                    // AlienVault OTX threat pulse count
    otx_url_count: 12,                     // Number of URLs associated with domain (from OTX url_list)
    otx_adversaries: ["APT28"],            // Named threat actors from OTX pulses
    otx_malware_families: ["PlugX"],       // Malware family names from OTX pulses
    otx_tlp: "white",                      // Most restrictive TLP across OTX pulses
    otx_attack_ids: ["T1566"],             // MITRE ATT&CK IDs from OTX pulses
    criminalip_enriched: true,
    criminalip_risk_score: "high",         // Domain risk score from Criminal IP
    criminalip_risk_grade: "A",            // Domain risk grade from Criminal IP
    criminalip_abuse_count: 3,             // Number of abuse reports for this domain
    criminalip_current_service: "web"      // Current service classification from Criminal IP
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT domain_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE (d.name, d.user_id, d.project_id) IS UNIQUE;

CREATE INDEX domain_user_project IF NOT EXISTS
FOR (d:Domain) ON (d.user_id, d.project_id);
```

---

### 2. Subdomain
Discovered subdomains/hostnames under a domain.

```cypher
(:Subdomain {
    name: "testphp.vulnweb.com",           // Full hostname (UNIQUE per tenant)
    has_dns_records: true,
    status: "200",                          // Primary HTTP status code as string, or "resolved"/"no_http"
    status_codes: [200, 301],               // All unique HTTP status codes seen (set after HTTP probe)
    http_live_url_count: 3,                 // Count of URLs with status < 500
    http_probed_at: datetime,               // When last HTTP-probed
    discovered_at: datetime,
    source: "crt.sh"                        // Discovery source: "crt.sh", "hackertarget", "knockpy",
                                            // "subfinder", "amass", "shodan_rdns", "shodan_dns",
                                            // "urlscan", "fofa", "otx_passive_dns", "censys_rdns",
                                            // "uncover"
    uncover_sources: ['shodan', 'censys'],  // Uncover engines that contributed (when source='uncover')
    uncover_total_raw: 42,                  // Uncover raw results count
    uncover_total_deduped: 30,              // Uncover deduplicated results count
})
```

**Status values:**
- `resolved` — Has DNS records, not yet HTTP-probed
- `no_http` — DNS resolves but no HTTP service responded
- `"200"`, `"301"`, `"403"`, `"404"`, `"500"`, etc. — Primary HTTP status code (lowest non-5xx, or lowest overall)

**Constraints:**
```cypher
CREATE CONSTRAINT subdomain_unique IF NOT EXISTS
FOR (s:Subdomain) REQUIRE (s.name, s.user_id, s.project_id) IS UNIQUE;
```

---

### 3. IP
IP addresses discovered through DNS resolution.

```cypher
(:IP {
    address: "44.228.249.3",               // IP address (UNIQUE per tenant)
    version: "ipv4",                        // ipv4 or ipv6
    is_cdn: true,
    cdn_name: "aws",
    asn: "AS16509",                         // Autonomous System Number
    asn_org: "Amazon.com, Inc.",

    // Geolocation (set by Shodan, Censys)
    country: "United States",
    country_code: "US",
    city: "Ashburn",
    timezone: "America/New_York",
    registered_country: "United States",
    latitude: 39.0469,
    longitude: -77.4903,

    // ASN enrichment (set by Censys)
    autonomous_system_name: "AMAZON-AES",
    autonomous_system_number: 14618,
    asn_bgp_prefix: "44.224.0.0/11",
    asn_description: "Amazon.com, Inc.",
    asn_country_code: "US",
    asn_rir: "ARIN",

    // OSINT enrichment flags and metadata
    censys_enriched: true,
    censys_last_seen: "2026-03-01T12:00:00Z",
    fofa_enriched: true,
    fofa_last_seen: "2026-03-20T08:00:00Z",  // last time FOFA indexed this asset (lastupdatetime)
    country_code: "US",                    // 2-letter country code (set by FOFA country field)
    os: "Linux",                           // OS fingerprint (set by FOFA os field)
    region: "Virginia",                    // Region/province (set by FOFA region field)
    netlas_enriched: true,
    isp: "Amazon.com, Inc.",               // set by Netlas (isp field) or FOFA (isp field)
    country: "US",                         // set by Netlas (geo.country) or FOFA (country_name) — may also be set by Shodan/Censys
    city: "Ashburn",                       // set by Netlas (geo.city) or FOFA (city)
    latitude: 39.04,                       // set by Netlas (geo.latitude)
    longitude: -77.49,                     // set by Netlas (geo.longitude)
    timezone: "America/New_York",          // set by Netlas (geo.time_zone)
    asn_org: "Amazon.com, Inc.",           // set by Netlas (whois.asn.name) or FOFA (as_organization)
    asn: "AS16509",                        // set by Netlas (geo.asn.number) or FOFA (as_number, normalised to "AS<n>")
    asn_bgp_prefix: "44.224.0.0/11",      // set by Netlas (geo.asn.route)
    zoomeye_enriched: true,
    zoomeye_last_seen: "2026-03-01T12:00:00Z",  // update_time from ZoomEye host record
    // ZoomEye also sets (when available): os, country, city, latitude, longitude, asn, isp
    otx_enriched: true,
    otx_pulse_count: 3,
    otx_reputation: 0,
    otx_url_count: 8,                      // Number of URLs associated with this IP (from OTX url_list)
    otx_adversaries: ["APT28"],            // Named threat actors from OTX pulses
    otx_malware_families: ["PlugX"],       // Malware family names from OTX pulses
    otx_tlp: "amber",                      // Most restrictive TLP across OTX pulses
    otx_attack_ids: ["T1059", "T1566"],    // MITRE ATT&CK IDs from OTX pulses
    country_name: "United States",         // Set by OTX geo (only when not already present)
    vt_enriched: true,
    vt_reputation: -5,
    vt_malicious_count: 2,
    vt_suspicious_count: 0,
    vt_harmless_count: 55,
    vt_undetected_count: 8,
    vt_tags: ["scanner", "vpn"],            // VirusTotal threat tags
    vt_community_malicious: 2,             // Community malicious votes
    vt_community_harmless: 80,             // Community harmless votes
    vt_last_analysis_date: 1704067200,     // Unix timestamp of last VirusTotal scan
    vt_network: "44.224.0.0/11",           // CIDR network range from VirusTotal
    vt_rir: "ARIN",                        // Regional Internet Registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC)
    vt_continent: "NA",                    // Continent code from VirusTotal
    vt_jarm: "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4",  // JARM TLS fingerprint
    criminalip_enriched: true,
    criminalip_score_inbound: "dangerous",     // Risk score for inbound traffic (integer 0-5 or label)
    criminalip_score_outbound: "safe",         // Risk score for outbound traffic
    criminalip_is_vpn: false,
    criminalip_is_proxy: false,
    criminalip_is_tor: false,
    criminalip_is_hosting: false,              // Hosting/datacenter IP
    criminalip_is_cloud: false,                // Cloud provider IP
    criminalip_is_mobile: false,               // Mobile carrier IP
    criminalip_is_darkweb: false,              // Associated with dark web activity
    criminalip_is_scanner: false,              // Known scanning/crawling source
    criminalip_is_snort: false,                // Listed in Snort/IDS rules
    criminalip_org_name: "DMZHOST",           // Organization name (WHOIS)
    criminalip_country: "nl",                  // Country code from WHOIS
    criminalip_city: "Amsterdam",              // City from WHOIS
    criminalip_latitude: 52.3716,              // Latitude from WHOIS
    criminalip_longitude: 4.8883,              // Longitude from WHOIS
    criminalip_asn_name: "Pptechnology Limited",  // AS name from WHOIS
    criminalip_asn_no: 48090,                  // AS number from WHOIS
    criminalip_ids_count: 2,                   // Count of IDS/Snort alerts for this IP
    criminalip_scanning_count: 20,             // Count of inbound scanning events recorded
    criminalip_categories: "[\"malware\", \"attack (Low)\"]"  // JSON list of IP category labels

    // Uncover discovery flags (set by ProjectDiscovery uncover multi-engine search)
    uncover_discovered: true,               // IP was first found via uncover target expansion
    uncover_enriched: true,                 // Uncover has processed this IP
    uncover_sources: ['shodan', 'censys'],  // Search engines that found results
    uncover_source_counts: '{"shodan": 5}', // JSON-encoded engine->count map
    uncover_total_raw: 42,                  // Total raw results before dedup
    uncover_total_deduped: 30,              // Total results after dedup
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT ip_unique IF NOT EXISTS
FOR (i:IP) REQUIRE (i.address, i.user_id, i.project_id) IS UNIQUE;
```

---

### 4. Port
Open ports discovered on IPs/hosts.

```cypher
(:Port {
    number: 80,                             // Port number
    protocol: "tcp",                        // tcp or udp
    state: "open",
    source: "naabu",                        // Discovery source: "naabu", "masscan", "shodan",
                                            // "censys", "fofa", "netlas", "zoomeye", "criminalip",
                                            // "uncover"

    // Nmap service version enrichment (set by update_graph_from_nmap)
    product: "nginx",                       // Product name from Nmap -sV
    version: "1.19.0",                      // Version from Nmap -sV
    cpe: "cpe:/a:f5:nginx:1.19.0",         // CPE string from Nmap
    nmap_scanned: true,                     // Flag: Nmap has probed this port
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT port_unique IF NOT EXISTS
FOR (p:Port) REQUIRE (p.number, p.protocol, p.ip_address, p.user_id, p.project_id) IS UNIQUE;
```

**Note:** Port nodes are connected to both IP and Subdomain to show which host has which port open.

---

### 5. Service
Services running on ports.

```cypher
(:Service {
    name: "http",                           // Service name
    product: "nginx",                       // Product name (if detected) — set by Nmap -sV, ZoomEye, Netlas
    version: "1.19.0",                      // Version (if detected) — set by Nmap -sV, ZoomEye, Netlas
    cpe: "cpe:/a:f5:nginx:1.19.0",         // CPE string — set by Nmap -sV
    banner: "nginx/1.19.0",                 // Raw banner (set by Censys, ZoomEye, Nmap, Netlas)
    extra_info: "Ubuntu",
    source: "censys",                       // Discovery source: "nmap", "censys", "fofa", "netlas", "zoomeye", "criminalip"

    // Censys-specific enrichment
    extended_service_name: "HTTPS",         // More specific service label (e.g. HTTPS vs HTTP)
    labels: ["HTTPS", "TLS"],              // Service classification tags from Censys
    http_title: "Example Domain",          // HTML title from HTTP response (Censys, Netlas, FOFA, ZoomEye portinfo.title)
    http_status_code: 200,                 // HTTP status code from HTTP probe (Censys, Netlas)
    software_products: ["nginx 1.23.4"],   // Detected software products and versions (Censys)

    // FOFA-specific enrichment
    app_protocol: "https",                 // Application-layer protocol (FOFA protocol field)
    jarm: "27d40d40d00040d00042d43d000000", // JARM TLS fingerprint (FOFA jarm field)
    tls_version: "TLSv1.3",               // TLS version (FOFA tls_version field)
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT service_unique IF NOT EXISTS
FOR (svc:Service) REQUIRE (svc.name, svc.port_number, svc.ip_address, svc.user_id, svc.project_id) IS UNIQUE;
```

---

### 6. BaseURL
Root/base web endpoints discovered through HTTP probing. These represent the entry points discovered by httpx.
Specific paths and endpoints discovered during vulnerability scanning are stored in separate Endpoint nodes.

```cypher
(:BaseURL {
    url: "http://testphp.vulnweb.com",     // Full base URL (UNIQUE per tenant)
    scheme: "http",                         // http or https
    host: "testphp.vulnweb.com",            // Hostname
    status_code: 200,
    content_type: "text/html",
    content_length: 2295,
    title: "Acunetix Test Site",
    server: "nginx/1.19.0",
    is_live: true,
    response_time_ms: null,                 // Response time in milliseconds

    // Discovery source
    source: "http_probe",                   // http_probe

    // Network info
    resolved_ip: "44.228.249.3",
    cname: null,                            // CNAME if any
    cdn: "aws",
    is_cdn: true,
    asn: null,

    // Fingerprints
    favicon_hash: "-1187092235",
    body_sha256: "a42521a54c7bcc2dbc2f7010dd22c17c566f3bda167e662c6086c94bf9ebfb62",
    header_sha256: "fbbea705962aa40edced75d2fb430f4a8295b7ab79345a272d1376dd150460cd",

    // Response metadata
    word_count: 11,
    line_count: 6
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT baseurl_unique IF NOT EXISTS
FOR (u:BaseURL) REQUIRE (u.url, u.user_id, u.project_id) IS UNIQUE;
```

---

### 7. Certificate
TLS/SSL certificates discovered during HTTP probing, GVM scanning, or Censys enrichment. Contains certificate metadata for security analysis.

```cypher
(:Certificate {
    subject_cn: "*.beta80group.it",          // Common Name (UNIQUE per tenant)
    user_id: "samgiam",                       // Owner/user identifier
    project_id: "project_2",                  // Project identifier
    issuer: "DigiCert Inc",                   // Certificate issuer (CN + org)
    not_before: "2025-09-02T00:00:00Z",       // Valid from date
    not_after: "2026-10-03T23:59:59Z",        // Expiration date
    san: ["*.beta80group.it", "beta80group.it"],  // Subject Alternative Names
    cipher: "TLS_AES_128_GCM_SHA256",         // TLS cipher suite
    tls_version: "TLSv1.3",                   // TLS version (if detected)
    subject_org: "Example Org",               // Certificate subject organization (set by FOFA certs_subject_org)
    is_valid: true,                           // Certificate validity flag (set by FOFA certs_valid)
    source: "http_probe",                     // Discovery source: "http_probe", "gvm", "censys", "fofa"

    // Censys-specific properties (when source = "censys")
    fingerprint: "sha256:A1B2C3...",          // Certificate fingerprint from Censys leaf_data

    // GVM-specific properties (when source = "gvm")
    serial: "01:AB:CD:...",                   // Certificate serial number
    sha256_fingerprint: "A1B2C3...",          // SHA-256 fingerprint
    scan_timestamp: "2026-02-12T23:10:29Z"    // When GVM scan ran
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT certificate_unique IF NOT EXISTS
FOR (c:Certificate) REQUIRE (c.subject_cn, c.user_id, c.project_id) IS UNIQUE;
```

---

### 8. Endpoint
Specific web application endpoints (paths) discovered through Katana crawling, Hakrawler crawling, ParamSpider parameter mining, jsluice JavaScript analysis, or vulnerability scanning.
These are linked to their parent BaseURL and contain discovered parameters.

```cypher
(:Endpoint {
    // Core properties
    path: "/artists.php",                   // Path without query string
    method: "GET",                          // HTTP method (GET, POST, PUT, DELETE, etc.)
    baseurl: "http://testphp.vulnweb.com",  // Parent base URL
    has_parameters: true,                   // Does this endpoint have parameters?
    full_url: "http://testphp.vulnweb.com/artists.php",  // Full URL without query params
    source: "katana_crawl",                 // katana_crawl, vuln_scan, resource_enum
    category: "dynamic",                    // dynamic, static, authentication, search, api, other
    query_param_count: 1,                   // Number of query parameters
    body_param_count: 0,                    // Number of body parameters
    path_param_count: 0,                    // Number of path parameters
    urls_found: 3,                          // Number of URLs pointing to this endpoint

    // Form properties (for POST endpoints discovered via HTML forms)
    is_form: true,                          // True if this endpoint receives form submissions
    form_enctype: "application/x-www-form-urlencoded",  // Form encoding type
    form_found_at_pages: [                  // Pages where this form was discovered
        "http://testphp.vulnweb.com/login.php",
        "http://testphp.vulnweb.com/index.php"
    ],
    form_input_names: ["username", "password"],  // Input field names from the form
    form_count: 2,                          // Number of pages containing this form

    // GraphQL enrichment (set by graphql_scan when an endpoint is detected as GraphQL)
    is_graphql: true,                                // True = endpoint is a GraphQL endpoint
    graphql_introspection_enabled: true,             // True = __schema introspection query succeeded
    graphql_schema_extracted: true,                  // True = full schema was successfully retrieved
    graphql_schema_hash: "sha256:...",               // SHA-256 of normalized schema JSON (change detection)
    graphql_schema_extracted_at: "2026-04-20T18:00:00+00:00", // ISO timestamp of last schema extraction
    graphql_queries: ["me", "users", "orders"],      // Up to 50 query operation names
    graphql_mutations: ["login", "createOrder"],     // Up to 50 mutation operation names
    graphql_subscriptions: ["onMessage"],            // Up to 50 subscription operation names
    graphql_queries_count: 23,                       // Total queries (not just the capped array)
    graphql_mutations_count: 8,                      // Total mutations
    graphql_subscriptions_count: 1,                  // Total subscriptions

    // graphql-cop external scanner capability flags (set regardless of result -- captures
    // negative signals like "GraphiQL exposed=false" as explicit state rather than silence)
    graphql_cop_ran: true,                           // True if graphql-cop executed against this endpoint
    graphql_cop_scanned_at: "2026-04-20T18:00:00+00:00", // ISO timestamp of last graphql-cop run
    graphql_graphiql_exposed: false,                 // GraphiQL / Playground IDE detected
    graphql_tracing_enabled: false,                  // Apollo tracing extension enabled
    graphql_get_allowed: false,                      // GET-method queries accepted (CSRF vector)
    graphql_field_suggestions_enabled: true,         // "Did you mean X?" errors leak schema fields
    graphql_batching_enabled: false                  // Array-based batched queries accepted
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT endpoint_unique IF NOT EXISTS
FOR (e:Endpoint) REQUIRE (e.path, e.method, e.baseurl, e.user_id, e.project_id) IS UNIQUE;
```

---

### 8. Parameter
URL parameters that represent potential attack vectors. These are discovered through Katana crawling,
Hakrawler crawling, ParamSpider passive parameter mining, jsluice JavaScript analysis, and marked as injectable when vulnerabilities are found through DAST scanning.

```cypher
(:Parameter {
    name: "artist",                         // Parameter name
    position: "query",                      // query, body, header, path
    endpoint_path: "/artists.php",          // Parent endpoint path
    baseurl: "http://testphp.vulnweb.com",  // Parent base URL
    sample_value: "1",                      // Example value seen
    is_injectable: true                     // Marked true if vuln found affecting this param
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT parameter_unique IF NOT EXISTS
FOR (p:Parameter) REQUIRE (p.name, p.position, p.endpoint_path, p.baseurl, p.user_id, p.project_id) IS UNIQUE;
```

---

### 9. Technology
Detected technologies, frameworks, and software.

```cypher
(:Technology {
    name: "PHP",                            // Technology name
    version: "5.6.40",                      // Primary version (if detected)
    versions_all: ["5.6.40"],               // All versions detected (from wappalyzer)
    name_version: "PHP:5.6.40",             // Combined identifier
    categories: ["Programming languages"],  // Technology categories
    confidence: 100,                        // Detection confidence (0-100)
    
    // Source tracking
    detected_by: "httpx",                   // httpx, wappalyzer, banner_grab
    
    // For CVE lookup matching
    product: "php",                         // Normalized product name for CVE lookup
    cpe_vendor: "php",                      // CPE vendor (if known)
    
    // CVE Summary (denormalized for quick access)
    known_cve_count: 17,
    critical_cve_count: 2,
    high_cve_count: 5,
    medium_cve_count: 10,
    low_cve_count: 0
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT technology_unique IF NOT EXISTS
FOR (t:Technology) REQUIRE (t.name, t.version, t.user_id, t.project_id) IS UNIQUE;
```

> **Note:** `version` uses empty string `''` (not NULL) when no version is detected, because composite constraints require all fields to be present.

---

### 10. Vulnerability
Discovered vulnerabilities. Six sources produce Vulnerability nodes, each with different property sets.

**Common properties (all sources):**
```cypher
(:Vulnerability {
    id: String,                              // Unique identifier
    user_id: String,                         // Multi-tenant isolation
    project_id: String,                      // Multi-tenant isolation
    source: "nuclei" | "gvm" | "security_check" | "netlas" | "nmap_nse" | "graphql_scan" | "takeover_scan",  // Scanner source
    name: String,                            // Vulnerability name
    description: String,                     // Description
    severity: "critical" | "high" | "medium" | "low" | "info",  // Always lowercase
    cvss_score: Float,                       // 0.0 to 10.0
})
```

**Nuclei-specific properties (source = "nuclei"):**
```cypher
(:Vulnerability {
    // Example
    id: "sqli-error-based-artists-artist",
    source: "nuclei",
    name: "Error based SQL Injection",
    severity: "critical",

    // Template info
    template_id: "sqli-error-based",
    template_path: "dast/vulnerabilities/sqli/sqli-error-based.yaml",
    template_url: "https://cloud.projectdiscovery.io/public/sqli-error-based",
    category: "sqli",                        // xss, sqli, rce, lfi, ssrf, exposure, etc.
    tags: ["sqli", "error", "dast", "vuln"],
    authors: ["geeknik", "pdteam"],
    references: [],

    // Classification
    cwe_ids: ["CWE-89"],
    cves: ["CVE-2021-12345"],                // Associated CVEs (as property)
    cvss_metrics: "CVSS:3.1/AV:N/...",

    // Attack details
    matched_at: "http://testphp.vulnweb.com/artists.php?artist=3'",
    matcher_name: "",
    matcher_status: true,
    extractor_name: "mysql",
    extracted_results: ["SQL syntax; check the manual..."],

    // Request/Response details
    request_type: "http",                    // http, dns, tcp, etc.
    scheme: "http",
    host: "testphp.vulnweb.com",
    port: "80",
    path: "/artists.php",
    matched_ip: "44.228.249.3",

    // DAST specific
    is_dast_finding: true,
    fuzzing_method: "GET",
    fuzzing_parameter: "artist",
    fuzzing_position: "query",               // query, body, header, path

    // Template metadata
    max_requests: 3,

    // Reproduction
    curl_command: "curl -X 'GET' ...",
    raw_request: "GET /artists.php?artist=3' HTTP/1.1\nHost: ...",
    raw_response: "HTTP/1.1 200 OK\nConnection: close\n...",

    // Timestamp
    timestamp: datetime,
    discovered_at: datetime,
})
```

**GVM-specific properties (source = "gvm"):**
```cypher
(:Vulnerability {
    // Example
    id: "gvm-1.3.6.1.4.1.25623.1.0.11213-15.160.68.117-8080",
    source: "gvm",
    name: "HTTP Debugging Methods (TRACE/TRACK) Enabled",
    severity: "medium",

    // OpenVAS NVT info
    oid: "1.3.6.1.4.1.25623.1.0.11213",     // NVT Object Identifier
    family: "Web Servers",                    // NVT family
    threat: "Medium",                         // GVM threat level

    // Target info
    target_ip: "15.160.68.117",
    target_port: 8080,
    target_hostname: "ec2-15-160-68-117.eu-south-1.compute.amazonaws.com",
    port_protocol: "tcp",

    // Remediation
    solution: "Disable the TRACE and TRACK methods...",
    solution_type: "Mitigation",
    cvss_vector: "AV:N/AC:M/Au:N/C:P/I:P/A:N",

    // Detection quality
    qod: 99,                                  // Quality of Detection (0-100)
    qod_type: "remote_vul",                   // Detection method type

    // CVE references (stored as property, no CVE node relationships)
    cve_ids: ["CVE-2003-1567", "CVE-2004-2320", "..."],

    // CISA & remediation status
    cisa_kev: false,                          // Listed in CISA Known Exploited Vulnerabilities
    remediated: false,                        // Marked as closed/patched by GVM re-scan

    // Scanner metadata
    scanner: "OpenVAS",
    scan_timestamp: "2026-02-12T23:09:59.655089",
})
```

**Netlas-specific properties (source = "netlas"):**
```cypher
(:Vulnerability {
    // Example — passive NVD-based vulnerability detection (version fingerprinting)
    id: "CVE-2021-44228",
    source: "netlas",
    name: "CVE-2021-44228",
    severity: "critical",
    cvss_score: 10.0,
    has_exploit: true,               // Known public exploit exists (from Netlas NVD data)
})
```

**Nmap NSE-specific properties (source = "nmap_nse"):**
```cypher
(:Vulnerability {
    // Example -- NSE script vulnerability detection
    id: "nmap-nse-ftp-vsftpd-backdoor-21-192.168.1.10",
    source: "nmap_nse",
    name: "ftp-vsftpd-backdoor",               // NSE script ID
    severity: "critical",                       // Mapped from NSE state (VULNERABLE = critical)
    type: "nmap_nse",                           // Vulnerability type
    state: "VULNERABLE",                        // NSE script state (VULNERABLE, NOT VULNERABLE, etc.)
    output: "vsFTPd version 2.3.4 backdoor...", // Full NSE script output
    cve_id: "CVE-2011-2523",                    // CVE extracted from NSE output (regex CVE-\d{4}-\d+)
})
```

**GraphQL-specific properties (source = "graphql_scan"):**
```cypher
(:Vulnerability {
    // Example -- introspection exposure
    id: "graphql_graphql_introspection_enabled_https___api_target_com__graphql",
    source: "graphql_scan",
    vulnerability_type: "graphql_introspection_enabled",  // or "graphql_sensitive_data_exposure"
    name: "GraphQL Introspection Enabled",
    severity: "medium",                                   // graphql_introspection_enabled = medium; sensitive_data = medium/high
    endpoint: "https://api.target.com/graphql",
    title: "GraphQL Introspection Query Enabled",
    description: "Introspection query returned full schema (23 queries, 8 mutations, 1 subscription)",
    evidence: "{\"queries_count\":23,\"mutations_count\":8,\"subscriptions_count\":1,\"sensitive_fields\":[\"User.hashedPassword\",\"User.apiKey\"],\"schema_hash\":\"sha256:...\"}",
    timestamp: datetime,
})
```

Vulnerability types emitted by `graphql_scan`:
- `graphql_introspection_enabled` — introspection query succeeded; schema extracted and stored on the Endpoint node (see the Endpoint block for `graphql_queries`, `graphql_mutations`, etc.)
- `graphql_sensitive_data_exposure` — schema contains fields matching sensitive-keyword heuristic (`password`, `secret`, `token`, `apiKey`, `ssn`, `credit`, `cvv`, etc.). Created as a separate Vulnerability when the introspection-enabled finding has ≥1 sensitive field.

Vulnerability types emitted by `graphql_cop` (external scanner, Phase 2):
- `graphql_field_suggestions_enabled` (LOW) — "Did you mean X?" field suggestions leak schema even with introspection off
- `graphql_ide_exposed` (LOW) — GraphiQL / GraphQL Playground UI reachable
- `graphql_get_method_allowed` (MEDIUM) — GraphQL queries accepted via GET (CSRF vector)
- `graphql_get_based_mutation` (MEDIUM) — mutations executable via GET
- `graphql_post_csrf` (MEDIUM) — POST with `application/x-www-form-urlencoded` accepted (CSRF)
- `graphql_tracing_enabled` (INFO) — Apollo tracing extension leaks execution metadata
- `graphql_unhandled_error` (INFO) — exception stack traces returned to client
- `graphql_alias_overloading` (HIGH, DoS) — 101-alias query accepted, rate-limit bypass
- `graphql_batch_query_allowed` (HIGH, DoS) — 10+ queries batched in one POST
- `graphql_directive_overloading` (HIGH, DoS) — many repeated directives accepted
- `graphql_circular_introspection` (HIGH, DoS) — deep nested introspection triggers recursion

Each `graphql_cop` Vulnerability's `evidence` field is a JSON blob containing `curl_verify` (a reproducer cURL command), `raw_severity` (graphql-cop's uppercase severity), and `graphql_cop_key` (internal test identifier).

Deterministic ID pattern: `graphql_{vulnerability_type}_{baseurl}_{path}` (colons, slashes, dots replaced with `_`). Enables MERGE-based deduplication across re-scans AND across scanners — if `graphql_cop` and the native scanner both detect introspection, they merge into one Vulnerability node.

**Subdomain-takeover-specific properties (source = "takeover_scan"):**
```cypher
(:Vulnerability {
    id: "takeover_<sha1-hex16>",              // hash(hostname+provider+method)
    source: "takeover_scan",
    type: "subdomain_takeover",
    name: "Subdomain Takeover — Heroku (CNAME)",
    severity: "high" | "medium" | "info",     // driven by verdict + scorer

    // Takeover-specific
    hostname: "promo.acme.com",                // subdomain flagged as takeover-prone
    cname_target: "acme-spring.herokuapp.com", // destination when CNAME-based (nullable)
    takeover_provider: "heroku",               // github-pages | heroku | aws-s3 | fastly | azure-* | ...
    takeover_method: "cname" | "dns" | "ns" | "mx" | "stale_a",
    confidence: 85,                            // 0..100 integer
    sources: ["subjack", "nuclei_takeover"],   // tools that confirmed the finding
    confirmation_count: 2,
    verdict: "confirmed" | "likely" | "manual_review",
    evidence: "Subjack confirmed Heroku takeover",
    tool_raw: "{...}",                         // JSON-encoded raw per-tool output (truncated to 50KB)
    first_seen: "2026-04-21T12:34:56Z",
    last_seen:  "2026-04-21T12:34:56Z",
})
```

Layered scanner: **Subjack** (DNS-first, Apache-2.0 Go binary baked into the recon image) + **Nuclei** with `-t http/takeovers/ -t dns/` against alive URLs. Findings are deduplicated by `(hostname, takeover_provider, takeover_method)`, then scored. A `verdict` of `manual_review` implies `severity="info"` to keep low-confidence findings out of the main alert stream unless the project's `takeoverManualReviewAutoPublish` setting is true. Relationship: `(:Subdomain)-[:HAS_VULNERABILITY]->(:Vulnerability)`; falls back to `(:Domain)` for the apex.

**Constraints:**
```cypher
CREATE INDEX vuln_severity IF NOT EXISTS
FOR (v:Vulnerability) ON (v.severity);

CREATE INDEX vuln_category IF NOT EXISTS
FOR (v:Vulnerability) ON (v.category);
```

---

### 11. CVE
Known CVEs from technology-based lookup.

```cypher
(:CVE {
    id: "CVE-2021-3618",                   // CVE ID (UNIQUE)
    cvss: 7.4,                              // CVSS score
    severity: "HIGH",                       // CRITICAL, HIGH, MEDIUM, LOW
    description: "ALPACA is an application layer...",
    published: datetime,
    source: "nvd",                          // Data source
    url: "https://nvd.nist.gov/vuln/detail/CVE-2021-3618",
    references: ["https://alpaca-attack.com/"]
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT cve_unique IF NOT EXISTS
FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE INDEX cve_severity IF NOT EXISTS
FOR (c:CVE) ON (c.severity);

CREATE INDEX cve_cvss IF NOT EXISTS
FOR (c:CVE) ON (c.cvss);
```

---

### 12. MitreData
CWE (Common Weakness Enumeration) data from MITRE enrichment. Each CVE can have a hierarchical chain
of CWE nodes representing the weakness hierarchy from root to leaf CWE.

```cypher
(:MitreData {
    id: "CVE-2021-3618-CWE-295",           // Unique ID (CVE + CWE combination)
    cve_id: "CVE-2021-3618",               // Parent CVE ID
    cwe_id: "CWE-295",                      // CWE identifier
    cwe_name: "Improper Certificate Validation",
    cwe_description: "The software does not validate, or incorrectly validates...",
    cwe_url: "https://cwe.mitre.org/data/definitions/295.html",
    abstraction: "Base",                    // Pillar, Class, Base, Variant
    is_leaf: true,                          // Is this the most specific CWE?
    platforms: ["Not Language-Specific"]    // Applicable platforms
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT mitredata_unique IF NOT EXISTS
FOR (m:MitreData) REQUIRE m.id IS UNIQUE;

CREATE INDEX idx_mitredata_tenant IF NOT EXISTS
FOR (m:MitreData) ON (m.user_id, m.project_id);
```

---

### 13. Capec
CAPEC (Common Attack Pattern Enumeration and Classification) nodes linked to CWE weaknesses.
Only created when a CWE has non-empty `related_capec` data.

```cypher
(:Capec {
    capec_id: "CAPEC-94",                  // CAPEC identifier (UNIQUE)
    numeric_id: 94,                         // Numeric ID
    name: "Man in the Middle Attack",
    description: "This type of attack targets the communication between two parties...",
    url: "https://capec.mitre.org/data/definitions/94.html",
    likelihood: "Medium",                   // High, Medium, Low
    severity: "Very High",                  // Very High, High, Medium, Low, Very Low
    prerequisites: "There are two components communicating with each other...",
    execution_flow: "[JSON stringified attack phases]",  // Attack execution steps
    related_cwes: ["CWE-295", "CWE-300"]   // Related CWE IDs
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT capec_unique IF NOT EXISTS
FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE;

CREATE INDEX capec_id IF NOT EXISTS
FOR (c:Capec) ON (c.capec_id);

CREATE INDEX idx_capec_tenant IF NOT EXISTS
FOR (c:Capec) ON (c.user_id, c.project_id);
```

---

### 14. DNSRecord
DNS records for subdomains.

```cypher
(:DNSRecord {
    type: "A",                              // A, AAAA, MX, NS, TXT, CNAME, SOA
    value: "44.228.249.3",                  // Record value
    ttl: 300                                // Time to live (if available)
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT dnsrecord_unique IF NOT EXISTS
FOR (dns:DNSRecord) REQUIRE (dns.type, dns.value, dns.subdomain, dns.user_id, dns.project_id) IS UNIQUE;
```

---

### 15. Header
HTTP response headers (all captured headers).

```cypher
(:Header {
    name: "X-Powered-By",                   // Header name
    value: "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1",
    is_security_header: false,              // Is this a security header?
    reveals_technology: true                // Does this reveal server tech?
})
```

**Common headers to capture:**
- `Server` - Web server identification
- `X-Powered-By` - Backend technology
- `X-AspNet-Version` - .NET version
- `Content-Type` - Content type info
- `Content-Encoding` - Compression info
- Security headers: `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy`, `Strict-Transport-Security`

**Constraints:**
```cypher
CREATE CONSTRAINT header_unique IF NOT EXISTS
FOR (h:Header) REQUIRE (h.name, h.value, h.baseurl, h.user_id, h.project_id) IS UNIQUE;
```

---

### 20. Traceroute

**Label:** `Traceroute`
**Created by:** GVM/OpenVAS scanner (log-level finding)
**Source:** Network route discovery via ICMP/TCP traceroute

| Property | Type | Description |
|----------|------|-------------|
| `target_ip` | String | Target IP address |
| `scanner_ip` | String | Scanner/source IP address |
| `hops` | String[] | Ordered list of hop IP addresses (scanner → target) |
| `distance` | Integer | Number of network hops between scanner and target |
| `source` | String | Always `"gvm"` |
| `scan_timestamp` | String | When the GVM scan was performed |
| `user_id` | String | Tenant user ID |
| `project_id` | String | Tenant project ID |

**Relationships:**
```cypher
(IP)-[:HAS_TRACEROUTE]->(Traceroute)
```

**Constraints:**
```cypher
CREATE CONSTRAINT traceroute_unique IF NOT EXISTS
FOR (tr:Traceroute) REQUIRE (tr.target_ip, tr.user_id, tr.project_id) IS UNIQUE;
```

**Visual:** Circle, dark cyan (#164e63), network layer family.

---

### 21. ExploitGvm

GVM/OpenVAS confirmed active exploitation. Created when a GVM "Active Check" NVT achieves QoD=100, meaning it actually executed a payload and received proof of compromise (e.g., command output showing `uid=0(root)`).

```cypher
(:ExploitGvm {
    id: "gvm-exploit-{oid}-{ip}-{port}",       // Deterministic ID
    user_id: String,                             // Tenant user ID
    project_id: String,                          // Tenant project ID
    attack_type: "cve_exploit",                  // Always cve_exploit for GVM
    severity: "critical",                        // Always critical - confirmed compromise
    name: "Apache HTTP Server ... - Active Check",
    target_ip: "15.160.68.117",
    target_port: 8080,
    target_hostname: "ec2-...",
    port_protocol: "tcp",
    cve_ids: ["CVE-2021-42013"],
    cisa_kev: true,                              // CISA Known Exploited Vulnerabilities flag
    description: "By doing the following HTTP request: ... uid=0(root)",
    evidence: "By doing the following HTTP request: ... uid=0(root)",
    solution: "Update to version 2.4.52 or later.",
    oid: "1.3.6.1.4.1.25623.1.0.146871",        // OpenVAS NVT OID
    family: "Web Servers",
    qod: 100,                                    // Quality of Detection (always 100)
    cvss_score: 9.8,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    source: "gvm",
    scanner: "OpenVAS",
    scan_timestamp: "2026-02-12T23:09:59.655089"
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT exploitgvm_unique IF NOT EXISTS
FOR (e:ExploitGvm) REQUIRE e.id IS UNIQUE;

CREATE INDEX idx_exploitgvm_tenant IF NOT EXISTS
FOR (e:ExploitGvm) ON (e.user_id, e.project_id);
```

**Relationships:**
```cypher
(ExploitGvm)-[:EXPLOITED_CVE]->(CVE)   // Only connection — links to the exploited CVE
```

**Visual:** Diamond shape, orange-600 color (#ea580c), always-on glow, lightning bolt icon.

---

### 22. ExternalDomain

Foreign domains encountered during recon that are outside the target scope.
These are **informational only** — they are never scanned, probed, or attacked.
They provide situational awareness about where the target's infrastructure redirects
to or what domains share certificates/hosting with the target.

```cypher
(:ExternalDomain {
    domain: "evil.com",                           // Foreign domain name (UNIQUE per tenant)
    user_id: "...",
    project_id: "...",

    // Discovery context
    sources: ["http_probe_redirect", "urlscan", "hakrawler", "jsluice"],  // How discovered (array)
    first_seen_at: datetime(),

    // Redirect context (from http_probe)
    redirect_from_urls: ["https://target.com/login"],   // In-scope URLs that redirected here
    redirect_to_urls: ["https://evil.com/landing"],     // The actual foreign URLs

    // Basic metadata (from whatever source provided it)
    status_codes_seen: ["200", "301"],
    titles_seen: ["Evil Landing Page"],
    servers_seen: ["nginx"],
    ips_seen: ["1.2.3.4"],
    countries_seen: ["CN"],

    times_seen: 3,                                // Total encounters across all sources
    updated_at: datetime()
})
```

| Property | Type | Description |
|----------|------|-------------|
| `domain` | String | Foreign domain name (UNIQUE per tenant) |
| `sources` | String[] | Discovery sources: http_probe_redirect, urlscan, gau, katana, hakrawler, jsluice, cert_discovery |
| `first_seen_at` | DateTime | When first encountered |
| `redirect_from_urls` | String[] | In-scope URLs that redirected to this domain |
| `redirect_to_urls` | String[] | The actual foreign URLs encountered |
| `status_codes_seen` | String[] | HTTP status codes seen |
| `titles_seen` | String[] | Page titles seen |
| `servers_seen` | String[] | Server headers seen |
| `ips_seen` | String[] | IP addresses seen (from URLScan) |
| `countries_seen` | String[] | Countries seen (from URLScan) |
| `times_seen` | Integer | Total encounters across all sources |
| `updated_at` | DateTime | Last updated |

**Constraints:**
```cypher
CREATE CONSTRAINT externaldomain_unique IF NOT EXISTS
FOR (ed:ExternalDomain) REQUIRE (ed.domain, ed.user_id, ed.project_id) IS UNIQUE;

CREATE INDEX idx_externaldomain_tenant IF NOT EXISTS
FOR (ed:ExternalDomain) ON (ed.user_id, ed.project_id);
```

**Relationship:**
```cypher
(Domain)-[:HAS_EXTERNAL_DOMAIN]->(ExternalDomain)
```

**Visual:** Dashed circle, warm stone gray (#8b8178).

---

### UserInput

User-provided values for partial recon runs. When a user triggers a partial recon (e.g., subdomain discovery) and adds custom input values, a UserInput node is created to track the provenance of those inputs and the results they produced.

**Created by:** `partial_recon.py` (partial recon pipeline)

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `id` | String (UUID) | Unique identifier (UNIQUE constraint) |
| `input_type` | String | Type of input: "subdomains", "ips", "urls", "domains" |
| `values` | String[] | User-provided values |
| `tool_id` | String | Tool that was run (e.g., "SubdomainDiscovery") |
| `source` | String | Always "user" |
| `status` | String | "running", "completed", "error" |
| `stats` | String | JSON-encoded run statistics |
| `created_at` | DateTime | When the partial recon was started |
| `completed_at` | DateTime | When it finished (null if still running) |

**Constraints:**
```cypher
CREATE CONSTRAINT userinput_unique IF NOT EXISTS
FOR (ui:UserInput) REQUIRE (ui.id) IS UNIQUE;

CREATE INDEX idx_userinput_tenant IF NOT EXISTS
FOR (ui:UserInput) ON (ui.user_id, ui.project_id);
```

**Relationships:**
```cypher
(Domain)-[:HAS_USER_INPUT]->(UserInput)    -- Domain has user-provided partial recon input
(UserInput)-[:PRODUCED]->(Subdomain)       -- Partial recon run produced this subdomain
(UserInput)-[:PRODUCED]->(IP)              -- Partial recon run produced this IP
```

---

### Secret

Secrets discovered in live web resources (JavaScript files, configuration files, etc.) during reconnaissance. This is a **generic, source-agnostic** node: jsluice populates it now, but any future secret discovery tool can create the same node type.

**Created by:** `resource_enum` phase (jsluice secrets extraction)

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `id` | string | Unique identifier: `secret-{user_id}-{project_id}-{dedup_hash}` |
| `user_id` | string | Tenant isolation |
| `project_id` | string | Tenant isolation |
| `secret_type` | string | Type of secret: `AWSAccessKey`, `APIKey`, `GCPCredential`, `GitHubToken`, etc. (from jsluice `kind`) |
| `severity` | string | `high`, `medium`, `low`, `info` |
| `source` | string | Discovery tool: `jsluice` (extensible to future tools) |
| `source_url` | string | URL of the file containing the secret (e.g., `https://example.com/js/app.js`) |
| `base_url` | string | Parent BaseURL |
| `sample` | string | Redacted sample — first 6 characters + `...` |
| `discovered_at` | string | Scan timestamp |
| `updated_at` | datetime | Last update time |

**Deduplication:** `secret_type + source_url + hash(data) + user_id + project_id`. Every unique secret value gets its own node. Re-scans update existing nodes via MERGE.

**Constraint:**
```cypher
CREATE CONSTRAINT secret_unique IF NOT EXISTS FOR (s:Secret) REQUIRE (s.id) IS UNIQUE
```

**Relationship:**
```cypher
(BaseURL)-[:HAS_SECRET]->(Secret)
```

**Visual:** Circle, rose-600 (#e11d48) — danger/attention-grabbing.

---

### ThreatPulse

OTX threat intelligence pulses — named threat reports associating indicators (IPs, domains) with adversaries, malware families, and attack patterns. Each pulse represents a community-published threat report on AlienVault OTX. Up to 10 pulses per indicator are stored.

**Created by:** `recon/otx_enrich.py` + `graph_db/mixins/osint_mixin.py::update_graph_from_otx()`

```cypher
(:ThreatPulse {
    pulse_id: "5a5b3a4f7e09f83e10b4a123",     // OTX pulse ID (UNIQUE per tenant)
    user_id: "...",
    project_id: "...",
    name: "Lazarus Group C2 Infrastructure",  // Pulse title
    adversary: "Lazarus Group",               // Named threat actor (APT group, etc.)
    malware_families: ["BLINDINGCAN", "HOPLIGHT"],  // Associated malware names
    attack_ids: ["T1566", "T1059"],           // MITRE ATT&CK technique IDs
    tags: ["apt", "north-korea", "banking"],  // Free-form community tags (up to 10)
    tlp: "white",                             // Traffic Light Protocol: "white","green","amber","red"
    author_name: "researcher@example.com",    // Pulse author
    targeted_countries: ["US", "UK", "JP"],   // Countries targeted by this threat
    modified: "2026-01-15T10:00:00Z",         // Last modified timestamp from OTX
    created_at: datetime(),
    updated_at: datetime()
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT threatpulse_unique IF NOT EXISTS
FOR (tp:ThreatPulse) REQUIRE (tp.pulse_id, tp.user_id, tp.project_id) IS UNIQUE;

CREATE INDEX idx_threatpulse_tenant IF NOT EXISTS
FOR (tp:ThreatPulse) ON (tp.user_id, tp.project_id);
```

**Relationships:**
```cypher
(IP)-[:APPEARS_IN_PULSE]->(ThreatPulse)
(Domain)-[:APPEARS_IN_PULSE]->(ThreatPulse)
```

**Visual:** Circle, red-orange (#dc4a22) — threat intelligence context.

---

### Malware

Malware samples (file hashes) associated with IPs or domains as reported by OSINT tools (OTX, VirusTotal). This is a **cross-tool** node type: OTX malware and VirusTotal malware samples both produce `Malware` nodes, allowing correlation across sources.

**Created by:** `graph_db/mixins/osint_mixin.py::update_graph_from_otx()` (source=otx), and future VirusTotal malware integration (source=virustotal)

```cypher
(:Malware {
    hash: "d41d8cd98f00b204e9800998ecf8427e",  // File hash (MD5 or SHA256, UNIQUE per tenant)
    user_id: "...",
    project_id: "...",
    hash_type: "md5",              // "md5", "sha256", "sha1", "unknown"
    file_type: "pe32",             // File type/class (e.g., "pe32", "pdf", "elf")
    file_name: "payload.exe",      // Original file name if available
    source: "otx",                 // Discovery source: "otx", "virustotal"
    first_seen: datetime(),
    updated_at: datetime()
})
```

**Constraints:**
```cypher
CREATE CONSTRAINT malware_unique IF NOT EXISTS
FOR (m:Malware) REQUIRE (m.hash, m.user_id, m.project_id) IS UNIQUE;

CREATE INDEX idx_malware_tenant IF NOT EXISTS
FOR (m:Malware) ON (m.user_id, m.project_id);
```

**Relationships:**
```cypher
(IP)-[:ASSOCIATED_WITH_MALWARE]->(Malware)
(Domain)-[:ASSOCIATED_WITH_MALWARE]->(Malware)
```

**Visual:** Circle, deep red (#991b1b) — confirmed malware indicator.

---

---

## 🔗 Relationships

### Domain Relationships

```cypher
// Domain owns subdomains
(Domain)-[:HAS_SUBDOMAIN]->(Subdomain)

// Domain encountered foreign domains during recon
(Domain)-[:HAS_EXTERNAL_DOMAIN]->(ExternalDomain)

// Domain WHOIS contacts (if needed as separate nodes)
(Domain)-[:REGISTERED_BY {registrar_url: "..."}]->(Registrar)

// OTX: historical IP resolutions (domain/passive_dns endpoint)
(Domain)-[:HISTORICALLY_RESOLVED_TO {first_seen: "...", last_seen: "...", record_type: "A"}]->(IP)

// OTX threat intelligence
(Domain)-[:APPEARS_IN_PULSE]->(ThreatPulse)
(Domain)-[:ASSOCIATED_WITH_MALWARE]->(Malware)

// Partial recon user inputs
(Domain)-[:HAS_USER_INPUT]->(UserInput)
```

---

### Subdomain Relationships

```cypher
// Subdomain resolves to IP addresses
(Subdomain)-[:RESOLVES_TO {record_type: "A"}]->(IP)

// Subdomain has DNS records
(Subdomain)-[:HAS_DNS_RECORD]->(DNSRecord)
```

---

### UserInput Relationships

```cypher
// Partial recon run produced subdomains and IPs
(UserInput)-[:PRODUCED]->(Subdomain)
(UserInput)-[:PRODUCED]->(IP)
```

---

### IP Relationships

```cypher
// IP has open ports
(IP)-[:HAS_PORT]->(Port)

// Port runs a service
(Port)-[:RUNS_SERVICE]->(Service)

// Service serves URLs (web endpoints)
(Service)-[:SERVES_URL]->(BaseURL)

// Subdomain links directly to BaseURL (fallback when Service -[:SERVES_URL]-> is absent,
// e.g. port 80 redirected to HTTPS so httpx didn't probe it, but crawlers discovered URLs under it)
(Subdomain)-[:HAS_BASE_URL]->(BaseURL)

// OTX threat intelligence
(IP)-[:APPEARS_IN_PULSE]->(ThreatPulse)
(IP)-[:ASSOCIATED_WITH_MALWARE]->(Malware)
```

---

### BaseURL Relationships

```cypher
// BaseURL has endpoints (discovered paths from vuln_scan)
(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)

// Endpoint has parameters
(Endpoint)-[:HAS_PARAMETER]->(Parameter)

// BaseURL uses technologies (detected by httpx/wappalyzer)
(BaseURL)-[:USES_TECHNOLOGY {confidence: 100, detected_by: "httpx"}]->(Technology)

// BaseURL has TLS certificate (if HTTPS)
(BaseURL)-[:HAS_CERTIFICATE]->(Certificate)

// IP has TLS certificate (GVM-discovered, non-HTTP TLS)
(IP)-[:HAS_CERTIFICATE]->(Certificate)

// BaseURL has HTTP headers
(BaseURL)-[:HAS_HEADER]->(Header)

// BaseURL has discovered secrets (from jsluice or future tools)
(BaseURL)-[:HAS_SECRET]->(Secret)

// Security check vulnerabilities (missing headers, etc.) connect to BaseURL
(BaseURL)-[:HAS_VULNERABILITY]->(Vulnerability)

// Note: DAST vulnerabilities connect via Endpoint (FOUND_AT) and Parameter (AFFECTS_PARAMETER)
// rather than directly to BaseURL, to avoid redundant connections in the graph.
// Path: BaseURL -> Endpoint <- Vulnerability -> Parameter
```

---

### Vulnerability Relationships

**IMPORTANT: No Redundant Connections & No Isolated Nodes**

Each vulnerability connects to exactly ONE **existing** parent node based on its context.
This ensures vulnerabilities are always connected to the graph (no isolated nodes).

| Finding Type | Connects To | Why |
|--------------|-------------|-----|
| IP-based URL (`http://15.161.171.153`) | **IP only** | URL host is an IP - connect to existing IP node |
| Hostname URL (`https://example.com`) | **BaseURL** (existing) | Connect to existing BaseURL from http_probe |
| Hostname URL (no BaseURL exists) | **Subdomain/Domain** | Fallback to host node if BaseURL not found |
| Host-only (SSL issues on `example.com:443`) | **Subdomain only** | It's about the host, not a specific URL |
| DAST findings (SQLi, XSS) | **Endpoint** (via FOUND_AT) | It's about the specific path/parameter |

**Key Rules:**
1. **Never create isolated BaseURL nodes** - only connect to existing nodes
2. **IP-based URLs connect to IP nodes** - keeps direct IP access findings connected
3. **Hostname URLs try BaseURL first** - falls back to Subdomain/Domain if not found

This avoids:
```
❌ Subdomain -[:HAS_VULNERABILITY]-> Vulnerability
❌ BaseURL -[:HAS_VULNERABILITY]-> Vulnerability  (same vuln, redundant!)

❌ Creating isolated BaseURL nodes for IP-based URLs like http://15.161.171.153
   (These would have no connection to IP nodes in the graph)
```

Instead, use graph traversal to find related entities:
```cypher
// Find all vulnerabilities for a subdomain (via BaseURL)
MATCH (s:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)
      -[:RUNS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
      -[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE s.name = $hostname
RETURN v

// Find direct IP access vulnerabilities
MATCH (s:Subdomain)-[:RESOLVES_TO]->(ip:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.type IN ['direct_ip_http', 'direct_ip_https']
RETURN s.name, ip.address, v.name, v.severity
```

```cypher
// Vulnerability affects parameter (the injectable parameter that was fuzzed)
(Vulnerability)-[:AFFECTS_PARAMETER]->(Parameter)

// Vulnerability found at endpoint (the path where the vulnerability was discovered)
(Vulnerability)-[:FOUND_AT]->(Endpoint)

// NOTE: Vulnerability nodes store CVE IDs as properties (cves list for nuclei,
// cve_ids list for GVM), NOT as relationships to CVE nodes.

// Security check vulnerabilities connect to the most specific EXISTING entity:
// Priority: IP (for IP-based URLs) > BaseURL > Subdomain/Domain

// - IP for IP-based URL findings (e.g., http://15.161.171.153 direct access)
//   Connects to existing IP node to stay integrated with graph
(IP)-[:HAS_VULNERABILITY]->(Vulnerability)

// - BaseURL for hostname URL findings (e.g., https://example.com missing headers)
//   Only connects to EXISTING BaseURL nodes (from http_probe)
(BaseURL)-[:HAS_VULNERABILITY]->(Vulnerability)

// - Subdomain/Domain for host-level findings (fallback when BaseURL doesn't exist)
(Subdomain)-[:HAS_VULNERABILITY]->(Vulnerability)
(Domain)-[:HAS_VULNERABILITY]->(Vulnerability)
```

---

### Technology Relationships

```cypher
// Technology has known CVEs (from CVE lookup via NVD, or from Nmap NSE scripts)
(Technology)-[:HAS_KNOWN_CVE]->(CVE)

// Technology runs on service (httpx detection via BaseURL)
(Service)-[:POWERED_BY]->(Technology)

// Service uses technology (Nmap -sV detection, e.g. Service:ftp:21 -> Technology:vsftpd/2.3.4)
(Service)-[:USES_TECHNOLOGY]->(Technology)

// Port has technology (Nmap -sV detection, e.g. Port:21/tcp -> Technology:vsftpd/2.3.4)
(Port)-[:HAS_TECHNOLOGY]->(Technology)

// NSE vulnerability found on technology (e.g. ftp-vsftpd-backdoor -> vsftpd/2.3.4)
(Vulnerability)-[:FOUND_ON]->(Technology)

// NSE vulnerability affects port (e.g. ftp-vsftpd-backdoor -> Port:21/tcp)
(Vulnerability)-[:AFFECTS]->(Port)

// NSE vulnerability has CVE (e.g. ftp-vsftpd-backdoor -> CVE-2011-2523)
(Vulnerability)-[:HAS_CVE]->(CVE)
```

**Nmap attack chain traversal** -- find all exploitable services in one query:
```cypher
MATCH (svc:Service)-[:USES_TECHNOLOGY]->(t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)
WHERE svc.project_id = $projectId
RETURN svc.name, svc.port_number, t.name, c.id
```

---

### CVE/MITRE Relationships

```cypher
// CVE has CWE weakness data
(CVE)-[:HAS_CWE]->(MitreData)

// MitreData (CWE) links to CAPEC attack patterns
// Only created when CWE has non-empty related_capec
(MitreData)-[:HAS_CAPEC]->(Capec)
```

---

## 📐 Complete Graph Visualization

```
┌──────────┐                        ┌─────────────┐
│ Registrar│◄──REGISTERED_BY────────│   Domain    │
└──────────┘                        │ (user_id,   │
                                    │ project_id) │
                                    └──────┬──────┘
                                           │
                                    HAS_SUBDOMAIN
                                           │
                    ┌──────────────────────▼──────────────────────┐
                    │                 Subdomain                    │
                    └──────┬─────────────────────────┬────────────┘
                           │                         │
                    HAS_DNS_RECORD              RESOLVES_TO
                           │                         │
                    ┌──────▼──────┐            ┌─────▼─────┐
                    │ DNSRecord   │            │    IP     │
                    └─────────────┘            └─────┬─────┘
                                                     │
                                                HAS_PORT
                                                     │
                                               ┌─────▼─────┐
                                               │   Port    │
                                               └─────┬─────┘
                                                     │
                                               RUNS_SERVICE
                                                     │
                                               ┌─────▼─────┐
                                               │  Service  │
                                               └──┬─────┬──┘
                                                  │     │
                                            SERVES_URL  POWERED_BY
                                                  │     │
                                            ┌─────▼───┐ │
                                            │ BaseURL │─┼─────────────┐
                                            └─┬───┬───┘ │             │
                                              │   │     │         HAS_HEADER
                                     HAS_ENDPOINT │     │             │
                                              │   │ USES_TECHNOLOGY   │
                                              │   │     │         ┌───▼───┐
                                              │   │     │         │Header │
                                              │   │     │         └───────┘
                                              │   │     │
                                        ┌─────▼──┐│     │
                                        │Endpoint││     │
                                        └──┬──┬──┘│ ┌───▼──────────┐
                                           │  │   │ │  Technology  │
                                    HAS_PARAMETER │ └───────┬──────┘
                                           │  │   │         │
                                           │  │FOUND_AT     │
                                           │  │   │   HAS_KNOWN_CVE
                                     ┌─────▼──┼─┐ │         │
                                     │Parameter│ │  ┌──────▼──────┐
                                     └─────┬──┼─┘ │  │     CVE     │
                                           │  │   │  └──────▲──────┘
                                 AFFECTS_PARAMETER│
                                           │  │   │
                                    ┌──────▼──▼───┤
                                    │ Vulnerability│ (CVE IDs stored as properties)
                                    │  (DAST)      │
                                    └──────────────┘


Security Check Vulnerabilities connect to EXISTING nodes only:

    IP-based URL findings (http://15.161.171.153):
    ┌────────┐  HAS_VULNERABILITY   ┌───────────────┐
    │   IP   │─────────────────────▶│ Vulnerability │
    │(exists)│                      │ (direct_ip_*) │
    └────────┘                      └───────────────┘

    Hostname URL findings (https://example.com):
    ┌─────────┐  HAS_VULNERABILITY   ┌───────────────┐
    │ BaseURL │─────────────────────▶│ Vulnerability │
    │ (exists)│                      │ (missing_hdr) │
    └─────────┘                      └───────────────┘

Note: Each vulnerability connects to exactly ONE EXISTING parent:
  - IP-based URL → IP node (keeps direct IP findings connected to graph)
  - Hostname URL → existing BaseURL (from http_probe)
  - Hostname URL (no BaseURL) → Subdomain/Domain (fallback)

Note: Subdomain -[:HAS_BASE_URL]-> BaseURL is a fallback relationship created when
resource_enum discovers URLs under a base URL that httpx didn't probe (e.g. port 80
redirected to HTTPS). This prevents orphaned BaseURL clusters in the graph.
  - No isolated nodes are created!
```

---

## 🔍 Key Query Patterns

### 1. Get All Assets for a Project
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
MATCH path = (d)-[*1..5]->(n)
RETURN d, path
```

### 2. Find Attack Surface (All Parameters)
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s:Subdomain)
      -[:RESOLVES_TO]->(ip:IP)
      -[:HAS_PORT]->(p:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:HAS_ENDPOINT]->(e:Endpoint)
      -[:HAS_PARAMETER]->(param:Parameter)
RETURN s.name AS host, svc.name AS service, p.number AS port, e.path AS endpoint, param.name AS parameter
```

### 3. Find All Critical Vulnerabilities
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s)
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:HAS_ENDPOINT]->(e:Endpoint)<-[:FOUND_AT]-(v:Vulnerability {severity: "critical"})
RETURN s.name AS host, svc.name AS service, u.url AS url, v.name AS vulnerability, v.matched_at AS proof
```

### 4. Technology to CVE Mapping (Risk Assessment)
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s)
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(port:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:USES_TECHNOLOGY]->(t:Technology)
      -[:HAS_KNOWN_CVE]->(c:CVE)
WHERE c.cvss >= 7.0
RETURN t.name AS technology, t.version AS version, svc.name AS service, port.number AS port,
       collect({cve: c.id, cvss: c.cvss, severity: c.severity}) AS cves
ORDER BY max(c.cvss) DESC
```

### 5. Find Potential Attack Paths (SQLi to Database)
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s)
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(port:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:HAS_ENDPOINT]->(e:Endpoint)<-[:FOUND_AT]-(v:Vulnerability)
WHERE v.category = "sqli"
MATCH (u)-[:USES_TECHNOLOGY]->(t:Technology)
WHERE t.name IN ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]
RETURN s.name AS host, svc.name AS service, port.number AS port, v.matched_at AS injection_point,
       v.extracted_results AS evidence, t.name AS database
```

### 6. Get Complete Host Profile
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s:Subdomain {name: $hostname})
OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)-[:RUNS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:SERVES_URL]->(u:BaseURL)-[:USES_TECHNOLOGY]->(tech:Technology)
OPTIONAL MATCH (u)-[:HAS_ENDPOINT]->(e:Endpoint)<-[:FOUND_AT]-(vuln:Vulnerability)
RETURN s, collect(DISTINCT ip) AS ips,
       collect(DISTINCT {port: port.number, service: svc.name}) AS services,
       collect(DISTINCT tech.name) AS technologies,
       collect(DISTINCT {name: vuln.name, severity: vuln.severity}) AS vulnerabilities
```

### 7. Vulnerability Summary by Category
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->()
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(:Port)
      -[:RUNS_SERVICE]->(:Service)
      -[:SERVES_URL]->(:BaseURL)
      -[:HAS_ENDPOINT]->(:Endpoint)<-[:FOUND_AT]-(v:Vulnerability)
RETURN v.category AS category,
       count(v) AS count,
       collect(DISTINCT v.severity) AS severities
ORDER BY count DESC
```

### 8. Most Common Vulnerability Types
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->()
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(:Port)
      -[:RUNS_SERVICE]->(:Service)
      -[:SERVES_URL]->(:BaseURL)
      -[:HAS_ENDPOINT]->(:Endpoint)<-[:FOUND_AT]-(v:Vulnerability)
RETURN v.template_id, v.name, v.severity, count(v) AS findings_count
ORDER BY findings_count DESC
LIMIT 10
```

### 9. Find All Injectable Parameters (Attack Surface)
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s)
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(port:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:HAS_ENDPOINT]->(e)
      -[:HAS_PARAMETER]->(p:Parameter {is_injectable: true})
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS_PARAMETER]->(p)
RETURN s.name AS host, svc.name AS service, port.number AS port, e.path AS endpoint, p.name AS parameter,
       p.position AS position, collect(v.category) AS vuln_types
```

### 10. HTTP Headers Analysis (Security Headers Check)
```cypher
MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
      -[:HAS_SUBDOMAIN]->(s)
      -[:RESOLVES_TO]->(:IP)
      -[:HAS_PORT]->(:Port)
      -[:RUNS_SERVICE]->(svc:Service)
      -[:SERVES_URL]->(u:BaseURL)
      -[:HAS_HEADER]->(h:Header)
WHERE h.is_security_header = true OR h.reveals_technology = true
RETURN s.name AS host, svc.name AS service, u.url AS url,
       collect({header: h.name, value: h.value, security: h.is_security_header}) AS headers
```

---

## 📋 Node Property Summary

| Node | Key Properties | Indexed |
|------|---------------|---------|
| Domain | name, user_id, project_id, target, modules_executed, whois_*, anonymous_mode, bruteforce_mode | ✅ Tenant composite unique |
| Subdomain | name, has_dns_records | ✅ Tenant composite unique |
| IP | address, version, is_cdn, cdn_name, asn | ✅ Tenant composite unique |
| Port | number, protocol, state, ip_address | ✅ Tenant composite unique |
| Service | name, product, version, banner, port_number, ip_address | ✅ Tenant composite unique |
| BaseURL | url, scheme, host, status_code, is_live, body_sha256 | ✅ Tenant composite unique |
| Endpoint | path, method, baseurl, has_parameters, source | ✅ Tenant composite unique |
| Parameter | name, position, endpoint_path, baseurl, is_injectable, sample_value | ✅ Tenant composite unique |
| Technology | name, version, categories, confidence, product, known_cve_count | ✅ Tenant composite unique |
| Certificate | subject_cn, issuer, not_before, not_after, source | ✅ Tenant composite unique |
| DNSRecord | type, value, subdomain, ttl | ✅ Tenant composite unique |
| Header | name, value, baseurl, is_security_header | ✅ Tenant composite unique |
| Traceroute | target_ip, scanner_ip, hops, distance, source | ✅ Tenant composite unique |
| Vulnerability | id, template_id, severity, category, matched_at, fuzzing_*, raw_request, raw_response, matched_ip | ✅ Unique (global) |
| CVE | id, cvss, severity, description, published | ✅ Unique (global) |
| MitreData | id, cve_id, cwe_id, cwe_name, cwe_description, abstraction, is_leaf | ✅ Unique (global) |
| Capec | capec_id, name, description, likelihood, severity, prerequisites | ✅ Unique (global) |
| ExploitGvm | id, source | ✅ Unique (global) |
| GithubHunt | id, target, scan_start_time, status, repos_scanned, secrets_found | ✅ Unique (global), ✅ Tenant index |
| GithubRepository | id, name | ✅ Unique (global), ✅ Tenant index |
| GithubPath | id, repository, path | ✅ Unique (global), ✅ Tenant index |
| GithubSecret | id, repository, path, secret_type, sample | ✅ Unique (global), ✅ Tenant index |
| GithubSensitiveFile | id, repository, path, secret_type | ✅ Unique (global), ✅ Tenant index |
| TrufflehogScan | id, target, scan_start_time, status, total_findings, verified_findings | ✅ Unique (global), ✅ Tenant index |
| TrufflehogRepository | id, name | ✅ Unique (global), ✅ Tenant index |
| TrufflehogFinding | id, detector_name, verified, file, commit, line, repository | ✅ Unique (global), ✅ Tenant index |
| Secret | id, secret_type, severity, source, source_url, base_url, sample | ✅ Unique (global), ✅ Tenant index |
| JsReconFinding | id, finding_type, severity, confidence, title, detail, source_url | ✅ Unique (global), ✅ Tenant index |

---

## 🚀 Initialization Cypher

Run this to set up constraints and indexes before importing data:

```cypher
// =============================================================================
// CONSTRAINTS — Tenant-scoped (per user_id + project_id)
// =============================================================================

CREATE CONSTRAINT domain_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE (d.name, d.user_id, d.project_id) IS UNIQUE;

CREATE CONSTRAINT subdomain_unique IF NOT EXISTS
FOR (s:Subdomain) REQUIRE (s.name, s.user_id, s.project_id) IS UNIQUE;

CREATE CONSTRAINT ip_unique IF NOT EXISTS
FOR (i:IP) REQUIRE (i.address, i.user_id, i.project_id) IS UNIQUE;

CREATE CONSTRAINT baseurl_unique IF NOT EXISTS
FOR (u:BaseURL) REQUIRE (u.url, u.user_id, u.project_id) IS UNIQUE;

CREATE CONSTRAINT port_unique IF NOT EXISTS
FOR (p:Port) REQUIRE (p.number, p.protocol, p.ip_address, p.user_id, p.project_id) IS UNIQUE;

CREATE CONSTRAINT service_unique IF NOT EXISTS
FOR (svc:Service) REQUIRE (svc.name, svc.port_number, svc.ip_address, svc.user_id, svc.project_id) IS UNIQUE;

CREATE CONSTRAINT technology_unique IF NOT EXISTS
FOR (t:Technology) REQUIRE (t.name, t.version, t.user_id, t.project_id) IS UNIQUE;

CREATE CONSTRAINT endpoint_unique IF NOT EXISTS
FOR (e:Endpoint) REQUIRE (e.path, e.method, e.baseurl, e.user_id, e.project_id) IS UNIQUE;

CREATE CONSTRAINT parameter_unique IF NOT EXISTS
FOR (p:Parameter) REQUIRE (p.name, p.position, p.endpoint_path, p.baseurl, p.user_id, p.project_id) IS UNIQUE;

CREATE CONSTRAINT header_unique IF NOT EXISTS
FOR (h:Header) REQUIRE (h.name, h.value, h.baseurl, h.user_id, h.project_id) IS UNIQUE;

CREATE CONSTRAINT dnsrecord_unique IF NOT EXISTS
FOR (dns:DNSRecord) REQUIRE (dns.type, dns.value, dns.subdomain, dns.user_id, dns.project_id) IS UNIQUE;

CREATE CONSTRAINT certificate_unique IF NOT EXISTS
FOR (c:Certificate) REQUIRE (c.subject_cn, c.user_id, c.project_id) IS UNIQUE;

CREATE CONSTRAINT traceroute_unique IF NOT EXISTS
FOR (tr:Traceroute) REQUIRE (tr.target_ip, tr.user_id, tr.project_id) IS UNIQUE;

CREATE CONSTRAINT secret_unique IF NOT EXISTS
FOR (s:Secret) REQUIRE (s.id) IS UNIQUE;

// =============================================================================
// CONSTRAINTS — Global (shared reference nodes)
// =============================================================================

CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;

CREATE CONSTRAINT cve_unique IF NOT EXISTS
FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT mitredata_unique IF NOT EXISTS
FOR (m:MitreData) REQUIRE m.id IS UNIQUE;

CREATE CONSTRAINT capec_unique IF NOT EXISTS
FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE;

CREATE CONSTRAINT exploitgvm_unique IF NOT EXISTS
FOR (e:ExploitGvm) REQUIRE e.id IS UNIQUE;

// =============================================================================
// INDEXES (query performance)
// =============================================================================

// =============================================================================
// TENANT COMPOSITE INDEXES (CRITICAL for multi-tenant query performance)
// All queries MUST filter by user_id + project_id FIRST to leverage these indexes
// =============================================================================

CREATE INDEX idx_domain_tenant IF NOT EXISTS
FOR (d:Domain) ON (d.user_id, d.project_id);

CREATE INDEX idx_subdomain_tenant IF NOT EXISTS
FOR (s:Subdomain) ON (s.user_id, s.project_id);

CREATE INDEX idx_subdomain_status IF NOT EXISTS
FOR (s:Subdomain) ON (s.status);

CREATE INDEX idx_ip_tenant IF NOT EXISTS
FOR (i:IP) ON (i.user_id, i.project_id);

CREATE INDEX idx_port_tenant IF NOT EXISTS
FOR (p:Port) ON (p.user_id, p.project_id);

CREATE INDEX idx_service_tenant IF NOT EXISTS
FOR (svc:Service) ON (svc.user_id, svc.project_id);

CREATE INDEX idx_baseurl_tenant IF NOT EXISTS
FOR (u:BaseURL) ON (u.user_id, u.project_id);

CREATE INDEX idx_endpoint_tenant IF NOT EXISTS
FOR (e:Endpoint) ON (e.user_id, e.project_id);

CREATE INDEX idx_parameter_tenant IF NOT EXISTS
FOR (p:Parameter) ON (p.user_id, p.project_id);

CREATE INDEX idx_technology_tenant IF NOT EXISTS
FOR (t:Technology) ON (t.user_id, t.project_id);

CREATE INDEX idx_vulnerability_tenant IF NOT EXISTS
FOR (v:Vulnerability) ON (v.user_id, v.project_id);

CREATE INDEX idx_cve_tenant IF NOT EXISTS
FOR (c:CVE) ON (c.user_id, c.project_id);

CREATE INDEX idx_mitredata_tenant IF NOT EXISTS
FOR (m:MitreData) ON (m.user_id, m.project_id);

CREATE INDEX idx_capec_tenant IF NOT EXISTS
FOR (c:Capec) ON (c.user_id, c.project_id);

CREATE INDEX idx_dnsrecord_tenant IF NOT EXISTS
FOR (dns:DNSRecord) ON (dns.user_id, dns.project_id);

CREATE INDEX idx_header_tenant IF NOT EXISTS
FOR (h:Header) ON (h.user_id, h.project_id);

CREATE INDEX idx_traceroute_tenant IF NOT EXISTS
FOR (tr:Traceroute) ON (tr.user_id, tr.project_id);

CREATE INDEX idx_secret_tenant IF NOT EXISTS
FOR (s:Secret) ON (s.user_id, s.project_id);

// =============================================================================
// ADDITIONAL INDEXES (attribute-based lookups within tenant data)
// =============================================================================

// Domain queries
CREATE INDEX domain_target IF NOT EXISTS
FOR (d:Domain) ON (d.target);

// Subdomain lookups
CREATE INDEX subdomain_name IF NOT EXISTS
FOR (s:Subdomain) ON (s.name);

// IP lookups
CREATE INDEX ip_address IF NOT EXISTS
FOR (i:IP) ON (i.address);

CREATE INDEX ip_cdn IF NOT EXISTS
FOR (i:IP) ON (i.is_cdn);

// BaseURL queries
CREATE INDEX baseurl_status IF NOT EXISTS
FOR (u:BaseURL) ON (u.status_code);

CREATE INDEX baseurl_live IF NOT EXISTS
FOR (u:BaseURL) ON (u.is_live);

// Technology lookups
CREATE INDEX tech_name IF NOT EXISTS
FOR (t:Technology) ON (t.name);

CREATE INDEX tech_name_version IF NOT EXISTS
FOR (t:Technology) ON (t.name, t.version);

CREATE INDEX tech_product IF NOT EXISTS
FOR (t:Technology) ON (t.product);

// Vulnerability queries (critical for attack chain analysis)
CREATE INDEX vuln_severity IF NOT EXISTS
FOR (v:Vulnerability) ON (v.severity);

CREATE INDEX vuln_category IF NOT EXISTS
FOR (v:Vulnerability) ON (v.category);

CREATE INDEX vuln_template IF NOT EXISTS
FOR (v:Vulnerability) ON (v.template_id);

CREATE INDEX vuln_dast IF NOT EXISTS
FOR (v:Vulnerability) ON (v.is_dast_finding);

// CVE queries
CREATE INDEX cve_severity IF NOT EXISTS
FOR (c:CVE) ON (c.severity);

CREATE INDEX cve_cvss IF NOT EXISTS
FOR (c:CVE) ON (c.cvss);

// Parameter queries (attack surface)
CREATE INDEX param_injectable IF NOT EXISTS
FOR (p:Parameter) ON (p.is_injectable);

// Secret queries
CREATE INDEX idx_secret_type IF NOT EXISTS
FOR (s:Secret) ON (s.secret_type);

CREATE INDEX idx_secret_severity IF NOT EXISTS
FOR (s:Secret) ON (s.severity);

CREATE INDEX idx_secret_source IF NOT EXISTS
FOR (s:Secret) ON (s.source);

```

---

## 📝 Notes for Implementation

1. **Deduplication**: Before creating nodes, check if they exist (MERGE vs CREATE)
2. **Timestamps**: Store as Neo4j datetime type for proper querying
3. **Arrays**: Neo4j supports array properties (tags, references, etc.)
4. **Large Text**: Keep descriptions under 10KB, store curl_command and request/response separately if needed
5. **Batch Import**: For large scans, use APOC procedures for batch imports

---

## 🗺️ JSON to Graph Mapping Reference

| JSON Path | Node Type | Key Properties |
|-----------|-----------|----------------|
| `metadata.*` | Domain | scan_timestamp, scan_type, target, modules_executed, anonymous_mode, bruteforce_mode |
| `whois.*` | Domain | registrar, creation_date, expiration_date, organization, country, city, state, address, registrant_postal_code, domain_name, referral_url, reseller |
| `subdomains[]` | Subdomain | name |
| `dns.subdomains.<host>.records.*` | DNSRecord | type, value |
| `dns.subdomains.<host>.ips.*` | IP | address, version |
| `port_scan.by_host.<host>.port_details[]` | Port | number, protocol |
| `port_scan.by_host.<host>.port_details[].service` | Service | name |
| `port_scan.ip_to_hostnames.*` | (relationship data) | IP ↔ Subdomain mapping |
| `http_probe.by_url.<url>.*` | BaseURL | url, status_code, content_*, server, cdn, *_hash, word_count, line_count, cname, asn |
| `http_probe.by_url.<url>.headers.*` | Header | name, value |
| `http_probe.by_url.<url>.technologies[]` | Technology | name, version |
| `http_probe.wappalyzer.all_technologies.*` | Technology | categories, confidence, versions_found |
| `vuln_scan.discovered_urls.dast_urls_with_params[]` | Endpoint | path, method, baseurl, has_parameters, source |
| `vuln_scan.discovered_urls.dast_urls_with_params[]` | Parameter | name, position, endpoint_path, baseurl, sample_value, is_injectable |
| `resource_enum.by_base_url.<url>.endpoints[]` | Endpoint | path, method, category, query_param_count, body_param_count, path_param_count, urls_found |
| `resource_enum.by_base_url.<url>.endpoints[].parameters.body[]` | Parameter | name, position='body', type, input_type, required |
| `resource_enum.forms[]` | Endpoint (update) | is_form, form_enctype, form_found_at_pages, form_input_names, form_count |
| `vuln_scan.by_target.<host>.findings[]` | Vulnerability | template_id, severity, matched_at, fuzzing_*, raw_request, raw_response, matched_ip, matcher_status, max_requests |
| `vuln_scan.by_target.<host>.findings[].raw.*` | Vulnerability | curl_command, extracted_results, extractor_name, authors (from raw.info.author) |
| `nmap_scan.services_detected[]` | Technology | name (product/version), version, cpe, source='nmap' |
| `nmap_scan.by_host.<host>.port_details[]` | Port (enriched) | product, version, cpe, nmap_scanned=true |
| `nmap_scan.by_host.<host>.port_details[]` | Service (enriched) | product, version, cpe |
| `nmap_scan.nse_vulns[]` | Vulnerability | name (script_id), severity, type='nmap_nse', output, state, cve_id |
| `nmap_scan.nse_vulns[].cve` | CVE | id, source='nmap_nse' |
| `technology_cves.by_technology.<tech>.*` | Technology | product, version, cve_count, critical_cve_count, high_cve_count |
| `technology_cves.by_technology.<tech>.cves[]` | CVE | id, cvss, severity, description, published, source, url, references |
| `technology_cves.by_technology.<tech>.cves[].mitre_attack.cwe_hierarchy` | MitreData | cwe_id, cwe_name, cwe_description, abstraction, is_leaf |
| `technology_cves.by_technology.<tech>.cves[].mitre_attack.cwe_hierarchy.child` | MitreData | (nested CWE hierarchy) |
| `technology_cves.by_technology.<tech>.cves[].mitre_attack.cwe_hierarchy.*.related_capec[]` | Capec | id, name, description, likelihood, severity, prerequisites, execution_flow |

### Relationship Mapping

| JSON Context | Relationship | From → To |
|--------------|--------------|-----------|
| `dns.subdomains.<host>.ips.ipv4[]` | RESOLVES_TO | Subdomain → IP |
| `port_scan.by_host.<host>.port_details[]` | HAS_PORT | IP → Port |
| `port_scan.by_host.<host>.port_details[].service` | RUNS_SERVICE | Port → Service |
| `port_scan.ip_to_hostnames.<ip>[]` | RESOLVES_TO | Subdomain → IP |
| `http_probe.by_url.<url>` | SERVES_URL | Service → BaseURL |
| `resource_enum.by_base_url.<url>` (orphan fallback) | HAS_BASE_URL | Subdomain → BaseURL |
| `http_probe.by_url.<url>.technologies[]` | USES_TECHNOLOGY | BaseURL → Technology |
| `vuln_scan.discovered_urls.dast_urls_with_params[]` | HAS_ENDPOINT | BaseURL → Endpoint |
| `vuln_scan.discovered_urls.dast_urls_with_params[]` | HAS_PARAMETER | Endpoint → Parameter |
| `vuln_scan.by_target.<host>.findings[]` | FOUND_AT | Vulnerability → Endpoint |
| `vuln_scan.by_target.<host>.findings[].raw.fuzzing_parameter` | AFFECTS_PARAMETER | Vulnerability → Parameter |
| `nmap_scan.services_detected[]` | USES_TECHNOLOGY | Service → Technology |
| `nmap_scan.services_detected[]` | HAS_TECHNOLOGY | Port → Technology |
| `nmap_scan.nse_vulns[]` | AFFECTS | Vulnerability → Port |
| `nmap_scan.nse_vulns[]` | FOUND_ON | Vulnerability → Technology |
| `nmap_scan.nse_vulns[].cve` | HAS_CVE | Vulnerability → CVE |
| `nmap_scan.nse_vulns[].cve` (+ services_detected match) | HAS_KNOWN_CVE | Technology → CVE |
| `technology_cves.by_technology.<tech>.cves[]` | HAS_KNOWN_CVE | Technology → CVE |
| `technology_cves.by_technology.<tech>.cves[].mitre_attack.cwe_hierarchy` | HAS_CWE | CVE → MitreData |
| `technology_cves.by_technology.<tech>.cves[].mitre_attack.cwe_hierarchy.*.related_capec[]` | HAS_CAPEC | MitreData → Capec |

---

## 📊 Derived/Aggregation Data (No Dedicated Nodes)

The JSON contains several aggregation structures that don't need dedicated nodes since they can be computed from the graph:

| JSON Path | Description | Query Alternative |
|-----------|-------------|-------------------|
| `http_probe.by_host.<host>.*` | Per-host summary (urls, technologies, servers, status_codes) | `MATCH (s:Subdomain)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SERVICE]->(svc)-[:SERVES_URL]->(u)...` |
| `http_probe.servers_found.*` | Server → URLs mapping | `MATCH (u:BaseURL) RETURN u.server, collect(u.url)` |
| `http_probe.technologies_found.*` | Technology → URLs mapping | `MATCH (u)-[:USES_TECHNOLOGY]->(t) RETURN t.name_version, collect(u.url)` |
| `http_probe.summary.by_status_code.*` | Count by status code | `MATCH (u:BaseURL) RETURN u.status_code, count(*)` |
| `vuln_scan.by_category.*` | Vulnerabilities grouped by category | `MATCH (v:Vulnerability) RETURN v.category, collect(v)` |
| `vuln_scan.by_target.<host>.severity_counts` | Severity counts per target | `MATCH (v:Vulnerability {target: $host}) RETURN v.severity, count(*)` |
| `vuln_scan.vulnerabilities.critical[]` | Critical vulns list | `MATCH (v:Vulnerability {severity: "critical"}) RETURN v` |
| `port_scan.all_ports[]` | All open ports list | `MATCH (p:Port) RETURN DISTINCT p.number` |

These are pre-computed for convenience in the JSON but the graph stores the source data.

---

## 🕵️ GitHub Intelligence Nodes

GitHub Secret Hunt findings are stored in a 5-level node hierarchy linked to the Domain root.
Only `SECRET` and `SENSITIVE_FILE` findings are ingested; `HIGH_ENTROPY` is excluded (too noisy).
Findings are deduplicated across commit history (same repo + path + secret_type = one node).

### GithubHunt (Scan Metadata)

```cypher
(:GithubHunt {
    id: "github-hunt-<user_id>-<project_id>",
    user_id: "samgiam",
    project_id: "first_test",
    target: "samugit83",
    scan_start_time: "2026-02-12T23:10:04.193830",
    scan_end_time: "2026-02-13T02:35:05.335142",
    duration_seconds: 12301.14,
    status: "completed",
    repos_scanned: 16,
    files_scanned: 15695,
    commits_scanned: 247,
    secrets_found: 952,
    sensitive_files: 18
})
```

**Relationship:** `Domain -[:HAS_GITHUB_HUNT]-> GithubHunt`

### GithubRepository (Scanned Repository)

```cypher
(:GithubRepository {
    id: "github-repo-<user_id>-<project_id>-<org/repo>",
    name: "samugit83/ai-superagent",
    user_id: "samgiam",
    project_id: "first_test"
})
```

**Relationship:** `GithubHunt -[:HAS_REPOSITORY]-> GithubRepository`

### GithubPath (File Path Within Repository)

Groups all findings from the same file path together.

```cypher
(:GithubPath {
    id: "github-path-<user_id>-<project_id>-<hash>",
    user_id: "samgiam",
    project_id: "first_test",
    repository: "samugit83/ai-superagent",
    path: "websocket_server/.env"
})
```

**Relationship:** `GithubRepository -[:HAS_PATH]-> GithubPath`

### GithubSecret (Leaked Secret Finding)

Leaf node for `type: "SECRET"` findings — API keys, credentials, tokens, connection strings.

```cypher
(:GithubSecret {
    id: "github-secret-<user_id>-<project_id>-<hash>",
    user_id: "samgiam",
    project_id: "first_test",
    repository: "samugit83/ai-superagent",
    path: "websocket_server/.env",
    secret_type: "Twilio Account SID",
    timestamp: "2026-02-12T23:10:31.917308",
    matches: 2,                            // (optional) number of matches
    sample: "AC5dt8wSP3BQ..."              // (optional) redacted sample
})
```

**Relationship:** `GithubPath -[:CONTAINS_SECRET]-> GithubSecret`

### GithubSensitiveFile (Sensitive File Finding)

Leaf node for `type: "SENSITIVE_FILE"` findings — .env files, config files, key files.

```cypher
(:GithubSensitiveFile {
    id: "github-sensitivefi-<user_id>-<project_id>-<hash>",
    user_id: "samgiam",
    project_id: "first_test",
    repository: "samugit83/ai-superagent",
    path: ".env",
    secret_type: "Environment Configuration File",
    timestamp: "2026-02-12T23:10:31.917308",
    matches: 1
})
```

**Relationship:** `GithubPath -[:CONTAINS_SENSITIVE_FILE]-> GithubSensitiveFile`

### Full Chain

```
Domain -[:HAS_GITHUB_HUNT]-> GithubHunt
    -[:HAS_REPOSITORY]-> GithubRepository
        -[:HAS_PATH]-> GithubPath
            -[:CONTAINS_SECRET]-> GithubSecret
            -[:CONTAINS_SENSITIVE_FILE]-> GithubSensitiveFile
```

### Constraints & Indexes

```cypher
CREATE CONSTRAINT githubhunt_unique IF NOT EXISTS
FOR (gh:GithubHunt) REQUIRE gh.id IS UNIQUE;

CREATE CONSTRAINT githubrepo_unique IF NOT EXISTS
FOR (gr:GithubRepository) REQUIRE gr.id IS UNIQUE;

CREATE CONSTRAINT githubpath_unique IF NOT EXISTS
FOR (gp:GithubPath) REQUIRE gp.id IS UNIQUE;

CREATE CONSTRAINT githubsecret_unique IF NOT EXISTS
FOR (gs:GithubSecret) REQUIRE gs.id IS UNIQUE;

CREATE CONSTRAINT githubsensitivefile_unique IF NOT EXISTS
FOR (gsf:GithubSensitiveFile) REQUIRE gsf.id IS UNIQUE;

CREATE INDEX idx_githubhunt_tenant IF NOT EXISTS
FOR (gh:GithubHunt) ON (gh.user_id, gh.project_id);

CREATE INDEX idx_githubrepo_tenant IF NOT EXISTS
FOR (gr:GithubRepository) ON (gr.user_id, gr.project_id);

CREATE INDEX idx_githubpath_tenant IF NOT EXISTS
FOR (gp:GithubPath) ON (gp.user_id, gp.project_id);

CREATE INDEX idx_githubsecret_tenant IF NOT EXISTS
FOR (gs:GithubSecret) ON (gs.user_id, gs.project_id);

CREATE INDEX idx_githubsensitivefile_tenant IF NOT EXISTS
FOR (gsf:GithubSensitiveFile) ON (gsf.user_id, gsf.project_id);
```

### Example Queries

```cypher
// Full chain: all GitHub findings for a project
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_GITHUB_HUNT]->(gh:GithubHunt)
      -[:HAS_REPOSITORY]->(gr:GithubRepository)
      -[:HAS_PATH]->(gp:GithubPath)
OPTIONAL MATCH (gp)-[:CONTAINS_SECRET]->(gs:GithubSecret)
OPTIONAL MATCH (gp)-[:CONTAINS_SENSITIVE_FILE]->(gsf:GithubSensitiveFile)
RETURN gr.name AS repository, gp.path AS path, gs.secret_type AS secret, gsf.secret_type AS sensitive_file

// Only leaked secrets (API keys, credentials, tokens)
MATCH (gs:GithubSecret {user_id: $userId, project_id: $projectId})
RETURN gs.repository, gs.secret_type, gs.path, gs.sample

// Only sensitive files (.env, config, key files)
MATCH (gsf:GithubSensitiveFile {user_id: $userId, project_id: $projectId})
RETURN gsf.repository, gsf.secret_type, gsf.path

// Count findings per repository
MATCH (gr:GithubRepository {user_id: $userId, project_id: $projectId})
      -[:HAS_PATH]->(gp:GithubPath)
OPTIONAL MATCH (gp)-[:CONTAINS_SECRET]->(gs:GithubSecret)
OPTIONAL MATCH (gp)-[:CONTAINS_SENSITIVE_FILE]->(gsf:GithubSensitiveFile)
WITH gr, count(gs) AS secrets, count(gsf) AS sensitive_files
RETURN gr.name AS repo, secrets, sensitive_files ORDER BY secrets + sensitive_files DESC
```

---

## 🔐 TruffleHog Secret Scanner Nodes

TruffleHog scan findings are stored in a 3-level node hierarchy linked to the Domain root.
TruffleHog uses detector-based credential verification and deep git history analysis.
Findings are deduplicated by `{repository}:{file}:{line}:{detector_name}`.

### TrufflehogScan (Scan Metadata)

```cypher
(:TrufflehogScan {
    id: "trufflehog-scan-<user_id>-<project_id>",
    user_id: "samgiam",
    project_id: "first_test",
    target: "samugit83",
    scan_start_time: "2026-03-20T14:10:04.193830",
    scan_end_time: "2026-03-20T16:35:05.335142",
    duration_seconds: 8701.14,
    status: "completed",
    total_findings: 47,
    verified_findings: 12,
    unverified_findings: 35,
    repositories_scanned: 16,
    updated_at: "2026-03-20T16:35:05.335142"
})
```

**Relationship:** `Domain -[:HAS_TRUFFLEHOG_SCAN]-> TrufflehogScan`

### TrufflehogRepository (Scanned Repository)

```cypher
(:TrufflehogRepository {
    id: "trufflehog-repo-<user_id>-<project_id>-<hash>",
    name: "samugit83/ai-superagent",
    user_id: "samgiam",
    project_id: "first_test",
    updated_at: "2026-03-20T16:35:05.335142"
})
```

**Relationship:** `TrufflehogScan -[:HAS_REPOSITORY]-> TrufflehogRepository`

### TrufflehogFinding (Detected Credential Finding)

Leaf node for individual credential findings detected by TruffleHog's detector engine.

```cypher
(:TrufflehogFinding {
    id: "trufflehog-finding-<user_id>-<project_id>-<hash>",
    user_id: "samgiam",
    project_id: "first_test",
    detector_name: "AWS",
    detector_description: "Amazon Web Services access key",
    verified: true,
    redacted: "AKIA2E0A8F3B1...",
    file: "deploy/config.yml",
    commit: "a3b2c1d",
    line: 42,
    link: "https://github.com/samugit83/ai-superagent/blob/a3b2c1d/deploy/config.yml#L42",
    extra_data: "{}",
    repository: "samugit83/ai-superagent",
    timestamp: "2026-03-20T14:12:31.917308",
    updated_at: "2026-03-20T14:12:31.917308"
})
```

**Dedup key:** `{repository}:{file}:{line}:{detector_name}`

**Relationship:** `TrufflehogRepository -[:HAS_FINDING]-> TrufflehogFinding`

### Full Chain

```
Domain -[:HAS_TRUFFLEHOG_SCAN]-> TrufflehogScan
    -[:HAS_REPOSITORY]-> TrufflehogRepository
        -[:HAS_FINDING]-> TrufflehogFinding
```

### Constraints & Indexes

```cypher
CREATE CONSTRAINT trufflehogscan_unique IF NOT EXISTS
FOR (ts:TrufflehogScan) REQUIRE ts.id IS UNIQUE;

CREATE CONSTRAINT trufflehogrepo_unique IF NOT EXISTS
FOR (tr:TrufflehogRepository) REQUIRE tr.id IS UNIQUE;

CREATE CONSTRAINT trufflehogfinding_unique IF NOT EXISTS
FOR (tf:TrufflehogFinding) REQUIRE tf.id IS UNIQUE;

CREATE INDEX idx_trufflehogscan_tenant IF NOT EXISTS
FOR (ts:TrufflehogScan) ON (ts.user_id, ts.project_id);

CREATE INDEX idx_trufflehogrepo_tenant IF NOT EXISTS
FOR (tr:TrufflehogRepository) ON (tr.user_id, tr.project_id);

CREATE INDEX idx_trufflehogfinding_tenant IF NOT EXISTS
FOR (tf:TrufflehogFinding) ON (tf.user_id, tf.project_id);
```

### Example Queries

```cypher
// Full chain: all TruffleHog findings for a project
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_TRUFFLEHOG_SCAN]->(ts:TrufflehogScan)
      -[:HAS_REPOSITORY]->(tr:TrufflehogRepository)
      -[:HAS_FINDING]->(tf:TrufflehogFinding)
RETURN tr.name AS repository, tf.detector_name AS detector, tf.file AS file, tf.verified AS verified

// Only verified findings
MATCH (tf:TrufflehogFinding {user_id: $userId, project_id: $projectId, verified: true})
RETURN tf.repository, tf.detector_name, tf.file, tf.line, tf.redacted

// Count findings per repository
MATCH (tr:TrufflehogRepository {user_id: $userId, project_id: $projectId})
      -[:HAS_FINDING]->(tf:TrufflehogFinding)
WITH tr, count(tf) AS total, sum(CASE WHEN tf.verified THEN 1 ELSE 0 END) AS verified
RETURN tr.name AS repo, total, verified ORDER BY total DESC
```

---

## 🔍 JS Recon Scanner

JS Recon performs deep JavaScript analysis beyond inline jsluice. It uses a hierarchical graph structure where each analyzed JS file is a node, and all findings from that file are linked to it.

### JsReconFinding (JS File + Analysis Findings)

The `JsReconFinding` label is used for two sub-types:

**1. JS File nodes** (`finding_type='js_file'`) -- one per analyzed JavaScript file:

```
(:JsReconFinding {
  id: "jsrf-{user_id}-{project_id}-file-{url_hash}",
  user_id: "{user_id}",
  project_id: "{project_id}",
  finding_type: "js_file",
  title: "app.js",                          // filename
  detail: "https://target.com/js/app.js",   // full URL or upload://filename
  is_uploaded: false,                        // true for manually uploaded files
  source_url: "https://target.com/js/app.js",
  base_url: "https://target.com",           // or 'upload' for uploaded files
  source: "js_recon",
  severity: "info",
  confidence: "high",
  discovered_at: "ISO timestamp"
})
```

**2. Finding nodes** (`finding_type != 'js_file'`) -- individual findings linked to their parent file:

```
(:JsReconFinding {
  id: "jsrf-{user_id}-{project_id}-{hash}",
  user_id: "{user_id}",
  project_id: "{project_id}",
  finding_type: "dependency_confusion|source_map_exposure|dom_sink|framework|dev_comment|source_map_reference",
  severity: "critical|high|medium|low|info",
  confidence: "high|medium|low",
  title: "Human-readable finding title",
  detail: "Full finding detail",
  evidence: "Matched pattern or code snippet (max 500 chars)",
  source_url: "JS file URL where finding was discovered",
  base_url: "Parent BaseURL or 'upload'",
  source: "js_recon",
  discovered_at: "ISO timestamp"
})
```

**Relationships (hierarchical: parent -> file -> findings):**
- `BaseURL -[:HAS_JS_FILE]-> JsReconFinding(js_file)` -- pipeline-crawled JS files
- `Domain -[:HAS_JS_FILE]-> JsReconFinding(js_file)` -- uploaded JS files
- `JsReconFinding(js_file) -[:HAS_JS_FINDING]-> JsReconFinding` -- findings from that file
- `JsReconFinding(js_file) -[:HAS_SECRET]-> Secret` -- secrets found in that file
- `JsReconFinding(js_file) -[:HAS_ENDPOINT]-> Endpoint` -- endpoints extracted from that file

### Extended Secret Properties (source='js_recon')

JS Recon secrets extend the existing Secret node with:
- `validation_status`: validated, invalid, unvalidated, skipped, incomplete
- `validation_info`: JSON string with validator response (scope, account info)
- `confidence`: high, medium, low
- `detection_method`: regex
- `key_type`: category (cloud, payment, auth, js_service, etc.)

### Constraints & Indexes

```cypher
CREATE CONSTRAINT jsreconfinding_unique IF NOT EXISTS
FOR (jf:JsReconFinding) REQUIRE jf.id IS UNIQUE;

CREATE INDEX idx_jsreconfinding_tenant IF NOT EXISTS
FOR (jf:JsReconFinding) ON (jf.user_id, jf.project_id);
```

### Example Queries

```cypher
-- All analyzed JS files
MATCH (file:JsReconFinding {finding_type: 'js_file', user_id: $userId, project_id: $projectId})
RETURN file.title as filename, file.source_url as url, file.is_uploaded as uploaded

-- All findings from a specific JS file
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(jf:JsReconFinding)
WHERE file.title CONTAINS 'app.js'
RETURN jf.finding_type, jf.severity, jf.title, jf.detail

-- Secrets found in JS files (traverses file hierarchy)
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s:Secret)
WHERE file.user_id = $userId AND file.project_id = $projectId
RETURN file.title as js_file, s.secret_type, s.sample, s.severity, s.validation_status

-- Full hierarchy: Domain -> JS files -> findings
MATCH (d:Domain)-[:HAS_JS_FILE]->(file:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(jf:JsReconFinding)
RETURN d.name, file.title, jf.finding_type, jf.severity, jf.title
ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
```

---

## ⚔️ Attack Chain Graph (EvoGraph)

The Attack Chain Graph is an evolutionary, persistent graph that runs **parallel** to the recon graph. Every agent conversation maps 1:1 to an `AttackChain` node (`chain_id` = session ID). Steps, findings, decisions, and failures are first-class nodes with typed intra-chain relationships and bridge relationships to the recon graph.

This replaces the standalone agent-created `Exploit` node with the richer `ChainFinding(finding_type="exploit_success")`.

### Design Principles

1. **1:1 Session Mapping**: Each agent conversation = one `AttackChain` node
2. **Causal Linking**: `ChainStep` nodes connected via `NEXT_STEP` for temporal ordering
3. **Typed Intelligence**: Findings, failures, and decisions are first-class nodes (not just strings)
4. **Bridge Relationships**: Chain nodes link to recon graph entities (IP, CVE, Service) via typed edges
5. **Cross-Session Memory**: Agent queries prior chains to avoid repeating failed approaches
6. **Async-Safe Writes**: Step writes are synchronous (blocking) to prevent race conditions; finding/failure/decision writes are fire-and-forget (async) — errors logged but never crash the agent
7. **MERGE Idempotency**: All writes use MERGE for checkpoint recovery safety

---

### AttackChain (Attack Session Root)

Root node for an agent attack session. Created when the agent starts a new conversation.

```cypher
(:AttackChain {
    chain_id: "session-abc123",              // Unique, equals agent session ID
    user_id: "samgiam",
    project_id: "first_test",
    title: "Exploit CVE-2021-41773 on target",  // First message excerpt
    objective: "Test Apache path traversal",
    status: "completed",                     // active | completed | aborted
    attack_path_type: "cve_exploit",         // cve_exploit | brute_force_credential_guess | <term>-unclassified
    total_steps: 8,
    successful_steps: 6,
    failed_steps: 2,
    phases_reached: ["informational", "exploitation"],
    final_outcome: "Exploitation successful via CVE-2021-41773",
    created_at: datetime(),
    updated_at: datetime()
})
```

**Relationships:**
- `AttackChain -[:HAS_STEP {order: N}]-> ChainStep` — Chain contains step (order = iteration)
- `AttackChain -[:CHAIN_TARGETS]-> Domain` — Always (project root)
- `AttackChain -[:CHAIN_TARGETS]-> IP` — When objective mentions an IP
- `AttackChain -[:CHAIN_TARGETS]-> Subdomain` — When objective mentions a hostname
- `AttackChain -[:CHAIN_TARGETS]-> Port` — When objective mentions a port
- `AttackChain -[:CHAIN_TARGETS]-> CVE` — When objective mentions CVE IDs

### ChainStep (Tool Execution Step)

Each tool execution in an attack chain. Contains the agent's thought process, tool output, and analysis.

```cypher
(:ChainStep {
    step_id: "step-uuid-123",               // Unique UUID
    chain_id: "session-abc123",
    user_id: "samgiam",
    project_id: "first_test",
    iteration: 3,
    phase: "exploitation",                   // informational | exploitation | post_exploitation
    tool_name: "metasploit_console",
    tool_args_summary: "{command: 'search CVE-2021-41773'}",
    thought: "Need to find a Metasploit module for this CVE...",
    reasoning: "CVE-2021-41773 is a path traversal in Apache 2.4.49",
    output_summary: "1 result: exploit/multi/http/apache_normalize_path_rce",
    output_analysis: "Found matching module. Rank: excellent.",
    success: true,
    error_message: null,
    duration_ms: 1200,
    created_at: datetime()
})
```

**Relationships:**
- `ChainStep -[:NEXT_STEP]-> ChainStep` — Sequential step ordering
- `ChainStep -[:PRODUCED]-> ChainFinding` — Step produced a finding
- `ChainStep -[:FAILED_WITH]-> ChainFailure` — Step failed with error
- `ChainStep -[:LED_TO]-> ChainDecision` — Step led to a strategic decision
- `ChainStep -[:STEP_TARGETED]-> IP` — Step targeted an IP (bridge to recon)
- `ChainStep -[:STEP_TARGETED]-> Subdomain` — Step targeted a hostname (bridge to recon)
- `ChainStep -[:STEP_TARGETED]-> Port` — Step targeted a port (bridge to recon)
- `ChainStep -[:STEP_EXPLOITED]-> CVE` — Step exploited a CVE (bridge to recon)
- `ChainStep -[:STEP_IDENTIFIED]-> Technology` — Step identified a technology (bridge to recon)

### ChainFinding (Discovery / Exploit Result)

A discovery made during an attack chain. Replaces the standalone `Exploit` node when `finding_type="exploit_success"`.

```cypher
(:ChainFinding {
    finding_id: "finding-uuid-456",          // Unique UUID
    chain_id: "session-abc123",
    user_id: "samgiam",
    project_id: "first_test",
    finding_type: "exploit_success",         // See finding_type enum below
    severity: "critical",                    // critical | high | medium | low | info
    title: "Meterpreter session opened via CVE-2021-41773",
    description: "Apache path traversal exploited for RCE",
    evidence: "Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:443)",
    confidence: 95,                          // 0-100
    phase: "exploitation",
    // Exploit-specific properties (only for finding_type="exploit_success"):
    attack_type: "cve_exploit",
    target_ip: "10.0.0.5",
    target_port: 443,
    cve_ids: ["CVE-2021-41773"],
    metasploit_module: "exploit/multi/http/apache_normalize_path_rce",
    payload: "linux/x64/meterpreter/reverse_tcp",
    session_id: 1,
    report: "Structured exploitation report...",
    commands_used: ["search CVE-2021-41773", "use 0", "set RHOSTS ...", "exploit"],
    created_at: datetime()
})
```

**Finding types:** `vulnerability_confirmed`, `credential_found`, `exploit_success`, `access_gained`, `privilege_escalation`, `service_identified`, `exploit_module_found`, `defense_detected`, `configuration_found`, `custom`

**Relationships:**
- `ChainFinding -[:FOUND_ON]-> IP` — Finding discovered on IP (bridge to recon)
- `ChainFinding -[:FOUND_ON]-> Subdomain` — Finding discovered on subdomain (bridge to recon)
- `ChainFinding -[:FINDING_RELATES_CVE]-> CVE` — Finding relates to CVE (bridge to recon)
- `ChainFinding -[:CREDENTIAL_FOR]-> Service` — Credential found for service (bridge to recon)

### ChainDecision (Strategic Pivot)

A strategic decision point in an attack chain — phase transitions, strategy changes, target switches.

```cypher
(:ChainDecision {
    decision_id: "decision-uuid-789",        // Unique UUID
    chain_id: "session-abc123",
    user_id: "samgiam",
    project_id: "first_test",
    decision_type: "phase_transition",       // phase_transition | strategy_change | target_switch
    from_state: "informational",
    to_state: "exploitation",
    reason: "Found exploitable CVE-2021-41773 on Apache 2.4.49",
    made_by: "user",                         // agent | user
    approved: true,
    created_at: datetime()
})
```

**Relationships:**
- `ChainStep -[:LED_TO]-> ChainDecision` — Step triggered this decision
- `ChainDecision -[:DECISION_PRECEDED]-> ChainStep` — Decision preceded this next step (connects decision into the sequential flow)

### ChainFailure (Failed Attempt with Lesson)

A failed attempt with a lesson learned, enabling the agent to avoid repeating mistakes across sessions.

```cypher
(:ChainFailure {
    failure_id: "failure-uuid-012",          // Unique UUID
    chain_id: "session-abc123",
    user_id: "samgiam",
    project_id: "first_test",
    failure_type: "exploit_failed",          // exploit_failed | authentication_failed | tool_error | timeout | connection_refused
    tool_name: "metasploit_console",
    error_category: "connection",
    error_message: "Connection refused on port 80",
    lesson_learned: "Target filters HTTP traffic, try HTTPS (443) instead",
    retry_possible: true,
    phase: "exploitation",
    created_at: datetime()
})
```

**Relationship:** `ChainStep -[:FAILED_WITH]-> ChainFailure`

### Full Chain

```
AttackChain -[:HAS_STEP {order: N}]-> ChainStep
    -[:NEXT_STEP]-> ChainStep (sequential linking)
    -[:PRODUCED]-> ChainFinding
    -[:FAILED_WITH]-> ChainFailure
    -[:LED_TO]-> ChainDecision
        -[:DECISION_PRECEDED]-> ChainStep (connects decision into the flow)

Bridge to Recon Graph (static, no animation):
Note: Bridges are only created for tool-execution steps. query_graph steps (read-only) create NO bridges.
    AttackChain -[:CHAIN_TARGETS]-> Domain / IP / Subdomain / Port / CVE  (extracted from objective text by LLM)
    ChainStep -[:STEP_TARGETED]-> IP / Subdomain / Port  (IP vs Subdomain depends on whether primary_target is an IP or hostname)
    ChainStep -[:STEP_EXPLOITED]-> CVE
    ChainStep -[:STEP_IDENTIFIED]-> Technology  (case-insensitive match on Technology.name)
    ChainFinding -[:FOUND_ON]-> IP / Subdomain  (IP vs Subdomain depends on whether related_ips value is an IP or hostname)
    ChainFinding -[:FINDING_RELATES_CVE]-> CVE
    ChainFinding -[:CREDENTIAL_FOR]-> Service
```

### Constraints & Indexes

```cypher
CREATE CONSTRAINT attack_chain_id IF NOT EXISTS
FOR (ac:AttackChain) REQUIRE ac.chain_id IS UNIQUE;

CREATE CONSTRAINT chain_step_id IF NOT EXISTS
FOR (s:ChainStep) REQUIRE s.step_id IS UNIQUE;

CREATE CONSTRAINT chain_finding_id IF NOT EXISTS
FOR (f:ChainFinding) REQUIRE f.finding_id IS UNIQUE;

CREATE CONSTRAINT chain_decision_id IF NOT EXISTS
FOR (d:ChainDecision) REQUIRE d.decision_id IS UNIQUE;

CREATE CONSTRAINT chain_failure_id IF NOT EXISTS
FOR (fl:ChainFailure) REQUIRE fl.failure_id IS UNIQUE;

CREATE INDEX idx_attackchain_tenant IF NOT EXISTS
FOR (ac:AttackChain) ON (ac.user_id, ac.project_id);

CREATE INDEX idx_chainstep_tenant IF NOT EXISTS
FOR (s:ChainStep) ON (s.user_id, s.project_id);

CREATE INDEX idx_chainfinding_tenant IF NOT EXISTS
FOR (f:ChainFinding) ON (f.user_id, f.project_id);

CREATE INDEX idx_chaindecision_tenant IF NOT EXISTS
FOR (d:ChainDecision) ON (d.user_id, d.project_id);

CREATE INDEX idx_chainfailure_tenant IF NOT EXISTS
FOR (fl:ChainFailure) ON (fl.user_id, fl.project_id);

CREATE INDEX idx_chainstep_chain IF NOT EXISTS
FOR (s:ChainStep) ON (s.chain_id);

CREATE INDEX idx_chainfinding_type IF NOT EXISTS
FOR (f:ChainFinding) ON (f.finding_type);

CREATE INDEX idx_chainfinding_severity IF NOT EXISTS
FOR (f:ChainFinding) ON (f.severity);

CREATE INDEX idx_chainfailure_type IF NOT EXISTS
FOR (fl:ChainFailure) ON (fl.failure_type);

CREATE INDEX idx_attackchain_status IF NOT EXISTS
FOR (ac:AttackChain) ON (ac.status);
```

### Example Queries

```cypher
// All attack chains for a project
MATCH (ac:AttackChain {user_id: $userId, project_id: $projectId})
RETURN ac.chain_id, ac.title, ac.status, ac.attack_path_type, ac.total_steps, ac.created_at
ORDER BY ac.created_at DESC
LIMIT 10

// Steps in a specific chain (ordered)
MATCH (ac:AttackChain {chain_id: "session-123", user_id: $userId, project_id: $projectId})
      -[:HAS_STEP]->(s:ChainStep)
RETURN s.iteration, s.phase, s.tool_name, s.success, s.output_summary
ORDER BY s.iteration

// All high-severity findings across chains
MATCH (f:ChainFinding {user_id: $userId, project_id: $projectId})
WHERE f.severity IN ["critical", "high"]
RETURN f.finding_type, f.title, f.severity, f.evidence, f.chain_id
ORDER BY f.created_at DESC
LIMIT 20

// Exploit successes (replaces Exploit node queries)
MATCH (f:ChainFinding {user_id: $userId, project_id: $projectId, finding_type: "exploit_success"})
RETURN f.target_ip, f.target_port, f.cve_ids, f.metasploit_module, f.evidence
LIMIT 20

// Failed attempts with lessons learned
MATCH (fl:ChainFailure {user_id: $userId, project_id: $projectId})
RETURN fl.failure_type, fl.tool_name, fl.error_message, fl.lesson_learned, fl.chain_id
ORDER BY fl.created_at DESC
LIMIT 20

// Cross-session: what was tried against a specific IP
MATCH (s:ChainStep {user_id: $userId, project_id: $projectId})-[:STEP_TARGETED]->(i:IP {address: "10.0.0.5"})
RETURN s.chain_id, s.tool_name, s.success, s.output_summary
ORDER BY s.created_at DESC

// Chain with all findings and failures
MATCH (ac:AttackChain {chain_id: "session-123", user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (ac)-[:HAS_STEP]->(s:ChainStep)-[:PRODUCED]->(f:ChainFinding)
OPTIONAL MATCH (s)-[:FAILED_WITH]->(fl:ChainFailure)
RETURN s.iteration, s.tool_name, f.title, fl.error_message
ORDER BY s.iteration

// Decisions made during a chain
MATCH (ac:AttackChain {chain_id: "session-123", user_id: $userId, project_id: $projectId})
      -[:HAS_STEP]->(s:ChainStep)-[:LED_TO]->(d:ChainDecision)
RETURN d.decision_type, d.from_state, d.to_state, d.reason, d.made_by, d.approved
ORDER BY s.iteration
```

---

## 🔮 Future Extensions (Not Implemented Yet)
- GVMScan, GVMVulnerability, DetectedProduct, OSFingerprint nodes (GVM integration - designed but not yet created by code; GVM vulns currently stored as Vulnerability nodes with source="gvm"; Traceroute nodes now implemented)
- `Screenshot` nodes linking to stored images
