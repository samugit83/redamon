import { ReactNode } from 'react'

const sectionTitleStyle = { fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: '#22c55e', marginBottom: '4px', marginTop: '10px' }
const firstSectionTitleStyle = { ...sectionTitleStyle, marginTop: 0 }
const paraStyle = { fontSize: '12px', lineHeight: '1.55', margin: '0 0 8px', color: '#e2e8f0' }
const codeStyle = { fontFamily: 'monospace', fontSize: '11px', padding: '1px 4px', borderRadius: '3px', backgroundColor: 'rgba(255,255,255,0.08)' }
const listStyle = { fontSize: '12px', lineHeight: '1.6', margin: '0 0 8px', paddingLeft: '16px', color: '#e2e8f0' }
const wrapperStyle = { maxWidth: '900px', minWidth: '720px' }

// ============================================================================
// DISCOVERY PHASE
// ============================================================================

const SubdomainDiscovery = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      The only graph input is the <strong>Domain</strong> node - the project's apex domain. Subdomain Discovery uses the domain name as the seed for multiple OSINT sources (Subfinder, Amass, certificate transparency logs, DNS bruteforce, etc., depending on the modules you have enabled).
    </p>
    <p style={paraStyle}>
      Each source returns a list of candidate hostnames. Candidates are merged, deduplicated, and validated to confirm they actually belong to the apex domain. Wildcard records and bogus mock subdomains are filtered out using puredns.
    </p>
    <p style={paraStyle}>
      You can also paste custom subdomains in the partial recon modal. They are validated to be in-scope (must end with the project domain) and merged into the same candidate set.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <p style={paraStyle}>
      Each confirmed subdomain becomes a <strong>Subdomain</strong> node attached to the project Domain via a <span style={codeStyle}>HAS_SUBDOMAIN</span> relationship. Then each subdomain is resolved live and the result expands the graph:
    </p>
    <ul style={listStyle}>
      <li><strong>IP nodes</strong> are created for every A/AAAA record, and linked to the Subdomain via <span style={codeStyle}>RESOLVES_TO</span> relationships (one per record type).</li>
      <li><strong>DNSRecord nodes</strong> are created for MX, NS, TXT, and CNAME records, attached via <span style={codeStyle}>HAS_DNS_RECORD</span>.</li>
      <li>The Subdomain node is tagged with its resolution state (resolved / unresolved / wildcard) and a discovery timestamp.</li>
      <li>The apex Domain node is enriched with WHOIS data (registrar, organization, country, registration dates) when WHOIS lookup is enabled.</li>
    </ul>
    <p style={paraStyle}>
      Existing nodes are reused (deduplicated) - running the scan again only adds newly discovered subdomains, never duplicates.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      When the <strong>AI TXT/SPF/DKIM Hint</strong> toggle is on, captured TXT records (including SPF/DKIM/DMARC) are regex-matched against the AI vendor catalogue. On match, the Subdomain carries <span style={codeStyle}>ai_service_hint</span> with the provider name (anthropic, openai, huggingface, replicate, langchain, langfuse, …). The <strong>AI NS Hint</strong> toggle is a weaker signal: NS records pointing at Vercel/Netlify/Replit/Modal tag the subdomain as <span style={codeStyle}>ai_service_hint=&quot;ai-hosting-candidate&quot;</span> only when no stronger TXT hint already exists.
    </p>
  </div>
)

const Github = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      The only input is the <strong>Domain</strong> node. The tool searches public GitHub for code and files mentioning the domain name (and related keywords like company name, common product names) using the GitHub API.
    </p>
    <p style={paraStyle}>
      Before each run, any prior GitHub scan data for this project is cleared so the new run starts fresh. This avoids stale findings from old scans being re-counted.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>One <strong>GithubHunt</strong> node summarises each scan run (start time, end time, repos scanned, files scanned), attached to the Domain via <span style={codeStyle}>HAS_GITHUB_HUNT</span>.</li>
      <li>Each matched repository becomes a <strong>GithubRepository</strong> node, linked to the GithubHunt.</li>
      <li>Each interesting file path becomes a <strong>GithubPath</strong> node, linked to its repository.</li>
      <li>Findings split into two types: <strong>GithubSecret</strong> (matched API keys, tokens, credentials) and <strong>GithubSensitiveFile</strong> (config files, env files, backups). Each is linked to its parent GithubPath.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are deduplicated by repo + path + secret type to avoid noise across multiple commits. High-entropy generic matches are filtered to reduce false positives.
    </p>
  </div>
)

const Uncover = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Input is the <strong>Domain</strong> node. Uncover queries multiple search engines for security data (Shodan, Censys, Fofa, ZoomEye, Quake, Hunter, etc.) using the domain name as the search term, then aggregates and deduplicates the results.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each new hostname becomes a <strong>Subdomain</strong> node linked to the Domain via <span style={codeStyle}>HAS_SUBDOMAIN</span>.</li>
      <li>Each new IP becomes an <strong>IP</strong> node, optionally linked to its Domain.</li>
      <li>Open ports reported by the search engines become <strong>Port</strong> nodes attached to their IPs via <span style={codeStyle}>HAS_PORT</span>.</li>
      <li>Each subdomain and IP is tagged with the list of upstream sources that returned it (e.g. "Shodan, Censys"), plus counters for total raw results vs deduplicated.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Out-of-scope hostnames returned by the search engines do not become Subdomain nodes - they're either skipped or stored as ExternalDomain nodes for traceability, depending on the project setting.
    </p>
  </div>
)

const Urlscan = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Input is the <strong>Domain</strong> node. URLScan runs in two phases:
    </p>
    <ol style={listStyle}>
      <li><strong>Discovery phase</strong> (before HTTP Probing) - queries the URLScan API for past scans of the domain, extracting subdomains, IPs, and full URLs from the results.</li>
      <li><strong>Enrichment phase</strong> (after HTTP Probing) - for each existing BaseURL in the graph, fetches its URLScan record (screenshot, server banner, page title) and attaches it to the BaseURL.</li>
    </ol>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>New in-scope hostnames become <strong>Subdomain</strong> nodes; out-of-scope hostnames are stored as <strong>ExternalDomain</strong> nodes for context.</li>
      <li>URLs with query parameters become <strong>Endpoint</strong> nodes (only if their parent BaseURL already exists) with <strong>Parameter</strong> nodes attached for each query key.</li>
      <li>The Domain is enriched with age data (domain age in days, apex domain age).</li>
      <li>Each IP is enriched with country, ASN, and ASN organization name from URLScan's data.</li>
      <li>Each BaseURL touched in phase 2 is enriched with screenshot URL, server header, and page title.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Phase 2 silently skips BaseURLs that no longer exist in the graph - this prevents stale URLScan data from re-creating deleted nodes.
    </p>
  </div>
)

const Gau = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Input comes from the <strong>Domain</strong> node and every <strong>Subdomain</strong> node in scope. For each one, the tool queries historical URL archives (the Wayback Machine, AlienVault OTX, Common Crawl) for any URL ever captured under that hostname.
    </p>
    <p style={paraStyle}>
      This is purely passive - no traffic is sent to the target. Discovered URLs may no longer exist on the live service, but they reveal the historical attack surface.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each discovered path becomes an <strong>Endpoint</strong> node, attached to the matching BaseURL via <span style={codeStyle}>HAS_ENDPOINT</span> (the BaseURL is created on the fly if missing).</li>
      <li>Query parameters become <strong>Parameter</strong> nodes attached to their Endpoint, with sample values pulled from the historical captures.</li>
      <li>The Domain is enriched with a total count of historically discovered URLs.</li>
      <li>Each touched BaseURL is tagged as enriched by Gau with a "last seen" timestamp.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Endpoints are deduplicated by path + HTTP method, so re-running Gau only adds genuinely new findings.
    </p>
  </div>
)

const ParamSpider = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Input comes from the <strong>Domain</strong> and every <strong>Subdomain</strong> node in scope. For each, ParamSpider queries the Wayback Machine for historical URLs that contain query parameters.
    </p>
    <p style={paraStyle}>
      Like Gau, this is passive - no traffic to the live target. Unlike Gau, the focus is specifically parameters: ParamSpider discovers parameters that may have been removed from the live service but are still useful to test.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each historical URL contributes an <strong>Endpoint</strong> node (created or reused) attached to its BaseURL.</li>
      <li>Each unique parameter name becomes a <strong>Parameter</strong> node attached to its Endpoint, marked as discovered by ParamSpider.</li>
      <li>The Domain is enriched with a total count of parameters discovered through this passive source.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Parameters from ParamSpider are merged with those from active discovery (Arjun, Katana) into a unified set on each Endpoint.
    </p>
  </div>
)

// ============================================================================
// SUBDOMAIN / DNS RESOLUTION & ENRICHMENT
// ============================================================================

const Shodan = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Shodan needs <strong>IP</strong> nodes. The list is built from every IP linked to the apex Domain plus every IP linked to any in-scope Subdomain (via <span style={codeStyle}>RESOLVES_TO</span>).
    </p>
    <p style={paraStyle}>
      Custom IPs/CIDRs entered in the partial recon modal are validated, expanded (CIDRs above /24 are rejected), and merged into the lookup list. Each one is queried against the Shodan API for its passive intelligence record.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>For each open port reported by Shodan, a <strong>Port</strong> node is created and linked to the IP via <span style={codeStyle}>HAS_PORT</span>.</li>
      <li>If a banner reveals a service, a <strong>Service</strong> node is created (with product, version, banner, module name) and linked via <span style={codeStyle}>RUNS_SERVICE</span>.</li>
      <li>Reverse-DNS hits that fall in scope create new <strong>Subdomain</strong> nodes; out-of-scope hits become <strong>ExternalDomain</strong> nodes for context.</li>
      <li>Passive CVEs known to Shodan become <strong>Vulnerability</strong> + <strong>CVE</strong> nodes linked to the IP via <span style={codeStyle}>HAS_VULNERABILITY</span>.</li>
      <li>The IP node itself is enriched with OS, ISP, organization, country, city, and is marked as enriched by Shodan.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Re-running Shodan refreshes the enrichment fields and adds any newly indexed ports/CVEs - existing nodes are reused, not duplicated.
    </p>
  </div>
)

const OsintEnrichment = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      An orchestrator that runs whichever OSINT sources you have enabled (Shodan, Censys, AlienVault OTX, NetLAS, VirusTotal, ZoomEye, CriminalIP). It feeds each enabled source the appropriate inputs from the graph:
    </p>
    <ul style={listStyle}>
      <li><strong>IP-based sources</strong> get every IP in scope (apex + resolved subdomains).</li>
      <li><strong>Domain-based sources</strong> get the apex Domain and in-scope Subdomain names.</li>
    </ul>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <p style={paraStyle}>
      Each source contributes its own slice of data, but the patterns are similar:
    </p>
    <ul style={listStyle}>
      <li>New <strong>Port</strong> + <strong>Service</strong> nodes for any open ports discovered by the source.</li>
      <li>Passive <strong>Vulnerability</strong> + <strong>CVE</strong> nodes for known CVEs the source has indexed against the IP.</li>
      <li>New <strong>Subdomain</strong> or <strong>DNSRecord</strong> nodes from passive DNS data.</li>
      <li><strong>ExternalDomain</strong> nodes for out-of-scope reverse-DNS hits, tagged with which source returned them.</li>
      <li>Each IP is enriched with source-specific properties (Censys ASN data, NetLAS network info, OTX threat tags, etc.) and tagged as enriched by each source that touched it.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      All sources run sequentially. The graph state from earlier sources is visible to later sources, so deduplication works across the whole orchestration.
    </p>
  </div>
)

// ============================================================================
// PORT SCANNING
// ============================================================================

const Naabu = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Naabu scans IP addresses (or CIDR ranges). Subdomains contribute via their resolved IPs - Naabu does not consume hostnames directly.
    </p>
    <p style={paraStyle}>The graph sources are merged additively (no priority chain):</p>
    <ol style={listStyle}>
      <li><strong>Apex Domain IPs</strong> - every IP linked to the root Domain node.</li>
      <li><strong>Subdomain IPs</strong> - every IP linked to any Subdomain (A/AAAA records).</li>
    </ol>
    <p style={paraStyle}>The merged list is deduplicated by IP. Custom inputs from the partial recon modal:</p>
    <ul style={listStyle}>
      <li><strong>Custom subdomains</strong> are resolved live; the resulting IPs join the scan list and are persisted as new Subdomain + IP nodes.</li>
      <li><strong>Custom IPs/CIDRs</strong> are added directly. They can be linked to an existing Subdomain via the modal's selector, or tracked as a generic user-provided input otherwise.</li>
    </ul>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each open port becomes a <strong>Port</strong> node attached to its IP via <span style={codeStyle}>HAS_PORT</span>, with state set to "open" and any banner string captured.</li>
      <li>If the banner reveals a service, a <strong>Service</strong> node is created and linked via <span style={codeStyle}>RUNS_SERVICE</span>.</li>
      <li>The IP node is updated with a fresh timestamp.</li>
      <li>The Domain is enriched with a port-scan timestamp and a total count of open ports across the project.</li>
    </ul>
    <p style={paraStyle}>
      Ports are deduplicated by (IP + port number + protocol). The output format is compatible with Masscan, so they can be run interchangeably or sequentially.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      When <strong>AI Port Catalog</strong> is enabled, open ports matching the AI port table (Ollama 11434, Qdrant 6333, Open WebUI 8080, vLLM, LiteLLM, Triton, Milvus, Gradio, ComfyUI, …) also MERGE a <strong>Technology</strong> node with <span style={codeStyle}>category=ai-*</span> linked to the Service via <span style={codeStyle}>:USES_TECHNOLOGY</span> with <span style={codeStyle}>detected_by=naabu-ai-port</span>. Shared ports (8000, 8080) are flagged for disambiguation and only promoted when a corroborating HTTP signal lands.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if the graph has zero IPs <em>and</em> zero Subdomains <em>and</em> no custom IPs/subdomains were entered.
    </p>
  </div>
)

const Masscan = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Masscan needs <strong>IP</strong> addresses. The input list is built from every IP linked to the apex Domain plus every IP linked to any Subdomain that successfully resolved (i.e. has at least one A or AAAA record).
    </p>
    <p style={paraStyle}>
      DNS resolution must run first - Masscan does not accept hostnames. CIDR notation is supported and is the recommended format for large IP ranges.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each open port becomes a <strong>Port</strong> node linked to its IP via <span style={codeStyle}>HAS_PORT</span>, with state "open".</li>
      <li>If banner-grabbing identifies a service, a <strong>Service</strong> node is created and linked via <span style={codeStyle}>RUNS_SERVICE</span>, with product, version, and CPE properties.</li>
      <li>The IP is enriched with CDN detection (whether it's behind Cloudflare, Akamai, Fastly, etc., and the CDN name).</li>
      <li>Port nodes get product/version/CPE properties from banner analysis.</li>
      <li>The Domain is enriched with a port scan timestamp, the scan type, the scan port configuration, and a total count of open ports.</li>
    </ul>
    <p style={paraStyle}>
      IPs that have no open ports and no hostname associations are skipped to avoid creating orphaned nodes. Existing Port nodes are reused, not duplicated.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      When <strong>AI Port Catalog</strong> is enabled, the same AI port table used by Naabu fires here too - open AI ports also MERGE a <strong>Technology</strong> node with <span style={codeStyle}>category=ai-*</span> linked to the Service via <span style={codeStyle}>:USES_TECHNOLOGY</span> with <span style={codeStyle}>detected_by=masscan-ai-port</span>.
    </p>
  </div>
)

const Nmap = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Nmap scans a list of IP addresses against a list of ports. Both come from the graph:
    </p>
    <ul style={listStyle}>
      <li><strong>IPs</strong> - read from IP nodes that already have Port relationships (output of Naabu/Masscan). Falls back to apex Domain IPs if no port-scan data exists yet.</li>
      <li><strong>Ports</strong> - the union of every Port node discovered in earlier phases. If no Port nodes exist, Nmap falls back to its built-in top-ports list.</li>
    </ul>
    <p style={paraStyle}>
      Custom IPs/CIDRs and ports from the partial recon modal merge with the graph data. CIDRs above /24 are rejected.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <p style={paraStyle}>
      Nmap is primarily an enrichment scanner - it doesn't usually create Port nodes (Naabu/Masscan does that), but it adds rich detail to existing ones:
    </p>
    <ul style={listStyle}>
      <li>Each scanned Port is enriched with detected product, version, and CPE.</li>
      <li>Each Service is enriched with the same detection metadata.</li>
      <li>For every detected product, a <strong>Technology</strong> node is created (or reused), linked from the Port via <span style={codeStyle}>HAS_TECHNOLOGY</span> and from the Service via <span style={codeStyle}>USES_TECHNOLOGY</span>. These Technology nodes feed the CVE Lookup phase downstream.</li>
      <li>If NSE scripts (Nmap's vulnerability scripts) report findings, they become <strong>Vulnerability</strong> nodes linked to the Port, with associated CVE nodes attached.</li>
      <li>The Port is tagged as scanned by Nmap.</li>
    </ul>
    <p style={paraStyle}>
      Runs as long as at least one IP is available (graph or custom). Without ports, falls back to Nmap's default top-ports list.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      When <strong>AI Runtime Version Regex</strong> is enabled, Nmap's <code>product</code>/<code>version</code> strings are matched against AI runtimes (Ollama, vLLM, LiteLLM, TGI, Triton, llama.cpp). On match the Service node also carries <span style={codeStyle}>ai_runtime_version</span>, which downstream CVE lookups can join against AI library CVE clusters.
    </p>
  </div>
)

const Tlsx = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      tlsx grabs the TLS certificate on each open port. Targets come from the graph:
    </p>
    <ul style={listStyle}>
      <li><strong>IPs</strong> - read from IP nodes that already have Port relationships (output of Naabu/Masscan).</li>
      <li><strong>Ports</strong> - the open ports on each IP, minus the HTTP/HTTPS ports the HTTP probe already grabs certs on. What remains is the gap: SMTPS, IMAPS, POP3S, LDAPS, FTPS and any other TLS port.</li>
    </ul>
    <p style={paraStyle}>
      When an IP has a known hostname, tlsx sends it as the SNI so a shared frontend returns the right certificate instead of its default one. Custom IPs and ports from the partial recon modal merge with the graph data.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <p style={paraStyle}>
      Each grabbed certificate becomes a <strong>Certificate</strong> node carrying issuer, SAN list, validity dates and posture flags (expired, self-signed, hostname mismatch, wildcard):
    </p>
    <ul style={listStyle}>
      <li>The Certificate is linked to its IP via <span style={codeStyle}>HAS_CERTIFICATE</span>.</li>
      <li>For each in-scope SAN hostname the certificate names, a <span style={codeStyle}>COVERS_HOST</span> edge is created to that Subdomain, making the SAN list traversable.</li>
      <li>The Service on that port is enriched with the negotiated TLS version, cipher and a service hint. Its name is never changed.</li>
      <li>In-scope SAN hostnames are also fed back into the scan as new probe targets. Foreign names are recorded but never scanned.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Runs before the HTTP probe so the hostnames it discovers become probe targets in the same scan. Certificate posture also feeds the TLS hygiene findings and the subdomain-takeover scoring.
    </p>
  </div>
)

// ============================================================================
// HTTP PROBING
// ============================================================================

const Httpx = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Httpx probes a flat list of URLs to find live HTTP services. Two sources, with port-scan-first / DNS-fallback logic:
    </p>
    <ol style={listStyle}>
      <li>
        <strong>Primary - Port nodes:</strong> for every (host, port) pair in the graph (Naabu/Masscan output), the protocol is picked by port number and detected service:
        <ul style={{ ...listStyle, marginTop: '4px', marginBottom: 0 }}>
          <li>port 443 or service detected as https/ssl/tls → <span style={codeStyle}>https://host</span></li>
          <li>port 80 or service detected as http → <span style={codeStyle}>http://host</span></li>
          <li>known HTTPS ports (8443, 4443, 9443, 8843) → https</li>
          <li>known HTTP ports (8080, 8000, 8888, 8008, 3000, 5000, 9000) → http</li>
          <li>unknown port → both <span style={codeStyle}>http://</span> and <span style={codeStyle}>https://</span> attempted</li>
        </ul>
      </li>
      <li style={{ marginTop: '6px' }}>
        <strong>Fallback - Subdomain nodes:</strong> only if the port-scan source produced zero URLs. For each resolved host, probes default ports plus a wide set of common HTTP/HTTPS alternates: 80, 443, 8080, 8000, 8888, 3000, 5000, 9000, 8443, 4443, 9443.
      </li>
    </ol>
    <p style={paraStyle}>
      Custom input from the partial recon modal: subdomains (resolved live, probed on custom ports if provided otherwise 80/443), IPs/CIDRs (probed directly, /24 max), and ports (applied globally to every host).
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each live URL becomes a <strong>BaseURL</strong> node, deduplicated by scheme + host + port.</li>
      <li>Each BaseURL is connected back to its host via the chain: Subdomain → IP → Service → BaseURL (or directly Subdomain → BaseURL if there's no port data).</li>
      <li>A <strong>Certificate</strong> node is created for every TLS handshake, attached to the IP via <span style={codeStyle}>HAS_CERTIFICATE</span>, with subject CN and issuer.</li>
      <li>BaseURLs are richly enriched: status code, content type, content length, page title, server header, location header, response time, HTTP version, TLS version, CDN detection, favicon hash.</li>
      <li>Wappalyzer fingerprints become tech-stack data on the BaseURL: framework name + version, CMS name + version. These also feed the CVE Lookup downstream.</li>
    </ul>
    <p style={paraStyle}>
      Live vs dead is determined by status code: anything &lt; 500 is treated as live (4xx counts because the host is responding). 5xx and connection failures are stored but not used as live targets downstream.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      When any of the four <strong>AI Surface Recon</strong> sub-toggles is on, the BaseURL also carries <span style={codeStyle}>is_ai_framework_detected</span>, <span style={codeStyle}>ai_framework_name</span>, and <span style={codeStyle}>ai_frontend_product_guess</span>. The header regex catches runtime / framework / proxy / SDK markers (<code>x-vllm-*</code>, <code>anthropic-ratelimit-*</code>, <code>x-langchain-*</code>, <code>x-litellm-*</code>, <code>cf-aig-*</code>, …). The favicon-hash and title-regex lookups identify AI frontend products (Open WebUI, LibreChat, Flowise, Dify, Gradio, …). Matching <strong>Technology</strong> nodes with <span style={codeStyle}>category=ai-*</span> are linked to the BaseURL via <span style={codeStyle}>:USES_TECHNOLOGY {`{detected_by: 'httpx-ai-*'}`}</span>.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if the graph has no Port-mapped hosts <em>and</em> no resolved Subdomains <em>and</em> the apex Domain has no IPs <em>and</em> no custom targets were entered.
    </p>
  </div>
)

// ============================================================================
// RESOURCE ENUMERATION
// ============================================================================

const Katana = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Katana's target list is the <strong>union of every available source</strong>, deduplicated. Sources are merged, never shadowed:
    </p>
    <ol style={listStyle}>
      <li><strong>BaseURL nodes</strong> - live URLs verified by HTTP Probing (status &lt; 500). httpx already picked the working scheme; the other scheme is NOT re-added for the same hostname.</li>
      <li><strong>Subdomain nodes</strong> - for every Subdomain whose host is <em>not</em> already represented by a BaseURL, both <span style={codeStyle}>http://&lt;sub&gt;</span> and <span style={codeStyle}>https://&lt;sub&gt;</span> are added. Catches subdomains discovered after httpx ran (or via Subfinder mid-pipeline).</li>
      <li><strong>Custom URLs</strong> from the partial recon modal - added and can be attached to an existing BaseURL via the modal's selector.</li>
    </ol>
    <p style={paraStyle}>
      Katana is the deepest crawler in the pipeline: it executes JavaScript (when JS Crawl is enabled) to discover paths that only become visible after the page renders, including SPA routes and dynamically loaded API endpoints.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each crawled path becomes an <strong>Endpoint</strong> node linked to its BaseURL via <span style={codeStyle}>HAS_ENDPOINT</span>.</li>
      <li>Each query parameter becomes a <strong>Parameter</strong> node linked to its Endpoint via <span style={codeStyle}>HAS_PARAMETER</span>, with sample values from observed traffic.</li>
      <li>HTML forms are aggregated across all pages where they appear. The result is stored on the Endpoint: form action, encoding type, input names, and the list of pages where the form was found.</li>
      <li>If the integrated Jsluice analysis is enabled, secrets found in JavaScript files become <strong>Secret</strong> nodes attached to the BaseURL via <span style={codeStyle}>HAS_SECRET</span>.</li>
      <li>Endpoints discovered with parameters are tagged so downstream tools (Nuclei DAST, Arjun) can prioritize them.</li>
      <li>The Domain is enriched with crawl metadata: total endpoints discovered, total parameters, total forms, and a timestamp.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Out-of-scope discoveries do not pollute the project graph - they're either ignored or stored as orphan nodes for traceability, depending on settings. Endpoints are deduplicated by path + method.
    </p>
  </div>
)

const ZapAjaxSpider = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      ZAP Ajax Spider starts from <strong>BaseURL</strong> nodes by default, using the live URLs verified by HTTP Probing as browser crawl seeds.
    </p>
    <p style={paraStyle}>
      When endpoint seeding mode is enabled, existing <strong>Endpoint</strong> nodes are also reconstructed into full URLs and added as seeds. Custom URLs from the partial recon modal are appended to the same target set.
    </p>
    <p style={paraStyle}>
      Header and cookie lines configured in the ZAP Ajax Spider settings are sent with every browser request to support authenticated crawling. They affect crawling behavior but are not surfaced in this workflow view.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Browser-discovered routes become <strong>Endpoint</strong> nodes through the existing resource enumeration graph conventions.</li>
      <li>Query strings and observed request inputs become <strong>Parameter</strong> nodes attached to their Endpoint.</li>
      <li>New in-scope origins become <strong>BaseURL</strong> nodes; out-of-scope hosts are represented as <strong>ExternalDomain</strong> nodes when graph storage rules allow it.</li>
      <li>Each discovered Endpoint is tagged with the ZAP Ajax Spider as its discovery source, while storage relationships and deduplication stay unchanged from the rest of resource enumeration.</li>
    </ul>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      If there are no BaseURLs and no custom URLs. Endpoint-only graph input can start the scan when endpoint seeding is enabled and graph Endpoints exist.
    </p>
  </div>
)

const Hakrawler = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Hakrawler's target list is built as the <strong>union of every available source</strong>, deduplicated:
    </p>
    <ol style={listStyle}>
      <li><strong>BaseURL nodes</strong> - live URLs from HTTP Probing (status &lt; 500), used in the scheme httpx confirmed.</li>
      <li><strong>Subdomain nodes</strong> not already covered by a BaseURL - added as <span style={codeStyle}>http://&lt;sub&gt;</span> and <span style={codeStyle}>https://&lt;sub&gt;</span> so newly discovered subs get crawled even if httpx hasn't re-run.</li>
      <li><strong>Custom URLs</strong> from the partial recon modal - appended; can be attached to an existing BaseURL.</li>
    </ol>
    <p style={paraStyle}>
      It is a lighter-weight crawler than Katana - fewer dependencies, faster, but does not execute JavaScript. Best used as a quick first pass or as an alternative when you don't need JS-rendered pages.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each discovered path becomes an <strong>Endpoint</strong> node attached to its BaseURL via <span style={codeStyle}>HAS_ENDPOINT</span>, tagged with source "Hakrawler".</li>
      <li>Query parameters become <strong>Parameter</strong> nodes linked via <span style={codeStyle}>HAS_PARAMETER</span>.</li>
      <li>The Domain is enriched with crawl metadata (endpoint counts, timestamp).</li>
      <li>Endpoints flagged as having parameters are marked so downstream tools can pick them up.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Endpoints are deduplicated across multiple crawl runs (and across crawlers - Hakrawler shares deduplication with Katana). Out-of-scope discoveries are skipped to keep the graph clean.
    </p>
  </div>
)

const Kiterunner = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Kiterunner brute-forces a target list against an API-route wordlist to find endpoints that don't appear in HTML or JavaScript (typical of API-only services). The target list is the <strong>union of every available source</strong>, deduplicated:
    </p>
    <ol style={listStyle}>
      <li><strong>BaseURL nodes</strong> - live URLs from HTTP Probing (preferred, scheme already verified).</li>
      <li><strong>Subdomain nodes</strong> not yet covered by a BaseURL - both <span style={codeStyle}>http://&lt;sub&gt;</span> and <span style={codeStyle}>https://&lt;sub&gt;</span> added, so freshly discovered subs get tested without re-running httpx.</li>
      <li><strong>Custom URLs</strong> from the partial recon modal.</li>
    </ol>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each confirmed API route becomes an <strong>Endpoint</strong> node tagged with category "api" and source "Kiterunner", linked to its BaseURL.</li>
      <li>HTTP methods detected from the response (GET, POST, PUT, DELETE) are stored on the Endpoint.</li>
      <li>Path query parameters become <strong>Parameter</strong> nodes attached to the Endpoint.</li>
      <li>If the endpoint reveals a versioned technology (e.g. "/api/v3/" pattern), a <strong>Technology</strong> node may be created.</li>
      <li>The Domain is enriched with API-discovery metadata.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Endpoints are deduplicated by (BaseURL + path + method). Different methods on the same path produce separate Endpoint nodes.
    </p>
  </div>
)

const Ffuf = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Ffuf appends wordlist entries to each base URL (e.g. <span style={codeStyle}>https://api.example.com/FUZZ</span>) to discover hidden paths or parameters. The base URL list is the <strong>union of every available source</strong>, deduplicated:
    </p>
    <ol style={listStyle}>
      <li><strong>BaseURL nodes</strong> - live URLs from HTTP Probing (status &lt; 500), used in the verified scheme.</li>
      <li><strong>Endpoint nodes</strong> - existing paths used as deeper fuzz roots (e.g. <span style={codeStyle}>https://host/path/FUZZ</span>).</li>
      <li><strong>Subdomain nodes</strong> not yet covered by a BaseURL - both <span style={codeStyle}>http://&lt;sub&gt;</span> and <span style={codeStyle}>https://&lt;sub&gt;</span> added so freshly discovered subs get fuzzed.</li>
      <li><strong>Custom URLs</strong> from the partial recon modal - added to the fuzz list and treated as live targets.</li>
    </ol>
    <p style={paraStyle}>
      When <strong>AI in Pipeline</strong> is enabled, file extensions are chosen per target by AI from response headers (Server, X-Powered-By, etc.). The static extension list is ignored. The AI call is cached by header fingerprint so multiple targets behind the same stack only cost one call.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each successful fuzz hit (a path not filtered by the configured status-code filters) becomes an <strong>Endpoint</strong> node linked to its BaseURL via <span style={codeStyle}>HAS_ENDPOINT</span>, tagged with source "Ffuf" and the wordlist used.</li>
      <li>Path query parameters become <strong>Parameter</strong> nodes attached to the Endpoint.</li>
      <li>If the fuzz reveals a new scheme/host combination, a new BaseURL node is created.</li>
      <li>The Domain is enriched with a count of endpoints discovered through fuzzing.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Endpoints are deduplicated by path + method. Fuzzing produces broader coverage than crawling but lower confidence - endpoints found by Ffuf alone are less likely to be linked from real application flow.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if there are zero live BaseURLs in the graph <em>and</em> no custom URLs were entered.
    </p>
  </div>
)

const Jsluice = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Jsluice consumes a list of URLs pointing to JavaScript resources. The list is built additively from two graph sources:
    </p>
    <ol style={listStyle}>
      <li><strong>Endpoint nodes</strong> - full URLs reconstructed from each Endpoint and its parent BaseURL, prioritizing those ending in <span style={codeStyle}>.js</span> or known JS path patterns.</li>
      <li><strong>BaseURL nodes</strong> - used as crawl roots when no specific JS endpoints exist yet.</li>
    </ol>
    <p style={paraStyle}>
      Custom URLs from the partial recon modal are appended to the analysis list. Jsluice fetches each JavaScript resource and parses it with JS-aware tooling to extract URL strings, API paths, embedded routes, and secrets.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each regex-matched secret in JS becomes a <strong>Secret</strong> node attached to the BaseURL via <span style={codeStyle}>HAS_SECRET</span>, with severity (HIGH / MEDIUM / INFO) and a redacted sample value.</li>
      <li>Each variable or API path extracted from JS source becomes either a new <strong>Endpoint</strong> + <strong>Parameter</strong> structure, or augments existing Endpoints if the path already exists.</li>
      <li>The BaseURL is enriched with the count of secrets found and an analysis timestamp.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Secrets are deduplicated by (type + source URL + content hash). Jsluice integrates into the Resource Enumeration pipeline - its findings are unified with those from Katana / Hakrawler.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if there are zero BaseURLs and zero Endpoints in the graph and no custom URLs were entered.
    </p>
  </div>
)

const SupplyChainRecon = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Supply Chain Recon works out which software packages the target actually ships, without ever seeing a
      manifest. It runs straight after JS Recon and re-uses what that scan already downloaded, so it sends no
      extra traffic of its own. Three sources, combined and deduplicated:
    </p>
    <ol style={listStyle}>
      <li><strong>Source maps</strong> - package names are mined out of the <span style={codeStyle}>node_modules</span> paths a published source map leaks. The most reliable source, and it covers nested and scoped packages.</li>
      <li><strong>JavaScript imports</strong> - module names referenced inside the bundles.</li>
      <li><strong>Technology nodes</strong> - the stack detected during HTTP probing, which is the source that usually carries a version number.</li>
    </ol>
    <p style={paraStyle}>
      From the partial recon modal you can add <strong>custom URLs</strong>; they are analysed alongside the
      BaseURL and Endpoint nodes already in the graph. The scan stops early if there is nothing to analyse
      (no URLs in the graph, none supplied, and no uploaded JavaScript).
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      The verdict step needs the offline vulnerability database to be present on the host. If it is missing or
      empty the scan reports a clear error instead of a misleading clean result.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Every harvested dependency becomes a <strong>Package</strong> node, identified by its package URL (for example <span style={codeStyle}>pkg:npm/lodash@4.17.21</span>) and tagged with how it was discovered. Packages found from a source-map path have no version, and are kept for inventory even though a version-specific advisory cannot match them.</li>
      <li>Each Package is linked to the <strong>BaseURL</strong> that serves it with <span style={codeStyle}>DEPENDS_ON</span>, so you can see which host ships which dependency. The BaseURL itself is only enriched with that link, never modified.</li>
      <li>A package that matches the offline database gets a <strong>MalPackageFinding</strong> node attached via <span style={codeStyle}>FLAGGED_AS</span>. A <span style={codeStyle}>malicious</span> verdict means the dependency itself is malware, typically a typosquat, and should be treated as critical. Known-vulnerable advisories are reported separately and are not written as findings.</li>
      <li>Running the scan again updates the same nodes instead of duplicating them, and packages found by the standalone Supply Chain scan merge into the same set.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      The whole verdict path is offline: the dependency list is never sent to a third-party service.
    </p>
  </div>
)

const JsRecon = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      JS Recon downloads JavaScript files and analyses them for sensitive data and hidden routes. Two graph sources, additive:
    </p>
    <ol style={listStyle}>
      <li><strong>Endpoint nodes</strong> - full URLs reconstructed from each Endpoint + parent BaseURL.</li>
      <li><strong>BaseURL nodes</strong> - used to crawl for JS files when no specific endpoints are known.</li>
    </ol>
    <p style={paraStyle}>
      Two extra inputs from the partial recon modal:
    </p>
    <ul style={listStyle}>
      <li><strong>Custom URLs</strong> - appended to the analysis list.</li>
      <li><strong>JS file uploads</strong> - uploaded <span style={codeStyle}>.js</span> files are analysed offline, skipping the URL-fetching step entirely. Useful for analysing JS bundles that aren't accessible via the live web.</li>
    </ul>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each regex-matched secret (API keys, hardcoded endpoints, auth tokens) becomes a <strong>Secret</strong> node attached to its source BaseURL.</li>
      <li>URLs found inside JS source become <strong>Endpoint</strong> nodes attached to the matching BaseURL, tagged with their source JS file.</li>
      <li>Variable assignments and route definitions extracted from JS produce <strong>Parameter</strong> nodes attached to relevant Endpoints.</li>
      <li>Detected JS libraries and frameworks (React, Vue, jQuery, etc.) become <strong>JsReconFinding</strong> nodes (with finding type "framework") attached to the analysed JS file via <span style={codeStyle}>HAS_JS_FINDING</span>. They are <em>not</em> currently promoted to Technology nodes, so they do not feed the CVE Lookup phase - that's a known gap.</li>
      <li><strong>AI SDK detection</strong> (Adversarial AI Phase 6): every bundle is also scanned for AI/LLM SDK imports, hard-coded provider keys, the <span style={codeStyle}>dangerouslyAllowBrowser</span> opt-in, and AI-frontend product markers in shipped JS chunks. Each hit becomes a <strong>JsReconFinding</strong> with finding type <span style={codeStyle}>ai-sdk-client</span>, <span style={codeStyle}>ai-sdk-key-literal</span>, <span style={codeStyle}>ai-sdk-browser-allowed</span>, <span style={codeStyle}>ai-frontend-detected</span>, or <span style={codeStyle}>ai-provider-url</span>. When a hard-coded AI key matches an existing Secret on the same JS file, that Secret node is enriched with an <span style={codeStyle}>ai_provider</span> property so generic secret queries pivot directly to the AI-context view.</li>
      <li>The BaseURL is enriched with arrays of detected frameworks, libraries, and a count of secrets found in JS.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Secrets from minified or transpiled JS are extracted using regex matching with severity scoring. Endpoint references found in JS but never linked from real navigation are still added - they expose APIs that may not appear via crawling.
    </p>
  </div>
)

const Arjun = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Arjun fuzzes endpoint URLs to discover hidden HTTP parameters. It tests across GET, POST, and JSON body, and reports parameters that produce a different response from the baseline. Two graph sources, additive:
    </p>
    <ol style={listStyle}>
      <li><strong>Endpoint nodes</strong> - full URLs reconstructed from Endpoint + parent BaseURL. Endpoints already known to have parameters are prioritized - Arjun discovers <em>additional</em> hidden parameters beyond the ones already known.</li>
      <li><strong>BaseURL nodes</strong> - used to test the root path when no specific endpoints exist.</li>
    </ol>
    <p style={paraStyle}>
      Custom URLs from the partial recon modal are appended to the test list.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each discovered hidden parameter becomes a <strong>Parameter</strong> node linked to its Endpoint via <span style={codeStyle}>HAS_PARAMETER</span>.</li>
      <li>Parameters from Arjun are tagged as discovered via fuzzing (no sample values - Arjun is discovery-only, it doesn't capture observed values).</li>
      <li>Each tested Endpoint is marked as Arjun-tested with a count of parameters found.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Arjun is most valuable on API endpoints where parameters aren't visible in HTML forms. Its parameters merge with those discovered passively (Gau, ParamSpider) and from crawling (Katana, Hakrawler) into a unified set on each Endpoint.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if there are zero BaseURLs and zero Endpoints in the graph and no custom URLs were entered.
    </p>
  </div>
)

const EndpointAiClassifier = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Reads every Endpoint, Parameter and BaseURL already in the graph. No URL is fetched and no probe is sent to the target. The classifier is pure pattern matching over data the rest of the resource enumeration step has already collected.
    </p>
    <ul style={listStyle}>
      <li><strong>Endpoint paths</strong> are matched against a catalogue of vendor-specific LLM routes (OpenAI <span style={codeStyle}>/v1/chat/completions</span>, Anthropic <span style={codeStyle}>/v1/messages</span>, Ollama <span style={codeStyle}>/api/chat</span>, Gemini <span style={codeStyle}>:generateContent</span>, Cohere <span style={codeStyle}>/v2/chat</span>, MCP <span style={codeStyle}>/mcp</span>, LangServe <span style={codeStyle}>/stream</span>, and similar) plus RAG ingestion / retrieval paths (OpenAI Vector Stores, Pinecone <span style={codeStyle}>/vectors/upsert</span>, Weaviate <span style={codeStyle}>/v1/objects</span>, Qdrant <span style={codeStyle}>/collections/.../points</span>).</li>
      <li><strong>Parent BaseURL</strong> is checked first. Ambiguous paths like <span style={codeStyle}>/search</span>, <span style={codeStyle}>/upload</span> and <span style={codeStyle}>/query</span> only count as RAG when their host already has an AI framework tag from the HTTP probing step, to avoid flagging every e-commerce search bar.</li>
      <li><strong>Parameter names</strong> are matched against a catalogue of prompt-injection field names (<span style={codeStyle}>prompt</span>, <span style={codeStyle}>messages</span>, <span style={codeStyle}>system</span>, <span style={codeStyle}>contents</span>, <span style={codeStyle}>inputs</span>, <span style={codeStyle}>arguments</span>, and similar) only when the parent endpoint is AI-classified.</li>
    </ul>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li><strong>Endpoint</strong> gets <span style={codeStyle}>ai_interface_type</span> set to one of <span style={codeStyle}>llm-chat</span>, <span style={codeStyle}>llm-completion</span>, <span style={codeStyle}>llm-embedding</span>, <span style={codeStyle}>llm-tool-call</span>, <span style={codeStyle}>sse-stream</span>, <span style={codeStyle}>mcp</span>, <span style={codeStyle}>llm-graphql</span>, or <span style={codeStyle}>non-llm</span>.</li>
      <li>Endpoints recognized as RAG also get <span style={codeStyle}>is_ai_rag_ingest=true</span>.</li>
      <li><strong>Parameter</strong> nodes on AI-classified endpoints get <span style={codeStyle}>is_ai_prompt_injectable=true</span> when their name matches the catalogue.</li>
      <li>No new nodes and no new relationships are created. Existing Endpoint and Parameter rows are enriched in place.</li>
    </ul>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only when the graph contains zero Endpoint nodes. The classifier has nothing to do when the URL discovery tools (Katana, Hakrawler, GAU, FFuf, ParamSpider, Arjun, Kiterunner, jsluice) have not produced any endpoints yet.
    </p>
  </div>
)

const AiSurfaceRecon = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Runs after Resource Enumeration and probes only hosts that already show an AI signal. Candidates come from the graph: Endpoints tagged as LLM or MCP by the Endpoint AI Classifier, BaseURLs flagged with an AI framework during HTTP probing, and Services on known AI vector-database ports. When a flagged host has no classified chat path, a small fixed list of canonical chat paths is tried against it.
    </p>
    <ul style={listStyle}>
      <li><strong>Chat endpoints</strong> are confirmed by sending a single 1-token request and reading the response shape.</li>
      <li><strong>MCP servers</strong> are detected by the Model Context Protocol handshake, then their tools, resources and prompts are listed.</li>
      <li><strong>API specs</strong> (OpenAPI / ai-plugin manifests) and model listings are fetched read-only to learn tool, vision, streaming support and the model family.</li>
    </ul>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li><strong>Endpoint</strong> is enriched with confirmed AI properties: interface type, streaming / tools / vision support, model-family guess, measured latency, and for MCP servers the server name, version, protocol, capabilities and tool counts.</li>
      <li><strong>Parameter</strong> nodes are created for each MCP tool argument and flagged when they look prompt-injectable.</li>
      <li><strong>Technology</strong> nodes are confirmed for detected AI runtimes and vector databases.</li>
      <li><strong>Vulnerability</strong> nodes are created for MCP tool poisoning, prompt injection and data-exfiltration hints found by static analysis, linked to the MCP Endpoint.</li>
    </ul>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      When the graph contains no AI-tagged Endpoints and no AI-flagged hosts. There is nothing to probe until HTTP probing and the Endpoint AI Classifier have surfaced at least one AI signal.
    </p>
  </div>
)

// ============================================================================
// VULNERABILITY / EXPLOITATION
// ============================================================================

const Nuclei = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Nuclei scans a flat list of URLs built as the <strong>union of every available source</strong>, deduplicated. Sources are merged, never shadowed - newly discovered subdomains that haven't been probed yet are still scanned alongside existing BaseURLs and Endpoints.
    </p>
    <ol style={listStyle}>
      <li>
        <strong>Endpoint nodes (resource_enum)</strong> - full URLs reconstructed from each Endpoint and its parent BaseURL, with sample parameter values filled in. Example: <span style={codeStyle}>https://api.example.com/users?id=1</span>. Highest fidelity.
      </li>
      <li>
        <strong>BaseURL nodes (httpx-verified live URLs)</strong> - included as-is. Example: <span style={codeStyle}>https://api.example.com:8443</span>. httpx already picked the working scheme, so the other scheme is NOT re-added for the same hostname.
      </li>
      <li>
        <strong>Subdomain nodes</strong> - for every Subdomain whose hostname is <em>not</em> already represented in sources 1 or 2, both <span style={codeStyle}>http://&lt;sub&gt;</span> and <span style={codeStyle}>https://&lt;sub&gt;</span> are added. This catches new subdomains discovered after httpx ran. Default ports only.
      </li>
      <li>
        <strong>IPs</strong> - only added when <em>Scan All IPs</em> is enabled in the Nuclei settings. Default off (hostnames only).
      </li>
    </ol>
    <p style={paraStyle}>
      Coverage is determined by exact hostname match (case-insensitive). Adding a hostname A via source 2 means <em>http://A</em> won't be re-added via source 3, but a different hostname B with no BaseURL still gets the fallback URLs.
    </p>
    <p style={paraStyle}>
      <strong>Domain</strong> and <strong>Technology</strong> are listed as inputs but they don't produce target URLs. They feed the post-scan enrichment phases: Technology → CVE Lookup, Domain → Security Checks (SPF, DMARC, DNSSEC, zone transfer).
    </p>
    <p style={paraStyle}>
      <strong>Include Tags</strong> drives whether the built-in ~8000-template pool runs at all. With tags set, nuclei loads the built-in pool and filters by those tags. With tags <em>empty</em>, the built-in pool is <em>not</em> loaded - only the custom templates you've selected run. If <em>both</em> tags and custom templates are empty, the detection pass is skipped (the run becomes a no-op unless DAST mode produces something). Default tags: <span style={codeStyle}>cve, xss, sqli, rce, lfi, ssrf, xxe, ssti</span>. Default exclude: <span style={codeStyle}>dos, fuzz</span> (kept out of production scans).
    </p>
    <p style={paraStyle}>
      <strong>DAST mode</strong> is a <em>filter</em>, not an additional source. When enabled, nuclei runs ONLY templates with a <span style={codeStyle}>fuzz:</span> directive (~300 of ~8000) - detection templates and your custom detection templates are skipped. Combine with DAST-native tags (<span style={codeStyle}>sqli, xss, ssrf, xxe, ssti, lfi, rce</span>); detection-class tags like <span style={codeStyle}>graphql, apollo, hasura, exposure</span> intersect to an empty set and the scan fatals.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each template finding becomes a <strong>Vulnerability</strong> node attached to the matched target via <span style={codeStyle}>FOUND_AT</span> (Endpoint or BaseURL, depending on what was matched).</li>
      <li>Each finding stores the template ID, severity, category, tags, references, CVSS score, the matched URL, the HTTP method, and (for fuzzing templates) the attack payload.</li>
      <li>If the template references CVEs, <strong>CVE</strong> nodes are created or linked via <span style={codeStyle}>INCLUDES_CVE</span>.</li>
      <li>If the template references a CWE, the Vulnerability is tagged with the CWE identifier (which Mitre Enrichment can later expand into full MitreData/CAPEC nodes).</li>
      <li>For DAST findings, the Vulnerability is linked to the affected <strong>Parameter</strong> node via <span style={codeStyle}>AFFECTS_PARAMETER</span>.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are deduplicated using a hash of (template ID + target host + fuzzed parameter + matched content) so re-running the scan doesn't duplicate previously found issues.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if the union is empty: zero BaseURLs <em>and</em> zero Endpoints <em>and</em> zero Subdomains in the graph <em>and</em> no custom URLs were entered.
    </p>
  </div>
)

const GraphqlScan = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      GraphQL Scan probes a list of candidate paths against each <strong>BaseURL</strong> in the graph (e.g. <span style={codeStyle}>/graphql</span>, <span style={codeStyle}>/api/graphql</span>, <span style={codeStyle}>/v1/graphql</span>). The candidate path list is configured in the GraphQL Scan settings.
    </p>
    <p style={paraStyle}>
      Existing <strong>Endpoint</strong> nodes - especially those already tagged as GraphQL by upstream tools (JS Recon, Katana) - are re-tested with deeper checks: introspection queries, batch queries, mutations, and field probing.
    </p>
    <p style={paraStyle}>
      The Input counter shows how many endpoints in the graph are <strong>already flagged as GraphQL</strong>. These get the deep-test path rather than blind path probing. Custom URLs from the partial recon modal are added as additional candidate paths for that scan run.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Endpoints that respond as valid GraphQL servers are tagged with type "graphql" and given a GraphQL version property.</li>
      <li>If introspection is enabled on the server, the schema is captured: a <strong>GraphqlSchema</strong> node is created and linked from the Endpoint via <span style={codeStyle}>HAS_SCHEMA</span>.</li>
      <li>Each schema field becomes a <strong>GraphqlField</strong> node, each custom type becomes a <strong>GraphqlType</strong>, and each public query becomes a <strong>GraphqlQuery</strong>, all linked from the schema.</li>
      <li>Endpoints with introspection enabled are flagged separately - this is itself a security finding worth investigating.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Capturing the full schema gives downstream tools (manual review, custom Nuclei templates, exploit scripts) the data they need for targeted attacks. Existing schema nodes are reused, not duplicated.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if there are zero BaseURLs <em>and</em> zero Endpoints in the graph <em>and</em> no custom URLs were entered.
    </p>
  </div>
)

const SubdomainTakeover = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Subdomain Takeover checks every <strong>Subdomain</strong> node in the graph for dangling DNS records - typically a CNAME pointing to a deprovisioned cloud service (S3, Heroku, GitHub Pages, Azure, etc.).
    </p>
    <p style={paraStyle}>
      Crucially, <strong>unresolved subdomains are still scanned</strong>. A subdomain with a CNAME but no A record is exactly the takeover signal we're looking for. If a subdomain ever existed in the graph but no longer resolves, it stays in the test list.
    </p>
    <p style={paraStyle}>
      BaseURL and Domain are listed as inputs but only used for context: the apex Domain bounds the scope filter, and existing BaseURLs help confirm the host was previously live. Custom subdomains from the partial recon modal must be in-scope (must end with the project domain) and are added to the scan list even if they don't resolve.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each vulnerable hostname produces a <strong>Vulnerability</strong> node carrying the matched provider (S3, Heroku, GitHub Pages, etc.), the takeover method (CNAME signature pattern), confidence score, source list, confirmation count, verdict, and the raw evidence captured during the test.</li>
      <li>The Vulnerability is attached to the matching <strong>Subdomain</strong> via <span style={codeStyle}>HAS_VULNERABILITY</span>. If the vulnerable hostname is the apex domain itself (no Subdomain node exists), it attaches to the <strong>Domain</strong> instead.</li>
      <li>Timestamps are stored on the Vulnerability: <em>first_seen</em> on creation and <em>last_seen</em> on every run, so re-running re-confirms (or invalidates) older findings without duplicating them.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are deduplicated per (hostname + provider). Re-running refreshes the verdict and last-seen timestamp rather than creating new nodes.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if there are no Subdomains in the graph and no custom subdomains were entered.
    </p>
  </div>
)

const VhostSni = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      VHost &amp; SNI Enumeration probes every IP discovered by port scanning, sending two crafted curl requests per candidate hostname. The candidate list is built per IP from up to seven sources, deduplicated and capped at the configured maximum:
    </p>
    <ul style={listStyle}>
      <li><strong>Subdomain</strong> nodes that resolve to the IP (via <span style={codeStyle}>RESOLVES_TO</span>).</li>
      <li><strong>ExternalDomain</strong> nodes that resolve to the same IP (out-of-scope, but co-hosted, often the highest-signal source).</li>
      <li>TLS Subject Alternative Names captured on each <strong>BaseURL</strong> served from this IP, plus any standalone <strong>Certificate</strong> nodes.</li>
      <li>CNAME targets recorded in <strong>DNSRecord</strong> entries.</li>
      <li>Reverse-DNS PTR record stored on the <strong>IP</strong> node.</li>
      <li>The default wordlist (~2,300 admin / dev / staging / internal / modern-stack prefixes), expanded as <span style={codeStyle}>{`{prefix}.{target_apex}`}</span>.</li>
      <li>Any custom wordlist provided in the section settings (newline-separated, prefixes or full hostnames).</li>
    </ul>
    <p style={paraStyle}>
      Each candidate is tested at two layers: the <strong>L7 test</strong> sends an HTTP request to the bare IP with an overridden <span style={codeStyle}>Host:</span> header (catches classic Apache/Nginx vhosts). The <strong>L4 test</strong> uses curl <span style={codeStyle}>--resolve</span> to force the TLS handshake to carry the candidate as SNI while still hitting the IP (catches modern reverse-proxy and ingress routing). Each response is compared to a baseline obtained by curling the IP with no overrides at all.
    </p>
    <p style={paraStyle}>
      In partial recon, the modal accepts <strong>Subdomain</strong> and <strong>IP</strong> inputs. Subdomains are validated as in-scope (must end with the project domain) and become extra candidates. IPs become extra targets to probe (with the same baseline + L7 + L4 logic).
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each anomaly produces a <strong>Vulnerability</strong> node typed as <em>Hidden Virtual Host</em> (L7 only), <em>Hidden SNI Route</em> (L4 only), or <em>Routing Inconsistency / Host Header Bypass</em> (L7 vs L4 disagreement). Severity is escalated to <em>medium</em> when the discovered hostname matches an internal-keyword pattern (admin, jenkins, k8s, vault, etc.) and to <em>high</em> when L7 and L4 routing disagree.</li>
      <li>The Vulnerability is attached to the discovered <strong>Subdomain</strong> via <span style={codeStyle}>HAS_VULNERABILITY</span>. For host-header-bypass findings the <strong>IP</strong> also gets the same Vulnerability so it surfaces in IP-level dashboards.</li>
      <li>Every probed Subdomain is enriched in place with <em>vhost_tested</em>, <em>vhost_hidden</em>, <em>vhost_routing_layer</em>, <em>vhost_status_code</em>, <em>vhost_size_delta</em>, and <em>sni_routed</em>.</li>
      <li>Every probed IP is enriched with <em>vhost_baseline_status</em>, <em>vhost_baseline_size</em>, <em>hosts_hidden_vhosts</em>, <em>hidden_vhost_count</em>, and <em>is_reverse_proxy</em>.</li>
      <li>For every confirmed hidden vhost, a <strong>BaseURL</strong> is created (with <em>discovery_source = vhost_sni_enum</em>) and linked to the Subdomain via <span style={codeStyle}>HAS_BASE_URL</span>, so a follow-up partial recon can route the new URL through Katana and Nuclei.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are deduplicated per <em>(hostname + IP + port + layer)</em>. Re-running refreshes <em>last_seen</em> rather than creating duplicates.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      If there are no IPs in the graph and no IP targets were provided in the modal, or if both L7 and L4 tests are disabled, or if curl is missing from the recon image. With graph candidates, default wordlist, and custom wordlist all turned off there is also nothing to test.
    </p>
  </div>
)

const WebCachePoison = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Web Cache Poisoning scans the live URLs already discovered by recon. The target list is the union of every probed <strong>BaseURL</strong> and every parameterized <strong>Endpoint</strong>, the same source set Nuclei uses. The technology fingerprint recorded on those nodes decides which framework-specific tests are eligible.
    </p>
    <ul style={listStyle}>
      <li><strong>BaseURL</strong> nodes confirmed live by HTTP probing.</li>
      <li><strong>Endpoint</strong> nodes discovered by crawling and parameter discovery.</li>
      <li>Hosts excluded by the Rules of Engagement are filtered out before any request is sent.</li>
    </ul>
    <p style={paraStyle}>
      Each URL is first checked for a usable cache (hit/miss signal from cache headers). Only cacheable URLs proceed. A unique cache-buster isolates every test into its own cache slot, so the real cache is never poisoned. The WCVS engine performs a broad sweep, then a native confirmation re-tests each candidate: it fetches a clean baseline, fetches again with a benign canary payload, then fetches a third time as an innocent visitor and checks whether the canary persisted from cache.
    </p>
    <p style={paraStyle}>
      In partial recon, the modal accepts custom <strong>URL</strong> inputs, attached to an existing BaseURL or recorded as generic user input. These are merged with the graph-derived targets unless graph targets are disabled.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each confirmed finding produces a <strong>Vulnerability</strong> node typed as <em>Web Cache Poisoning</em>, carrying the unkeyed vector (header or parameter), the impact class (stored XSS, open redirect, deception, or denial of service), a confidence score and tier (Confirmed, Strong, or Tentative), and a reproduction link.</li>
      <li>The Vulnerability is attached to the affected <strong>Endpoint</strong> via <span style={codeStyle}>HAS_VULNERABILITY</span>, and to the parent <strong>BaseURL</strong> as well for host-level findings.</li>
      <li>If crawling never created the affected Endpoint or BaseURL, the scan creates them so the finding is never orphaned.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are deduplicated per <em>(technique + URL + vector)</em>. Re-running updates the existing Vulnerability rather than creating duplicates. Only findings at or above the configured confidence threshold are stored.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      If there are no live BaseURLs in the graph and no custom URLs were provided in the modal, or if none of the target URLs are served through a cache, there is nothing to test.
    </p>
  </div>
)

const SecurityChecks = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      Security Checks runs <strong>multiple parallel input streams</strong>, one per check category. There is no single target list - each individual check (~27 of them in the settings) picks the input it needs from the graph:
    </p>
    <ul style={listStyle}>
      <li><strong>BaseURLs</strong> → header checks (Referrer-Policy, COOP/CORP/COEP, Cache-Control, CSP), session/cookie checks, login form checks, insecure form action checks.</li>
      <li><strong>IPs</strong> → Direct IP Access checks, port-based checks (admin ports exposed, exposed databases, Redis without auth, Kubernetes API exposed, SMTP open relay), TLS expiry on direct IPs.</li>
      <li><strong>Subdomains</strong> → DNS checks (SPF missing, DMARC missing, DNSSEC missing, zone transfer), TLS expiry on hostnames.</li>
      <li><strong>Domain (apex)</strong> → DNS-level checks scoped to the root domain (apex SPF, apex DMARC).</li>
    </ul>
    <p style={paraStyle}>
      All four sources are <strong>additive</strong> - there's no priority chain. Disabling a specific toggle in the settings skips that check's input slice. Custom subdomains, IPs, and URLs from the partial recon modal merge into the appropriate pool.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each finding becomes a <strong>Vulnerability</strong> node, attached to the affected target (BaseURL, IP, Subdomain, or Domain) via <span style={codeStyle}>HAS_VULNERABILITY</span>.</li>
      <li>The Vulnerability stores the check name, severity, description, and any specific evidence (e.g. "Set-Cookie header missing Secure flag"; "TLS certificate expires in 12 days").</li>
      <li>Some checks also enrich the target node directly: a BaseURL gets tagged with which security headers are present vs missing; deprecated TLS versions and insecure cookie flags are stored as boolean properties.</li>
      <li>The Domain is enriched with a security-assessment timestamp.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Findings are typically low-severity but high volume - the value is in tracking compliance and configuration drift over time. Re-running updates the timestamps and adds any newly applicable findings.
    </p>

    <div style={sectionTitleStyle}>When the scan refuses to start</div>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only if all four input pools are empty <em>and</em> no custom targets were entered. Individual checks are silently skipped when their specific input pool is empty.
    </p>
  </div>
)

const CveLookup = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      CVE Lookup consumes <strong>Technology</strong> nodes - created upstream by Nmap (from service banners), HTTP Probing (from Wappalyzer fingerprints), and JS Recon (from detected libraries).
    </p>
    <p style={paraStyle}>
      Each Technology node carries a product name and a version. The tool queries CVE databases (NVD primarily, with Vulners as an alternate source) for any CVE matching that product + version combination.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each matching CVE becomes a <strong>CVE</strong> node attached to the Technology via <span style={codeStyle}>HAS_CVE</span>.</li>
      <li>The CVE node stores the CVSS score, CVSS metrics, description, and references.</li>
      <li>Through the existing graph chain (Port → Technology, Service → Technology), the CVE is reachable from the affected Port and Service nodes for attack-surface visibility.</li>
      <li>If MITRE Enrichment is enabled, each CVE is further linked to a <strong>MitreData</strong> (CWE) node which itself links to <strong>Capec</strong> (attack pattern) nodes.</li>
      <li>The Technology is enriched with a count of associated CVEs and a "high-impact CVE" flag if any of its CVEs exceeds the configured CVSS threshold.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Re-running refreshes existing CVE properties (CVSS scores can change as the database is updated) and adds any newly published CVEs matching known technologies.
    </p>
  </div>
)

const Mitre = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      MITRE Enrichment consumes <strong>CVE</strong> nodes - created upstream by CVE Lookup and Nuclei. For each CVE, the tool fetches its CWE (Common Weakness Enumeration) mappings and the related CAPEC (Common Attack Pattern Enumeration) data.
    </p>
    <p style={paraStyle}>
      The CVE → CWE → CAPEC mappings come from the public CVE2CAPEC database, then the detailed CWE and CAPEC metadata is pulled from MITRE's official feeds. Both data sources are cached locally with a TTL to avoid repeated downloads.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each CWE becomes a <strong>MitreData</strong> node linked from the CVE via <span style={codeStyle}>HAS_CWE</span>. It carries the CWE name, description, abstraction level, mapping kind, structure, common consequences, mitigations, and detection methods.</li>
      <li>Each related attack pattern becomes a <strong>Capec</strong> node linked from the MitreData via <span style={codeStyle}>HAS_CAPEC</span>. It stores the pattern name, description, likelihood, severity, prerequisites, examples, and execution flow.</li>
      <li>The CVE is tagged as enriched by MITRE.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Only CWEs with direct CAPEC mappings are created - inherited mappings from parent CWEs are intentionally excluded as they tend to be inaccurate. ATT&amp;CK and D3FEND are not part of this enrichment by design.
    </p>
  </div>
)

// ============================================================================
// EXPORT MAP
// ============================================================================

const OriginDiscovery = (
  <div style={wrapperStyle}>
    <div style={firstSectionTitleStyle}>How input is generated</div>
    <p style={paraStyle}>
      The input is every <strong>CDN-fronted host</strong> already in the graph - a Subdomain or IP that a prior HTTP probe classified as sitting behind a CDN/WAF (it carries a CDN name or a favicon hash). Hosts that are not fronted are skipped: there is nothing to unmask.
    </p>
    <p style={paraStyle}>
      For each fronted host, candidate origin IPs are gathered from non-CDN subdomains, SPF/MX email records, certificate transparency, the site&apos;s favicon hash (Shodan/FOFA/ZoomEye), certificate search (Censys), passive DNS (OTX/VirusTotal), and DNS history (SecurityTrails/ViewDNS). You can also enter a Subdomain in the partial recon modal; IPs are graph-sourced only, never entered by hand, because a discovered origin IP is an output of this tool.
    </p>
    <p style={{ ...paraStyle, margin: 0 }}>
      Every candidate that points at a private, internal, or cloud-metadata address is dropped before it is ever contacted, and the engagement&apos;s excluded-hosts list is honored.
    </p>

    <div style={sectionTitleStyle}>How output transforms the graph</div>
    <ul style={listStyle}>
      <li>Each confirmed origin becomes an <strong>IP</strong> node marked as an origin (with the discovery method and confidence), reusing the existing IP node when one is already present.</li>
      <li>A <span style={codeStyle}>HAS_ORIGIN</span> link is drawn from the fronted <strong>Subdomain</strong> to that IP.</li>
      <li>The exposure is recorded as a <strong>Vulnerability</strong> (a WAF bypass) attached to the IP, plus a <span style={codeStyle}>WAF_BYPASS_VIA</span> link, so it flows into reports like any other finding.</li>
    </ul>
    <p style={{ ...paraStyle, margin: 0 }}>
      Re-running reuses existing nodes; the same origin never duplicates.
    </p>
  </div>
)

export const INPUT_LOGIC_TOOLTIPS: Record<string, ReactNode> = {
  // Discovery
  SubdomainDiscovery,
  Github,
  Uncover,
  Urlscan,
  Gau,
  ParamSpider,
  // Resolution / Enrichment
  Shodan,
  OsintEnrichment,
  // Port scanning
  Naabu,
  Masscan,
  Nmap,
  Tlsx,
  // HTTP probing
  Httpx,
  // Resource enumeration
  Katana,
  ZapAjaxSpider,
  Hakrawler,
  Kiterunner,
  Ffuf,
  Jsluice,
  JsRecon,
  SupplyChainRecon,
  Arjun,
  EndpointAiClassifier,
  AiSurfaceRecon,
  // Vulnerability / exploitation
  Nuclei,
  GraphqlScan,
  SubdomainTakeover,
  VhostSni,
  WebCachePoison,
  SecurityChecks,
  OriginDiscovery,
  CveLookup,
  Mitre,
}
