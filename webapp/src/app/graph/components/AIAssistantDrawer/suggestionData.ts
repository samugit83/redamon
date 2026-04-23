export interface SESuggestion { label: string; prompt: string }
export interface SESection { osLabel?: string; suggestions: SESuggestion[] }
export interface SESubGroup { id: string; title: string; items: SESection[] }

// =============================================================================
// INFORMATIONAL SUGGESTION DATA
// =============================================================================

export const INFORMATIONAL_GROUPS: SESubGroup[] = [
  {
    id: 'attack_surface',
    title: 'Attack Surface Overview',
    items: [
      {
        suggestions: [
          { label: 'Full attack surface map', prompt: 'Query the graph to list all domains, subdomains, IP addresses, open ports, and running services. Organize results by domain hierarchy and highlight internet-facing assets.' },
          { label: 'Subdomain enumeration summary', prompt: 'Query the graph for all subdomains and their DNS records (A, AAAA, CNAME, MX, NS, TXT). Identify wildcard DNS, dangling CNAMEs, and potential subdomain takeover candidates.' },
          { label: 'External IP and port inventory', prompt: 'Query the graph for all IP addresses and their open ports with service/version detection. Group by IP and flag uncommon or high-risk ports (e.g., 445, 3389, 6379, 27017).' },
          { label: 'ASN and network mapping', prompt: 'Query the graph for all ASN information, IP ranges, and reverse DNS records. Map out which networks and hosting providers are in scope.' },
          { label: 'CDN and WAF detection summary', prompt: 'Query the graph for all CDN/WAF detections. Identify which assets are behind Cloudflare, Akamai, AWS CloudFront, etc., and which are directly exposed.' },
        ],
      },
    ],
  },
  {
    id: 'vuln_analysis',
    title: 'Vulnerability Analysis',
    items: [
      {
        suggestions: [
          { label: 'Critical and high severity CVEs', prompt: 'Query the graph for all vulnerabilities with CVSS >= 7.0, sorted by severity. For each, show the CVE ID, CVSS score, affected service/technology, and the host where it was found.' },
          { label: 'CISA KEV matches', prompt: 'Query the graph for all discovered CVEs, then use web_search to check which ones appear in the CISA Known Exploited Vulnerabilities catalog. List matches with their required remediation dates.' },
          { label: 'Exploitable CVEs with Metasploit modules', prompt: 'Query the graph for all CVEs found, then use web_search to identify which ones have known Metasploit exploit modules. List the module path, target service, and affected host.' },
          { label: 'Prioritized risk summary', prompt: 'Query the graph for all vulnerabilities, technologies, and exposed services. Create a prioritized risk assessment ranked by: 1) CVSS score, 2) exploit availability, 3) exposure level. Include a top-10 most critical findings table.' },
          { label: 'CVEs with public exploit code', prompt: 'Query the graph for all CVEs, then use web_search to find which have public exploit code on GitHub or ExploitDB. List the CVE, affected asset, and exploit URL for each.' },
        ],
      },
    ],
  },
  {
    id: 'tech_intel',
    title: 'Technology & Version Intelligence',
    items: [
      {
        suggestions: [
          { label: 'Outdated software inventory', prompt: 'Query the graph for all detected technologies with version numbers and CPE identifiers. Use web_search to check each for known CVEs and end-of-life status. Flag any outdated or unsupported versions.' },
          { label: 'Web server and framework versions', prompt: 'Query the graph for all web technologies (Apache, Nginx, IIS, Tomcat, WordPress, Drupal, etc.) with their versions. Identify which versions have known critical vulnerabilities.' },
          { label: 'Database and cache services', prompt: 'Query the graph for all database and cache services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch). List their versions, exposed ports, and whether authentication is required.' },
          { label: 'CMS and application detection', prompt: 'Query the graph for CMS platforms (WordPress, Joomla, Drupal, etc.) and web frameworks. Use web_search to find known vulnerabilities for each detected version.' },
          { label: 'Technology stack by host', prompt: 'Query the graph to build a complete technology stack (OS, web server, language, framework, database, CDN) for each host. Identify mismatches and unusual configurations.' },
        ],
      },
    ],
  },
  {
    id: 'web_recon',
    title: 'Web Application Recon',
    items: [
      {
        suggestions: [
          { label: 'Discovered endpoints and parameters', prompt: 'Query the graph for all web endpoints, their HTTP methods, parameters, and response codes. Highlight endpoints with user-input parameters that could be injection targets.' },
          { label: 'Admin panels and login pages', prompt: 'Query the graph for endpoints matching common admin/login paths (/admin, /login, /wp-admin, /manager, /console, /dashboard). Use execute_curl to verify which are accessible and identify the technology behind them.' },
          { label: 'API endpoint discovery', prompt: 'Query the graph for all endpoints that look like API routes (/api/, /v1/, /graphql, /rest/). Use execute_curl to probe a sample of them for authentication requirements, response formats, and exposed data.' },
          { label: 'Sensitive file and directory exposure', prompt: 'Use execute_curl to probe for common sensitive paths: /.git/config, /.env, /robots.txt, /sitemap.xml, /.well-known/, /backup/, /debug/, /phpinfo.php on all discovered web hosts.' },
          { label: 'Form and input analysis', prompt: 'Query the graph for all discovered parameters and forms. Categorize them by input type (search, login, upload, comment, API) and flag candidates for SQLi, XSS, SSRF, and file upload testing.' },
        ],
      },
    ],
  },
  {
    id: 'network_recon',
    title: 'Network Reconnaissance',
    items: [
      {
        suggestions: [
          { label: 'Deep Nmap scan on key targets', prompt: 'Identify the top 5 most interesting hosts from the graph (those with most services or vulnerabilities), then run execute_nmap with -sV -sC -O for detailed service detection, default script scanning, and OS fingerprinting.' },
          { label: 'UDP service discovery', prompt: 'Run execute_nmap with -sU --top-ports 50 against the primary targets to discover UDP services like DNS (53), SNMP (161), TFTP (69), NTP (123), and IPMI (623).' },
          { label: 'Quick port scan on new targets', prompt: 'Use execute_naabu to perform a fast SYN scan on all in-scope IPs, then compare results with the graph data to identify any newly discovered open ports.' },
          { label: 'SMB and NetBIOS enumeration', prompt: 'Run execute_nmap with --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode against any hosts with port 445/139 open. Report accessible shares and security configuration.' },
          { label: 'Nmap NSE vulnerability scripts', prompt: 'Run execute_nmap with --script vuln against the top targets to discover additional vulnerabilities not found by Nuclei. Compare with existing graph data to identify new findings.' },
        ],
      },
    ],
  },
  {
    id: 'cred_exposure',
    title: 'Credential & Secret Exposure',
    items: [
      {
        suggestions: [
          { label: 'GitHub leaked secrets inventory', prompt: 'Query the graph for all GitHub secrets found (API keys, tokens, passwords, private keys). Categorize by type, affected service, and assess which ones could still be valid.' },
          { label: 'Validate leaked credentials', prompt: 'Query the graph for all discovered GitHub secrets and credentials. Use execute_curl or execute_code to test which API keys and tokens are still active without triggering rate limits.' },
          { label: 'Brute-forceable service inventory', prompt: 'Query the graph for all services that expose authentication (SSH, FTP, RDP, SMB, MySQL, PostgreSQL, HTTP Basic/Form Auth, Tomcat Manager). List host, port, and service type for each.' },
          { label: 'Default credential lookup', prompt: 'Query the graph for all discovered services and technologies. Use web_search to look up default credentials for each vendor/product, then compile a list of default username/password pairs to test.' },
        ],
      },
    ],
  },
  {
    id: 'tls_security',
    title: 'TLS & Security Configuration',
    items: [
      {
        suggestions: [
          { label: 'TLS certificate audit', prompt: 'Query the graph for all TLS certificates. Report expired or soon-to-expire certs, self-signed certs, wildcard certs, weak key sizes, and JARM fingerprint anomalies.' },
          { label: 'HTTP security headers analysis', prompt: 'Query the graph for all security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy). Flag missing or misconfigured headers per host.' },
          { label: 'SSL/TLS weakness scan', prompt: 'Run execute_nmap with --script ssl-enum-ciphers on all HTTPS hosts. Identify weak ciphers (RC4, DES, export), deprecated protocols (SSLv3, TLS 1.0/1.1), and missing features like PFS.' },
          { label: 'CORS and cookie security audit', prompt: 'Use execute_curl to check CORS headers (Access-Control-Allow-Origin) and cookie attributes (Secure, HttpOnly, SameSite) on all discovered web applications. Flag overly permissive configurations.' },
        ],
      },
    ],
  },
  {
    id: 'osint_research',
    title: 'OSINT & Research',
    items: [
      {
        suggestions: [
          { label: 'Research top CVEs in depth', prompt: 'Query the graph for the 5 highest CVSS vulnerabilities. For each, use web_search to find: exploit PoCs, Metasploit modules, affected versions, patch status, and real-world exploitation reports.' },
          { label: 'Search for exploit PoCs', prompt: 'Query the graph for all CVEs found, then use web_search to search GitHub and ExploitDB for proof-of-concept exploit code. Summarize available PoCs with links and assess reliability.' },
          { label: 'Searchsploit local lookup', prompt: 'Query the graph for all technologies and versions, then use kali_shell to run searchsploit against each technology/version combination. Report all matching exploits from ExploitDB.' },
          { label: 'CVE exploit chain analysis', prompt: 'Query the graph for all vulnerabilities on each host. Use web_search to research whether any combination of findings could be chained into a multi-step attack (e.g., info disclosure + auth bypass + RCE).' },
        ],
      },
    ],
  },
  {
    id: 'shodan_dork',
    title: 'Shodan & Google Dork OSINT',
    items: [
      {
        osLabel: 'Shodan',
        suggestions: [
          { label: 'Full Shodan host profile', prompt: 'Use shodan with action="host" on all in-scope IP addresses to get detailed info: open ports, service banners, SSL certificates, known CVEs, OS detection, and organization. Compare findings with the graph data to identify gaps.' },
          { label: 'Search for exposed services in target org', prompt: 'Use shodan with action="search" and query "org:<target-organization>" to discover all internet-facing devices belonging to the target. Identify shadow IT, forgotten servers, and services not found by active scanning.' },
          { label: 'Find vulnerable hosts (has_vuln filter)', prompt: 'Use shodan with action="search" and query "net:<target-range> has_vuln:true" to find hosts with known CVEs. Cross-reference with graph data to prioritize exploitation targets.' },
          { label: 'Subdomain discovery via Shodan DNS', prompt: 'Use shodan with action="dns_domain" on the target domain to enumerate subdomains and DNS records. Compare with graph data to find subdomains missed by other recon tools.' },
          { label: 'Reverse DNS on target IPs', prompt: 'Use shodan with action="dns_reverse" on all discovered IP addresses to find hostnames and identify shared hosting or virtual hosts that could expand the attack surface.' },
          { label: 'Count exposed services before deep scan', prompt: 'Use shodan with action="count" and queries like "net:<range> port:22", "net:<range> port:3389", "net:<range> port:445" to estimate the attack surface size without consuming search credits.' },
        ],
      },
      {
        osLabel: 'Google Dork',
        suggestions: [
          { label: 'Find exposed sensitive files', prompt: 'Use google_dork with query "site:<target-domain> filetype:sql OR filetype:env OR filetype:log OR filetype:bak OR filetype:conf" to discover publicly indexed sensitive files like database dumps, environment configs, and logs.' },
          { label: 'Discover admin panels and login pages', prompt: 'Use google_dork with query "site:<target-domain> inurl:admin OR inurl:login OR inurl:dashboard OR inurl:console OR intitle:\\"admin panel\\"" to find exposed management interfaces indexed by Google.' },
          { label: 'Find directory listings', prompt: 'Use google_dork with query "site:<target-domain> intitle:\\"index of /\\" OR intitle:\\"directory listing\\"" to discover open directory listings that may expose sensitive files, source code, or backups.' },
          { label: 'Discover exposed API docs and endpoints', prompt: 'Use google_dork with query "site:<target-domain> inurl:swagger OR inurl:api-docs OR inurl:graphql OR filetype:json \\"openapi\\"" to find publicly indexed API documentation and endpoint schemas.' },
          { label: 'Find configuration and credential leaks', prompt: 'Use google_dork with query "site:<target-domain> filetype:xml OR filetype:yaml OR filetype:ini OR filetype:cfg \\"password\\" OR \\"secret\\" OR \\"api_key\\"" to discover leaked configuration files containing credentials.' },
          { label: 'Discover error pages with stack traces', prompt: 'Use google_dork with query "site:<target-domain> \\"stack trace\\" OR \\"fatal error\\" OR \\"exception\\" OR \\"debug\\" OR \\"traceback\\"" to find error pages that leak internal paths, framework versions, and database details.' },
          { label: 'Find exposed Git and SVN repositories', prompt: 'Use google_dork with query "site:<target-domain> inurl:.git OR inurl:.svn OR inurl:.hg OR intitle:\\"index of /.git\\"" to discover exposed version control repositories that may contain source code and secrets.' },
          { label: 'Comprehensive dork sweep', prompt: 'Run a comprehensive Google dork sweep against the target domain: search for exposed files (sql, env, log, bak), admin panels, directory listings, error pages, API docs, and git repos. Compile all findings into a prioritized report.' },
        ],
      },
    ],
  },
  {
    id: 'active_verify',
    title: 'Active Verification',
    items: [
      {
        suggestions: [
          { label: 'Nuclei verification of top CVEs', prompt: 'Query the graph for the 10 highest severity vulnerabilities, then use execute_nuclei to re-verify each one with targeted template IDs. Confirm which are true positives and provide proof.' },
          { label: 'Probe for exposed admin interfaces', prompt: 'Use execute_curl to probe all discovered web hosts for common admin paths (/admin, /manager/html, /wp-admin, /phpmyadmin, /console). Record response codes, redirects, and page content.' },
          { label: 'Version fingerprinting via curl', prompt: 'Use execute_curl to collect detailed HTTP response headers and body content from all web servers. Extract exact version strings from Server headers, X-Powered-By, generator meta tags, and error pages.' },
          { label: 'Nuclei full template scan', prompt: 'Run execute_nuclei with a broad template set (cves, misconfiguration, exposure, default-logins) against the top 3 targets. Report all findings categorized by severity.' },
          { label: 'Test for path traversal', prompt: 'Use execute_curl to test path traversal payloads (../../../etc/passwd, ..\\\\..\\\\..\\\\windows\\\\win.ini) against all discovered web endpoints that accept file path parameters. Report any successful reads.' },
        ],
      },
    ],
  },
]

// =============================================================================
// EXPLOITATION SUGGESTION DATA
// =============================================================================

export const EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cve_exploit',
    title: 'CVE (MSF)',
    items: [
      {
        suggestions: [
          { label: 'Exploit the most critical CVE', prompt: 'Query the graph for the highest CVSS vulnerability with a known Metasploit module. Set up and launch the exploit using metasploit_console to gain a remote shell on the target.' },
          { label: 'Exploit a critical CVE and open a session', prompt: 'Find the most critical CVE on the target, exploit it with Metasploit, and open a Meterpreter shell session. Confirm the session is stable and report the access level obtained.' },
          { label: 'Exploit a known RCE vulnerability', prompt: 'Query the graph for Remote Code Execution (RCE) CVEs, select the most promising one, search for its Metasploit module, configure it, and exploit the target to gain a shell.' },
          { label: 'Chain vulnerabilities for RCE', prompt: 'Analyze all discovered vulnerabilities on the target. Chain multiple lower-severity findings together (e.g., info disclosure + auth bypass + injection) to achieve remote code execution.' },
          { label: 'Exploit a web server CVE', prompt: 'Query the graph for CVEs affecting web servers (Apache, Nginx, IIS, Tomcat). Find the Metasploit module, configure it for the target, and exploit it to gain a shell.' },
        ],
      },
    ],
  },
  {
    id: 'brute_force',
    title: 'Credential Testing',
    items: [
      {
        suggestions: [
          { label: 'Test SSH credentials and explore the server', prompt: 'Use execute_hydra to test SSH credentials on the target using common username/password lists. Once access is gained, enumerate sensitive files, users, and configuration.' },
          { label: 'Test default credentials on all services', prompt: 'Query the graph for all services with authentication (Tomcat, Jenkins, phpMyAdmin, databases, FTP, SSH). Use execute_hydra and execute_curl to test default and common credentials on each.' },
          { label: 'Leverage GitHub secrets to access the server', prompt: 'Query the graph for GitHub secrets (credentials, API keys, tokens). Use any discovered credentials to attempt SSH, FTP, database, or web admin access. Report what access was gained.' },
          { label: 'Test web login form credentials', prompt: 'Query the graph for login form endpoints. Use execute_hydra with http-post-form to test credentials using common wordlists. Report any successful logins.' },
          { label: 'Database credential testing', prompt: 'Query the graph for exposed database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017). Use execute_hydra to test common credentials, then connect and enumerate databases.' },
          { label: 'FTP anonymous and credential testing', prompt: 'Query the graph for all FTP services. Test for anonymous access first, then use execute_hydra to test common credentials. Enumerate any accessible files and directories.' },
        ],
      },
    ],
  },
  {
    id: 'web_attacks',
    title: 'Web Application Attacks',
    items: [
      {
        suggestions: [
          { label: 'Exploit SQL injection on web forms', prompt: 'Query the graph for web endpoints with input parameters. Use kali_shell with sqlmap to test for SQL injection vulnerabilities, then extract database schema, tables, and sensitive data.' },
          { label: 'Upload a web shell via file upload', prompt: 'Query the graph for file upload endpoints. Craft and upload a PHP/JSP/ASPX web shell using execute_curl with various bypass techniques (extension tricks, content-type manipulation). Confirm remote command execution.' },
          { label: 'Test for command injection', prompt: 'Query the graph for endpoints with parameters that could interact with OS commands. Use execute_curl to test command injection payloads (;id, |whoami, $(id), `id`). Escalate any confirmed injection to a reverse shell.' },
          { label: 'Exploit SSRF vulnerabilities', prompt: 'Query the graph for endpoints that accept URL parameters. Use execute_curl to test SSRF payloads targeting internal services (http://127.0.0.1, http://169.254.169.254 for cloud metadata, internal admin panels).' },
          { label: 'Test for directory traversal and LFI', prompt: 'Query the graph for endpoints with file path parameters. Use execute_curl to test directory traversal payloads to read /etc/passwd, /etc/shadow, application config files, and attempt LFI to RCE via log poisoning.' },
          { label: 'Exploit XSS for session hijacking', prompt: 'Query the graph for endpoints with reflected or stored XSS potential. Craft XSS payloads using execute_curl to test for JavaScript execution and demonstrate session cookie theft.' },
        ],
      },
    ],
  },
  {
    id: 'dos',
    title: 'Availability Testing',
    items: [
      {
        suggestions: [
          { label: 'Test service availability (auto-select best vector)', prompt: 'Perform an availability test against the target. Analyze the discovered services and vulnerabilities from the graph, select the most effective test vector (known CVE, HTTP application, Layer 4 flood, or application logic), execute the test, and verify the service impact.' },
          { label: 'Test web server resilience', prompt: 'Test the web server resilience on the target. Choose the best approach based on the server type and version — try slowloris, slow POST, known CVE modules, or crafted crash requests. Verify the service impact.' },
          { label: 'Stress test target service availability', prompt: 'Test the resilience of the target service to availability disruption. Try multiple test vectors (up to the configured max attempts), document which ones succeed and which fail, and report whether the service is resilient or vulnerable.' },
        ],
      },
      {
        osLabel: 'Known CVE Availability Tests',
        suggestions: [
          { label: 'Test RDP resilience via MS12-020', prompt: 'Use Metasploit auxiliary/dos/windows/rdp/ms12_020_maxchannelids to test the RDP service on the target. First verify vulnerability with nmap --script rdp-ms12-020, then execute the module and verify the service impact.' },
          { label: 'Test IIS via MS15-034 (HTTP.sys)', prompt: 'Use Metasploit auxiliary/dos/http/ms15_034_ulonglongadd to test IIS on the target via the HTTP.sys Range header vulnerability. Verify the web server availability impact.' },
          { label: 'Test Apache via Range header', prompt: 'Use Metasploit auxiliary/dos/http/apache_range_dos to test an Apache web server (< 2.2.21) by sending overlapping Range header requests. Verify the service impact.' },
          { label: 'Search for availability test modules for target service', prompt: 'Search Metasploit for DoS modules matching the target service (search auxiliary/dos/<service>). Select the most applicable module, configure it, and execute to test the service.' },
        ],
      },
      {
        osLabel: 'HTTP Application Testing',
        suggestions: [
          { label: 'Slowloris (incomplete headers)', prompt: 'Use slowhttptest in Slowloris mode (-H) to test the web server connection pool by sending incomplete HTTP headers. Keep connections open and verify the web server availability impact.' },
          { label: 'Slow POST body (R.U.D.Y.)', prompt: 'Use slowhttptest in Slow POST mode (-B) to send HTTP POST requests with an extremely slow body transmission rate. Target form endpoints and verify the web server availability impact.' },
          { label: 'Range header test', prompt: 'Use slowhttptest in Range mode (-R) to send requests with multiple overlapping Range header values, testing server memory handling. Verify the Apache web server availability impact.' },
          { label: 'Hash collision test (PHP/Java/Python)', prompt: 'Use Metasploit auxiliary/dos/http/hashcollision_dos to send crafted POST parameters that trigger hash collision in the web framework, consuming CPU. Verify the application availability impact.' },
        ],
      },
      {
        osLabel: 'Layer 4 Flooding',
        suggestions: [
          { label: 'TCP SYN flood test', prompt: 'Use hping3 with SYN flood mode (hping3 -S --flood) against the target port to test its connection state table resilience. Run for the configured duration and verify the service availability impact.' },
          { label: 'UDP flood test', prompt: 'Use hping3 in UDP flood mode (hping3 --udp --flood) against the target UDP service (DNS, SNMP). Verify the service availability impact.' },
          { label: 'ICMP flood test', prompt: 'Use hping3 in ICMP flood mode (hping3 --icmp --flood) to test the target network link saturation resilience. Verify the availability impact on services.' },
        ],
      },
      {
        osLabel: 'Application Logic DoS',
        suggestions: [
          { label: 'ReDoS (regex backtracking test)', prompt: 'Identify an endpoint that processes regex input. Use execute_code (Python) to craft a regex-bomb payload that causes catastrophic backtracking, then send it to the endpoint and verify it hangs or times out.' },
          { label: 'XML entity expansion test', prompt: 'Use execute_code (Python) to craft an XML billion laughs payload (nested entity expansion) and POST it to an endpoint that parses XML. Verify the server availability impact.' },
          { label: 'GraphQL depth/complexity test', prompt: 'Use execute_code (Python) to craft a deeply nested GraphQL query that exceeds the server query depth limit. Send it to the GraphQL endpoint and verify it causes excessive resource consumption.' },
          { label: 'Resource exhaustion via API test', prompt: 'Use execute_code (Python) to send rapid concurrent requests to an expensive API endpoint (large file generation, complex queries, heavy computation). Verify the service availability impact.' },
        ],
      },
      {
        osLabel: 'Single-Request Crash',
        suggestions: [
          { label: 'Range header overflow test', prompt: 'Use execute_curl to send a request with an oversized Range header value (bytes=0-18446744073709551615) to test for an integer overflow vulnerability in the web server. Verify the service availability impact.' },
          { label: 'Malformed Content-Length test', prompt: 'Use execute_curl to send a POST request with an absurdly large Content-Length header to test the web server memory allocation handling. Verify the service availability impact.' },
          { label: 'Header size limit test', prompt: 'Use execute_curl to send a request with an extremely large custom header (10KB+) to test the web server header buffer handling. Verify the service availability impact.' },
        ],
      },
    ],
  },
  {
    id: 'manual_exploit',
    title: 'Manual Exploitation',
    items: [
      {
        suggestions: [
          { label: 'Nuclei-verified exploit execution', prompt: 'Query the graph for Nuclei-confirmed vulnerabilities. For the most critical one, use execute_curl or execute_code to manually craft and send the exploit payload. Confirm exploitation and demonstrate impact.' },
          { label: 'Custom exploit script from PoC', prompt: 'Query the graph for the most critical CVE, then use web_search to find a public exploit PoC. Adapt it using execute_code (Python) to work against the target, execute it, and confirm exploitation.' },
          { label: 'Reverse shell via curl exploitation', prompt: 'Identify a confirmed RCE vulnerability on a web target. Use execute_curl to manually exploit it and inject a reverse shell payload (bash, python, or netcat). Set up the listener in kali_shell.' },
          { label: 'Exploit misconfigured service', prompt: 'Query the graph for services with known misconfigurations (unauthenticated Redis, open MongoDB, exposed Docker API, Kubernetes dashboard). Use kali_shell tools to exploit the misconfiguration and gain access.' },
          { label: 'Exploit exposed management interface', prompt: 'Query the graph for management interfaces (Tomcat Manager, Jenkins, JMX, phpMyAdmin). Attempt access using discovered or default credentials, then leverage the interface to deploy a payload or execute commands.' },
        ],
      },
    ],
  },
]

// =============================================================================
// POST-EXPLOITATION SUGGESTION DATA
// =============================================================================

export const POST_EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cred_harvest',
    title: 'Credential Harvesting & Cracking',
    items: [
      {
        suggestions: [
          { label: 'Hunt for secrets and credentials', prompt: 'Search the compromised server for passwords, API keys, tokens, and secrets in config files, environment variables, .env files, .bash_history, application configs, and web server configs. Report all findings.' },
          { label: 'Dump and crack password hashes', prompt: 'Extract password hashes from /etc/shadow (Linux) or SAM database (Windows via Meterpreter hashdump). Use kali_shell with john or hashcat to crack the hashes with common wordlists.' },
          { label: 'Database credential extraction', prompt: 'Search for database connection strings and credentials in web application config files (wp-config.php, .env, settings.py, application.properties, web.config). Connect to found databases and dump user/credential tables.' },
          { label: 'Extract private keys and certificates', prompt: 'Search the filesystem for SSH private keys (~/.ssh/id_rsa, /etc/ssh/), TLS private keys, PFX/P12 files, and PGP keys. Test each key for passwordless access to other systems.' },
          { label: 'Browser and application credential dump', prompt: 'Search for saved credentials in browser profiles, password managers, FTP client configs (FileZilla), email client configs, and application credential stores. Extract and organize all found credentials.' },
        ],
      },
    ],
  },
  {
    id: 'privesc',
    title: 'Privilege Escalation',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'SUID/SGID binary exploitation', prompt: 'Run find / -perm -4000 2>/dev/null to list all SUID binaries. Cross-reference with GTFOBins using web_search to find exploitable binaries. Attempt privilege escalation via the most promising vector.' },
          { label: 'Sudo misconfiguration exploitation', prompt: 'Run sudo -l to check sudo permissions. Identify any NOPASSWD entries, wildcard abuse, or LD_PRELOAD/LD_LIBRARY_PATH exploitation paths. Use GTFOBins to escalate to root.' },
          { label: 'Writable cron job exploitation', prompt: 'Enumerate all cron jobs (crontab -l, /etc/crontab, /etc/cron.d/*, /var/spool/cron/). Find any writable scripts executed by root. Inject a reverse shell or add a backdoor user to escalate privileges.' },
          { label: 'Linux kernel exploit check', prompt: 'Collect kernel version (uname -a), distribution info, and installed packages. Use web_search to find applicable kernel exploits (DirtyPipe, DirtyCow, etc.). Compile and run the most suitable exploit via execute_code.' },
          { label: 'Capability-based escalation', prompt: 'Run getcap -r / 2>/dev/null to find binaries with special capabilities. Check for cap_setuid, cap_dac_read_search, cap_net_raw, or cap_sys_admin. Exploit the capabilities to escalate to root.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Windows service misconfiguration', prompt: 'Use Meterpreter getsystem and check for unquoted service paths, writable service binaries, and modifiable service configurations. Exploit the most promising vector to escalate to SYSTEM.' },
          { label: 'Token impersonation (Potato attacks)', prompt: 'Check current privileges with whoami /priv. If SeImpersonatePrivilege is enabled, use a Potato attack (JuicyPotato, PrintSpoofer, GodPotato) via metasploit_console to escalate to SYSTEM.' },
          { label: 'Credential harvesting with Mimikatz', prompt: 'Load Mimikatz via Meterpreter (load kiwi) and run creds_all to dump plaintext passwords, NTLM hashes, and Kerberos tickets from memory. Report all harvested credentials.' },
        ],
      },
    ],
  },
  {
    id: 'lateral_movement',
    title: 'Lateral Movement',
    items: [
      {
        suggestions: [
          { label: 'Map internal network and pivot', prompt: 'Enumerate network interfaces (ifconfig/ipconfig), ARP tables (arp -a), routing tables, and /etc/hosts. Discover internal hosts and subnets, then set up Meterpreter autoroute to pivot into the internal network.' },
          { label: 'Harvest SSH keys and move laterally', prompt: 'Collect all SSH keys (~/.ssh/), known_hosts, authorized_keys, and bash_history SSH commands. Attempt to SSH into discovered internal hosts using the harvested keys and any cracked credentials.' },
          { label: 'Port forwarding for internal access', prompt: 'Set up Meterpreter port forwarding (portfwd add) to access internal services that are not directly reachable. Forward interesting internal ports (web admin panels, databases, RDP) to the attacker machine.' },
          { label: 'Internal service enumeration', prompt: 'From the compromised host, use kali_shell to scan the internal network (nmap or naabu) for additional hosts and services. Identify high-value targets like domain controllers, databases, file servers, and CI/CD systems.' },
          { label: 'SMB/WinRM lateral movement', prompt: 'Use discovered credentials to attempt lateral movement via SMB (psexec, smbexec) or WinRM to other Windows hosts. Use metasploit_console modules like exploit/windows/smb/psexec.' },
        ],
      },
    ],
  },
  {
    id: 'data_exfil',
    title: 'Data Access Verification',
    items: [
      {
        suggestions: [
          { label: 'Verify database access and enumerate data', prompt: 'Find database credentials in application config files. Connect to the database (MySQL, PostgreSQL, MongoDB) and enumerate all databases, tables, and verify access to sensitive data (users, credentials, PII, financial records). Document the scope of accessible data.' },
          { label: 'Source code and configuration exposure assessment', prompt: 'Search for application source code repositories (.git directories), deployment scripts, CI/CD configs, Dockerfiles, and Kubernetes manifests. Analyze for hardcoded secrets and document the exposure.' },
          { label: 'Backup file discovery', prompt: 'Search for backup files: *.bak, *.sql, *.dump, *.tar.gz, *.zip in common backup locations (/backup, /var/backups, /tmp, /opt, home directories). Assess and document what sensitive data is accessible via unprotected backups.' },
          { label: 'Email and document exposure assessment', prompt: 'Search for emails (Maildir, mbox), documents (*.pdf, *.docx, *.xlsx), and spreadsheets containing sensitive information. Look in home directories, /var/mail, and application data directories. Document the scope of accessible data.' },
          { label: 'Cloud credential exposure assessment', prompt: 'Search for cloud provider credentials: AWS (~/.aws/credentials), GCP (service account JSON), Azure (azure.json), and Kubernetes configs (~/.kube/config). Test validity and document accessible cloud resources.' },
        ],
      },
    ],
  },
  {
    id: 'persistence',
    title: 'Persistence Risk Assessment',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'Test cron job persistence vector', prompt: 'Assess whether the compromised access allows adding a cron job that would survive reboots. Add a benign test entry to crontab and verify it persists. Document the persistence risk for remediation recommendations.' },
          { label: 'Test SSH key injection vector', prompt: 'Assess whether the compromised access allows injecting an SSH public key into authorized_keys files. Generate a test key pair, inject it, and verify passwordless SSH access. Document the persistence risk.' },
          { label: 'Test unauthorized account creation', prompt: 'Assess whether the compromised access allows creating new user accounts with elevated privileges. Attempt to create a test account and verify access. Document the persistence risk for remediation.' },
          { label: 'Test systemd service persistence vector', prompt: 'Assess whether the compromised access allows creating a systemd service that executes on boot. Write a benign test service, enable it, and verify it starts on restart. Document the persistence risk.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Test registry run key persistence', prompt: 'Assess whether the compromised access allows adding a registry run key (HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run) for persistence. Add a benign test entry and verify it executes on login. Document the risk.' },
          { label: 'Test scheduled task persistence', prompt: 'Assess whether the compromised access allows creating scheduled tasks for persistence. Create a benign test task and verify execution on startup. Document the persistence risk for remediation.' },
          { label: 'Test Meterpreter persistence mechanism', prompt: 'Use Meterpreter persistence module to assess whether the system is vulnerable to auto-starting payload persistence. Document the persistence vector and recommend mitigations.' },
        ],
      },
    ],
  },
  {
    id: 'sys_enum',
    title: 'System & Environment Enumeration',
    items: [
      {
        suggestions: [
          { label: 'Full system enumeration', prompt: 'Collect comprehensive system information: OS version, kernel, hostname, architecture, installed packages, running processes, logged-in users, environment variables, mounted filesystems, and scheduled tasks.' },
          { label: 'User and group enumeration', prompt: 'Enumerate all user accounts (/etc/passwd, net user), groups (/etc/group), sudo permissions, login history (lastlog, wtmp), and currently logged-in users. Identify service accounts and privileged users.' },
          { label: 'Network configuration mapping', prompt: 'Map all network interfaces, IP addresses, routing tables, DNS configuration, active connections (netstat/ss), listening services, firewall rules (iptables/ufw), and ARP neighbors.' },
          { label: 'Process and service audit', prompt: 'List all running processes with their owners and command lines (ps aux). Identify services running as root, unusual processes, and processes with network connections. Check for Docker/container environments.' },
          { label: 'Installed software and patch level', prompt: 'List all installed packages and their versions (dpkg -l, rpm -qa, pip list, npm list -g). Identify security patches applied and missing. Flag any software with known privilege escalation vulnerabilities.' },
          { label: 'Proof of access (web server)', prompt: 'Locate the web server document root and place a proof-of-access file (e.g., pentest-proof.txt) demonstrating write access was achieved. Take a screenshot via execute_curl to document the result for the engagement report.' },
        ],
      },
    ],
  },
]
