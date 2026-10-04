/**
 * Prefilled MCP server templates - 10 publicly-available, security-relevant
 * MCP servers chosen for RedAmon's pentest workflow.
 *
 * Each preset fills `id, name, description, transport, url/command/args,
 * default_phases, auth structure, env structure` - but leaves `token` and
 * any user-specific values empty so the user just pastes their key (if
 * needed) and clicks Test → "+ add all" to auto-import discovered tools.
 *
 * URLs are verified live as of writing. The free auth requirements are
 * accurate; quotas/policies on the upstream services may change.
 */

import type { MCPServer } from './schema'

export type PresetCategory = 'osint' | 'research' | 'web' | 'security' | 'utility'

export interface McpPreset {
  /** Unique key for this preset (not the user's saved server id). */
  key: string
  /** Display label in the picker. */
  label: string
  category: PresetCategory
  /** Short blurb shown in the card. */
  blurb: string
  /** What this is useful for in a pentest context. */
  whyForRedamon: string
  /** Public docs / signup URL. */
  docsUrl: string
  /** Whether the user must paste an auth token before Test will succeed. */
  authRequired: boolean
  /** Friendly hint about how to obtain auth. */
  authHint?: string
  /** Fully-typed template merged into the new-server form on click. */
  template: MCPServer
}

const ALL_PHASES = ['informational', 'exploitation', 'post_exploitation'] as const

/** Stub helper - the form's `emptyServer()` shape we extend per preset. */
const baseTemplate = (overrides: Partial<MCPServer>): MCPServer => ({
  id: '',
  name: '',
  description: '',
  enabled: true,
  transport: 'streamable_http',
  default_phases: [...ALL_PHASES],
  tags: [],
  url: '',
  headers: {},
  auth: undefined,
  connect_timeout: 60,
  read_timeout: 600,
  command: '',
  args: [],
  env: {},
  cwd: '',
  encoding: 'utf-8',
  tools: [],
  ...overrides,
})

export const MCP_PRESETS: McpPreset[] = [
  // -------------------------------------------------------------------------
  // 1) DeepWiki - anonymous, easiest first test
  // -------------------------------------------------------------------------
  {
    key: 'deepwiki',
    label: 'DeepWiki',
    category: 'research',
    blurb: 'Cognition\'s public-repo Q&A. Ask any GitHub repo natural-language questions.',
    whyForRedamon: 'Research vulnerable libraries, understand exploit code in public PoC repos, audit dependencies before targeting them.',
    docsUrl: 'https://docs.devin.ai/work-with-devin/deepwiki-mcp',
    authRequired: false,
    template: baseTemplate({
      id: 'deepwiki',
      name: 'DeepWiki',
      description: 'Q&A over any public GitHub repository (no auth required)',
      transport: 'streamable_http',
      url: 'https://mcp.deepwiki.com/mcp',
      default_phases: ['informational'],
      tags: ['research', 'github'],
    }),
  },

  // -------------------------------------------------------------------------
  // 2) GitHub MCP (official) - code search, vulnerable-repo hunting
  // -------------------------------------------------------------------------
  {
    key: 'github',
    label: 'GitHub',
    category: 'osint',
    blurb: 'Official GitHub MCP - code/issue/PR search across all of GitHub.',
    whyForRedamon: 'Find exploit PoCs, search for credentials in public repos, identify vulnerable code patterns, supply-chain analysis.',
    docsUrl: 'https://github.com/github/github-mcp-server',
    authRequired: true,
    authHint: 'Generate a fine-grained PAT (read-only is enough): https://github.com/settings/personal-access-tokens',
    template: baseTemplate({
      id: 'github',
      name: 'GitHub',
      description: 'Official GitHub MCP - code, issues, PRs, security advisories',
      transport: 'streamable_http',
      url: 'https://api.githubcopilot.com/mcp/',
      default_phases: ['informational', 'exploitation'],
      tags: ['osint', 'code', 'github'],
      auth: { type: 'bearer', token: '' },
    }),
  },

  // -------------------------------------------------------------------------
  // 3) Hugging Face - research papers, security ML, datasets
  // -------------------------------------------------------------------------
  {
    key: 'huggingface',
    label: 'Hugging Face',
    category: 'research',
    blurb: 'Search HF models, datasets, papers, and Spaces.',
    whyForRedamon: 'Find security research papers (e.g., recent CVE writeups, exploitation techniques), datasets for fuzzing, ML-based vuln-detection tools.',
    docsUrl: 'https://huggingface.co/mcp',
    authRequired: true,
    authHint: 'Read-only token from https://huggingface.co/settings/tokens',
    template: baseTemplate({
      id: 'huggingface',
      name: 'Hugging Face',
      description: 'Search models, datasets, papers, Spaces',
      transport: 'streamable_http',
      url: 'https://huggingface.co/mcp',
      default_phases: ['informational'],
      tags: ['research', 'ml'],
      auth: { type: 'bearer', token: '' },
    }),
  },

  // -------------------------------------------------------------------------
  // 4) Context7 - up-to-date library documentation (Upstash)
  // -------------------------------------------------------------------------
  {
    key: 'context7',
    label: 'Context7',
    category: 'research',
    blurb: 'Up-to-date library/framework documentation - Upstash hosted.',
    whyForRedamon: 'Look up current API surface of libraries you\'re probing (e.g., to understand authentication flows or find deprecated/removed protections).',
    docsUrl: 'https://github.com/upstash/context7',
    authRequired: false,
    authHint: 'Optional: get a free API key from https://context7.com for higher rate limits',
    template: baseTemplate({
      id: 'context7',
      name: 'Context7',
      description: 'Library/framework docs lookup (Upstash)',
      transport: 'streamable_http',
      url: 'https://mcp.context7.com/mcp',
      default_phases: ['informational', 'exploitation'],
      tags: ['research', 'docs'],
    }),
  },

  // -------------------------------------------------------------------------
  // 5) Brave Search - OSINT search alternative to Tavily/Google
  // -------------------------------------------------------------------------
  {
    key: 'brave_search',
    label: 'Brave Search',
    category: 'osint',
    blurb: 'Web + local search via Brave Search API.',
    whyForRedamon: 'Independent OSINT search engine - useful when Tavily/Google rate limits hit during recon, or for cross-checking results from a different index.',
    docsUrl: 'https://api.search.brave.com/',
    authRequired: true,
    authHint: 'Free tier 2k req/month at https://api.search.brave.com/app/keys',
    template: baseTemplate({
      id: 'brave_search',
      name: 'Brave Search',
      description: 'Web/local search via Brave Search API (free 2k/mo)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-brave-search'],
      env: { BRAVE_API_KEY: '' },
      default_phases: ['informational'],
      tags: ['osint', 'search'],
    }),
  },

  // -------------------------------------------------------------------------
  // 6) Memory - persistent knowledge graph across sessions
  // -------------------------------------------------------------------------
  {
    key: 'memory',
    label: 'Memory (knowledge graph)',
    category: 'utility',
    blurb: 'Persistent entity-relation memory the agent can read/write.',
    whyForRedamon: 'Carry findings across sessions: track confirmed credentials, persistent shells, mapped subdomain → CVE relationships beyond a single chat.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers/tree/main/src/memory',
    authRequired: false,
    template: baseTemplate({
      id: 'memory',
      name: 'Memory',
      description: 'Persistent knowledge graph across sessions',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-memory'],
      env: { MEMORY_FILE_PATH: '/app/logs/mcp_memory.json' },
      default_phases: [...ALL_PHASES],
      tags: ['utility', 'memory'],
    }),
  },

  // -------------------------------------------------------------------------
  // 7) Sequential Thinking - explicit step-by-step reasoning tool
  // -------------------------------------------------------------------------
  {
    key: 'sequential_thinking',
    label: 'Sequential Thinking',
    category: 'utility',
    blurb: 'Structured multi-step reasoning tool - externalizes the agent\'s chain-of-thought.',
    whyForRedamon: 'Force the LLM to plan exploit chains explicitly: enumerate steps, revise hypothesis, document decision points. Audit-trail-friendly.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking',
    authRequired: false,
    template: baseTemplate({
      id: 'sequential_thinking',
      name: 'Sequential Thinking',
      description: 'Structured chain-of-thought / hypothesis-revision tool',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-sequential-thinking'],
      default_phases: [...ALL_PHASES],
      tags: ['utility', 'reasoning'],
    }),
  },

  // -------------------------------------------------------------------------
  // 8) Filesystem - read/write within a sandboxed agent-local dir
  // -------------------------------------------------------------------------
  {
    key: 'filesystem',
    label: 'Filesystem (sandboxed)',
    category: 'utility',
    blurb: 'Read/write files in a sandboxed directory inside the agent container.',
    whyForRedamon: 'Stash exfiltrated files, build wordlists/payloads incrementally, save reverse-shell artifacts between iterations. Sandboxed to /app/logs/sandbox.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem',
    authRequired: false,
    template: baseTemplate({
      id: 'filesystem',
      name: 'Filesystem',
      description: 'Sandboxed file ops in /app/logs/sandbox (agent container)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/app/logs/sandbox'],
      default_phases: ['exploitation', 'post_exploitation'],
      tags: ['utility', 'fs'],
    }),
  },

  // -------------------------------------------------------------------------
  // 9) Shodan - internet-wide host/port intel (heavy pentest staple)
  // -------------------------------------------------------------------------
  {
    key: 'shodan',
    label: 'Shodan',
    category: 'security',
    blurb: 'Internet-wide host / port / banner intel via Shodan API.',
    whyForRedamon: 'Map external attack surface, find exposed services, banner-grab without touching the target. Augments execute_naabu by adding pre-existing scan data + CVE matches.',
    docsUrl: 'https://github.com/burtthecoder/mcp-shodan',
    authRequired: true,
    authHint: 'Shodan API key required. Free key at https://account.shodan.io/register',
    template: baseTemplate({
      id: 'shodan',
      name: 'Shodan',
      description: 'Internet-wide reconnaissance via Shodan API',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@burtthecoder/mcp-shodan'],
      env: { SHODAN_API_KEY: '' },
      default_phases: ['informational'],
      tags: ['security', 'osint', 'recon'],
    }),
  },

  // -------------------------------------------------------------------------
  // 10) VirusTotal - file/URL/IP threat intel
  // -------------------------------------------------------------------------
  {
    key: 'virustotal',
    label: 'VirusTotal',
    category: 'security',
    blurb: 'File hash / URL / IP / domain reputation via VirusTotal API.',
    whyForRedamon: 'Triage suspicious artifacts found during scans, check IP reputation before exfil callbacks, identify known-malicious domains hosted on target subdomains.',
    docsUrl: 'https://github.com/burtthecoder/mcp-virustotal',
    authRequired: true,
    authHint: 'Free public API key at https://www.virustotal.com/gui/my-apikey',
    template: baseTemplate({
      id: 'virustotal',
      name: 'VirusTotal',
      description: 'File / URL / IP / domain reputation analysis',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@burtthecoder/mcp-virustotal'],
      env: { VIRUSTOTAL_API_KEY: '' },
      default_phases: ['informational', 'exploitation'],
      tags: ['security', 'threat-intel'],
    }),
  },

  // -------------------------------------------------------------------------
  // 11) OSINT Toolkit (badchars) - 37 tools across 12 sources
  // -------------------------------------------------------------------------
  {
    key: 'osint_toolkit',
    label: 'OSINT Toolkit',
    category: 'osint',
    blurb: '37-tool OSINT suite: DNS, WHOIS, crt.sh, GeoIP, BGP, Wayback, Hackertarget - works without API keys.',
    whyForRedamon: 'Single-call DNS recon (lookups, reverse, SPF chain, DMARC, wildcards, SRV), CT log search (crt.sh), passive ASN/BGP analysis. Fills gaps the kali-sandbox tools don\'t cover natively.',
    docsUrl: 'https://github.com/badchars/osint-mcp-server',
    authRequired: false,
    authHint: 'Optional: SHODAN_API_KEY, VT_API_KEY, ST_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET unlock 14 extra tools',
    template: baseTemplate({
      id: 'osint_toolkit',
      name: 'OSINT Toolkit',
      description: 'DNS, WHOIS, crt.sh, GeoIP, BGP, Wayback (37 tools, no auth required)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'osint-mcp-server'],
      env: {
        // Leaving these in the form so the user can fill them when they
        // want premium tools active. Empty = those tools just don't show up.
        SHODAN_API_KEY: '',
        VT_API_KEY: '',
        ST_API_KEY: '',
      },
      default_phases: ['informational'],
      tags: ['osint', 'dns', 'recon'],
    }),
  },

  // -------------------------------------------------------------------------
  // 12) Threat Intel (AbuseIPDB + GreyNoise + AlienVault OTX + abuse.ch)
  // -------------------------------------------------------------------------
  {
    key: 'threat_intel',
    label: 'Threat Intel (AbuseIPDB + GreyNoise + OTX)',
    category: 'security',
    blurb: 'Unified threat feed: AbuseIPDB, GreyNoise, AlienVault OTX, abuse.ch.',
    whyForRedamon: 'IP reputation enrichment - distinguish opportunistic scanners from targeted attackers, validate exfil destinations, check WAF blocklists. Multiple feeds cross-corroborate.',
    docsUrl: 'https://github.com/aplaceforallmystuff/mcp-threatintel',
    authRequired: false,
    authHint: 'Most feeds require free API keys (AbuseIPDB, GreyNoise, OTX). abuse.ch Feodo Tracker works without auth.',
    template: baseTemplate({
      id: 'threat_intel',
      name: 'Threat Intel',
      description: 'AbuseIPDB + GreyNoise + OTX + abuse.ch unified feed',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'mcp-threatintel-server'],
      env: {
        ABUSEIPDB_API_KEY: '',
        GREYNOISE_API_KEY: '',
        OTX_API_KEY: '',
        ABUSECH_AUTH_KEY: '',
      },
      default_phases: ['informational', 'post_exploitation'],
      tags: ['security', 'threat-intel'],
    }),
  },

  // -------------------------------------------------------------------------
  // 13) Tavily Search - web search alternative
  // -------------------------------------------------------------------------
  {
    key: 'tavily',
    label: 'Tavily Search',
    category: 'osint',
    blurb: 'Web search + extract + crawl tuned for LLM consumption.',
    whyForRedamon: 'Backup for built-in web_search if Tavily key isn\'t set globally; also exposes extract/crawl tools the built-in lacks. Useful when scoping a target - fetch their entire site.',
    docsUrl: 'https://docs.tavily.com/documentation/mcp',
    authRequired: true,
    authHint: 'Free tier 1k req/month at https://app.tavily.com/home',
    template: baseTemplate({
      id: 'tavily_mcp',
      name: 'Tavily Search',
      description: 'Web search, extract, crawl (LLM-optimized)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'tavily-mcp@latest'],
      env: { TAVILY_API_KEY: '' },
      default_phases: ['informational'],
      tags: ['osint', 'search'],
    }),
  },

  // -------------------------------------------------------------------------
  // 14) Exa Search - neural search (semantic)
  // -------------------------------------------------------------------------
  {
    key: 'exa',
    label: 'Exa Search',
    category: 'osint',
    blurb: 'Neural / semantic web search - finds by meaning not keywords.',
    whyForRedamon: 'Find writeups by description ("recent CVE-2024 RCEs in Java deserializers"), discover similar PoCs to a known exploit, semantic search for vendor-specific advisories.',
    docsUrl: 'https://github.com/exa-labs/exa-mcp-server',
    authRequired: true,
    authHint: 'Free tier at https://dashboard.exa.ai/api-keys',
    template: baseTemplate({
      id: 'exa',
      name: 'Exa',
      description: 'Neural web search + crawling + research',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'exa-mcp-server'],
      env: { EXA_API_KEY: '' },
      default_phases: ['informational'],
      tags: ['osint', 'search'],
    }),
  },

  // -------------------------------------------------------------------------
  // 15) DuckDuckGo Search - privacy-friendly OSINT, no auth
  // -------------------------------------------------------------------------
  {
    key: 'duckduckgo',
    label: 'DuckDuckGo Search',
    category: 'osint',
    blurb: 'Privacy-focused web search (no API key, no IP fingerprinting).',
    whyForRedamon: 'Stealth-mode OSINT search that doesn\'t correlate with your project\'s Tavily/Brave keys. Useful when you want zero attribution to your infra during attribution-sensitive recon.',
    docsUrl: 'https://github.com/nickclyde/duckduckgo-mcp-server',
    authRequired: false,
    template: baseTemplate({
      id: 'duckduckgo',
      name: 'DuckDuckGo',
      description: 'Privacy-friendly web search via DuckDuckGo',
      transport: 'stdio',
      command: 'uvx',
      args: ['duckduckgo-mcp-server'],
      default_phases: ['informational'],
      tags: ['osint', 'search', 'stealth'],
    }),
  },

  // -------------------------------------------------------------------------
  // 16) PostgreSQL - DB schema/query for SQLi-confirmed targets
  // -------------------------------------------------------------------------
  {
    key: 'postgres',
    label: 'PostgreSQL',
    category: 'security',
    blurb: 'Read-only PostgreSQL queries via connection string.',
    whyForRedamon: 'Once SQLi grants DB access, point this at the captured DSN to enumerate schemas/tables/users/permissions structurally - much cleaner than crafting SQL through the injection point.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers/tree/main/src/postgres',
    authRequired: true,
    authHint: 'Replace the placeholder URL in args with your captured/local connection string',
    template: baseTemplate({
      id: 'postgres',
      name: 'PostgreSQL',
      description: 'Read-only DB schema + query inspection',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://USER:PASS@HOST:5432/DBNAME'],
      default_phases: ['exploitation', 'post_exploitation'],
      tags: ['security', 'database'],
    }),
  },

  // -------------------------------------------------------------------------
  // 17) Slack - exfil findings / notify on milestones
  // -------------------------------------------------------------------------
  {
    key: 'slack',
    label: 'Slack',
    category: 'utility',
    blurb: 'Post messages and read channel history.',
    whyForRedamon: 'Notify your team Slack when the agent confirms a vuln, completes a phase, or needs human approval. Also useful as a low-noise output channel during long unattended scans.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers-archived/tree/main/src/slack',
    authRequired: true,
    authHint: 'SLACK_BOT_TOKEN (xoxb-...) + SLACK_TEAM_ID. Create a Slack app at https://api.slack.com/apps',
    template: baseTemplate({
      id: 'slack',
      name: 'Slack',
      description: 'Post messages, read channels',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-slack'],
      env: { SLACK_BOT_TOKEN: '', SLACK_TEAM_ID: '' },
      default_phases: [...ALL_PHASES],
      tags: ['utility', 'notifications'],
    }),
  },

  // -------------------------------------------------------------------------
  // 18) Wikipedia - neutral context source
  // -------------------------------------------------------------------------
  {
    key: 'wikipedia',
    label: 'Wikipedia',
    category: 'research',
    blurb: 'Article search and content retrieval from Wikipedia.',
    whyForRedamon: 'Background on a target organization, vendor history, biographical info on email enumeration targets. Neutral source independent of your search-API rate limits.',
    docsUrl: 'https://github.com/Rudra-ravi/wikipedia-mcp',
    authRequired: false,
    template: baseTemplate({
      id: 'wikipedia',
      name: 'Wikipedia',
      description: 'Article search and content retrieval',
      transport: 'stdio',
      command: 'uvx',
      args: ['wikipedia-mcp'],
      default_phases: ['informational'],
      tags: ['research', 'osint'],
    }),
  },

  // -------------------------------------------------------------------------
  // 19) OWASP ZAP - local web app scanner via MCP integration add-on
  // -------------------------------------------------------------------------
  {
    key: 'owasp_zap',
    label: 'OWASP ZAP',
    category: 'security',
    blurb: 'Spider, active scan, and alert analysis via OWASP ZAP.',
    whyForRedamon: 'Drives ZAP\'s active scanner from the agent - automated XSS/SQLi/SSRF/path-traversal hunts on web targets, with payload variation that nuclei templates don\'t cover.',
    docsUrl: 'https://www.zaproxy.org/blog/2026-04-02-zap-mcp-server/',
    authRequired: true,
    authHint: 'Run ZAP locally → Marketplace → install "MCP Integration" add-on → copy the security key from Options → MCP Integration. Adjust the URL if you bind to a non-default port.',
    template: baseTemplate({
      id: 'owasp_zap',
      name: 'OWASP ZAP',
      description: 'Web app scanner - spider, active scan, alerts',
      transport: 'streamable_http',
      url: 'http://host.docker.internal:8282/mcp',
      auth: { type: 'bearer', token: '' },
      default_phases: ['exploitation'],
      tags: ['security', 'web', 'scanner'],
    }),
  },

  // -------------------------------------------------------------------------
  // 20) Censys Platform - internet asset map (hosted streamable_http)
  // -------------------------------------------------------------------------
  {
    key: 'censys',
    label: 'Censys Platform',
    category: 'security',
    blurb: 'Internet-wide asset / certificate / service intel via Censys Search API.',
    whyForRedamon: 'Independent corroboration of Shodan data; Censys often catches assets Shodan misses. Strong on TLS/cert intel - find shadow IT subdomains via SAN-list mining.',
    docsUrl: 'https://docs.censys.com/docs/platform-mcp-server',
    authRequired: true,
    authHint: 'Personal Access Token + Organization ID from https://platform.censys.io. Free tier available.',
    template: baseTemplate({
      id: 'censys',
      name: 'Censys Platform',
      description: 'Internet-wide asset, cert, and service intelligence',
      transport: 'streamable_http',
      url: 'https://mcp.platform.censys.io/platform/mcp/',
      auth: { type: 'bearer', token: '' },
      headers: { 'X-Organization-ID': '' },
      default_phases: ['informational'],
      tags: ['security', 'osint', 'recon'],
    }),
  },

  // -------------------------------------------------------------------------
  // 21) Hunter.io - email enumeration / domain → people
  // -------------------------------------------------------------------------
  {
    key: 'hunter',
    label: 'Hunter.io',
    category: 'osint',
    blurb: 'Domain → email pattern, email finder, verifier (hosted MCP).',
    whyForRedamon: 'Phishing simulation prep, social-engineering target enumeration, AD username-pattern discovery (often emails == usernames). Free tier 25 req/month.',
    docsUrl: 'https://hunter.io/api-documentation/v2',
    authRequired: true,
    authHint: 'Free key at https://hunter.io/api-keys (25 requests/month free tier).',
    template: baseTemplate({
      id: 'hunter',
      name: 'Hunter.io',
      description: 'Email enumeration, finder, verifier',
      transport: 'streamable_http',
      url: 'https://mcp.hunter.io/mcp',
      auth: { type: 'bearer', token: '' },
      default_phases: ['informational'],
      tags: ['osint', 'email', 'social-eng'],
    }),
  },

  // -------------------------------------------------------------------------
  // 22) HaveIBeenPwned (HIBP) - credential breach intel
  // -------------------------------------------------------------------------
  {
    key: 'hibp',
    label: 'HaveIBeenPwned',
    category: 'security',
    blurb: 'Credential / password / domain breach lookup via HIBP API.',
    whyForRedamon: 'Check whether emails captured during recon appear in known breaches → predict valid passwords for credential stuffing. Domain-wide search reveals breach exposure for the entire target.',
    docsUrl: 'https://www.npmjs.com/package/@darrenjrobinson/hibp-mcp',
    authRequired: true,
    authHint: 'HIBP API key from https://haveibeenpwned.com/API/Key ($3.50/month minimum - required for breach lookups).',
    template: baseTemplate({
      id: 'hibp',
      name: 'HaveIBeenPwned',
      description: 'Credential / domain / password breach intel',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@darrenjrobinson/hibp-mcp'],
      env: { HIBP_API_KEY: '' },
      default_phases: ['informational', 'exploitation'],
      tags: ['security', 'creds', 'breach'],
    }),
  },

  // -------------------------------------------------------------------------
  // 23) mitmproxy - HTTP/S interception, replay, fuzzing
  // -------------------------------------------------------------------------
  {
    key: 'mitmproxy',
    label: 'mitmproxy',
    category: 'security',
    blurb: 'Inspect / modify / replay HTTP(S) traffic via mitmproxy.',
    whyForRedamon: 'Active web-app pentest beyond what curl can do - capture mobile-app / SPA traffic, manipulate JWT tokens mid-flight, replay session-fixation payloads. Complements execute_playwright.',
    docsUrl: 'https://pypi.org/project/mitmproxy-mcp/',
    authRequired: false,
    template: baseTemplate({
      id: 'mitmproxy',
      name: 'mitmproxy',
      description: 'Inspect / modify / replay HTTP(S) traffic',
      transport: 'stdio',
      command: 'uvx',
      args: ['mitmproxy-mcp'],
      default_phases: ['exploitation'],
      tags: ['security', 'web', 'mitm'],
    }),
  },

  // -------------------------------------------------------------------------
  // 24) SQLite - local SQL queries against exfiltrated DBs
  // -------------------------------------------------------------------------
  {
    key: 'sqlite',
    label: 'SQLite',
    category: 'security',
    blurb: 'Read SQLite databases via SQL queries.',
    whyForRedamon: 'Triage exfiltrated SQLite files (mobile-app DBs, Chrome cookies/history, Slack desktop, Signal, password managers). Many high-value artifacts ship as .db files.',
    docsUrl: 'https://github.com/modelcontextprotocol/servers-archived/tree/main/src/sqlite',
    authRequired: true,
    authHint: 'Adjust the --db-path argument to point at the SQLite file you want to query.',
    template: baseTemplate({
      id: 'sqlite',
      name: 'SQLite',
      description: 'Read SQLite databases via SQL',
      transport: 'stdio',
      command: 'uvx',
      args: ['mcp-server-sqlite', '--db-path', '/app/logs/sandbox/target.db'],
      default_phases: ['exploitation', 'post_exploitation'],
      tags: ['security', 'database', 'forensics'],
    }),
  },

  // -------------------------------------------------------------------------
  // 25) Notion - engagement notes / report drafts
  // -------------------------------------------------------------------------
  {
    key: 'notion',
    label: 'Notion',
    category: 'utility',
    blurb: 'Read / write Notion pages and databases.',
    whyForRedamon: 'Stream findings into a structured engagement workspace as the agent confirms vulns. Pages can become draft sections of the final pentest report. 22 tools.',
    docsUrl: 'https://github.com/makenotion/notion-mcp-server',
    authRequired: true,
    authHint: 'Create an internal integration at https://www.notion.so/my-integrations and copy the Internal Integration Token. Share target pages with the integration.',
    template: baseTemplate({
      id: 'notion',
      name: 'Notion',
      description: 'Notion page / database read & write (22 tools)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@notionhq/notion-mcp-server'],
      env: { NOTION_TOKEN: '' },
      default_phases: [...ALL_PHASES],
      tags: ['utility', 'reporting'],
    }),
  },

  // -------------------------------------------------------------------------
  // 26) Browserbase - cloud headless browser, anti-detection
  // -------------------------------------------------------------------------
  {
    key: 'browserbase',
    label: 'Browserbase',
    category: 'web',
    blurb: 'Cloud headless browser with stealth + residential proxies.',
    whyForRedamon: 'When the local Playwright/Puppeteer hits aggressive bot detection (Cloudflare Turnstile, PerimeterX, Akamai), Browserbase provides residential-IP-backed sessions with anti-detection profiles.',
    docsUrl: 'https://github.com/browserbase/mcp-server-browserbase',
    authRequired: true,
    authHint: 'Sign up at https://browserbase.com - has a free tier. Need API key + project ID.',
    template: baseTemplate({
      id: 'browserbase',
      name: 'Browserbase',
      description: 'Cloud headless browser with anti-detection',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@browserbasehq/mcp'],
      env: {
        BROWSERBASE_API_KEY: '',
        BROWSERBASE_PROJECT_ID: '',
      },
      default_phases: ['informational', 'exploitation'],
      tags: ['web', 'browser', 'stealth'],
    }),
  },

  // -------------------------------------------------------------------------
  // 27) Snyk - open-source dependency vulnerability scanning
  // -------------------------------------------------------------------------
  {
    key: 'snyk',
    label: 'Snyk',
    category: 'security',
    blurb: 'Open-source dependency / SAST scanning via Snyk CLI.',
    whyForRedamon: 'Scan target source you\'ve exfiltrated or have access to (open-source dependencies, package.json, requirements.txt, etc.) for known CVEs and license risks.',
    docsUrl: 'https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli/developer-guardrails-for-agentic-workflows/snyk-mcp-early-access',
    authRequired: true,
    authHint: 'Free Snyk account at https://app.snyk.io. Get token via `snyk auth`. Free tier covers open-source scans.',
    template: baseTemplate({
      id: 'snyk',
      name: 'Snyk',
      description: 'Open-source dependency + SAST scanning',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'snyk@latest', 'mcp', '-t', 'stdio'],
      env: { SNYK_TOKEN: '' },
      default_phases: ['informational', 'exploitation'],
      tags: ['security', 'sast'],
    }),
  },

  // -------------------------------------------------------------------------
  // 28) Stripe - payment / fraud testing
  // -------------------------------------------------------------------------
  {
    key: 'stripe',
    label: 'Stripe',
    category: 'security',
    blurb: 'Stripe API access (use test-mode keys for fraud / card-testing scenarios).',
    whyForRedamon: 'When pentesting an e-commerce target that uses Stripe, you can validate the merchant\'s test-mode flow, simulate fraudulent card patterns, and check webhook signature verification with safe test keys.',
    docsUrl: 'https://www.npmjs.com/package/@stripe/mcp',
    authRequired: true,
    authHint: 'Use a Stripe TEST-MODE restricted key (sk_test_...) only. Never use live keys for pentest scenarios.',
    template: baseTemplate({
      id: 'stripe',
      name: 'Stripe',
      description: 'Stripe API (use test-mode keys for fraud testing)',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@stripe/mcp', '--tools=all'],
      env: { STRIPE_API_KEY: '' },
      default_phases: ['exploitation'],
      tags: ['security', 'payments'],
    }),
  },

  // -------------------------------------------------------------------------
  // 29) Linear - issue tracking, milestone reporting
  // -------------------------------------------------------------------------
  {
    key: 'linear',
    label: 'Linear',
    category: 'utility',
    blurb: 'Linear API - create / read / update issues for pentest engagement tracking.',
    whyForRedamon: 'Convert each confirmed vulnerability into a Linear issue automatically (severity, repro steps, evidence). Sync with the client\'s remediation team during long engagements.',
    docsUrl: 'https://linear.app/docs/mcp',
    authRequired: true,
    authHint: 'Personal API key from https://linear.app/settings/api (use Authorization: Bearer <key> directly - supported by Linear MCP).',
    template: baseTemplate({
      id: 'linear',
      name: 'Linear',
      description: 'Linear issue tracking',
      transport: 'streamable_http',
      url: 'https://mcp.linear.app/mcp',
      auth: { type: 'bearer', token: '' },
      default_phases: [...ALL_PHASES],
      tags: ['utility', 'reporting'],
    }),
  },

  // -------------------------------------------------------------------------
  // 30) Trivy - container image / IaC vuln scanner
  // -------------------------------------------------------------------------
  {
    key: 'trivy',
    label: 'Trivy',
    category: 'security',
    blurb: 'Vuln scanner for containers, IaC, secrets, OS packages.',
    whyForRedamon: 'Scan target Docker images / Kubernetes manifests / Terraform after exfil - identifies vulnerable base images, hard-coded secrets, IaC misconfig (open security groups, public S3, etc).',
    docsUrl: 'https://github.com/aquasecurity/trivy-mcp',
    authRequired: false,
    authHint: 'Pre-installed in the agent image (the Trivy binary + its `mcp` plugin). Just save and Test — no setup needed. No auth required for local scans.',
    template: baseTemplate({
      id: 'trivy',
      name: 'Trivy',
      description: 'Vuln scanner: containers / IaC / secrets / OS pkgs',
      transport: 'stdio',
      command: 'trivy',
      args: ['mcp'],
      default_phases: ['informational', 'exploitation'],
      tags: ['security', 'cloud', 'iac'],
    }),
  },

  // -------------------------------------------------------------------------
  // 31) Prowler (via Ship CLI) - AWS / Azure / GCP audit
  // -------------------------------------------------------------------------
  {
    key: 'prowler',
    label: 'Prowler',
    category: 'security',
    blurb: 'Multi-cloud (AWS/Azure/GCP) security audit via Prowler.',
    whyForRedamon: 'When you obtain cloud credentials, runs 300+ checks against the target tenancy: IAM mistakes, public S3, weak RDS encryption, open NSGs, etc. Catches things the basic AWS MCP can\'t.',
    docsUrl: 'https://github.com/cloudshipai/ship',
    authRequired: true,
    authHint: 'REQUIRES SETUP: the Ship CLI is a Go binary from cloudshipai (NOT a pip package). Install it in the agent container: docker compose exec agent bash -c "curl -sSL https://raw.githubusercontent.com/cloudshipai/ship/main/install.sh | bash" - then `ship mcp prowler`. Provide read-only AWS creds via env.',
    template: baseTemplate({
      id: 'prowler',
      name: 'Prowler',
      description: 'Multi-cloud (AWS/Azure/GCP) security audit',
      transport: 'stdio',
      command: 'ship',
      args: ['mcp', 'prowler'],
      env: {
        AWS_ACCESS_KEY_ID: '',
        AWS_SECRET_ACCESS_KEY: '',
        AWS_REGION: 'us-east-1',
      },
      default_phases: ['post_exploitation'],
      tags: ['security', 'cloud', 'audit'],
    }),
  },

  // -------------------------------------------------------------------------
  // 32) CVE Intel (mukul975) - NVD / EPSS / CISA KEV / MITRE ATT&CK
  // -------------------------------------------------------------------------
  {
    key: 'cve_intel_extra',
    label: 'CVE Intel (NVD+EPSS+KEV+ATT&CK)',
    category: 'security',
    blurb: '27 vuln-intel tools across 21 APIs - NVD, EPSS, CISA KEV, MITRE ATT&CK.',
    whyForRedamon: 'Deeper CVE context than the built-in cve_intel tool: EPSS exploitation probability, CISA known-exploited status, ATT&CK technique mappings, OSV cross-reference. Useful for prioritizing exploit targets.',
    docsUrl: 'https://github.com/mukul975/cve-mcp-server',
    authRequired: false,
    authHint: 'Pre-installed in the agent image (the `cve-mcp` command). Just save and Test — no setup needed. Optional NVD_API_KEY and GITHUB_TOKEN unlock higher rate limits / more tools; paste them in env if you have them.',
    template: baseTemplate({
      id: 'cve_intel_extra',
      name: 'CVE Intel (extended)',
      description: 'NVD + EPSS + CISA KEV + MITRE ATT&CK lookups',
      transport: 'stdio',
      command: 'cve-mcp',
      args: [],
      env: { NVD_API_KEY: '', GITHUB_TOKEN: '' },
      default_phases: ['informational', 'exploitation'],
      tags: ['security', 'vuln-intel'],
    }),
  },

  // -------------------------------------------------------------------------
  // 33) GhidraMCP - reverse engineering / binary analysis
  // -------------------------------------------------------------------------
  {
    key: 'ghidra',
    label: 'GhidraMCP',
    category: 'security',
    blurb: 'Drive Ghidra (NSA reverse engineering framework) for binary analysis.',
    whyForRedamon: 'When you exfiltrate proprietary binaries (Linux ELF, Windows PE, mobile-app native libs), this lets the LLM disassemble / decompile / search strings + xrefs to find auth bypasses, hard-coded secrets, vulns.',
    docsUrl: 'https://github.com/LaurieWired/GhidraMCP',
    authRequired: true,
    authHint: 'REQUIRES SETUP: install Ghidra in the agent container, install the GhidraMCP plugin, then point the bridge script at your Ghidra project. See repo README for full instructions.',
    template: baseTemplate({
      id: 'ghidra',
      name: 'GhidraMCP',
      description: 'Ghidra-driven reverse engineering',
      transport: 'stdio',
      command: 'python',
      args: ['/opt/GhidraMCP/bridge_mcp_ghidra.py'],
      default_phases: ['exploitation', 'post_exploitation'],
      tags: ['security', 'reverse-engineering'],
    }),
  },

  // -------------------------------------------------------------------------
  // 34) Serply - Google SERP API (dorks, News, Scholar) via hosted MCP
  // -------------------------------------------------------------------------
  {
    key: 'serply',
    label: 'Serply Search',
    category: 'osint',
    blurb: 'Google web, News and Scholar results via Serply (hosted MCP).',
    whyForRedamon: 'Passive Google dorking (site:, filetype:, inurl:) and target footprinting without a SerpAPI key; also News and Scholar searches for company and people research.',
    docsUrl: 'https://serply.io/mcp',
    authRequired: true,
    authHint: 'API key from https://serply.io (2,500 free credits for 30 days, no card). Paste it as the X-Api-Key header value.',
    template: baseTemplate({
      id: 'serply',
      name: 'Serply Search',
      description: 'Google web, News and Scholar search via Serply',
      transport: 'streamable_http',
      url: 'https://api.serply.io/mcp',
      headers: { 'X-Api-Key': '' },
      default_phases: ['informational'],
      tags: ['osint', 'search'],
    }),
  },
]

export const PRESET_CATEGORY_LABELS: Record<PresetCategory, string> = {
  osint: 'OSINT',
  research: 'Research',
  web: 'Web / HTTP',
  security: 'Security',
  utility: 'Utility',
}
