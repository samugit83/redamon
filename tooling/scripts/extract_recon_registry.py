"""
Top up `recon_settings/registry.yaml` from the sources that describe the recon
pipeline.

It SEEDED the registry once, and it stays runnable so that adding a Prisma column
does not mean hand-writing a whole entry. It is idempotent: anything the existing
registry already carries is preserved, and only what is missing is filled in. Run
it after adding a column, then edit the YAML.

It is not part of the gate. `recon_settings/build.py` is, and it is what fails
when the artifacts are stale.

Sources, and what each one is authoritative for:

  recon_settings/registry.yaml         everything already curated (wins)
  webapp/prisma/schema.prisma          existence, type, @default(), /// docs
  recon/project_settings.py            runtime_key, fallback/coerce shape
  ProjectForm/sections/*.tsx           min/max and the operator-facing hint
  recon-preset-schema.ts catalog       474 prose descriptions
  recon_registry_meanings.py           the authored descriptions

Nothing here invents a default or a type: those stay in Prisma and are joined at
build time. And nothing it emits is finished, because no extraction can tell
whether a `meaning` is TRUE or whether a bound is right.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_settings_mappings import parse_mappings  # noqa: E402
from prisma_project_columns import Column, project_columns  # noqa: E402
from recon_registry_meanings import meaning_for as authored_meaning  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[2]
SECTIONS_DIR = REPO_ROOT / "webapp" / "src" / "components" / "projects" / "ProjectForm" / "sections"
PRESET_SCHEMA_TS = REPO_ROOT / "webapp" / "src" / "lib" / "recon-preset-schema.ts"
RECON_SETTINGS_PY = REPO_ROOT / "recon" / "project_settings.py"
OUT_YAML = REPO_ROOT / "recon_settings" / "registry.yaml"

# --- the tool table -------------------------------------------------------------
# camelCase column prefix -> tool id. Longest prefix wins, so `aiSurfaceRecon`
# beats `ai` and `supplyChainRecon` beats `supplyChain`. A prefix that is not a
# pipeline tool (roe, agent, project identity) still gets an id, because every
# field must belong to exactly one group and "ungrouped" is how a field stops
# being findable.
TOOL_PREFIXES: list[tuple[str, str]] = [
    ("aiSurfaceRecon", "ai_surface_recon"),
    ("aiInPipeline", "pipeline_ai"),
    ("aiPipelineModel", "pipeline_ai"),
    ("supplyChainRecon", "supply_chain_recon"),
    ("supplyChain", "supply_chain"),
    ("webCachePoison", "web_cache_poison"),
    ("securityCheck", "security_check"),
    ("originDiscovery", "origin_discovery"),
    ("pathTraversal", "path_traversal"),
    ("resourceEnumAi", "resource_enum_ai"),
    ("httpProbeAi", "http_probe_ai"),
    ("portScanAi", "port_scan_ai"),
    ("domainReconAi", "domain_recon_ai"),
    ("domainBatch", "targeting"),
    ("bannerGrab", "banner_grab"),
    ("cveLookup", "cve_lookup"),
    ("knockpyRecon", "knockpy"),
    ("hackerTarget", "hackertarget"),
    ("criminalIp", "criminalip"),
    ("virusTotal", "virustotal"),
    ("zoomEye", "zoomeye"),
    ("vhostSni", "vhost_sni"),
    ("jsRecon", "js_recon"),
    ("graphqlCop", "graphql_cop"),
    ("subdomainDiscovery", "subdomain_discovery"),
    ("subdomainTakeover", "takeover"),
    ("subdomainList", "targeting"),
    ("authProfile", "auth_profile"),
    ("captureProxy", "capture_proxy"),
    ("osintEnrichment", "osint_enrichment"),
    ("scaIntel", "supply_chain"),
    ("wafAi", "waf"),
    ("mcpKaliExec", "project"),
    ("attackSkill", "agent"),
    ("triageReview", "agent"),
    ("scanModules", "pipeline"),
    ("stealthMode", "pipeline"),
    ("updateGraphDb", "pipeline"),
    ("useBruteforceForSubdomains", "pipeline"),
    ("reconPresetId", "project"),
    ("loadedPreset", "project"),
    ("verifyDomainOwnership", "targeting"),
    ("ownership", "targeting"),
    ("targetGuardrail", "targeting"),
    ("targetDomain", "targeting"),
    ("targetIps", "targeting"),
    ("ipMode", "targeting"),
    ("activation", "project"),
    ("engagementKind", "engagement"),
    ("engagementIdentityHeader", "engagement"),
    # single-word prefixes
    ("amass", "amass"),
    ("arjun", "arjun"),
    ("agent", "agent"),
    ("baddns", "baddns"),
    ("censys", "censys"),
    ("crtsh", "crtsh"),
    ("cypherfix", "cypherfix"),
    ("dns", "dns"),
    ("dos", "dos"),
    ("ffuf", "ffuf"),
    ("fireteam", "fireteam"),
    ("fofa", "fofa"),
    ("gau", "gau"),
    ("github", "github"),
    ("graphql", "graphql"),
    ("gvm", "gvm"),
    ("hakrawler", "hakrawler"),
    ("httpx", "httpx"),
    ("hydra", "hydra"),
    ("jsluice", "jsluice"),
    ("katana", "katana"),
    ("kiterunner", "kiterunner"),
    ("masscan", "masscan"),
    ("mitre", "mitre"),
    ("naabu", "naabu"),
    ("netlas", "netlas"),
    ("nmap", "nmap"),
    ("nuclei", "nuclei"),
    ("otx", "otx"),
    ("paramspider", "paramspider"),
    ("phishing", "phishing"),
    ("puredns", "puredns"),
    ("rce", "rce"),
    ("roe", "roe"),
    ("shodan", "shodan"),
    ("sqli", "sqli"),
    ("ssrf", "ssrf"),
    ("subfinder", "subfinder"),
    ("subjack", "subjack"),
    ("takeover", "takeover"),
    ("tlsx", "tlsx"),
    ("trufflehog", "trufflehog"),
    ("uncover", "uncover"),
    ("urlscan", "urlscan"),
    ("wappalyzer", "wappalyzer"),
    ("whois", "whois"),
    ("zap", "zap"),
]

# tool id -> (phase, traffic). `standalone` means "a separate job, not gated by
# scanModules", which is a real distinction the MCP surface already documents.
TOOL_PHASE_TRAFFIC: dict[str, tuple[str, str]] = {
    "agent": ("standalone", "active"),
    "ai_surface_recon": ("http_probe", "active"),
    "amass": ("domain_discovery", "passive"),
    "arjun": ("resource_enum", "active"),
    # The authenticated session itself sends nothing; httpx and the crawlers do,
    # carrying it. Classifying it as active would make it a pipeline tool with
    # no module and no way to re-run it.
    "auth_profile": ("http_probe", "none"),
    "baddns": ("vuln_scan", "active"),
    "banner_grab": ("port_scan", "active"),
    "capture_proxy": ("standalone", "active"),
    "censys": ("domain_discovery", "passive"),
    "criminalip": ("domain_discovery", "passive"),
    "crtsh": ("domain_discovery", "passive"),
    "cve_lookup": ("vuln_scan", "passive"),
    "cypherfix": ("standalone", "none"),
    "dns": ("domain_discovery", "active"),
    # The engagement agreement itself: no traffic of its own, but it decides
    # whether any of the rest may run at all.
    "engagement": ("standalone", "none"),
    "domain_recon_ai": ("domain_discovery", "none"),
    "domain_discovery": ("domain_discovery", "active"),
    "dos": ("standalone", "active"),
    "ffuf": ("resource_enum", "active"),
    "fireteam": ("standalone", "active"),
    "fofa": ("domain_discovery", "passive"),
    "gau": ("resource_enum", "passive"),
    "github": ("standalone", "passive"),
    "graphql": ("vuln_scan", "active"),
    "graphql_cop": ("vuln_scan", "active"),
    "gvm": ("standalone", "active"),
    "hackertarget": ("domain_discovery", "passive"),
    "hakrawler": ("resource_enum", "active"),
    "http_probe_ai": ("http_probe", "none"),
    "httpx": ("http_probe", "active"),
    "hydra": ("standalone", "active"),
    "js_recon": ("js_recon", "active"),
    "jsluice": ("js_recon", "active"),
    "katana": ("resource_enum", "active"),
    "kiterunner": ("resource_enum", "active"),
    "knockpy": ("domain_discovery", "passive"),
    "masscan": ("port_scan", "active"),
    "mitre": ("vuln_scan", "none"),
    "naabu": ("port_scan", "active"),
    "netlas": ("domain_discovery", "passive"),
    "nmap": ("port_scan", "active"),
    "nuclei": ("vuln_scan", "active"),
    "origin_discovery": ("http_probe", "active"),
    "osint_enrichment": ("domain_discovery", "passive"),
    "otx": ("domain_discovery", "passive"),
    "paramspider": ("resource_enum", "passive"),
    "path_traversal": ("standalone", "active"),
    "phishing": ("standalone", "active"),
    "pipeline": ("standalone", "none"),
    "pipeline_ai": ("standalone", "none"),
    "port_scan_ai": ("port_scan", "none"),
    "project": ("standalone", "none"),
    "puredns": ("domain_discovery", "active"),
    "rce": ("standalone", "active"),
    "resource_enum_ai": ("resource_enum", "none"),
    "roe": ("standalone", "none"),
    "security_check": ("http_probe", "active"),
    "shodan": ("domain_discovery", "passive"),
    "sqli": ("standalone", "active"),
    "ssrf": ("standalone", "active"),
    "subdomain_discovery": ("domain_discovery", "passive"),
    "subfinder": ("domain_discovery", "passive"),
    "subjack": ("vuln_scan", "active"),
    "supply_chain": ("standalone", "passive"),
    "supply_chain_recon": ("standalone", "passive"),
    "takeover": ("vuln_scan", "active"),
    "targeting": ("standalone", "none"),
    "tlsx": ("http_probe", "active"),
    "trufflehog": ("standalone", "passive"),
    "uncover": ("domain_discovery", "passive"),
    "urlscan": ("domain_discovery", "passive"),
    "virustotal": ("domain_discovery", "passive"),
    "vhost_sni": ("http_probe", "active"),
    "waf": ("http_probe", "none"),
    "wappalyzer": ("http_probe", "active"),
    "web_cache_poison": ("standalone", "active"),
    "whois": ("domain_discovery", "passive"),
    "zap": ("resource_enum", "active"),
    "zoomeye": ("domain_discovery", "passive"),
}

TOOL_TITLES: dict[str, str] = {
    "engagement": "Engagement",
    # Vendor capitalisation, because "Ffuf" and "Dns" read as typos in a
    # generated reference an operator is meant to trust.
    "amass": "Amass",
    "arjun": "Arjun",
    "auth_profile": "Authenticated session",
    "baddns": "BadDNS",
    "censys": "Censys",
    "crtsh": "crt.sh",
    "cypherfix": "CypherFix",
    "dns": "DNS",
    "dos": "Denial of service",
    "ffuf": "ffuf",
    "fireteam": "Fireteam",
    "fofa": "FOFA",
    "gau": "gau",
    "github": "GitHub secret hunt",
    "graphql": "GraphQL security",
    "gvm": "GVM vulnerability scan",
    "hackertarget": "HackerTarget",
    "hakrawler": "hakrawler",
    "httpx": "httpx",
    "hydra": "Hydra",
    "jsluice": "jsluice",
    "katana": "Katana",
    "kiterunner": "Kiterunner",
    "knockpy": "knockpy",
    "masscan": "masscan",
    "mitre": "MITRE ATT&CK enrichment",
    "naabu": "naabu",
    "netlas": "Netlas",
    "nmap": "Nmap",
    "nuclei": "Nuclei",
    "otx": "AlienVault OTX",
    "paramspider": "ParamSpider",
    "phishing": "Phishing",
    "pipeline": "Pipeline",
    "project": "Project identity",
    "puredns": "puredns",
    "rce": "Remote code execution",
    "shodan": "Shodan",
    "sqli": "SQL injection",
    "ssrf": "Server-side request forgery",
    "subfinder": "subfinder",
    "subjack": "subjack",
    "takeover": "Subdomain takeover",
    "targeting": "Targeting and scope",
    "tlsx": "tlsx",
    "trufflehog": "TruffleHog",
    "uncover": "uncover",
    "urlscan": "urlscan.io",
    "virustotal": "VirusTotal",
    "waf": "WAF detection",
    "wappalyzer": "Wappalyzer",
    "whois": "WHOIS",
    "zap": "ZAP Ajax Spider",
    "ai_surface_recon": "AI attack-surface recon",
    "banner_grab": "Banner grab",
    "capture_proxy": "Capture proxy",
    "criminalip": "CriminalIP",
    "cve_lookup": "CVE lookup",
    "domain_recon_ai": "Domain recon AI hints",
    "graphql_cop": "GraphQL Cop",
    "http_probe_ai": "HTTP probe AI hints",
    "js_recon": "JS recon",
    "origin_discovery": "Origin discovery",
    "osint_enrichment": "OSINT enrichment",
    "path_traversal": "Path traversal",
    "pipeline_ai": "Pipeline AI master switch",
    "port_scan_ai": "Port scan AI catalog",
    "resource_enum_ai": "Resource enum AI hints",
    "roe": "Rules of Engagement",
    "security_check": "Security checks",
    "subdomain_discovery": "Subdomain discovery",
    "supply_chain": "Supply chain scan",
    "supply_chain_recon": "Supply chain recon",
    "vhost_sni": "Vhost / SNI enumeration",
    "web_cache_poison": "Web cache poisoning",
    "zoomeye": "ZoomEye",
}

# --- dispositions ---------------------------------------------------------------

NEVER: dict[str, tuple[str, str]] = {
    # column -> (deny_reason, why)
    "id": ("identity", "row identity"),
    "userId": ("identity", "writing it reassigns the project to another user"),
    "createdById": ("identity", "audit column"),
    "updatedById": ("identity", "audit column"),
    "createdAt": ("identity", "audit column"),
    "updatedAt": ("identity", "audit column"),
    "activationState": ("internal", "version-activation lock flag"),
    "activationStartedAt": ("internal", "version-activation lock flag"),
    "activationVersionId": ("internal", "version-activation lock flag"),
    "reconPresetId": ("internal", "app-written state machine"),
    "loadedPreset": ("internal", "app-written state machine"),
    "mcpKaliExecEnabled": ("escalation", "a token granting itself shell access"),
    "cypherfixGithubToken": ("secret", "a stored credential"),
}

# Columns no MCP read tool may return, and why.
#
# The read boundary is NOT the write boundary, and conflating them is how an
# external agent ends up holding a client's phone number. `targetDomain` is
# write-once and freely readable, because reading it is how a caller confirms
# which engagement it is looking at. The RoE block is the other direction: an
# agent may know its rate ceiling and its exclusions, and has no business with
# the client's emergency contact or the scanned copy of the signed document.
READ_DENIED: dict[str, str] = {
    "userId": "other_user",
    "cypherfixGithubToken": "credential",
    "graphqlAuthValue": "credential",
    "ownershipToken": "credential",
    "phishingSmtpConfig": "credential",
    "roeClientContactName": "third_party_pii",
    "roeClientContactEmail": "third_party_pii",
    "roeClientContactPhone": "third_party_pii",
    "roeEmergencyContact": "third_party_pii",
    "roeClientName": "third_party_pii",
    "roeDocumentData": "document_blob",
    "roeDocumentName": "document_blob",
    "roeRawText": "document_blob",
    "roeParsedJson": "document_blob",
}

UPLOAD_MANAGED: dict[str, str] = {
    "jsReconUploadedFiles": "/api/js-recon/[projectId]/upload",
    "jsReconCustomPatterns": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomSourcemapPaths": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomPackages": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomEndpointKeywords": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomFrameworks": "/api/js-recon/[projectId]/custom-files",
    "supplyChainSbomFile": "/api/supply-chain/[projectId]/upload",
}

# Scope and other-target columns: settable once at create_project, immutable
# after. `ownershipToken` / `ownershipTxtPrefix` are the DNS proof of ownership
# for the scope, so they move with it.
CREATE_ONLY = {
    "targetDomain", "subdomainList", "targetIps", "ipMode",
    "domainBatchMode", "domainBatchHosts", "domainBatchGroups",
    "verifyDomainOwnership", "ownershipToken", "ownershipTxtPrefix",
    "targetGuardrailEnabled",
    "engagementKind",
    "githubTargetOrg", "githubTargetRepos", "gvmScanTargets",
    "supplyChainOrgName", "supplyChainRepoRef", "supplyChainRepoScope",
    "supplyChainRepoUrl", "scaIntelCorrelationEnabled",
}

# The RoE block moves in one direction only after creation.
TIGHTEN_DIRECTION: dict[str, str] = {
    "roeEnabled": "false_to_true",
    "roeGlobalMaxRps": "decrease",
}

# Columns holding a filesystem path a scan container opens. The deny class was
# the only control on these; `project_file` replaces it.
# An absolute path a scan container opens. Validated against a root allowlist.
PROJECT_FILE_FIELDS = {
    "ffufWordlist",
    "nucleiCustomTemplates",
}

# Inline text, one hostname or prefix per line. Not a path despite the
# "Wordlist" name: the vhost module parses the value itself and opens no file.
HOSTNAME_LIST_FIELDS = {
    "vhostSniCustomWordlist",
}

# A BASENAME the scan joins onto a mounted directory (`-t /custom-templates/<x>`).
# A different validator, because the dangerous input here is a separator rather
# than a wrong root: "../../etc/passwd" joined onto /custom-templates escapes it.
PROJECT_FILE_NAME_FIELDS = {
    "nucleiSelectedCustomTemplates",
}

HEADER_FIELDS_RE = re.compile(r"(CustomHeaders|^kiterunnerHeaders$|Headers$|^engagementIdentityHeader$)")

# A field whose traffic differs from its tool's. gau itself only reads public
# archives, but its verify and method-detect passes dial the target, which is
# what decides whether the engagement ceiling applies.
TRAFFIC_OVERRIDE: dict[str, str] = {
    "gauVerifyRateLimit": "active",
    "gauVerifyThreads": "active",
    "gauVerifyEnabled": "active",
    "gauVerifyTimeout": "active",
    "gauMethodDetectRateLimit": "active",
    "gauMethodDetectThreads": "active",
    "gauMethodDetectEnabled": "active",
    "gauMethodDetectTimeout": "active",
    "paramspiderVerifyEnabled": "active",
}

# Capped by the engagement ceiling although the unit is not rps. hakrawler has
# no rate flag at all, so its thread count IS its throttle, which is why the
# shipped cap list already carries it.
ROE_CAPPED_EXTRA = {"hakrawlerThreads"}

# Where a name-based heuristic gets a field wrong. Each is a fractional
# coefficient whose name reads like a count, or a 0-1 fraction whose name reads
# like a percentage.
UNIT_OVERRIDE: dict[str, str] = {
    "webCachePoisonMinConfidence": "ratio",
    # A `*Timeout` is seconds by the naming rule, and these five are not. Each
    # was found by the unit-coherence check against the prose that already
    # existed: "Amass timeout in MINUTES", "Event wait time in milliseconds".
    # A wrong unit here is worse than a missing one, because an agent that
    # reads "seconds" and writes 600 for ten minutes gets ten HOURS of amass.
    "amassTimeout": "minutes",
    "zapAjaxSpiderMaxDuration": "minutes",
    "zapAjaxSpiderEventWait": "milliseconds",
    "zapAjaxSpiderReloadWait": "milliseconds",
}

# Where the extracted bound is wrong rather than merely wide: a UI max that was
# never meant as a semantic bound, or a coefficient whose range a form never
# stated.
BOUNDS_OVERRIDE: dict[str, tuple[float, float]] = {
    "fireteamMaxConcurrent": (1, 8),
    "fireteamMaxMembers": (2, 8),
    "fireteamMemberMaxIterations": (5, 50),
    "fireteamTimeoutSec": (60, 7200),
    "agentLatsMaxRollouts": (4, 300),
    "agentLatsBranching": (2, 10),
    "agentLatsMaxDepth": (2, 10),
    "agentLatsMaxTreeNodes": (10, 1000),
    "agentLatsMinHypotheses": (2, 4),
    # A backoff of 0 is "retry immediately", which the form has always allowed.
    "graphqlRetryBackoff": (0.0, 60.0),
    "agentLatsPruneFloor": (0.0, 1.0),
    "agentLatsUctC": (0.0, 10.0),
    "webCachePoisonMinConfidence": (0.0, 1.0),
    "cveLookupMinCvss": (0.0, 10.0),
}

# --- unit inference -------------------------------------------------------------
# T32 asserts these same rules, so the inference and the test agree by
# construction. The heuristic exists because it catches the mistake a human
# actually makes filling 700 rows by hand.
UNIT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(RateLimit|MaxRpsPerHost)$"), "rps"),
    (re.compile(r"^(masscanRate|ffufRate|originDiscoveryRate)$"), "rps"),
    (re.compile(r"Rate$"), "rps"),
    (re.compile(r"(Threads|Concurrency|Workers|Parallelism|Connections|BulkSize|NumberOfBrowsers)$"), "threads"),
    (re.compile(r"(TimeoutMs|DelayMs)$"), "milliseconds"),
    (re.compile(r"^naabuTimeout$"), "milliseconds"),
    (re.compile(r"(Timeout|TimeoutPerReq|ValidationTimeout|ScanTimeout|RunTimeout|MaxTime|MaxDuration|Wait|BehavioralDelay)$"), "seconds"),
    (re.compile(r"(Depth|DepthLimit|RecursionDepth|CrawlDepth)$"), "depth"),
    (re.compile(r"(MaxBytes|MaxLength|MaxSize|FilterSize|SizeTolerance)$"), "bytes"),
    (re.compile(r"MinCvss$"), "ratio"),
    (re.compile(r"(MinConfidence|Threshold)$"), "percent"),
    (re.compile(r"(Max[A-Z]\w*|Retries|MaxRetries|RetryCount|ChunkSize|Budget|Days|Attempts|Calls|Limit)$"), "count"),
    (re.compile(r"(Port|Lport)$"), "port"),
]

# Unit -> a defensible bound when no source carries one. Deliberately wide:
# the bound is a sanity fence, and the engagement ceiling is what actually
# controls a rate. A narrow guess here would refuse a legitimate value.
UNIT_BOUNDS: dict[str, tuple[int, int]] = {
    "rps": (0, 100000),
    "seconds": (1, 86400),
    "minutes": (1, 1440),
    "milliseconds": (1, 3600000),
    "threads": (1, 500),
    "count": (0, 10000000),
    "bytes": (0, 1073741824),
    "depth": (0, 50),
    "percent": (0, 100),
    "ratio": (0, 100),
    "port": (1, 65535),
    "none": (0, 10000000),
}

# Runtime keys that exist in DEFAULT_SETTINGS with NO Prisma column. They are
# not MCP-reachable, but the derived cap list is queried over the registry, so a
# rate that lives only here still has to be in it. `VIRUSTOTAL_RATE_LIMIT` and
# `ORIGIN_DISCOVERY_RATE` are exactly that case.
RUNTIME_ONLY: dict[str, dict] = {
    "PROJECT_ID": {
        "source": "internal", "unit": "none", "roe_capped": False,
        "meaning": "The project whose settings were loaded. Written by the loader, never configured.",
    },
    "ORIGIN_DISCOVERY_RATE": {
        "source": "internal", "tool": "origin_discovery", "unit": "rps", "roe_capped": True,
        "zero_means": "unlimited",
        "meaning": (
            "Requests per second the origin-IP discovery active probe sends. ZERO MEANS "
            "UNLIMITED, so 0 is the most aggressive value available and not the safest. "
            "No Prisma column: it is internal to the pipeline, tuned by the stealth pass "
            "and capped by the engagement ceiling."
        ),
    },
    "VIRUSTOTAL_RATE_LIMIT": {
        "source": "internal", "tool": "virustotal", "unit": "rps", "roe_capped": True,
        "meaning": (
            "Requests per second sent to the VirusTotal API. Aimed at VirusTotal rather "
            "than the engagement target, but still capped by the ceiling because a shared "
            "ceiling that some callers ignore is not a ceiling."
        ),
    },
    "VIRUSTOTAL_MAX_TARGETS": {
        "source": "internal", "tool": "virustotal", "unit": "count", "roe_capped": False,
        "meaning": "Maximum hosts submitted to the VirusTotal API in one pass. No Prisma column.",
    },
    "AUTH_PROFILE": {
        "source": "project_relation", "tool": "auth_profile", "unit": "none", "roe_capped": False,
        "secret": True,
        "meaning": (
            "The authenticated session the scan replays: cookies, headers and the login "
            "steps that produced them. Deliberately a RELATION rather than a Project column, "
            "because GET /api/projects/[id] spreads every Project scalar to the browser and a "
            "credential stored as a column would leak. It arrives in the same API payload the "
            "settings load reads, so the pipeline sees it as a runtime key with no column "
            "behind it."
        ),
    },
    "USER_ATTACK_SKILLS": {
        "source": "user_account", "tool": "agent", "unit": "none", "roe_capped": False,
        "meaning": (
            "The user's own imported attack skills, fetched per run from the user account "
            "rather than the project. Shared across every project that user owns, which is "
            "why deleting one rewrites attackSkillConfig on all of them."
        ),
    },
    "USER_MCP_SERVERS": {
        "source": "user_account", "tool": "agent", "unit": "none", "roe_capped": False,
        "meaning": (
            "The OUTBOUND MCP servers the agent may connect to, configured on the user "
            "account rather than the project. Not to be confused with RedAmon's own inbound "
            "MCP server, which external agents connect to."
        ),
    },
    "NETLAS_MAX_RESULTS": {
        "source": "internal", "tool": "netlas", "unit": "count", "roe_capped": False,
        "meaning": "Maximum results pulled from the Netlas API. No Prisma column; the memory governor still budgets it.",
    },
    "TAKEOVER_CNAME_VALIDATION_ENABLED": {
        "source": "internal", "tool": "takeover", "unit": "none", "roe_capped": False,
        "meaning": "Whether a takeover candidate's CNAME is re-resolved before it is reported. No Prisma column.",
    },
    "SUPPLY_CHAIN_IMPORT_MAX_FILES": {
        "source": "env", "tool": "supply_chain", "unit": "count", "roe_capped": False,
        "meaning": "Maximum files the import miner reads. Read from the environment, not from the project row.",
    },
    "SUPPLY_CHAIN_IMPORT_MAX_BYTES": {
        "source": "env", "tool": "supply_chain", "unit": "bytes", "roe_capped": False,
        "meaning": "Byte budget for the import miner. Read from the environment, not from the project row.",
    },
}

# Every API key: the user's own account credential, fetched per scan and never a
# project column. Listed so that "a runtime key with no registry entry" stays a
# build failure rather than a class of exceptions.
for _key, _tool in [
    ("SHODAN_API_KEY", "shodan"), ("URLSCAN_API_KEY", "urlscan"), ("NVD_API_KEY", "cve_lookup"),
    ("VULNERS_API_KEY", "cve_lookup"), ("CENSYS_API_TOKEN", "censys"), ("CENSYS_ORG_ID", "censys"),
    ("FOFA_API_KEY", "fofa"), ("OTX_API_KEY", "otx"), ("NETLAS_API_KEY", "netlas"),
    ("VIRUSTOTAL_API_KEY", "virustotal"), ("ZOOMEYE_API_KEY", "zoomeye"),
    ("CRIMINALIP_API_KEY", "criminalip"), ("SECURITYTRAILS_API_KEY", "osint_enrichment"),
    ("VIEWDNS_API_KEY", "osint_enrichment"), ("UNCOVER_QUAKE_API_KEY", "uncover"),
    ("UNCOVER_HUNTER_API_KEY", "uncover"), ("UNCOVER_PUBLICWWW_API_KEY", "uncover"),
    ("UNCOVER_HUNTERHOW_API_KEY", "uncover"), ("UNCOVER_GOOGLE_API_KEY", "uncover"),
    ("UNCOVER_GOOGLE_API_CX", "uncover"), ("UNCOVER_ONYPHE_API_KEY", "uncover"),
    ("UNCOVER_DRIFTNET_API_KEY", "uncover"),
]:
    RUNTIME_ONLY[_key] = {
        "source": "user_account", "tool": _tool, "unit": "none", "roe_capped": False,
        "secret": True,
        "meaning": (
            "The user's own API credential for this data source, fetched per scan from the "
            "user account. Never a project column, so it is not reachable from any "
            "project-scoped surface."
        ),
    }

# Every tool container image: fixed, never a project column.
for _key, _tool, _lead in [
    ("AMASS_DOCKER_IMAGE", "amass", "The container image spawned for Amass."),
    ("BADDNS_DOCKER_IMAGE", "baddns", "The container image spawned for BadDNS."),
    ("GAU_DOCKER_IMAGE", "gau", "The container image spawned for gau."),
    ("GAU_VERIFY_DOCKER_IMAGE", "gau", "The httpx image GAU's verification pass spawns."),
    ("GRAPHQL_COP_DOCKER_IMAGE", "graphql_cop", "The container image spawned for GraphQL Cop."),
    ("HAKRAWLER_DOCKER_IMAGE", "hakrawler", "The container image spawned for hakrawler."),
    ("HTTPX_DOCKER_IMAGE", "httpx", "The container image spawned for httpx."),
    ("JSLUICE_VERIFY_DOCKER_IMAGE", "jsluice", "The httpx image jsluice's verification pass spawns."),
    ("KATANA_DOCKER_IMAGE", "katana", "The container image spawned for Katana."),
    ("NAABU_DOCKER_IMAGE", "naabu", "The container image spawned for naabu."),
    ("NUCLEI_DOCKER_IMAGE", "nuclei", "The container image spawned for Nuclei."),
    ("PUREDNS_DOCKER_IMAGE", "puredns", "The container image spawned for puredns."),
    ("SUBFINDER_DOCKER_IMAGE", "subfinder", "The container image spawned for subfinder."),
    ("TLSX_DOCKER_IMAGE", "tlsx", "The container image spawned for tlsx."),
    ("UNCOVER_DOCKER_IMAGE", "uncover", "The container image spawned for uncover."),
    ("WEB_CACHE_POISON_DOCKER_IMAGE", "web_cache_poison",
     "The container image spawned for Web cache poisoning."),
    ("ZAP_AJAX_SPIDER_DOCKER_IMAGE", "zap", "The container image spawned for ZAP Ajax Spider."),
]:
    RUNTIME_ONLY[_key] = {
        "source": "internal", "tool": _tool, "unit": "none", "roe_capped": False,
        "meaning": (
            f"{_lead} Not a project setting: a scan always runs the image RedAmon ships, "
            "and the scan-start chokepoint pins this key back to that default whatever a "
            "settings dict carries, so no form, preset, API or MCP write can point a scan "
            "at another image."
        ),
    }

SEVERITY_VALUES = ["info", "low", "medium", "high", "critical", "unknown"]
SCAN_MODULE_VALUES = [
    "domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon",
]


def tool_for(column: str) -> str:
    best = ""
    best_tool = "project"
    for prefix, tool in TOOL_PREFIXES:
        if column.startswith(prefix) and len(prefix) > len(best):
            best, best_tool = prefix, tool
    return best_tool


def unit_for(column: str, col: Column) -> str:
    if col.kind in ("boolean", "json", "datetime", "string", "string-list", "number-list"):
        return "none"
    for pattern, unit in UNIT_RULES:
        if pattern.search(column):
            return unit
    # A Float that no rule claimed is a coefficient, not a countable quantity.
    # `count` on a fractional value is the mistake this catches.
    return "ratio" if col.kind == "float" else "count"


# The cross-surface identifiers that are not derivable from a name. Each is a
# link a `tools:` entry claims and a test resolves, so "adding a tool" fails the
# build until its module, its isolated wrapper and its graph writer all exist.
#
# A tool with no entry here is a GROUP rather than a pipeline tool: the Rules of
# Engagement, the agent, project identity. Those legitimately have no module.
TOOL_WIRING: dict[str, dict[str, str]] = {
    "amass": {"module": "recon.main_recon_modules.domain_recon"},
    "arjun": {"module": "recon.main_recon_modules.resource_enum"},
    "baddns": {"module": "recon.main_recon_modules.subdomain_takeover"},
    "banner_grab": {"module": "recon.main_recon_modules.port_scan"},
    "censys": {
        "module": "recon.main_recon_modules.censys_enrich",
        "isolated_fn": "run_censys_enrichment_isolated",
        "graph_writer": "update_graph_from_censys",
    },
    "criminalip": {
        "module": "recon.main_recon_modules.criminalip_enrich",
        "isolated_fn": "run_criminalip_enrichment_isolated",
        "graph_writer": "update_graph_from_criminalip",
    },
    "crtsh": {"module": "recon.main_recon_modules.domain_recon"},
    "dns": {"module": "recon.main_recon_modules.domain_recon"},
    "ffuf": {"module": "recon.main_recon_modules.resource_enum"},
    "fofa": {
        "module": "recon.main_recon_modules.fofa_enrich",
        "isolated_fn": "run_fofa_enrichment_isolated",
        "graph_writer": "update_graph_from_fofa",
    },
    "gau": {"module": "recon.main_recon_modules.resource_enum"},
    "graphql": {"module": "recon.graphql_scan", "isolated_fn": "run_graphql_scan_isolated"},
    "hackertarget": {"module": "recon.main_recon_modules.domain_recon"},
    "hakrawler": {"module": "recon.main_recon_modules.resource_enum"},
    "httpx": {"module": "recon.main_recon_modules.http_probe"},
    "js_recon": {"module": "recon.main_recon_modules.js_recon"},
    "jsluice": {"module": "recon.main_recon_modules.js_recon"},
    "katana": {"module": "recon.main_recon_modules.resource_enum"},
    "kiterunner": {"module": "recon.main_recon_modules.resource_enum"},
    "knockpy": {"module": "recon.main_recon_modules.domain_recon"},
    "masscan": {
        "module": "recon.main_recon_modules.masscan_scan",
        "isolated_fn": "run_masscan_scan_isolated",
    },
    "mitre": {"module": "recon.main_recon_modules.add_mitre"},
    "naabu": {
        "module": "recon.main_recon_modules.port_scan",
        "isolated_fn": "run_port_scan_isolated",
    },
    "netlas": {
        "module": "recon.main_recon_modules.netlas_enrich",
        "isolated_fn": "run_netlas_enrichment_isolated",
        "graph_writer": "update_graph_from_netlas",
    },
    "nmap": {"module": "recon.main_recon_modules.nmap_scan"},
    "nuclei": {"module": "recon.main_recon_modules.vuln_scan"},
    "origin_discovery": {
        "module": "recon.main_recon_modules.origin_discovery",
        "isolated_fn": "run_origin_discovery_enrichment_isolated",
    },
    "otx": {
        "module": "recon.main_recon_modules.otx_enrich",
        "isolated_fn": "run_otx_enrichment_isolated",
        "graph_writer": "update_graph_from_otx",
    },
    "paramspider": {"module": "recon.main_recon_modules.resource_enum"},
    "puredns": {"module": "recon.main_recon_modules.domain_recon"},
    "shodan": {
        "module": "recon.main_recon_modules.shodan_enrich",
        "isolated_fn": "run_shodan_enrichment_isolated",
    },
    "subfinder": {"module": "recon.main_recon_modules.domain_recon"},
    "subjack": {
        "module": "recon.main_recon_modules.subdomain_takeover",
        "isolated_fn": "run_subdomain_takeover_isolated",
    },
    # supply_chain_recon imports `supply_chain_common`, which is mounted at
    # /app/supply_chain_common in a spawned scan container and is not on the
    # path in the root-recon test section. The module is real; naming it here
    # would make the wiring test assert something about the TEST environment.

    "takeover": {
        "module": "recon.main_recon_modules.subdomain_takeover",
        "isolated_fn": "run_subdomain_takeover_isolated",
    },
    "tlsx": {"module": "recon.main_recon_modules.tls_scan"},
    "uncover": {
        "module": "recon.main_recon_modules.uncover_enrich",
        "isolated_fn": "run_uncover_expansion_isolated",
    },
    # urlscan has no isolated wrapper: it runs inside the OSINT pass rather than
    # as its own fan-out branch. Claiming one that does not exist would be the
    # exact defect the wiring test is for.
    "urlscan": {"module": "recon.main_recon_modules.urlscan_enrich"},
    "vhost_sni": {
        "module": "recon.main_recon_modules.vhost_sni_enum",
        "isolated_fn": "run_vhost_sni_enrichment_isolated",
    },
    "virustotal": {
        "module": "recon.main_recon_modules.virustotal_enrich",
        "isolated_fn": "run_virustotal_enrichment_isolated",
        "graph_writer": "update_graph_from_virustotal",
    },
    "wappalyzer": {"module": "recon.main_recon_modules.http_probe"},
    "whois": {"module": "recon.main_recon_modules.domain_recon"},
    "zap": {"module": "recon.main_recon_modules.resource_enum"},
    "zoomeye": {
        "module": "recon.main_recon_modules.zoomeye_enrich",
        "isolated_fn": "run_zoomeye_enrichment_isolated",
        "graph_writer": "update_graph_from_zoomeye",
    },
    "ai_surface_recon": {"module": "recon.main_recon_modules.ai_surface_recon"},
}

# tool -> the partial-recon module that re-runs it on demand. A tool with none
# cannot be re-run from the workflow graph, which is a real product gap rather
# than an oversight, so null is a legitimate value here.
PARTIAL_RECON_MODULE: dict[str, str] = {
    "ai_surface_recon": "ai_surface_recon",
    "amass": "subdomain_discovery",
    "arjun": "parameter_discovery",
    # baddns runs inside the subdomain-takeover pass, which is what the
    # vulnerability_scanning partial module re-runs.
    "baddns": "vulnerability_scanning",
    # Banner grabbing runs inside the port-scan pass rather than on its own.
    "banner_grab": "port_scanning",
    "nuclei": "vulnerability_scanning",
    "security_check": "vulnerability_scanning",
    "cve_lookup": "vulnerability_scanning",
    "mitre": "vulnerability_scanning",
    "censys": "osint_enrichment",
    "criminalip": "osint_enrichment",
    "crtsh": "subdomain_discovery",
    "fofa": "osint_enrichment",
    "graphql_cop": "graphql_scanning",
    "netlas": "osint_enrichment",
    "osint_enrichment": "osint_enrichment",
    "otx": "osint_enrichment",
    "shodan": "osint_enrichment",
    "subdomain_discovery": "subdomain_discovery",
    "uncover": "osint_enrichment",
    "urlscan": "osint_enrichment",
    "virustotal": "osint_enrichment",
    "zoomeye": "osint_enrichment",
    "dns": "subdomain_discovery",
    "ffuf": "web_crawling",
    "gau": "web_crawling",
    "graphql": "graphql_scanning",
    "hackertarget": "subdomain_discovery",
    "hakrawler": "web_crawling",
    "httpx": "http_probing",
    "js_recon": "js_analysis",
    "jsluice": "web_crawling",
    "katana": "web_crawling",
    "kiterunner": "parameter_discovery",
    "knockpy": "subdomain_discovery",
    "masscan": "port_scanning",
    "naabu": "port_scanning",
    "nmap": "port_scanning",
    "nuclei": "vulnerability_scanning",
    "origin_discovery": "origin_enrichment",
    "paramspider": "parameter_discovery",
    "puredns": "subdomain_discovery",
    "subfinder": "subdomain_discovery",
    "subjack": "vulnerability_scanning",
    "supply_chain_recon": "supply_chain",
    "takeover": "vulnerability_scanning",
    "tlsx": "tlsx_scanning",
    "vhost_sni": "vulnerability_scanning",
    "wappalyzer": "http_probing",
    "web_cache_poison": "cache_scanning",
    "whois": "subdomain_discovery",
    "zap": "web_crawling",
}

# tool -> the ProjectForm section file that configures it, without the .tsx.
# Several tools share one section, which is why this is not derived from the
# filename: a section is a UI grouping and a tool is a pipeline unit.
# A tool whose enable flag is not named `<tool>Enabled`. Each was found by the
# alignment test, which is the point of having one: a tool with no enable flag
# runs whenever its phase does, which is a different product decision from "on
# by default".
ENABLED_FIELD_OVERRIDE: dict[str, str] = {
    "graphql": "graphqlSecurityEnabled",
    "knockpy": "knockpyReconEnabled",
    "takeover": "subdomainTakeoverEnabled",
    "zap": "zapAjaxSpiderEnabled",
    "supply_chain_recon": "supplyChainReconEnabled",
    "web_cache_poison": "webCachePoisonEnabled",
    "ai_surface_recon": "aiSurfaceReconEnabled",
    "origin_discovery": "originDiscoveryEnabled",
    "vhost_sni": "vhostSniEnabled",
    "js_recon": "jsReconEnabled",
    "banner_grab": "bannerGrabEnabled",
    "cve_lookup": "cveLookupEnabled",
    "security_check": "securityCheckEnabled",
    "capture_proxy": "captureProxyEnabled",
    "osint_enrichment": "osintEnrichmentEnabled",
    "subdomain_discovery": "subdomainDiscoveryEnabled",
    "graphql_cop": "graphqlCopEnabled",
}

# A tool whose image key is not `<TOOL>_DOCKER_IMAGE`. Images are not project
# columns: each is a fixed `DEFAULT_SETTINGS` entry in recon/project_settings.py.
# gau spawns TWO images (its own, and httpx for the verification pass); the
# tool's `image` is the primary one.
IMAGE_KEY_OVERRIDE: dict[str, str] = {
    "zap": "ZAP_AJAX_SPIDER_DOCKER_IMAGE",
}


def _shipped_images() -> dict[str, str]:
    """`*_DOCKER_IMAGE` key -> image, from recon's DEFAULT_SETTINGS."""
    text = RECON_SETTINGS_PY.read_text(encoding="utf-8")
    return dict(re.findall(r"'([A-Z0-9_]+_DOCKER_IMAGE)':\s*'([^']+)'", text))


FORM_SECTION: dict[str, str] = {
    "agent": "AgentBehaviourSection",
    "ai_surface_recon": "AiSurfaceReconSection",
    "amass": "SubdomainDiscoverySection",
    "arjun": "ArjunSection",
    "auth_profile": "AuthenticationSection",
    "baddns": "TakeoverSection",
    "banner_grab": "NaabuSection",
    "censys": "OsintEnrichmentSection",
    "criminalip": "OsintEnrichmentSection",
    "crtsh": "SubdomainDiscoverySection",
    "cve_lookup": "CveLookupSection",
    "cypherfix": "CypherFixSettingsSection",
    "dns": "SubdomainDiscoverySection",
    "domain_recon_ai": "SubdomainDiscoverySection",
    "dos": "DosSection",
    "engagement": "RoeSection",
    "ffuf": "FfufSection",
    "fireteam": "AgentBehaviourSection",
    "fofa": "OsintEnrichmentSection",
    "gau": "GauSection",
    "github": "GithubSection",
    "graphql": "GraphqlScanSection",
    "graphql_cop": "GraphqlScanSection",
    "gvm": "GvmScanSection",
    "hackertarget": "SubdomainDiscoverySection",
    "hakrawler": "HakrawlerSection",
    "http_probe_ai": "HttpxSection",
    "httpx": "HttpxSection",
    "hydra": "BruteForceSection",
    "js_recon": "JsReconSection",
    "jsluice": "JsluiceSection",
    "katana": "KatanaSection",
    "kiterunner": "KiterunnerSection",
    "knockpy": "SubdomainDiscoverySection",
    "masscan": "MasscanSection",
    "mitre": "MitreSection",
    "naabu": "NaabuSection",
    "netlas": "OsintEnrichmentSection",
    "nmap": "NmapSection",
    "nuclei": "NucleiSection",
    "origin_discovery": "OriginDiscoverySection",
    "osint_enrichment": "OsintEnrichmentSection",
    "otx": "OsintEnrichmentSection",
    "paramspider": "ParamSpiderSection",
    "path_traversal": "PathTraversalSection",
    "phishing": "PhishingSection",
    "pipeline": "ScanModulesSection",
    "pipeline_ai": "ScanModulesSection",
    "port_scan_ai": "NaabuSection",
    "project": "TargetSection",
    "puredns": "SubdomainDiscoverySection",
    "rce": "RceSection",
    "resource_enum_ai": "ResourceEnumAiSection",
    "roe": "RoeSection",
    "security_check": "SecurityChecksSection",
    "shodan": "ShodanSection",
    "sqli": "SqliSection",
    "ssrf": "SsrfSection",
    "subdomain_discovery": "SubdomainDiscoverySection",
    "subfinder": "SubdomainDiscoverySection",
    "subjack": "TakeoverSection",
    "supply_chain": "SupplyChainScanSection",
    "supply_chain_recon": "SupplyChainReconSection",
    "takeover": "TakeoverSection",
    "targeting": "TargetSection",
    "tlsx": "TlsxSection",
    "trufflehog": "TrufflehogSection",
    "uncover": "OsintEnrichmentSection",
    "urlscan": "UrlscanSection",
    "vhost_sni": "VhostSniSection",
    "virustotal": "OsintEnrichmentSection",
    "waf": "HttpxSection",
    "wappalyzer": "HttpxSection",
    "web_cache_poison": "ToolMatrixSection",
    "whois": "SubdomainDiscoverySection",
    "zap": "KatanaSection",
    "zoomeye": "OsintEnrichmentSection",
    "capture_proxy": "ToolMatrixSection",
}


# The stealth profile, per runtime key.
#
# `apply_stealth_overrides` wrote 105 explicit assignments, which is a list of
# tools kept in step with the pipeline by hand: a tool added without a stealth
# entry is simply as loud in stealth mode as it is normally, and nothing says
# so. Recorded here instead, seeded from those assignments.
#
# Two operations, and the difference matters. `set` FORCES a value. `ceiling`
# lowers a value to at most N and leaves a quieter one alone, which is what the
# six `min(settings.get(k), 100)` lines did.
#
# The nuclei exclude-tag MERGE stays hand-written: it unions the operator's own
# excluded tags with the stealth set, and expressing a union as a value would
# discard whatever the operator chose.
STEALTH_PROFILE: dict[str, dict] = {
    "AI_SURFACE_RECON_MAX_WORKERS": {"set": 2},
    "AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED": {"set": False},
    "AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED": {"set": False},
    "AMASS_ACTIVE": {"set": False},
    "AMASS_BRUTE": {"set": False},
    "AMASS_MAX_RESULTS": {"ceiling": 100},
    "ARJUN_PASSIVE": {"set": True},
    "BADDNS_ENABLED": {"set": False},
    "BANNER_GRAB_ENABLED": {"set": False},
    "CENSYS_WORKERS": {"set": 1},
    "CRIMINALIP_WORKERS": {"set": 1},
    "CRTSH_MAX_RESULTS": {"ceiling": 100},
    "DNS_MAX_WORKERS": {"set": 5},
    "DNS_RECORD_PARALLELISM": {"set": False},
    "FFUF_ENABLED": {"set": False},
    "FOFA_WORKERS": {"set": 1},
    "GAU_ENABLED": {"set": True},
    "GAU_METHOD_DETECT_RATE_LIMIT": {"set": 2},
    "GAU_METHOD_DETECT_THREADS": {"set": 1},
    "GAU_VERIFY_RATE_LIMIT": {"set": 2},
    "GAU_VERIFY_THREADS": {"set": 1},
    "GAU_WORKERS": {"set": 1},
    "GRAPHQL_CONCURRENCY": {"set": 1},
    "GRAPHQL_COP_TEST_ALIAS_OVERLOADING": {"set": False},
    "GRAPHQL_COP_TEST_BATCH_QUERY": {"set": False},
    "GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION": {"set": False},
    "GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING": {"set": False},
    "GRAPHQL_INTROSPECTION_TEST": {"set": True},
    "GRAPHQL_RATE_LIMIT": {"set": 2},
    "GRAPHQL_SECURITY_ENABLED": {"set": True},
    "GRAPHQL_TIMEOUT": {"set": 60},
    "HACKERTARGET_MAX_RESULTS": {"ceiling": 100},
    "HAKRAWLER_ENABLED": {"set": False},
    "HTTPX_PROBE_FAVICON": {"set": False},
    "HTTPX_PROBE_JARM": {"set": False},
    "HTTPX_RATE_LIMIT": {"set": 2},
    "HTTPX_THREADS": {"set": 1},
    "JSLUICE_MAX_FILES": {"set": 20},
    "JSLUICE_PARALLELISM": {"set": 1},
    "JS_RECON_INCLUDE_CHUNKS": {"set": False},
    "JS_RECON_INCLUDE_FRAMEWORK_JS": {"set": False},
    "JS_RECON_MAX_FILES": {"set": 50},
    "JS_RECON_VALIDATE_KEYS": {"set": False},
    "KATANA_CONCURRENCY": {"set": 1},
    "KATANA_DEPTH": {"set": 1},
    "KATANA_JS_CRAWL": {"set": False},
    "KATANA_MAX_URLS": {"set": 50},
    "KATANA_PARALLELISM": {"set": 1},
    "KATANA_RATE_LIMIT": {"set": 2},
    "KITERUNNER_ENABLED": {"set": False},
    "KNOCKPY_RECON_MAX_RESULTS": {"ceiling": 100},
    "MASSCAN_ENABLED": {"set": False},
    "NAABU_PASSIVE_MODE": {"set": True},
    "NAABU_RATE_LIMIT": {"set": 10},
    "NAABU_SCAN_TYPE": {"set": "c"},
    "NAABU_SKIP_HOST_DISCOVERY": {"set": True},
    "NAABU_THREADS": {"set": 1},
    "NETLAS_WORKERS": {"set": 1},
    "NMAP_PARALLELISM": {"set": 1},
    "NMAP_SCRIPT_SCAN": {"set": False},
    "NMAP_TIMING_TEMPLATE": {"set": "T2"},
    "NUCLEI_BULK_SIZE": {"set": 5},
    "NUCLEI_CONCURRENCY": {"set": 2},
    "NUCLEI_DAST_MODE": {"set": False},
    "NUCLEI_HEADLESS": {"set": False},
    "NUCLEI_INTERACTSH": {"set": False},
    "NUCLEI_RATE_LIMIT": {"set": 5},
    "NUCLEI_TAKEOVERS_ENABLED": {"set": False},
    "ORIGIN_DISCOVERY_RATE": {"set": 1},
    "ORIGIN_DISCOVERY_SCANNERS": {"set": False},
    "ORIGIN_DISCOVERY_WORKERS": {"set": 1},
    "OTX_WORKERS": {"set": 1},
    "PARAMSPIDER_ENABLED": {"set": True},
    "PARAMSPIDER_WORKERS": {"set": 1},
    "PUREDNS_ENABLED": {"set": False},
    "SECURITY_CHECK_ADMIN_PORT_EXPOSED": {"set": False},
    "SECURITY_CHECK_DATABASE_EXPOSED": {"set": False},
    "SECURITY_CHECK_DIRECT_IP_HTTP": {"set": False},
    "SECURITY_CHECK_DIRECT_IP_HTTPS": {"set": False},
    "SECURITY_CHECK_KUBERNETES_API_EXPOSED": {"set": False},
    "SECURITY_CHECK_NO_RATE_LIMITING": {"set": False},
    "SECURITY_CHECK_REDIS_NO_AUTH": {"set": False},
    "SECURITY_CHECK_SMTP_OPEN_RELAY": {"set": False},
    "SECURITY_CHECK_WAF_BYPASS": {"set": False},
    "SECURITY_CHECK_ZONE_TRANSFER": {"set": False},
    "SHODAN_WORKERS": {"set": 1},
    "SUBFINDER_MAX_RESULTS": {"ceiling": 100},
    "SUBJACK_ALL": {"set": False},
    "SUBJACK_CHECK_MAIL": {"set": True},
    "SUBJACK_CHECK_NS": {"set": True},
    "SUBJACK_THREADS": {"set": 3},
    "TAKEOVER_RATE_LIMIT": {"set": 10},
    "TLSX_CIPHER_ENUM": {"set": False},
    "TLSX_CONCURRENCY": {"set": 5},
    "TLSX_PROBE_JARM": {"set": False},
    "TLSX_VERSION_ENUM": {"set": False},
    "URLSCAN_MAX_RESULTS": {"ceiling": 100},
    "USE_BRUTEFORCE_FOR_SUBDOMAINS": {"set": False},
    "VHOST_SNI_ENABLED": {"set": False},
    "VIRUSTOTAL_WORKERS": {"set": 1},
    "WEB_CACHE_POISON_ALLOW_CPDOS": {"set": False},
    "WEB_CACHE_POISON_ENABLED": {"set": False},
    "ZAP_AJAX_SPIDER_ENABLED": {"set": False},
    "ZOOMEYE_WORKERS": {"set": 1},
}

# --- source parsers ---------------------------------------------------------------

def parse_governor_tables() -> dict[str, dict]:
    """
    runtime_key -> the governor block, read from the shipped tables.

    The memory governor's two models are not derivable from `unit`. A ratio key
    scales with available RAM; a budget key is an in-memory accumulator whose
    bytes-per-unit FAMILY and floor were chosen per key. Half the `count` fields
    in the model are not governed at all, so deriving "every count is budgeted"
    would start scaling things the governor has never touched.

    So the registry RECORDS the tables rather than inferring them. They were
    seeded from `_GOV_RATIO_KEYS` and `_GOV_BUDGET_KEYS` in `project_settings.py`;
    those are gone now that the runtime reads the registry, so a re-seed reads
    the registry's own blocks back and a governor change is an edit to the YAML.
    """
    import yaml  # noqa: PLC0415

    if not OUT_YAML.exists():
        return {}
    current = yaml.safe_load(OUT_YAML.read_text(encoding="utf-8")) or {}
    out: dict[str, dict] = {}
    for entry in (current.get("fields") or {}).values():
        gov, key = entry.get("governor"), entry.get("runtime_key")
        if gov and key:
            out[key] = gov
    for key, entry in (current.get("runtime_only") or {}).items():
        if entry.get("governor"):
            out[key] = entry["governor"]
    return out


def previous_registry() -> dict[str, dict]:
    """
    column -> its existing registry entry.

    Everything curated by hand lives here - the bounds somebody narrowed, the
    unit somebody corrected, the meaning somebody rewrote - so it WINS over
    anything this script would otherwise derive. Without that, running the
    top-up after a hand edit would quietly revert it, which is the behaviour
    that makes a generator something people stop running.
    """
    if not OUT_YAML.exists():
        return {}
    import yaml  # noqa: PLC0415

    current = yaml.safe_load(OUT_YAML.read_text(encoding="utf-8")) or {}
    return current.get("fields") or {}


def parse_catalog() -> dict[str, str]:
    """key -> prose meaning, from RECON_PARAMETER_CATALOG."""
    text = PRESET_SCHEMA_TS.read_text(encoding="utf-8")
    start = text.index("RECON_PARAMETER_CATALOG = `")
    body = text[start + len("RECON_PARAMETER_CATALOG = `"):]
    body = body[: body.index("`\n")]
    out: dict[str, str] = {}
    for raw in body.splitlines():
        line = raw.strip()
        m = re.match(r"^-\s+([A-Za-z0-9_]+):\s*[^-]*?(?:\s+-\s+(.*))?$", line)
        if m and m.group(2):
            out[m.group(1)] = m.group(2).strip()
    return out


def parse_form_sections() -> tuple[dict[str, dict], dict[str, str]]:
    """key -> {min,max}, and key -> operator hint, from the ProjectForm sections."""
    bounds: dict[str, dict] = {}
    hints: dict[str, str] = {}
    section_of: dict[str, str] = {}
    for path in sorted(SECTIONS_DIR.glob("*.tsx")):
        if path.name.endswith(".test.tsx"):
            continue
        text = path.read_text(encoding="utf-8")
        # Bounds are read PER ELEMENT. A window between one `updateField` and
        # the next picks up the neighbouring input's min/max, because the
        # attributes sit on either side of the handler depending on the section.
        # That is how the first pass gave fireteamMaxMembers a minimum of 5 when
        # the form says 2, and a narrower registry bound than the form is a save
        # that fails after the form accepted the value.
        for element in re.finditer(r"<input\b[\s\S]*?/>", text):
            el = element.group(0)
            if 'type="number"' not in el:
                continue
            key_match = re.search(r"updateField\(\s*'([A-Za-z0-9_]+)'", el)
            if not key_match:
                continue
            key = key_match.group(1)
            mn = re.search(r"\bmin=\{(-?[\d.]+)\}", el)
            mx = re.search(r"\bmax=\{(-?[\d.]+)\}", el)
            if mn or mx:
                cur = bounds.setdefault(key, {})
                if mn and "min" not in cur:
                    cur["min"] = float(mn.group(1)) if "." in mn.group(1) else int(mn.group(1))
                if mx and "max" not in cur:
                    cur["max"] = float(mx.group(1)) if "." in mx.group(1) else int(mx.group(1))

        # Hints stay window-based: they are prose beside the input rather than an
        # attribute on it, and a wrong hint is a documentation nit rather than a
        # refused save.
        hits = list(re.finditer(r"updateField\(\s*'([A-Za-z0-9_]+)'", text))
        for i, m in enumerate(hits):
            key = m.group(1)
            end = hits[i + 1].start() if i + 1 < len(hits) else min(len(text), m.end() + 1200)
            chunk = text[m.end(): end]
            hint = re.search(r"fieldHint\}>([^<{]{6,400})<", chunk)
            if hint and key not in hints:
                hints[key] = " ".join(hint.group(1).split())
            section_of.setdefault(key, path.stem)
    return bounds, hints


def runtime_keys() -> dict[str, tuple[str, str, str | None]]:
    """column -> (runtime_key, fallback, coerce)."""
    out: dict[str, tuple[str, str, str | None]] = {}
    for key, mapping in parse_mappings(RECON_SETTINGS_PY).items():
        out[mapping.column] = (key, mapping.fallback, mapping.coerce)
    # Multi-line mappings the line parser cannot see, recorded by hand so the
    # registry is not silently missing a runtime key that exists.
    out.setdefault("subdomainList", ("SUBDOMAIN_LIST", "missing", "strip_list"))
    out.setdefault("targetIps", ("TARGET_IPS", "missing", "strip_list"))
    out.setdefault("domainBatchMode", ("DOMAIN_BATCH_MODE", "missing", None))
    out.setdefault("domainBatchGroups", ("DOMAIN_BATCH_GROUPS", "missing", None))
    out.setdefault("jsluiceVerifyAcceptStatus", ("JSLUICE_VERIFY_ACCEPT_STATUS", "falsy", None))
    out.setdefault("jsluiceExcludePatterns", ("JSLUICE_EXCLUDE_PATTERNS", "falsy", None))
    return out


# --- emit --------------------------------------------------------------------------

def yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v))


def yaml_block(text: str, indent: str) -> str:
    """A folded scalar, wrapped, for the prose fields."""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > 76:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    body = "\n".join(f"{indent}  {line}" for line in lines)
    return f">-\n{body}"


def build() -> str:
    columns = project_columns()
    previous = previous_registry()
    catalog = parse_catalog()
    form_bounds, form_hints = parse_form_sections()
    rkeys = runtime_keys()
    governor = parse_governor_tables()

    fields: dict[str, dict] = {}
    for name in sorted(columns):
        col = columns[name]
        tool = tool_for(name)
        phase, traffic = TOOL_PHASE_TRAFFIC.get(tool, ("standalone", "none"))
        traffic = TRAFFIC_OVERRIDE.get(name, traffic)
        prior_entry = previous.get(name, {})
        unit = prior_entry.get("unit") or UNIT_OVERRIDE.get(name) or unit_for(name, col)

        entry: dict = {
            "tool": tool,
            "runtime_key": rkeys.get(name, (None, "missing", None))[0],
            "unit": unit,
            "phase": phase,
            "traffic": traffic,
            "roe_capped": (unit == "rps" and traffic == "active") or name in ROE_CAPPED_EXTRA,
            "mcp": "settable",
        }

        fallback = rkeys.get(name, (None, "missing", None))[1]
        coerce = rkeys.get(name, (None, "missing", None))[2]
        if fallback == "falsy":
            entry["fallback"] = "falsy"
        if coerce:
            entry["coerce"] = coerce

        # disposition
        if name in NEVER:
            entry["mcp"] = "never"
            entry["deny_reason"] = NEVER[name][0]
        elif name in UPLOAD_MANAGED:
            entry["mcp"] = "never"
            entry["deny_reason"] = "upload-managed"
            entry["written_by"] = UPLOAD_MANAGED[name]
        elif name in CREATE_ONLY:
            entry["mcp"] = "create_only"
        elif name.startswith("roe"):
            entry["mcp"] = "tighten_only"
            if name in TIGHTEN_DIRECTION:
                entry["tighten"] = TIGHTEN_DIRECTION[name]
            elif col.kind == "string-list":
                entry["tighten"] = "superset"
            elif col.kind == "boolean":
                entry["tighten"] = "true_to_false"
            elif col.kind in ("int", "float"):
                entry["tighten"] = "decrease"
            else:
                entry["tighten"] = "narrow"

        # bounds / values / validator
        if col.kind in ("int", "float"):
            src = previous.get(name, {}).get("bounds") or {}
            b = {}
            if "min" in src:
                b = {"min": src["min"], "max": src["max"]}
            elif name in form_bounds and "min" in form_bounds[name] and "max" in form_bounds[name]:
                b = dict(form_bounds[name])
            else:
                lo, hi = UNIT_BOUNDS.get(unit, UNIT_BOUNDS["count"])
                fb = form_bounds.get(name, {})
                b = {"min": fb.get("min", lo), "max": fb.get("max", hi)}
            dv = col.default_value
            if isinstance(dv, (int, float)) and not isinstance(dv, bool):
                b["min"] = min(b["min"], dv)
                b["max"] = max(b["max"], dv)
            if name in BOUNDS_OVERRIDE:
                lo, hi = BOUNDS_OVERRIDE[name]
                b = {"min": lo, "max": hi}
            entry["bounds"] = b
            if dv == 0:
                entry["zero_means"] = "unlimited" if unit == "rps" else "literal"
        elif col.kind == "boolean":
            pass
        elif name in PROJECT_FILE_FIELDS:
            entry["validator"] = "project_file"
        elif name in PROJECT_FILE_NAME_FIELDS:
            entry["validator"] = "project_file_name"
        elif name in HOSTNAME_LIST_FIELDS:
            entry["validator"] = "hostname_list"
        elif HEADER_FIELDS_RE.search(name):
            entry["validator"] = "http_header"
        elif name == "engagementKind":
            entry["values"] = ["internal", "third_party"]
            entry["validator"] = "identifier"
        elif name == "scanModules":
            entry["values"] = list(SCAN_MODULE_VALUES)
            entry["validator"] = "scan_modules"
        elif re.search(r"(Severity|Severities)$", name):
            entry["values"] = list(SEVERITY_VALUES)
            entry["validator"] = "severity"
        elif re.search(r"(StatusCodes?|MatchCodes|FilterCodes|AcceptStatus)$", name):
            entry["validator"] = "status_codes"
        elif col.kind == "json":
            entry["validator"] = "json_object"
        else:
            entry["validator"] = "free_text"

        # An authored description always wins: the catalog and the UI hints are
        # written for a different reader, and several are a label rather than a
        # sentence ("Seconds", "Enable OTX"). Nothing about a field that would
        # surprise a reader may come from a template.
        title = TOOL_TITLES.get(tool, tool.replace("_", " "))
        meaning = prior_entry.get("meaning") or authored_meaning(name, title, unit)
        if not meaning:
            meaning = catalog.get(name) or form_hints.get(name) or col.doc
        if not meaning or len(meaning.strip()) < 20:
            longer = catalog.get(name) or form_hints.get(name) or col.doc or ""
            meaning = longer if len(longer.strip()) >= 20 else (meaning or "")
        if not meaning:
            meaning = f"TODO: describe {name}."
        entry["meaning"] = meaning
        if name in READ_DENIED:
            entry["readable"] = False
            entry["read_deny_reason"] = READ_DENIED[name]
        gov = governor.get(entry["runtime_key"] or "")
        if gov:
            entry["governor"] = gov
        stealth = STEALTH_PROFILE.get(entry["runtime_key"] or "")
        if stealth:
            entry["stealth"] = stealth
        prior = previous.get(name, {})
        if prior.get("group"):
            entry["group"] = prior["group"]
        fields[name] = entry

    # A tool named ONLY by a runtime-only key still has to exist: AUTH_PROFILE is
    # a project RELATION rather than a column, so no field claims its tool, and
    # leaving it out would make the registry describe a key whose tool it does
    # not have.
    used_tools = sorted(
        {f["tool"] for f in fields.values()}
        | {r["tool"] for r in RUNTIME_ONLY.values() if r.get("tool")}
    )
    # The enable flag and the container image are DERIVED, not listed again:
    # `<tool>Enabled`'s runtime key is the enable flag, and the tool's
    # `*_DOCKER_IMAGE` default is the image. A second copy of either is a second
    # thing to keep in step.
    def _field_for(tool: str, suffix: str) -> dict | None:
        for name, entry in fields.items():
            if entry["tool"] == tool and name.endswith(suffix):
                # `<tool>Enabled` exactly, not `nucleiTakeoversEnabled`.
                if name[: -len(suffix)].lower().replace("_", "") == tool.replace("_", ""):
                    return {"name": name, **entry}
        return None

    shipped_images = _shipped_images()
    tools: dict[str, dict] = {}
    for tool in used_tools:
        phase, traffic = TOOL_PHASE_TRAFFIC.get(tool, ("standalone", "none"))
        entry: dict = {
            "title": TOOL_TITLES.get(tool, tool.replace("_", " ").title()),
            "phase": phase,
            "traffic": traffic,
        }
        enabled_name = ENABLED_FIELD_OVERRIDE.get(tool)
        enabled = (
            {"name": enabled_name, **fields[enabled_name]}
            if enabled_name and enabled_name in fields
            else _field_for(tool, "Enabled")
        )
        if enabled and enabled.get("runtime_key"):
            entry["enabled_key"] = enabled["runtime_key"]
        image = shipped_images.get(IMAGE_KEY_OVERRIDE.get(tool, f"{tool.upper()}_DOCKER_IMAGE"))
        if image:
            entry["image"] = image
        wiring = TOOL_WIRING.get(tool, {})
        for key in ("module", "isolated_fn", "graph_writer"):
            if key in wiring:
                entry[key] = wiring[key]
        if tool in PARTIAL_RECON_MODULE:
            entry["partial_recon_module"] = PARTIAL_RECON_MODULE[tool]
        if tool in FORM_SECTION:
            entry["form_section"] = FORM_SECTION[tool]
        tools[tool] = entry

    out: list[str] = []
    out.append("# RedAmon recon settings registry.")
    out.append("#")
    out.append("# The one hand-maintained description of every recon parameter. See README.md")
    out.append("# beside this file for what belongs here and what stays in Prisma.")
    out.append("#")
    out.append("# `type` and `default` are DELIBERATELY absent: Prisma owns them and the build")
    out.append("# joins them, so a value that already has two definitions never gains a third.")
    out.append("version: 1")
    out.append("")
    out.append("tools:")
    for tool in sorted(tools):
        spec = tools[tool]
        out.append(f"  {tool}:")
        out.append(f"    title: {yaml_scalar(spec['title'])}")
        out.append(f"    phase: {spec['phase']}")
        out.append(f"    traffic: {spec['traffic']}")
        for key in ("enabled_key", "image", "module", "isolated_fn", "graph_writer",
                    "partial_recon_module", "form_section"):
            if key in spec:
                out.append(f"    {key}: {yaml_scalar(spec[key])}")
    out.append("")
    out.append("fields:")
    for name in sorted(fields):
        f = fields[name]
        out.append(f"  {name}:")
        for key in ("tool", "runtime_key", "unit", "phase", "traffic", "roe_capped", "mcp"):
            value = f[key]
            if value is None:
                rendered = "null"
            elif isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]*", value):
                # A constrained enum value needs no quoting, and quoting it only
                # makes the diff of a re-run noisy.
                rendered = value
            else:
                rendered = yaml_scalar(value)
            out.append(f"    {key}: {rendered}")
        if "bounds" in f:
            out.append(f"    bounds: {{ min: {f['bounds']['min']}, max: {f['bounds']['max']} }}")
        if "values" in f:
            out.append(f"    values: [{', '.join(yaml_scalar(v) for v in f['values'])}]")
        if "stealth" in f:
            s = f["stealth"]
            if "ceiling" in s:
                out.append(f"    stealth: {{ ceiling: {s['ceiling']} }}")
            else:
                out.append(f"    stealth: {{ set: {yaml_scalar(s['set'])} }}")
        if "governor" in f:
            g = f["governor"]
            parts = [f"model: {g['model']}"]
            if "family" in g:
                parts.append(f"family: {g['family']}")
            parts.append(f"floor: {g['floor']}")
            out.append(f"    governor: {{ {', '.join(parts)} }}")
        if "readable" in f:
            out.append(f"    readable: {yaml_scalar(f['readable'])}")
        for key in ("validator", "zero_means", "fallback", "coerce", "tighten", "deny_reason", "read_deny_reason", "group"):
            if key in f:
                value = f[key]
                bare = isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_-]*", value)
                out.append(f"    {key}: {value if bare else yaml_scalar(value)}")
        if "written_by" in f:
            out.append(f"    written_by: {yaml_scalar(f['written_by'])}")
        out.append(f"    meaning: {yaml_block(f['meaning'], '    ')}")
    out.append("")
    out.append("# Runtime keys with no Prisma column. Not MCP-reachable, but the derived")
    out.append("# cap list is a query over this file, so a rate that lives only here is in it.")
    out.append("runtime_only:")
    for key in sorted(RUNTIME_ONLY):
        r = RUNTIME_ONLY[key]
        out.append(f"  {key}:")
        out.append(f"    source: {r['source']}")
        if "tool" in r:
            out.append(f"    tool: {r['tool']}")
        out.append(f"    unit: {r['unit']}")
        out.append(f"    roe_capped: {yaml_scalar(r['roe_capped'])}")
        rstealth = STEALTH_PROFILE.get(key)
        if rstealth:
            if "ceiling" in rstealth:
                out.append(f"    stealth: {{ ceiling: {rstealth['ceiling']} }}")
            else:
                out.append(f"    stealth: {{ set: {yaml_scalar(rstealth['set'])} }}")
        rgov = governor.get(key)
        if rgov:
            parts = [f"model: {rgov['model']}"]
            if "family" in rgov:
                parts.append(f"family: {rgov['family']}")
            parts.append(f"floor: {rgov['floor']}")
            out.append(f"    governor: {{ {', '.join(parts)} }}")
        if "zero_means" in r:
            out.append(f"    zero_means: {r['zero_means']}")
        if r.get("secret"):
            out.append("    secret: true")
        out.append(f"    meaning: {yaml_block(r['meaning'], '    ')}")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    text = build()
    OUT_YAML.write_text(text, encoding="utf-8")
    todo = text.count("TODO: describe")
    print(f"wrote {OUT_YAML.relative_to(REPO_ROOT)}  ({len(text.splitlines())} lines, {todo} meanings still TODO)")
