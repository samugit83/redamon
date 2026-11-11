"""
Descriptions for the recon parameters no existing source documents.

`RECON_PARAMETER_CATALOG` covers 474 fields and the ProjectForm hints cover more,
but roughly 280 columns reach the registry with nothing to say about them, and a
field an agent cannot read about is one it guesses at.

Two mechanisms, and the split is deliberate:

  TEMPLATES  formulaic families where the name genuinely determines the meaning
             (a `*DockerImage`, a `*Timeout`, a per-check toggle). Writing 200
             near-identical sentences by hand would produce 200 chances to get
             one subtly wrong.

  OVERRIDES  everything carrying real semantics: the RoE block, the targeting
             columns, the zero-means-unlimited rates, anything whose behaviour
             would surprise a reader who only had the name.

A template never wins over an override. No test can check that a description is
TRUE, so the rule is that anything non-obvious goes in OVERRIDES where a human
wrote it deliberately.
"""
from __future__ import annotations

import re

# --- the hand-written ones ------------------------------------------------------------

OVERRIDES: dict[str, str] = {
    # --- row identity, never a pipeline parameter --------------------------------
    "id": "The project's primary key. Row identity, not configuration.",
    "userId": (
        "The owning user. Writing it reassigns the project to someone else and "
        "configures nothing, which is why it is closed on every surface."
    ),
    "name": "The project's display name. Ordinary metadata, shown in every list and header.",
    "description": "Free-text notes about the engagement, shown beside the project name.",
    "createdAt": "When the project row was created. Written by the database.",
    "updatedAt": "When the project row last changed. Written by the database on every update.",
    "createdById": "The user who created the project. Populated going forward only; may be null on older rows.",
    "updatedById": "The user who last updated the project. Populated going forward only; may be null on older rows.",
    "activationState": (
        "The version-activation lock. Taken while a saved scan version rewrites the graph "
        "and released afterwards; it is a lock flag the application owns, not a setting."
    ),
    "activationStartedAt": (
        "When the current version activation took the lock. Used to detect a stale lock left "
        "by a crashed activation."
    ),
    "activationVersionId": "The scan version currently being activated. Written by the activation state machine.",
    "reconPresetId": (
        "The preset last applied to this project, recorded so the UI can show which one it "
        "came from. Written by the apply path, not configured directly."
    ),
    "loadedPreset": (
        "The name of the preset last loaded into this project and a fingerprint of the "
        "settings it produced. The UI shows the preset as applied only while the saved "
        "settings still match the fingerprint. Written by the load path, not configured directly."
    ),
    "mcpKaliExecEnabled": (
        "Whether MCP tokens on this project may run shell commands in the Kali sandbox. It "
        "decides what a credential can do rather than how the pipeline scans, so it is "
        "closed on the MCP surface: a token that could set it would be granting itself "
        "shell access."
    ),

    # --- targeting: the scope, write-once -----------------------------------------
    "targetDomain": (
        "The single root domain this engagement covers. THE scope column: every phase "
        "derives its hosts from it and the target guardrail measures against it. Set once "
        "at creation and immutable afterwards, because changing it on an existing project "
        "turns a rescan credential into one aimed at a third party. Leading and trailing "
        "whitespace is stripped at load."
    ),
    "subdomainList": (
        "Hosts seeded into the scan in addition to whatever discovery finds. Part of the "
        "engagement scope, so it is write-once. Empty entries are dropped and every entry "
        "is whitespace-stripped at load."
    ),
    "targetIps": (
        "The IP addresses or CIDR ranges scanned when ipMode is on. Part of the engagement "
        "scope, so it is write-once. Empty entries are dropped and every entry is stripped "
        "at load."
    ),
    "ipMode": (
        "Switches targeting from a domain to the explicit IP list. Mutually exclusive with "
        "domainBatchMode, and part of the scope, so it is write-once."
    ),
    "targetGuardrailEnabled": (
        "The hard guardrail that refuses to scan a host outside the declared scope. Turning "
        "it off removes the control that keeps the pipeline inside its engagement, which is "
        "why it moves with the scope and cannot change on an existing project."
    ),
    "verifyDomainOwnership": (
        "Requires a DNS TXT record proving control of the target before any active phase "
        "runs. Part of the scope's proof, so it is write-once."
    ),
    "ownershipToken": (
        "The secret published in the ownership TXT record. Compared against what DNS "
        "returns, so it proves the scope rather than configuring a tool."
    ),
    "ownershipTxtPrefix": (
        "The label the ownership TXT record is looked up under, prepended to the target "
        "domain. Moves with the scope."
    ),

    # --- Rules of Engagement: tighten-only ------------------------------------------
    "roeAllowDos": (
        "Whether denial-of-service techniques are permitted. Off means the DoS module and "
        "every aggression switch that could exhaust a target are refused at scan start, "
        "whatever their own toggles say. After creation this may only go true to false."
    ),
    "roeAllowDataExfiltration": (
        "Whether a finding may be proven by moving data off the target. Off means the "
        "out-of-band callback paths and collector egress are refused at scan start. After "
        "creation this may only go true to false."
    ),
    "roeAllowSocialEngineering": (
        "Whether techniques aimed at people rather than systems are permitted. After "
        "creation this may only go true to false."
    ),
    "roeAllowPhysicalAccess": (
        "Whether the engagement covers physical access. Recorded for the report; the "
        "pipeline has no physical capability. After creation this may only go true to false."
    ),
    "roeAllowProductionTesting": (
        "Whether production systems are in scope. Off is a statement the operator makes "
        "about the estate, not something the scanner can verify, so it constrains what an "
        "agent may choose rather than what a tool can reach."
    ),
    "roeAllowAccountLockout": (
        "Whether a technique that can lock a real account out is permitted. Off keeps "
        "credential attacks to a single attempt per account. After creation this may only "
        "go true to false."
    ),
    "roeEnabled": (
        "The master switch for the Rules of Engagement. While it is off there is NO rate "
        "ceiling at all, whatever roeGlobalMaxRps says, because the capper is gated on "
        "this flag. After creation it may only go false to true."
    ),
    "roeGlobalMaxRps": (
        "The engagement's request-rate ceiling, in requests per second. Every per-tool rate "
        "is capped to it at scan start, including the ones whose own value means "
        "'unlimited'. ZERO MEANS NO CEILING, so a project with roeEnabled on and this at 0 "
        "is not rate-limited. After creation it may only decrease, and never back to 0 once "
        "it is non-zero."
    ),
    "roeExcludedHosts": (
        "Hosts that must never be touched even though they fall inside the target scope. "
        "After creation this may only grow: an agent that discovers a new exclusion applies "
        "it immediately, and one that wants to remove an exclusion asks a human."
    ),
    "roeExcludedHostReasons": (
        "Why each excluded host is excluded, keyed by host. Read by the report; it does not "
        "itself exclude anything."
    ),
    "roeForbiddenTools": (
        "Tools that may not run on this engagement, by name, whatever their own enable flag "
        "says. Enforced at scan start. After creation this list may only grow."
    ),
    "roeForbiddenCategories": (
        "Technique categories that may not run on this engagement. Enforced at scan start "
        "against each module's category. After creation this list may only grow."
    ),
    "roeMaxSeverityPhase": (
        "The most severe phase the engagement permits, which bounds how far an attack chain "
        "may be taken. After creation it may only move toward the less severe end."
    ),
    "roeTimeWindowEnabled": "Whether scanning is restricted to an agreed time window.",
    "roeTimeWindowStartTime": "Local start of the permitted scanning window, as HH:MM.",
    "roeTimeWindowEndTime": "Local end of the permitted scanning window, as HH:MM.",
    "roeTimeWindowTimezone": "The IANA timezone the scanning window's times are read in.",
    "roeTimeWindowDays": "Days of the week on which scanning is permitted.",
    "roeEngagementStartDate": "The first date the engagement authorises any activity.",
    "roeEngagementEndDate": "The last date the engagement authorises any activity.",
    "roeEngagementType": "How the engagement is classified in the report: pentest, bug bounty, red team and so on.",
    "roeClientName": "The client the engagement is for, as it should appear in the report.",
    "roeClientContactName": "The named client contact for this engagement.",
    "roeClientContactEmail": "Where to reach the client contact by email.",
    "roeClientContactPhone": "Where to reach the client contact by phone.",
    "roeEmergencyContact": "Who to reach out of hours if a scan causes an incident.",
    "roeIncidentProcedure": "What to do if the engagement causes an outage or a security incident.",
    "roeCriticalFindingNotify": "Whether a critical finding triggers an immediate notification rather than waiting for the report.",
    "roeStatusUpdateFrequency": "How often the client expects a progress update during the engagement.",
    "roeComplianceFrameworks": "Compliance frameworks the engagement is conducted under, recorded for the report.",
    "roeDataRetentionDays": "How many days findings and captured data may be kept after the engagement ends.",
    "roeRequireDataEncryption": "Whether engagement data must be encrypted at rest.",
    "roeSensitiveDataHandling": "The agreed handling rule for sensitive data encountered during the engagement.",
    "roeThirdPartyProviders": "Third-party providers hosting in-scope assets, who may need their own notification.",
    "roeNotes": "Free-text engagement notes that did not fit another field.",
    "roeRawText": "The Rules of Engagement document as plain text, kept so the report can quote it.",
    "roeParsedJson": "The structured form extracted from the uploaded document, which populated the fields above.",
    "roeDocumentName": "The filename of the uploaded Rules of Engagement document.",
    "roeDocumentMimeType": "The media type of the uploaded Rules of Engagement document.",
    "roeDocumentData": "The uploaded Rules of Engagement document itself, stored so the engagement carries its own authority.",

    # --- rates whose zero is the fastest value ---------------------------------------
    "naabuRateLimit": (
        "Packets per second naabu sends, across all hosts combined. The engagement ceiling "
        "caps it at scan start, so a value above the ceiling is rewritten rather than refused."
    ),
    "masscanRate": (
        "Packets per second masscan sends. Masscan is the fastest port scanner here and the "
        "one most likely to be noticed; the engagement ceiling caps it at scan start."
    ),
    "httpxRateLimit": "Requests per second httpx sends while probing. Capped by the engagement ceiling at scan start.",
    "nucleiRateLimit": (
        "Requests per second nuclei sends, across all templates and all targets combined "
        "rather than per template. Capped by the engagement ceiling at scan start."
    ),
    "gauVerifyRateLimit": (
        "Requests per second the gau verification pass sends. gau itself only reads public "
        "archives, but verification dials the target, so this is active traffic and the "
        "engagement ceiling caps it."
    ),
    "gauMethodDetectRateLimit": (
        "Requests per second the gau method-detection pass sends to the target. Active "
        "traffic despite gau's passive reputation, so the engagement ceiling caps it."
    ),
    "kiterunnerMethodDetectRateLimit": (
        "Requests per second the kiterunner method-detection pass sends. Capped by the "
        "engagement ceiling at scan start."
    ),
    "arjunRateLimit": (
        "Requests per second arjun sends while probing for parameters. ZERO MEANS "
        "UNLIMITED, so 0 is the most aggressive value available and not the safest. Under "
        "an engagement ceiling a 0 here is rewritten to the ceiling at scan start."
    ),
    "ffufRate": (
        "Requests per second ffuf sends. ZERO MEANS UNLIMITED, so 0 is the most aggressive "
        "value available and not the safest, and it is also the shipped default. Under an "
        "engagement ceiling a 0 here is rewritten to the ceiling at scan start."
    ),
    "webCachePoisonMaxRpsPerHost": (
        "Requests per second the web-cache-poisoning scan sends to any ONE host. ZERO MEANS "
        "UNLIMITED, so 0 is the most aggressive value available and not the safest. Under an "
        "engagement ceiling a 0 here is rewritten to the ceiling at scan start."
    ),
    "purednsRateLimit": (
        "DNS queries per second puredns sends to its resolvers. ZERO MEANS UNLIMITED, so 0 "
        "is the most aggressive value available and not the safest. Under an engagement "
        "ceiling a 0 here is rewritten to the ceiling at scan start."
    ),

    # --- targeting-adjacent tool config --------------------------------------------
    "githubTargetOrg": (
        "The GitHub organisation the secret hunt scans. It points a scanner at someone "
        "else's assets, so it is scope by another name: settable when the project is "
        "created and immutable afterwards."
    ),
    "supplyChainRepoUrl": (
        "The repository the supply-chain scan clones. It becomes a git clone argument "
        "against a third party's infrastructure, so it is write-once like the scope."
    ),
    "supplyChainOrgName": (
        "The GitHub organisation whose repositories the supply-chain scan walks. Points the "
        "scanner at someone else's assets, so it is write-once."
    ),
    "supplyChainOrgRef": "The git ref checked out in each organisation repository, when one is pinned.",
    "supplyChainRepoRef": "The git ref checked out in the scanned repository. Write-once with the repository it belongs to.",
    "supplyChainRepoScope": "Which parts of the repository the scan reads. Write-once with the repository it belongs to.",
    "supplyChainSbomFile": (
        "The uploaded SBOM this project analyses. Written only by the upload endpoint, which "
        "also places the file on disk; a second writer could name a file the project never "
        "uploaded."
    ),
    "supplyChainInputMode": "Whether the supply-chain scan reads an uploaded SBOM, a repository, or an organisation.",
    "supplyChainEcosystems": "Package ecosystems the supply-chain scan analyses, such as npm, pypi or go.",
    "supplyChainOrgMaxRepos": "Maximum repositories walked when scanning an organisation.",
    "supplyChainOrgIncludeForks": "Whether forked repositories are included when scanning an organisation.",
    "supplyChainOrgIncludeArchived": "Whether archived repositories are included when scanning an organisation.",
    "scaIntelCorrelationEnabled": (
        "Whether supply-chain findings are correlated against the wider intelligence set. It "
        "reaches beyond this project's own assets, so it moves with the scope."
    ),

    # --- js recon uploads -------------------------------------------------------------
    "jsReconUploadedFiles": (
        "JavaScript files uploaded for analysis rather than fetched from the target. Written "
        "only by the upload endpoint, which also places each file on disk."
    ),
    "jsReconCustomPatterns": (
        "The uploaded custom secret-pattern file. Written only by the custom-files endpoint, "
        "which also places it on disk."
    ),
    "jsReconCustomSourcemapPaths": "The uploaded custom source-map path list. Written only by the custom-files endpoint.",
    "jsReconCustomPackages": "The uploaded custom package list. Written only by the custom-files endpoint.",
    "jsReconCustomEndpointKeywords": "The uploaded custom endpoint-keyword list. Written only by the custom-files endpoint.",
    "jsReconCustomFrameworks": "The uploaded custom framework-signature list. Written only by the custom-files endpoint.",

    # --- things whose name misleads ----------------------------------------------------
    "jsluiceExtractSecrets": (
        "Whether jsluice reports secret-shaped strings it finds in JavaScript. A feature "
        "toggle, not a credential: it decides what the tool looks for, and any secret found "
        "belongs to the target."
    ),
    "nmapTimingTemplate": (
        "Nmap's timing template, T0 to T5. Higher is faster and noisier; the stealth pass "
        "forces T2. Not a wordlist despite once being classified with them."
    ),
    "nucleiAutoUpdateTemplates": (
        "Whether nuclei refreshes its template set before scanning. It fetches from the "
        "public template repository, so it is an egress decision as well as a freshness one."
    ),
    "nucleiNewTemplatesOnly": "Restricts the run to templates added since the last template update, for a fast re-check.",
    "nucleiSelectedCustomTemplates": (
        "Which of this project's uploaded custom templates to run. Each entry is a path a "
        "scan container opens, so it is validated against the project's own upload directory."
    ),
    "rceAggressivePayloads": (
        "Whether the RCE technique uses payloads that can leave a running process or a "
        "changed file behind, rather than proof-of-concept ones that only echo."
    ),
    "wappalyzerNpmVersion": (
        "The npm version of Wappalyzer the scan container installs at run time. It is "
        "fetched from the public registry during the scan, so it decides what code runs "
        "inside the container."
    ),
    "attackSkillConfig": (
        "Per-project enable state for the built-in attack skills. Rewritten across every "
        "project when a user deletes one of their own skills."
    ),
    "agentToolPhaseMap": "Per-project overrides for which engagement phase each agent tool belongs to.",
    "triageReviewBudget": "How many findings one triage job may review before it stops and reports what it got through.",
    "captureProxyEnabled": (
        "Whether the HTTP capture proxy records the scan's traffic. Capture runs off the "
        "scan's critical path, so a capture failure never fails the scan."
    ),
    "cveLookupSource": "Which vulnerability database CVE enrichment queries.",
    "cveLookupMaxCves": "Maximum CVEs attached to one service before enrichment stops adding more.",
    "wappalyzerMinConfidence": "The confidence percentage below which a Wappalyzer technology match is discarded.",
    "wappalyzerRequireHtml": "Whether a technology match requires an HTML response, which suppresses matches on JSON and binary endpoints.",
    # Retired columns, kept so an upgrade or a rollback never drops data. Spelled
    # out because the templates would describe them as live: aiSurfaceReconCacheEnabled
    # matches `*Enabled` ("Whether ... runs").
    "jsReconStandaloneCrawlScope": (
        "Retired: nothing reads it. JS recon has no standalone crawl; it analyses the "
        "JavaScript the pipeline's crawlers found. Closed on every surface, with no input."
    ),
    "jsReconStandaloneCrawlDepth": (
        "Retired: nothing reads it. JS recon has no standalone crawl; it analyses the "
        "JavaScript the pipeline's crawlers found. Closed on every surface, with no input."
    ),
    "katanaScope": (
        "Retired: nothing reads it. Katana always crawls with field scope fqdn. Closed on "
        "every surface, with no input."
    ),
    "aiSurfaceReconCacheEnabled": (
        "Retired: nothing reads it. AI attack-surface recon has no probe cache, and one that "
        "skipped re-testing would leave earlier findings unchecked. Closed on every surface, "
        "with no input."
    ),
    "jsReconRegexPatterns": "Additional regular expressions applied to retrieved JavaScript, on top of the shipped set.",
    "kiterunnerMethodDetectionMode": "How kiterunner establishes which HTTP methods a discovered route accepts.",
    "trufflehogIncludeDetectors": "Restricts the run to these detectors. Empty means every detector runs.",
    "trufflehogExcludeDetectors": "Detectors that never run, whatever the include list says.",
    "trufflehogFilterEntropy": "The Shannon entropy below which a candidate string is discarded before detection runs.",
    "trufflehogDropUnverifiedJwt": "Discards JWTs that could not be verified, which are the bulk of the false positives in this class.",
    "trufflehogAllowVerificationOverlap": "Whether several detectors may verify the same candidate, which costs requests but catches more.",
    "trufflehogMaxDecodeDepth": "How many nested encodings are unwrapped before giving up on a candidate.",
    "trufflehogForceSkipArchives": "Skips archives entirely rather than extracting them, which is faster and misses anything inside.",
    "trufflehogForceSkipBinaries": "Skips binary files rather than scanning them for embedded strings.",
    "hydraExtraChecks": "Additional protocol-specific checks run alongside the credential attempts.",
    "agentPayloadUseHttps": "Whether a generated payload calls back over HTTPS rather than plain HTTP.",
    "agentBruteforceSpeed": "How aggressively the agent's credential attacks run, which trades attempts per second against lockout risk.",
    "agentBruteForceMaxWordlistAttempts": "The attempt ceiling for one credential attack, which is what keeps it from running a whole wordlist against a live account.",
    "agentLatsPhaseExploitation": "Whether the LATS search runs during the exploitation phase as well as reconnaissance.",
    "agentLatsShadowMode": "Runs the LATS search without acting on its choices, so its behaviour can be observed before it is trusted.",
    "agentGuardrailEnabled": "The agent's own scope guardrail, which refuses a tool call aimed outside the project's targets.",
    "agentRequireToolConfirmation": "Whether every agent tool call waits for a human to approve it.",
    "agentRequireApprovalForExploitation": "Whether the agent must be approved before it moves from reconnaissance into exploitation.",
    "agentRequireApprovalForPostExploitation": "Whether the agent must be approved before it acts on a host it has already compromised.",
    "agentActivatePostExplPhase": "Whether the post-exploitation phase is available to the agent at all.",
    "agentKaliInstallEnabled": "Whether the agent may install additional packages inside its Kali sandbox.",
    "agentChiselTunnelEnabled": "Whether the agent may stand up a chisel tunnel, which gives it network reach beyond its own container.",
    "agentNgrokTunnelEnabled": "Whether the agent may expose a local listener through ngrok, which makes it reachable from the public internet.",
    "agentCreateGraphImageOnInit": "Renders a picture of the graph when a session starts, so the agent begins with a view of the estate.",
    "cypherfixRequireApproval": "Whether a CypherFix patch must be approved by a human before it is pushed.",
    "fireteamEnabled": "Whether the agent may split work across a fireteam of sub-agents.",
    "fireteamAllowedPhases": "Engagement phases in which the fireteam may operate.",
    "fireteamConfirmationTimeoutSec": "How long a fireteam member waits for confirmation before giving up on a step.",
    "mitreEnrichRecon": "Attaches MITRE ATT&CK technique references to recon findings.",
    "mitreEnrichGvm": "Attaches MITRE ATT&CK technique references to GVM findings.",
    "mitreIncludeCwe": "Includes the CWE weakness reference alongside each technique.",
    "mitreIncludeCapec": "Includes the CAPEC attack-pattern reference alongside each technique.",
    "mitreAutoUpdateDb": "Whether the MITRE dataset is refreshed before enrichment runs.",
    "gvmCleanupAfterScan": "Removes the GVM task and its target after the scan, which keeps the appliance from accumulating state.",
    "githubScanCommits": "Walks commit history as well as the working tree, which is where most leaked secrets actually live.",
    "githubScanGists": "Includes the organisation members' public gists in the hunt.",
    "githubScanMembers": "Includes the organisation members' own repositories in the hunt.",
    "githubOutputJson": "Emits machine-readable output alongside the human-readable report.",
    "masscanBanners": "Whether masscan grabs a service banner as well as recording the open port, which turns a SYN scan into a connecting one.",
    "naabuSkipHostDiscovery": "Skips the ping sweep and scans every listed host directly, which is slower but finds hosts that do not answer ICMP.",
    "naabuVerifyPorts": "Re-probes each discovered port before reporting it, which removes the false positives a fast SYN scan produces.",
    "naabuExcludeCdn": "Skips hosts that resolve to a CDN, where a port result describes the CDN rather than the target.",
    "naabuDisplayCdn": "Reports CDN-fronted hosts rather than dropping them silently, so the operator can see what was skipped.",
    "nucleiScanAllIps": "Scans every IP a host resolves to rather than the first, which matters behind round-robin DNS.",
    "nucleiSystemResolvers": "Uses the container's own DNS resolvers rather than nuclei's defaults.",
    "purednsSkipValidation": "Skips the wildcard-validation pass, which is much faster and lets wildcard DNS flood the results.",
    "jsReconIncludeFrameworkJs": "Includes framework bundles, which are large, mostly third-party, and occasionally where a key is embedded.",
    "jsReconIncludeChunks": "Includes lazily-loaded chunks, which multiplies the file count on a modern bundler's output.",
    "jsReconIncludeArchivedJs": "Includes JavaScript recovered from web archives, which can reveal endpoints the live site no longer exposes.",
    "jsReconSourceMaps": "Retrieves source maps when they are published, which recovers the original source rather than the bundle.",
    "jsReconDependencyCheck": "Checks the packages a bundle names against known-vulnerable versions.",
    "jsReconFrameworkDetect": "Identifies the framework a bundle was built with, which decides which later checks apply.",
    "jsReconExtractEndpoints": "Extracts API endpoints referenced in JavaScript, which is the main reason to read it at all.",
    "jsluiceExtractUrls": "Extracts URLs jsluice finds in JavaScript.",
    "ffufRecursion": "Follows a discovered directory down into its own contents, which multiplies the request count.",
    "ffufRecursionDepth": "How many directories deep recursion goes before it stops.",
    "ffufAutoCalibrate": "Learns what a 'not found' response looks like on this target before filtering, which removes most soft-404 noise.",
    "ffufSmartFuzz": "Picks extensions and wordlist entries from what the target has already revealed rather than fuzzing blind.",
    "ffufFollowRedirects": "Follows a redirect rather than recording it, which can turn one request into several.",
    "gauFilterDeadEndpoints": "Drops archived URLs that no longer respond, so the result reflects the live surface.",
    "gauVerbose": "Emits per-URL progress, which is useful while debugging and noisy otherwise.",
    "hakrawlerIncludeSubs": "Follows links onto subdomains of the target rather than staying on one host.",
    "katanaJsCrawl": "Renders JavaScript with a headless browser, which finds routes a static crawl cannot and costs far more per page.",
    "katanaDepth": "How many links deep the crawl goes from each seed URL.",
    "katanaMaxUrls": "The crawl stops after this many URLs, which is what bounds a crawl on a large site.",
    "kiterunnerDetectMethods": "Establishes which HTTP methods each discovered route accepts, at the cost of extra requests per route.",
    "httpxFollowRedirects": "Follows a redirect to its destination rather than recording the redirect itself.",
    "httpxIncludeResponseHeaders": "Records the full response headers, which later checks read and which make the output much larger.",
    "httpxCustomHeaders": (
        "Extra headers sent with every httpx request. Validated: a header may not contain CR "
        "or LF, and Host, Authorization, Cookie and Proxy-* are refused, because each would "
        "change where the request goes or what it carries rather than annotating it."
    ),
    "shodanHostLookup": "Looks each discovered IP up in Shodan, which costs one API credit per host.",
    "shodanReverseDns": "Asks Shodan for the names an IP is known by, which often reveals hosts DNS enumeration missed.",
    "shodanDomainDns": "Pulls Shodan's own DNS record set for the domain.",
    "securityCheckTlsExpiryDays": "How many days before expiry a certificate starts being reported as expiring soon.",
    "securityCheckMaxWorkers": "How many security checks run concurrently.",
    "hackerTargetMaxResults": "Maximum subdomains taken from the HackerTarget API in one pass.",
    "knockpyReconMaxResults": "Maximum subdomains taken from a knockpy run.",
    "crtshMaxResults": "Maximum certificate-transparency records read from crt.sh in one pass.",
    "subfinderMaxResults": "Maximum subdomains taken from a subfinder run.",
    "amassMaxResults": "Maximum subdomains taken from an amass run.",
    "amassBruteWordlists": "Wordlists amass brute-forces with. Only the shipped list names are accepted.",
    "trufflehogArchiveMaxDepth": "How many nested archives are extracted before the scan stops descending.",
    "trufflehogArchiveMaxSize": "The largest archive extracted, in bytes. A larger one is skipped rather than exhausting the container.",
    "trufflehogArchiveTimeout": "Seconds one archive extraction may take before it is abandoned.",
    "trufflehogDetectorTimeout": "Seconds one detector may spend verifying a candidate before it is abandoned.",
    "trufflehogConcurrency": "How many sources trufflehog scans at once.",
    "engagementKind": (
        "Who the target belongs to, and therefore what has to be true before a scan may "
        "start. 'internal' is your own estate. 'third_party' is somebody else's, and such a "
        "project MUST carry a non-zero rate ceiling and an authorization record or "
        "start_recon refuses it. Set at creation and immutable afterwards: converting a "
        "project after the fact would either claim an authority nobody granted or drop a "
        "ceiling a human put there. Every project created before this field existed reads "
        "as 'internal', so an old project with no ceiling is flagged rather than blocked."
    ),
    "engagementIdentityHeader": (
        "A header every request carries so the target's operators can attribute the traffic "
        "to this engagement, for example 'X-Bug-Bounty: your-handle'. Empty sends none. "
        "Many programs require one, and it is the difference between a scan that gets a "
        "question and one that gets a block. Validated like any other header: no CR or LF, "
        "and not Host, Authorization, Cookie or Proxy-*."
    ),
    # The five timeouts whose unit is not seconds. Spelled out in words as well
    # as declared, because the name says "Timeout" and a reader who assumes
    # seconds writes a value off by 60 or 1000.
    "amassTimeout": (
        "How long amass may run, in MINUTES rather than seconds. The name reads like every "
        "other timeout in the model and the unit does not match it."
    ),
    "zapAjaxSpiderMaxDuration": (
        "How long the ZAP Ajax Spider may crawl one seed, in MINUTES rather than seconds."
    ),
    "zapAjaxSpiderEventWait": (
        "How long the Ajax Spider waits after firing a DOM event, in MILLISECONDS. Too low "
        "and a single-page app has not rendered its new state before the crawler reads it."
    ),
    "zapAjaxSpiderReloadWait": (
        "How long the Ajax Spider waits after a page reload, in MILLISECONDS."
    ),
    "naabuTimeout": (
        "How long naabu waits for a port to answer, in MILLISECONDS. At the default of 10000 "
        "a full sweep of an unresponsive host is slow; below about 1000 a distant host starts "
        "reading as closed."
    ),
    "dosMaxDuration": (
        "The longest one denial-of-service attempt may run, in seconds. It is only reachable "
        "at all when roeAllowDos permits the technique."
    ),
    "agentLogMaxMb": "The size at which the agent's log file rolls, in megabytes.",
    "nucleiFollowRedirects": (
        "Follows a redirect while running a template rather than matching on the redirect "
        "itself. A template that expects its payload to land on the final page needs this; "
        "one matching a redirect header does not."
    ),
}

# --- the formulaic ones ------------------------------------------------------------------

def _tool_label(tool_title: str) -> str:
    return tool_title

TEMPLATES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"DockerImage$"),
        "The container image spawned for {tool}. Any value outside the shipped allowlist is "
        "silently pinned back to the default at scan start, with a [guardrail] line recording "
        "it, so the field is open and the runtime is the control.",
    ),
    (
        re.compile(r"^(\w+?)Enabled$"),
        "Whether {tool} runs. Configuration is two levels: this flag decides whether the tool "
        "runs INSIDE its phase, and scanModules decides whether the phase runs at all. Setting "
        "one without the other is a silent no-op.",
    ),
    (
        re.compile(r"(Timeout|ScanTimeout|RunTimeout|ValidationTimeout)$"),
        "How long {tool} may spend before it is abandoned, in {unit}. A run that hits it "
        "contributes whatever it found so far rather than failing the scan.",
    ),
    (
        re.compile(r"(Threads|Concurrency|Workers|Parallelism|Connections)$"),
        "How many {tool} operations run at once. The memory governor scales it down when the "
        "host is short of RAM, so the effective value can be below what is written here.",
    ),
    (
        re.compile(r"RateLimit$"),
        "Requests per second {tool} sends. Capped to the engagement ceiling at scan start, so a "
        "value above the ceiling is rewritten rather than refused.",
    ),
    (
        re.compile(r"(MaxResults|MaxUrls|MaxFiles|MaxEndpoints|MaxCandidates|MaxRepos|MaxCommits|MaxCves)$"),
        "The most results {tool} accumulates in one pass. The memory governor budgets it against "
        "available RAM, so the effective value can be below what is written here.",
    ),
    (
        re.compile(r"(MaxRetries|Retries|RetryCount)$"),
        "How many times {tool} retries a failed request before giving up on it.",
    ),
    (
        re.compile(r"^securityCheck(?!Enabled$|Timeout$|MaxWorkers$)"),
        "Whether this individual check runs during the security-check pass. Each check is one "
        "condition tested against what the earlier phases already found; turning it off removes "
        "that finding class without affecting the rest.",
    ),
    (
        re.compile(r"^httpxProbe"),
        "Whether httpx records this attribute while probing. Each probe adds work per host, and "
        "several add requests beyond the first, so the set of probes decides both how much the "
        "scan learns and how loud it is.",
    ),
    (
        re.compile(r"^agentLats"),
        "Part of the agent's LATS search configuration, which is how it explores several "
        "candidate actions before committing to one.",
    ),
    (
        re.compile(r"^mitre"),
        "Part of MITRE ATT&CK enrichment, which annotates findings with the technique they "
        "correspond to. Enrichment reads existing findings and sends no traffic.",
    ),
]


def meaning_for(column: str, tool_title: str, unit: str) -> str | None:
    """A description for a column, or None when no source has one."""
    if column in OVERRIDES:
        return OVERRIDES[column]
    unit_word = {
        "seconds": "seconds",
        "minutes": "minutes",
        "milliseconds": "milliseconds",
    }.get(unit, "seconds")
    for pattern, template in TEMPLATES:
        if pattern.search(column):
            return template.format(tool=_tool_label(tool_title), unit=unit_word)
    return None
