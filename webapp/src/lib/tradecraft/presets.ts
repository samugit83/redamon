/**
 * The Quick Add presets of the tradecraft resource form, and the URLs workspace import
 * offers from them (workspaceImport/presets.ts).
 *
 * `key` is a preset's stable identity: a resource added from a preset records it
 * (`presetKey`, OQ-6), so a key never changes once shipped, even when the name does.
 * The type is a chip; `presetSettings` says which per-resource fields a preset fills (§6.12).
 */
import type { SiteType } from './agentContract'
import type { ResourceOverrides } from './settingsSpec'

/** The per-resource fields a preset fills in the form (§6.12). */
export interface PresetSettings {
  /** Absent: Auto, detection decides. */
  forcedType?: SiteType
  overrides?: ResourceOverrides
  /** Override keys whose value was not checked against the live site: manual checkpoint MC-3. */
  unverified?: string[]
}

export interface TradecraftPreset {
  key: string
  name: string
  url: string
  type: string
  description: string
  featured?: boolean
}

// Curated list of 100 popular, well-maintained, openly-licensed (or
// explicitly-public) security knowledge resources. Hand-picked to:
//  - Spread across all 6 types so users see how the catalog mixes them
//  - Avoid sites with anti-scraping ToS, login walls, or paywalls
//  - Prefer canonical / authoritative references actively maintained
// The source keeps the curation grouping; ALPHABETICAL_PRESETS is what Quick Add lists.
export const TRADECRAFT_PRESETS: readonly TradecraftPreset[] = [
  // === MkDocs-wiki / mdBook ===
  { key: 'hacktricks', name: 'HackTricks', url: 'https://book.hacktricks.wiki', type: 'mkdocs-wiki', description: 'Comprehensive offensive security wiki (web, AD, cloud, privesc, mobile)' },
  { key: 'the-hacker-recipes', name: 'The Hacker Recipes', url: 'https://www.thehacker.recipes', type: 'mkdocs-wiki', description: 'Pentest methodology by ShutdownRepo - AD, web, infra, exploit-dev' },
  { key: 'ctf-field-guide', name: 'CTF Field Guide', url: 'https://trailofbits.github.io/ctf/', type: 'mkdocs-wiki', description: 'Trail of Bits CTF guide - vulns, RE, forensics, web, exploits' },
  { key: 'ctf101', name: 'CTF101', url: 'https://ctf101.org', type: 'mkdocs-wiki', description: 'Beginner CTF reference - crypto, forensics, RE, web, binex categories' },

  // === GitBook ===
  { key: 'practical-ctf-jorian-woltjer', name: 'Practical CTF (Jorian Woltjer)', url: 'https://book.jorianwoltjer.com', type: 'gitbook', description: 'CTF + hacking technique notes (web, AD, crypto, binex, mobile)' },
  { key: 'ired-team', name: 'ired.team', url: 'https://www.ired.team', type: 'gitbook', description: 'Red team / offensive security notes - AD, evasion, persistence' },

  // === GitHub repos (markdown-based knowledge bases) ===
  { key: 'payloadsallthethings', name: 'PayloadsAllTheThings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', type: 'github-repo', description: 'Payload library + bypass cheatsheets organized per vulnerability class' },
  { key: 'internalallthethings', name: 'InternalAllTheThings', url: 'https://github.com/swisskyrepo/InternalAllTheThings', type: 'github-repo', description: 'Active Directory + post-exploitation cheatsheets (sister of PATT)' },
  { key: 'hardwareallthethings', name: 'HardwareAllTheThings', url: 'https://github.com/swisskyrepo/HardwareAllTheThings', type: 'github-repo', description: 'Hardware/IoT pentest references - UART, JTAG, BLE, Zigbee' },
  { key: 'h4cker-omar-santos', name: 'h4cker (Omar Santos)', url: 'https://github.com/The-Art-of-Hacking/h4cker', type: 'github-repo', description: 'Curated hacking resources (>10k references), per-topic folders' },
  { key: 'peass-ng', name: 'PEASS-ng', url: 'https://github.com/peass-ng/PEASS-ng', type: 'github-repo', description: 'WinPEAS / LinPEAS / MacPEAS privilege-escalation script suite' },
  { key: 'seclists', name: 'SecLists', url: 'https://github.com/danielmiessler/SecLists', type: 'github-repo', description: 'Wordlists for usernames, passwords, URLs, fuzzing payloads' },
  { key: 'awesome-pentest', name: 'awesome-pentest', url: 'https://github.com/enaqx/awesome-pentest', type: 'github-repo', description: 'Curated meta-list of pentest tools, books, conferences, OS distros' },
  { key: 'awesome-bug-bounty', name: 'awesome-bug-bounty', url: 'https://github.com/djadmin/awesome-bug-bounty', type: 'github-repo', description: 'Bug-bounty curated list - programs, writeups, tools' },
  { key: 'awesome-cloud-security', name: 'awesome-cloud-security', url: 'https://github.com/4ARMED/awesome-cloud-security', type: 'github-repo', description: 'AWS / GCP / Azure cloud security tooling and writeups' },
  { key: 'awesome-web-hacking', name: 'awesome-web-hacking', url: 'https://github.com/infoslack/awesome-web-hacking', type: 'github-repo', description: 'Web pentest tools, books, papers, vulnerable apps' },
  { key: 'awesome-android-security', name: 'awesome-android-security', url: 'https://github.com/saeidshirazi/awesome-android-security', type: 'github-repo', description: 'Android security learning path - tools, papers, exploits' },
  { key: 'xairy-linux-kernel-exploitation', name: 'xairy/linux-kernel-exploitation', url: 'https://github.com/xairy/linux-kernel-exploitation', type: 'github-repo', description: 'Curated Linux kernel exploitation resources, papers, writeups' },
  { key: 'privilege-escalation', name: 'Privilege-Escalation', url: 'https://github.com/Ignitetechnologies/Privilege-Escalation', type: 'github-repo', description: 'Linux + Windows privesc cheatsheets and lab walkthroughs' },
  { key: 'api-security-checklist', name: 'API-Security-Checklist', url: 'https://github.com/shieldfy/API-Security-Checklist', type: 'github-repo', description: 'Best-practices checklist for designing/testing secure REST APIs' },
  { key: 'ctf-tools', name: 'ctf-tools', url: 'https://github.com/zardus/ctf-tools', type: 'github-repo', description: 'CTF tool installer collection - pwn, RE, forensics, crypto, web' },
  { key: 'owasp-cheatsheets', name: 'OWASP CheatSheets', url: 'https://github.com/OWASP/CheatSheetSeries', type: 'github-repo', description: 'Concise OWASP cheatsheets per topic (XSS, CSRF, auth, JWT, ...)' },
  { key: 'owasp-wstg', name: 'OWASP WSTG', url: 'https://github.com/OWASP/wstg', type: 'github-repo', description: 'OWASP Web Security Testing Guide - methodology source markdown' },
  { key: 'owasp-mastg', name: 'OWASP MASTG', url: 'https://github.com/OWASP/owasp-mastg', type: 'github-repo', description: 'OWASP Mobile Application Security Testing Guide (iOS + Android)' },
  { key: 'cheat-sh', name: 'cheat.sh', url: 'https://github.com/chubin/cheat.sh', type: 'github-repo', description: 'Unified CLI cheatsheets (`curl cheat.sh/<cmd>`), security tools incl.' },
  { key: 'awesome-iot-hacks', name: 'awesome-iot-hacks', url: 'https://github.com/nebgnahz/awesome-iot-hacks', type: 'github-repo', description: 'IoT security resources - papers, talks, vulnerable hardware' },
  { key: 'awesome-malware-analysis', name: 'awesome-malware-analysis', url: 'https://github.com/rshipp/awesome-malware-analysis', type: 'github-repo', description: 'Reverse engineering, sandboxing, YARA, packers, behavior analysis' },
  { key: 'awesome-ctf', name: 'awesome-ctf', url: 'https://github.com/apsdehal/awesome-ctf', type: 'github-repo', description: 'CTF tools and resources catalog - wargames, RE, web, forensics' },
  { key: 'awesome-osint', name: 'awesome-osint', url: 'https://github.com/jivoi/awesome-osint', type: 'github-repo', description: 'OSINT investigation tools and frameworks (people, infra, geo)' },
  { key: 'awesome-shodan-queries', name: 'awesome-shodan-queries', url: 'https://github.com/jakejarvis/awesome-shodan-queries', type: 'github-repo', description: 'Curated Shodan dorks for finding exposed services and devices' },
  { key: 'awesome-windows-domain-hardening', name: 'awesome-windows-domain-hardening', url: 'https://github.com/PaulSec/awesome-windows-domain-hardening', type: 'github-repo', description: 'Active Directory hardening references and offensive playbooks' },
  { key: 'awesome-redteam', name: 'awesome-redteam', url: 'https://github.com/yeyintminthuhtut/Awesome-Red-Teaming', type: 'github-repo', description: 'Red team operator resources - initial access, recon, persistence' },
  { key: 'awesome-fuzzing', name: 'awesome-fuzzing', url: 'https://github.com/cpuu/awesome-fuzzing', type: 'github-repo', description: 'Fuzzing harnesses, frameworks, papers, tutorials' },

  // === CVE PoC databases ===
  { key: 'trickest-cve', name: 'trickest/cve', url: 'https://github.com/trickest/cve', type: 'cve-poc-db', description: 'Auto-aggregated CVE → public PoC index. Use cve_id="CVE-YYYY-NNNNN"' },
  { key: '0xmarcio-cve', name: '0xMarcio/cve', url: 'https://github.com/0xMarcio/cve', type: 'cve-poc-db', description: 'Alternative CVE → PoC index with extended metadata' },
  { key: 'nomi-sec-poc-in-github', name: 'nomi-sec/PoC-in-GitHub', url: 'https://github.com/nomi-sec/PoC-in-GitHub', type: 'cve-poc-db', description: 'Daily-updated CVE PoC index scraped from GitHub repos' },

  // === Sphinx / ReadTheDocs ===
  { key: 'scapy-docs', name: 'Scapy docs', url: 'https://scapy.readthedocs.io/en/latest/', type: 'sphinx-docs', description: 'Python packet crafting library - protocols, fuzzing, scapy.layers' },
  { key: 'volatility-3', name: 'Volatility 3', url: 'https://volatility3.readthedocs.io/en/latest/', type: 'sphinx-docs', description: 'Memory forensics framework - plugins, OS profiles, Vol3 API' },
  { key: 'mitmproxy-docs', name: 'Mitmproxy docs', url: 'https://docs.mitmproxy.org/stable/', type: 'sphinx-docs', description: 'TLS-MITM proxy - addons, scripting, intercept replay' },
  { key: 'sliver-c2', name: 'Sliver C2', url: 'https://sliver.sh/docs', type: 'sphinx-docs', description: 'Open-source C2 framework documentation (BishopFox)' },

  // === Agentic-crawl: real security blogs (no published sitemap) ===
  { key: '0xpatrik-patrik-hudak', name: '0xpatrik (Patrik Hudak)', url: 'https://0xpatrik.com', type: 'agentic-crawl', description: 'Subdomain takeovers, OSINT, recon automation, asset discovery' },
  { key: 'synacktiv-publications', name: 'Synacktiv publications', url: 'https://www.synacktiv.com/en/publications.html', type: 'agentic-crawl', description: 'French pentest firm writeups - AD, cloud, mobile, exploit-dev' },
  { key: 'doyensec-research', name: 'Doyensec research', url: 'https://blog.doyensec.com', type: 'agentic-crawl', description: 'Boutique appsec research - Electron, Java, GraphQL, Solidity' },
  { key: 'specterops', name: 'SpecterOps', url: 'https://posts.specterops.io', type: 'agentic-crawl', description: 'Red team / Active Directory deep dives (BloodHound team)' },
  { key: 'project-zero', name: 'Project Zero', url: 'https://googleprojectzero.blogspot.com', type: 'agentic-crawl', description: 'Google P0 vuln research - kernel, browser, mobile 0-days' },
  { key: 'spaceraccoon-eugene-lim', name: 'Spaceraccoon (Eugene Lim)', url: 'https://spaceraccoon.dev', type: 'agentic-crawl', description: 'Web/cloud/IoT writeups, supply-chain attacks, bug bounty postmortems' },
  { key: 'adsecurity-sean-metcalf', name: 'Adsecurity (Sean Metcalf)', url: 'https://adsecurity.org', type: 'agentic-crawl', description: 'Active Directory attack/defense - Kerberos, ADCS, replication abuse' },
  { key: 'trail-of-bits-blog', name: 'Trail of Bits blog', url: 'https://blog.trailofbits.com', type: 'agentic-crawl', description: 'Cryptography, smart contracts, fuzzing, OS-level security research' },
  { key: 'tarlogic-blog', name: 'Tarlogic blog', url: 'https://www.tarlogic.com/blog', type: 'agentic-crawl', description: 'Spanish pentest firm - Kerberos, AD, RT TTPs, threat intel' },
  { key: 'assetnote-research', name: 'Assetnote research', url: 'https://blog.assetnote.io', type: 'agentic-crawl', description: 'Attack-surface management research and 0-days in enterprise software' },

  // === ADDITIONAL 50 (deep-researched, mostly unique niches) ===
  { key: '0xdf-htb-writeups', name: '0xdf HTB writeups', url: 'https://0xdf.gitlab.io', type: 'agentic-crawl', description: 'HackTheBox machine writeups - exploitation chains, AD, web, binex' },
  { key: 'atomic-red-team', name: 'atomic-red-team', url: 'https://github.com/redcanaryco/atomic-red-team', type: 'github-repo', description: 'Red Canary library: MITRE ATT&CK technique simulations as runnable tests' },
  { key: 'att-ck-matrix', name: 'ATT&CK matrix', url: 'https://attack.mitre.org', type: 'agentic-crawl', description: 'MITRE adversary tactics + techniques + procedures (TTP) reference' },
  { key: 'awesome-active-directory', name: 'awesome-active-directory', url: 'https://github.com/Orange-Cyberdefense/awesome-activedirectory', type: 'github-repo', description: 'Active Directory attack/defense - Kerberos, ADCS, ACL, GPO, lateral mvmt' },
  { key: 'awesome-asset-discovery', name: 'awesome-asset-discovery', url: 'https://github.com/redhuntlabs/Awesome-Asset-Discovery', type: 'github-repo', description: 'Asset discovery / attack-surface mapping tools and methodologies' },
  { key: 'awesome-bluetooth-security', name: 'awesome-bluetooth-security', url: 'https://github.com/engn33r/awesome-bluetooth-security', type: 'github-repo', description: 'BLE/Bluetooth Classic attack research, sniffing, fuzzing, papers' },
  { key: 'awesome-burp-extensions', name: 'awesome-burp-extensions', url: 'https://github.com/snoopysecurity/awesome-burp-extensions', type: 'github-repo', description: 'Curated Burp Suite extension catalog by category (auth, recon, fuzzing)' },
  { key: 'awesome-exploit-development', name: 'awesome-exploit-development', url: 'https://github.com/FabioBaroni/awesome-exploit-development', type: 'github-repo', description: 'Userland + kernel exploit-dev resources, papers, tutorials, tools' },
  { key: 'awesome-hacker-search-engines', name: 'awesome-hacker-search-engines', url: 'https://github.com/edoardottt/awesome-hacker-search-engines', type: 'github-repo', description: 'Recon-oriented search engines - Shodan, Censys, Fofa, ZoomEye, etc.' },
  { key: 'awesome-hacking-meta', name: 'awesome-hacking (meta)', url: 'https://github.com/Hack-with-Github/Awesome-Hacking', type: 'github-repo', description: 'Meta-list pointing at every other awesome-* security list (single-hop index)' },
  { key: 'awesome-honeypots', name: 'awesome-honeypots', url: 'https://github.com/paralax/awesome-honeypots', type: 'github-repo', description: 'Honeypot deployments, frameworks, deception tools, defensive use' },
  { key: 'awesome-incident-response', name: 'awesome-incident-response', url: 'https://github.com/meirwah/awesome-incident-response', type: 'github-repo', description: 'DFIR tooling - triage, memory, disk, timeline, threat hunting' },
  { key: 'awesome-mobile-security', name: 'awesome-mobile-security', url: 'https://github.com/vaib25vicky/awesome-mobile-security', type: 'github-repo', description: 'iOS + Android offensive - Frida, Jadx, MOBSF, root-detection bypasses' },
  { key: 'awesome-pcaptools', name: 'awesome-pcaptools', url: 'https://github.com/caesar0301/awesome-pcaptools', type: 'github-repo', description: 'PCAP capture, analysis, and protocol-dissection tooling' },
  { key: 'awesome-sec-talks', name: 'awesome-sec-talks', url: 'https://github.com/PaulSec/awesome-sec-talks', type: 'github-repo', description: 'Conference talks library (DEFCON, BlackHat, BSides, OffensiveCon, ...)' },
  { key: 'awesome-vehicle-security', name: 'awesome-vehicle-security', url: 'https://github.com/jaredthecoder/awesome-vehicle-security', type: 'github-repo', description: 'Automotive security - CAN-bus, OBD-II, telematics, V2X' },
  { key: 'awesome-windows-pentest', name: 'awesome-windows-pentest', url: 'https://github.com/zer1t0/awesome-windows-pentest', type: 'github-repo', description: 'Windows-focused offensive - privesc, lateral movement, evasion' },
  { key: 'awesome-yara', name: 'awesome-yara', url: 'https://github.com/InQuest/awesome-yara', type: 'github-repo', description: 'YARA rule collections, tools, tutorials, malware-classification rules' },
  { key: 'bishop-fox-blog', name: 'Bishop Fox blog', url: 'https://bishopfox.com/blog', type: 'agentic-crawl', description: 'Bishop Fox security research - appsec, cloud, recon, vulnerabilities' },
  { key: 'building-secure-contracts-crytic', name: 'building-secure-contracts (crytic)', url: 'https://github.com/crytic/building-secure-contracts', type: 'github-repo', description: 'Solidity / EVM smart-contract security knowledge base by Trail of Bits' },
  { key: 'capec', name: 'CAPEC', url: 'https://capec.mitre.org', type: 'agentic-crawl', description: 'MITRE Common Attack Pattern Enumeration - abstract attack catalog' },
  { key: 'consensys-sc-best-practices', name: 'ConsenSys SC best-practices', url: 'https://github.com/Consensys/smart-contract-best-practices', type: 'github-repo', description: 'Web3 smart-contract security recommendations (vulnerabilities + design)' },
  { key: 'cwe', name: 'CWE', url: 'https://cwe.mitre.org', type: 'agentic-crawl', description: 'MITRE Common Weakness Enumeration - root-cause vulnerability taxonomy' },
  { key: 'd3fend', name: 'D3FEND', url: 'https://d3fend.mitre.org', type: 'agentic-crawl', description: 'MITRE defensive countermeasure matrix (counterpart to ATT&CK offensive)' },
  { key: 'exploitdb-mirror', name: 'ExploitDB (mirror)', url: 'https://github.com/offensive-security/exploitdb', type: 'github-repo', description: 'Public exploit archive (the searchsploit data) as raw markdown / code' },
  { key: 'frida-docs', name: 'Frida docs', url: 'https://frida.re/docs/home/', type: 'agentic-crawl', description: 'Dynamic binary instrumentation framework (mobile + desktop hooking)' },
  { key: 'gtfobins-source', name: 'GTFOBins (source)', url: 'https://github.com/GTFOBins/GTFOBins.github.io', type: 'github-repo', description: 'Linux binaries that can be abused for privesc / shell escape (YAML source)' },
  { key: 'includesecurity-blog', name: 'IncludeSecurity blog', url: 'https://blog.includesecurity.com', type: 'agentic-crawl', description: 'IncludeSecurity research - appsec, mobile, IoT, supply-chain bugs' },
  { key: 'ioactive-labs', name: 'IOActive Labs', url: 'https://labs.ioactive.com', type: 'agentic-crawl', description: 'IOActive research - automotive, ICS, hardware, mobile, cryptography' },
  { key: 'lolbas-source', name: 'LOLBAS (source)', url: 'https://github.com/LOLBAS-Project/LOLBAS', type: 'github-repo', description: 'Windows signed-binary abuse for offensive use (YAML source per binary)' },
  { key: 'netspi-blog', name: 'NetSPI blog', url: 'https://www.netspi.com/blog', type: 'agentic-crawl', description: 'NetSPI research - AD, cloud, IoT, mobile, ML pentesting writeups' },
  { key: 'nviso-labs', name: 'nViso labs', url: 'https://blog.nviso.eu', type: 'agentic-crawl', description: 'nViso research - malware analysis, RT, mobile, cloud, blue+red mix' },
  { key: 'outflank-blog', name: 'Outflank blog', url: 'https://www.outflank.nl/blog', type: 'agentic-crawl', description: 'Outflank red-team tradecraft - initial access, evasion, persistence' },
  { key: 'owasp-top-10', name: 'OWASP Top 10', url: 'https://github.com/OWASP/Top10', type: 'github-repo', description: 'OWASP Top 10 web vulns - current and prior versions, methodology' },
  { key: 'pentest-partners-blog', name: 'PenTest Partners blog', url: 'https://www.pentestpartners.com/security-blog', type: 'agentic-crawl', description: 'PTP security research - IoT, automotive, maritime, broadcast, retail' },
  { key: 'pwntools-docs', name: 'pwntools docs', url: 'https://docs.pwntools.com', type: 'sphinx-docs', description: 'Python pwntools API reference - exploit dev primitives, ROP, shellcode' },
  { key: 'quarkslab-blog', name: 'Quarkslab blog', url: 'https://blog.quarkslab.com', type: 'agentic-crawl', description: 'Quarkslab research - RE, crypto, hardware, mobile, vulnerability research' },
  { key: 'redteaming-cheatsheet-0xjs', name: 'RedTeaming_CheatSheet (0xJs)', url: 'https://github.com/0xJs/RedTeaming_CheatSheet', type: 'github-repo', description: 'Concise red-team cheatsheets - AD, lateral, persistence, evasion' },
  { key: 'rhino-security-labs', name: 'Rhino Security Labs', url: 'https://rhinosecuritylabs.com/blog', type: 'agentic-crawl', description: 'Cloud + AWS + AD pentest writeups, Pacu authors' },
  { key: 'shubs-io-shubham-shah', name: 'shubs.io (Shubham Shah)', url: 'https://shubs.io', type: 'agentic-crawl', description: 'Bug bounty deep-dives - auth bypasses, SSRF, file uploads, race conditions' },
  { key: 'sigma-rules', name: 'Sigma rules', url: 'https://github.com/SigmaHQ/sigma', type: 'github-repo', description: 'Generic detection rule format + community rule library (SIEM-portable)' },
  { key: 'star-labs-sg', name: 'Star Labs SG', url: 'https://starlabs.sg/blog', type: 'agentic-crawl', description: 'STAR Labs research - browser/kernel exploitation, n-day, supply-chain' },
  { key: 'swc-registry', name: 'SWC Registry', url: 'https://swcregistry.io', type: 'agentic-crawl', description: 'Smart Contract Weakness Classification (Web3 equivalent of CWE)' },
  { key: 'vulhub', name: 'vulhub', url: 'https://github.com/vulhub/vulhub', type: 'github-repo', description: 'Pre-built Docker images for known CVEs - practice exploitation safely' },
  { key: 'watchtowr-blog', name: 'watchTowr blog', url: 'https://blog.watchtowr.com', type: 'agentic-crawl', description: 'watchTowr Labs - n-day weaponization, surface scanning, deep technical RE' },
  { key: 'wireshark-wiki', name: 'Wireshark Wiki', url: 'https://wiki.wireshark.org', type: 'agentic-crawl', description: 'Protocol dissection notes, capture techniques, sample PCAPs per protocol' },
  { key: 'withsecure-labs', name: 'WithSecure Labs', url: 'https://labs.withsecure.com', type: 'agentic-crawl', description: 'WithSecure research - RT TTPs, malware, AD, cloud, mobile' },
  { key: 'yara-rules', name: 'YARA-Rules', url: 'https://github.com/Yara-Rules/rules', type: 'github-repo', description: 'Community-maintained YARA rule library - malware families, APT, packers' },
  { key: 'web3-attacks-crytic', name: 'Web3 Attacks (crytic)', url: 'https://github.com/crytic/not-so-smart-contracts', type: 'github-repo', description: 'Examples of vulnerable Solidity patterns (re-entrancy, oracle, governance)' },
  { key: 'owasp-api-top-10', name: 'OWASP API Top 10', url: 'https://github.com/OWASP/API-Security', type: 'github-repo', description: 'OWASP REST/GraphQL API Top 10 vulnerability catalog with examples' },
]

// Shown first in Quick Add, in this order, and never repeated in the alphabetical list.
// Checked on 15 November 2026: both websites allow crawling in their robots.txt and
// publish a sitemap; the three repositories are public, under the MIT licence.
export const FEATURED_PRESETS: readonly TradecraftPreset[] = [
  {
    key: 'web-hacking-techniques-index',
    name: 'Web Hacking Techniques Index',
    // The #evidence fragment of the published link never reaches the site and would make
    // a second address for the same page; the query selects the 2026 AI collection.
    url: 'https://webhacklist.com/?year=2026-ai',
    type: 'agentic-crawl',
    description: 'Interactive archive of the Top 10 Web Hacking Techniques research and nominations; this address opens its 2026 AI collection. Same archive as the GitHub preset',
    featured: true,
  },
  {
    key: 'web-hacking-techniques-archive-github',
    name: 'Web Hacking Techniques archive (GitHub)',
    url: 'https://github.com/irsdl/webhacklist',
    type: 'github-repo',
    description: 'Every Top 10 Web Hacking Techniques nominee since 2006, preserved (MIT). Same archive as the website preset',
    featured: true,
  },
  {
    key: 'claude-bughunter',
    name: 'Claude-BugHunter',
    url: 'https://github.com/elementalsouls/Claude-BugHunter',
    type: 'github-repo',
    description: 'Bug hunting and external red-team skill bundle: 82 skills, 681 disclosed-report patterns across 24 vulnerability classes, identity and infrastructure attack matrices (MIT)',
    featured: true,
  },
  {
    key: 'agentic-bug-hunter',
    name: 'Agentic-Bug-Hunter',
    url: 'https://github.com/awarexone/Agentic-Bug-Hunter',
    type: 'github-repo',
    description: 'AI-powered bug bounty hunting toolkit (MIT)',
    featured: true,
  },
  {
    key: 'hexbrain-payloads',
    name: 'HexBrain payloads',
    url: 'https://hexbrainai.com/payloads',
    type: 'agentic-crawl',
    description: 'Payloads, techniques and filter bypasses for 64 vulnerability topics (1,123 passages), drawn from PayloadsAllTheThings',
    featured: true,
  },
]

export const ALPHABETICAL_PRESETS: readonly TradecraftPreset[] = [...TRADECRAFT_PRESETS].sort(
  (a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
)

/** Every preset, in Quick Add order: the Featured group, then the alphabetical list. */
export const ALL_PRESETS: readonly TradecraftPreset[] = [...FEATURED_PRESETS, ...ALPHABETICAL_PRESETS]

export function presetByKey(key: string): TradecraftPreset | undefined {
  return ALL_PRESETS.find(p => p.key === key)
}

/**
 * A type is forced only where the address proves it: a github.com repository is a repository and a
 * CVE archive is one; the Featured websites are the ones §6.12 names. Every other chip stays a
 * hint, because a wrong forced type fails the add where detection would fall back to a crawl.
 */
const FORCED_BY_CHIP: Readonly<Record<string, SiteType>> = { 'github-repo': 'github-repo', 'cve-poc-db': 'cve-poc-db' }

const add = (items: string[]) => ({ mode: 'add' as const, items })

const SETTINGS_BY_KEY: Readonly<Record<string, PresetSettings>> = {
  // §6.12: the rule files of these repositories are YAML or YARA, not Markdown.
  'lolbas-source': { overrides: { 'knownTypes.githubFileTypes': add(['.yml']) } },
  'sigma-rules': { overrides: { 'knownTypes.githubFileTypes': add(['.yml']) } },
  'yara-rules': { overrides: { 'knownTypes.githubFileTypes': add(['.yar']) } },
  // A very large repository, better narrowed by folder (§6.5).
  'exploitdb-mirror': { overrides: { 'type.github.includeFolders': ['exploits/'] }, unverified: ['type.github.includeFolders'] },
  // The CVE archives: their file layout. trickest/cve is the layout 1.x was written for.
  'trickest-cve': { overrides: { 'type.cve.pathPatterns': ['{year}/{cve}.md'] }, unverified: ['type.cve.pathPatterns'] },
  'nomi-sec-poc-in-github': { overrides: { 'type.cve.pathPatterns': ['{year}/{cve}.json'] }, unverified: ['type.cve.pathPatterns'] },
  '0xmarcio-cve': { overrides: { 'type.cve.pathPatterns': ['{year}/{cve}.md', '{year}/{cve}/README.md'] }, unverified: ['type.cve.pathPatterns'] },
  // Versioned Read the Docs sites keep their search index under the version's folder.
  'scapy-docs': { overrides: { 'type.docs.searchIndexUrl': 'https://scapy.readthedocs.io/en/latest/searchindex.js' }, unverified: ['type.docs.searchIndexUrl'] },
  'volatility-3': { overrides: { 'type.docs.searchIndexUrl': 'https://volatility3.readthedocs.io/en/latest/searchindex.js' }, unverified: ['type.docs.searchIndexUrl'] },
  // Featured websites (§6.12 "Settings it carries"): their sitemap, which the Auto strategy reads
  // (robots.txt's Sitemap: line included); HexBrain stays inside /payloads.
  'web-hacking-techniques-index': { forcedType: 'agentic-crawl', overrides: { 'crawl.strategy': 'auto' } },
  'hexbrain-payloads': {
    forcedType: 'agentic-crawl',
    overrides: { 'crawl.strategy': 'auto', 'crawl.includePaths': add(['/payloads/*']), 'crawl.stayInFolder': true },
  },
}

/** The fields the form fills when a person picks the preset. */
export function presetSettings(preset: TradecraftPreset): PresetSettings {
  const own = SETTINGS_BY_KEY[preset.key] ?? {}
  const forcedType = own.forcedType ?? FORCED_BY_CHIP[preset.type]
  return {
    ...(forcedType ? { forcedType } : {}),
    ...(own.overrides ? { overrides: structuredClone(own.overrides) } : {}),
    ...(own.unverified ? { unverified: [...own.unverified] } : {}),
  }
}

/** The keys of the presets that carry settings of their own, beyond a forced type. */
export function presetsWithSettings(): string[] {
  return Object.keys(SETTINGS_BY_KEY)
}
