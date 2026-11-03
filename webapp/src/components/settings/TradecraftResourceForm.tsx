'use client'

import { useState, useEffect, useMemo } from 'react'
import { Loader2, Eye, EyeOff, Search } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './Settings.module.css'

export interface TradecraftResource {
  id?: string
  name: string
  slug?: string
  url: string
  enabled?: boolean
  resourceType?: string
  summary?: string
  githubTokenOverride?: string
  cacheTtlSec?: number
  llmModel?: string
  lastVerifiedAt?: string | null
  lastRefreshedAt?: string | null
  lastError?: string
}

interface QuickAdd {
  name: string
  url: string
  type: string
  description: string
}

// Curated list of 100 popular, well-maintained, openly-licensed (or
// explicitly-public) security knowledge resources, sorted alphabetically
// by name. Hand-picked to:
//  - Spread across all 6 types so users see how the catalog mixes them
//  - Avoid sites with anti-scraping ToS, login walls, or paywalls
//  - Prefer canonical / authoritative references actively maintained
//
// Type is shown as a chip but the backend always re-detects on add - the
// chip here is just a hint for the user.
const QUICK_ADD_PRESETS_RAW: QuickAdd[] = [
  // === MkDocs-wiki / mdBook ===
  { name: 'HackTricks', url: 'https://book.hacktricks.wiki', type: 'mkdocs-wiki', description: 'Comprehensive offensive security wiki (web, AD, cloud, privesc, mobile)' },
  { name: 'The Hacker Recipes', url: 'https://www.thehacker.recipes', type: 'mkdocs-wiki', description: 'Pentest methodology by ShutdownRepo - AD, web, infra, exploit-dev' },
  { name: 'CTF Field Guide', url: 'https://trailofbits.github.io/ctf/', type: 'mkdocs-wiki', description: 'Trail of Bits CTF guide - vulns, RE, forensics, web, exploits' },
  { name: 'CTF101', url: 'https://ctf101.org', type: 'mkdocs-wiki', description: 'Beginner CTF reference - crypto, forensics, RE, web, binex categories' },

  // === GitBook ===
  { name: 'Practical CTF (Jorian Woltjer)', url: 'https://book.jorianwoltjer.com', type: 'gitbook', description: 'CTF + hacking technique notes (web, AD, crypto, binex, mobile)' },
  { name: 'ired.team', url: 'https://www.ired.team', type: 'gitbook', description: 'Red team / offensive security notes - AD, evasion, persistence' },

  // === GitHub repos (markdown-based knowledge bases) ===
  { name: 'PayloadsAllTheThings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', type: 'github-repo', description: 'Payload library + bypass cheatsheets organized per vulnerability class' },
  { name: 'InternalAllTheThings', url: 'https://github.com/swisskyrepo/InternalAllTheThings', type: 'github-repo', description: 'Active Directory + post-exploitation cheatsheets (sister of PATT)' },
  { name: 'HardwareAllTheThings', url: 'https://github.com/swisskyrepo/HardwareAllTheThings', type: 'github-repo', description: 'Hardware/IoT pentest references - UART, JTAG, BLE, Zigbee' },
  { name: 'h4cker (Omar Santos)', url: 'https://github.com/The-Art-of-Hacking/h4cker', type: 'github-repo', description: 'Curated hacking resources (>10k references), per-topic folders' },
  { name: 'PEASS-ng', url: 'https://github.com/peass-ng/PEASS-ng', type: 'github-repo', description: 'WinPEAS / LinPEAS / MacPEAS privilege-escalation script suite' },
  { name: 'SecLists', url: 'https://github.com/danielmiessler/SecLists', type: 'github-repo', description: 'Wordlists for usernames, passwords, URLs, fuzzing payloads' },
  { name: 'awesome-pentest', url: 'https://github.com/enaqx/awesome-pentest', type: 'github-repo', description: 'Curated meta-list of pentest tools, books, conferences, OS distros' },
  { name: 'awesome-bug-bounty', url: 'https://github.com/djadmin/awesome-bug-bounty', type: 'github-repo', description: 'Bug-bounty curated list - programs, writeups, tools' },
  { name: 'awesome-cloud-security', url: 'https://github.com/4ARMED/awesome-cloud-security', type: 'github-repo', description: 'AWS / GCP / Azure cloud security tooling and writeups' },
  { name: 'awesome-web-hacking', url: 'https://github.com/infoslack/awesome-web-hacking', type: 'github-repo', description: 'Web pentest tools, books, papers, vulnerable apps' },
  { name: 'awesome-android-security', url: 'https://github.com/saeidshirazi/awesome-android-security', type: 'github-repo', description: 'Android security learning path - tools, papers, exploits' },
  { name: 'xairy/linux-kernel-exploitation', url: 'https://github.com/xairy/linux-kernel-exploitation', type: 'github-repo', description: 'Curated Linux kernel exploitation resources, papers, writeups' },
  { name: 'Privilege-Escalation', url: 'https://github.com/Ignitetechnologies/Privilege-Escalation', type: 'github-repo', description: 'Linux + Windows privesc cheatsheets and lab walkthroughs' },
  { name: 'API-Security-Checklist', url: 'https://github.com/shieldfy/API-Security-Checklist', type: 'github-repo', description: 'Best-practices checklist for designing/testing secure REST APIs' },
  { name: 'ctf-tools', url: 'https://github.com/zardus/ctf-tools', type: 'github-repo', description: 'CTF tool installer collection - pwn, RE, forensics, crypto, web' },
  { name: 'OWASP CheatSheets', url: 'https://github.com/OWASP/CheatSheetSeries', type: 'github-repo', description: 'Concise OWASP cheatsheets per topic (XSS, CSRF, auth, JWT, ...)' },
  { name: 'OWASP WSTG', url: 'https://github.com/OWASP/wstg', type: 'github-repo', description: 'OWASP Web Security Testing Guide - methodology source markdown' },
  { name: 'OWASP MASTG', url: 'https://github.com/OWASP/owasp-mastg', type: 'github-repo', description: 'OWASP Mobile Application Security Testing Guide (iOS + Android)' },
  { name: 'cheat.sh', url: 'https://github.com/chubin/cheat.sh', type: 'github-repo', description: 'Unified CLI cheatsheets (`curl cheat.sh/<cmd>`), security tools incl.' },
  { name: 'awesome-iot-hacks', url: 'https://github.com/nebgnahz/awesome-iot-hacks', type: 'github-repo', description: 'IoT security resources - papers, talks, vulnerable hardware' },
  { name: 'awesome-malware-analysis', url: 'https://github.com/rshipp/awesome-malware-analysis', type: 'github-repo', description: 'Reverse engineering, sandboxing, YARA, packers, behavior analysis' },
  { name: 'awesome-ctf', url: 'https://github.com/apsdehal/awesome-ctf', type: 'github-repo', description: 'CTF tools and resources catalog - wargames, RE, web, forensics' },
  { name: 'awesome-osint', url: 'https://github.com/jivoi/awesome-osint', type: 'github-repo', description: 'OSINT investigation tools and frameworks (people, infra, geo)' },
  { name: 'awesome-shodan-queries', url: 'https://github.com/jakejarvis/awesome-shodan-queries', type: 'github-repo', description: 'Curated Shodan dorks for finding exposed services and devices' },
  { name: 'awesome-windows-domain-hardening', url: 'https://github.com/PaulSec/awesome-windows-domain-hardening', type: 'github-repo', description: 'Active Directory hardening references and offensive playbooks' },
  { name: 'awesome-redteam', url: 'https://github.com/yeyintminthuhtut/Awesome-Red-Teaming', type: 'github-repo', description: 'Red team operator resources - initial access, recon, persistence' },
  { name: 'awesome-fuzzing', url: 'https://github.com/cpuu/awesome-fuzzing', type: 'github-repo', description: 'Fuzzing harnesses, frameworks, papers, tutorials' },

  // === CVE PoC databases ===
  { name: 'trickest/cve', url: 'https://github.com/trickest/cve', type: 'cve-poc-db', description: 'Auto-aggregated CVE → public PoC index. Use cve_id="CVE-YYYY-NNNNN"' },
  { name: '0xMarcio/cve', url: 'https://github.com/0xMarcio/cve', type: 'cve-poc-db', description: 'Alternative CVE → PoC index with extended metadata' },
  { name: 'nomi-sec/PoC-in-GitHub', url: 'https://github.com/nomi-sec/PoC-in-GitHub', type: 'cve-poc-db', description: 'Daily-updated CVE PoC index scraped from GitHub repos' },

  // === Sphinx / ReadTheDocs ===
  { name: 'Scapy docs', url: 'https://scapy.readthedocs.io/en/latest/', type: 'sphinx-docs', description: 'Python packet crafting library - protocols, fuzzing, scapy.layers' },
  { name: 'Volatility 3', url: 'https://volatility3.readthedocs.io/en/latest/', type: 'sphinx-docs', description: 'Memory forensics framework - plugins, OS profiles, Vol3 API' },
  { name: 'Mitmproxy docs', url: 'https://docs.mitmproxy.org/stable/', type: 'sphinx-docs', description: 'TLS-MITM proxy - addons, scripting, intercept replay' },
  { name: 'Sliver C2', url: 'https://sliver.sh/docs', type: 'sphinx-docs', description: 'Open-source C2 framework documentation (BishopFox)' },

  // === Agentic-crawl: real security blogs (no published sitemap) ===
  { name: '0xpatrik (Patrik Hudak)', url: 'https://0xpatrik.com', type: 'agentic-crawl', description: 'Subdomain takeovers, OSINT, recon automation, asset discovery' },
  { name: 'Synacktiv publications', url: 'https://www.synacktiv.com/en/publications.html', type: 'agentic-crawl', description: 'French pentest firm writeups - AD, cloud, mobile, exploit-dev' },
  { name: 'Doyensec research', url: 'https://blog.doyensec.com', type: 'agentic-crawl', description: 'Boutique appsec research - Electron, Java, GraphQL, Solidity' },
  { name: 'SpecterOps', url: 'https://posts.specterops.io', type: 'agentic-crawl', description: 'Red team / Active Directory deep dives (BloodHound team)' },
  { name: 'Project Zero', url: 'https://googleprojectzero.blogspot.com', type: 'agentic-crawl', description: 'Google P0 vuln research - kernel, browser, mobile 0-days' },
  { name: 'Spaceraccoon (Eugene Lim)', url: 'https://spaceraccoon.dev', type: 'agentic-crawl', description: 'Web/cloud/IoT writeups, supply-chain attacks, bug bounty postmortems' },
  { name: 'Adsecurity (Sean Metcalf)', url: 'https://adsecurity.org', type: 'agentic-crawl', description: 'Active Directory attack/defense - Kerberos, ADCS, replication abuse' },
  { name: 'Trail of Bits blog', url: 'https://blog.trailofbits.com', type: 'agentic-crawl', description: 'Cryptography, smart contracts, fuzzing, OS-level security research' },
  { name: 'Tarlogic blog', url: 'https://www.tarlogic.com/blog', type: 'agentic-crawl', description: 'Spanish pentest firm - Kerberos, AD, RT TTPs, threat intel' },
  { name: 'Assetnote research', url: 'https://blog.assetnote.io', type: 'agentic-crawl', description: 'Attack-surface management research and 0-days in enterprise software' },

  // === ADDITIONAL 50 (deep-researched, mostly unique niches) ===
  // 0xdf's Hugo-static blog - full HackTheBox writeups, very high signal
  { name: '0xdf HTB writeups', url: 'https://0xdf.gitlab.io', type: 'agentic-crawl', description: 'HackTheBox machine writeups - exploitation chains, AD, web, binex' },
  // Atomic Red Team - execute MITRE ATT&CK techniques as test scripts
  { name: 'atomic-red-team', url: 'https://github.com/redcanaryco/atomic-red-team', type: 'github-repo', description: 'Red Canary library: MITRE ATT&CK technique simulations as runnable tests' },
  // MITRE ATT&CK matrix - taxonomy for adversary TTPs
  { name: 'ATT&CK matrix', url: 'https://attack.mitre.org', type: 'agentic-crawl', description: 'MITRE adversary tactics + techniques + procedures (TTP) reference' },
  // Orange Cyberdefense AD list - separate from red-team broadly
  { name: 'awesome-active-directory', url: 'https://github.com/Orange-Cyberdefense/awesome-activedirectory', type: 'github-repo', description: 'Active Directory attack/defense - Kerberos, ADCS, ACL, GPO, lateral mvmt' },
  // Asset / attack-surface discovery
  { name: 'awesome-asset-discovery', url: 'https://github.com/redhuntlabs/Awesome-Asset-Discovery', type: 'github-repo', description: 'Asset discovery / attack-surface mapping tools and methodologies' },
  { name: 'awesome-bluetooth-security', url: 'https://github.com/engn33r/awesome-bluetooth-security', type: 'github-repo', description: 'BLE/Bluetooth Classic attack research, sniffing, fuzzing, papers' },
  { name: 'awesome-burp-extensions', url: 'https://github.com/snoopysecurity/awesome-burp-extensions', type: 'github-repo', description: 'Curated Burp Suite extension catalog by category (auth, recon, fuzzing)' },
  { name: 'awesome-exploit-development', url: 'https://github.com/FabioBaroni/awesome-exploit-development', type: 'github-repo', description: 'Userland + kernel exploit-dev resources, papers, tutorials, tools' },
  // Search-engine catalog (Shodan/Censys/Fofa/etc.)
  { name: 'awesome-hacker-search-engines', url: 'https://github.com/edoardottt/awesome-hacker-search-engines', type: 'github-repo', description: 'Recon-oriented search engines - Shodan, Censys, Fofa, ZoomEye, etc.' },
  // Hack-with-Github mega meta list
  { name: 'awesome-hacking (meta)', url: 'https://github.com/Hack-with-Github/Awesome-Hacking', type: 'github-repo', description: 'Meta-list pointing at every other awesome-* security list (single-hop index)' },
  { name: 'awesome-honeypots', url: 'https://github.com/paralax/awesome-honeypots', type: 'github-repo', description: 'Honeypot deployments, frameworks, deception tools, defensive use' },
  { name: 'awesome-incident-response', url: 'https://github.com/meirwah/awesome-incident-response', type: 'github-repo', description: 'DFIR tooling - triage, memory, disk, timeline, threat hunting' },
  { name: 'awesome-mobile-security', url: 'https://github.com/vaib25vicky/awesome-mobile-security', type: 'github-repo', description: 'iOS + Android offensive - Frida, Jadx, MOBSF, root-detection bypasses' },
  // PCAP / network forensics tooling
  { name: 'awesome-pcaptools', url: 'https://github.com/caesar0301/awesome-pcaptools', type: 'github-repo', description: 'PCAP capture, analysis, and protocol-dissection tooling' },
  { name: 'awesome-sec-talks', url: 'https://github.com/PaulSec/awesome-sec-talks', type: 'github-repo', description: 'Conference talks library (DEFCON, BlackHat, BSides, OffensiveCon, ...)' },
  { name: 'awesome-vehicle-security', url: 'https://github.com/jaredthecoder/awesome-vehicle-security', type: 'github-repo', description: 'Automotive security - CAN-bus, OBD-II, telematics, V2X' },
  { name: 'awesome-windows-pentest', url: 'https://github.com/zer1t0/awesome-windows-pentest', type: 'github-repo', description: 'Windows-focused offensive - privesc, lateral movement, evasion' },
  { name: 'awesome-yara', url: 'https://github.com/InQuest/awesome-yara', type: 'github-repo', description: 'YARA rule collections, tools, tutorials, malware-classification rules' },
  // Bishop Fox - real research blog (rarely scraped)
  { name: 'Bishop Fox blog', url: 'https://bishopfox.com/blog', type: 'agentic-crawl', description: 'Bishop Fox security research - appsec, cloud, recon, vulnerabilities' },
  // Web3 - Trail of Bits' canonical Solidity security guide
  { name: 'building-secure-contracts (crytic)', url: 'https://github.com/crytic/building-secure-contracts', type: 'github-repo', description: 'Solidity / EVM smart-contract security knowledge base by Trail of Bits' },
  // CAPEC - attack pattern taxonomy
  { name: 'CAPEC', url: 'https://capec.mitre.org', type: 'agentic-crawl', description: 'MITRE Common Attack Pattern Enumeration - abstract attack catalog' },
  // ConsenSys Solidity best practices
  { name: 'ConsenSys SC best-practices', url: 'https://github.com/Consensys/smart-contract-best-practices', type: 'github-repo', description: 'Web3 smart-contract security recommendations (vulnerabilities + design)' },
  // CWE - weakness taxonomy
  { name: 'CWE', url: 'https://cwe.mitre.org', type: 'agentic-crawl', description: 'MITRE Common Weakness Enumeration - root-cause vulnerability taxonomy' },
  // D3FEND - defensive technique matrix (counterpart to ATT&CK)
  { name: 'D3FEND', url: 'https://d3fend.mitre.org', type: 'agentic-crawl', description: 'MITRE defensive countermeasure matrix (counterpart to ATT&CK offensive)' },
  // ExploitDB GitHub mirror - works without searchsploit binary
  { name: 'ExploitDB (mirror)', url: 'https://github.com/offensive-security/exploitdb', type: 'github-repo', description: 'Public exploit archive (the searchsploit data) as raw markdown / code' },
  // Frida instrumentation toolkit
  { name: 'Frida docs', url: 'https://frida.re/docs/home/', type: 'agentic-crawl', description: 'Dynamic binary instrumentation framework (mobile + desktop hooking)' },
  // GTFOBins - Linux SUID/sudo abuse
  { name: 'GTFOBins (source)', url: 'https://github.com/GTFOBins/GTFOBins.github.io', type: 'github-repo', description: 'Linux binaries that can be abused for privesc / shell escape (YAML source)' },
  // IncludeSecurity blog
  { name: 'IncludeSecurity blog', url: 'https://blog.includesecurity.com', type: 'agentic-crawl', description: 'IncludeSecurity research - appsec, mobile, IoT, supply-chain bugs' },
  // IOActive Labs research
  { name: 'IOActive Labs', url: 'https://labs.ioactive.com', type: 'agentic-crawl', description: 'IOActive research - automotive, ICS, hardware, mobile, cryptography' },
  // LOLBAS - Living Off the Land Binaries (Windows)
  { name: 'LOLBAS (source)', url: 'https://github.com/LOLBAS-Project/LOLBAS', type: 'github-repo', description: 'Windows signed-binary abuse for offensive use (YAML source per binary)' },
  // NetSPI blog - pentest writeups
  { name: 'NetSPI blog', url: 'https://www.netspi.com/blog', type: 'agentic-crawl', description: 'NetSPI research - AD, cloud, IoT, mobile, ML pentesting writeups' },
  // nViso labs - European security research
  { name: 'nViso labs', url: 'https://blog.nviso.eu', type: 'agentic-crawl', description: 'nViso research - malware analysis, RT, mobile, cloud, blue+red mix' },
  // Outflank - established Dutch red team
  { name: 'Outflank blog', url: 'https://www.outflank.nl/blog', type: 'agentic-crawl', description: 'Outflank red-team tradecraft - initial access, evasion, persistence' },
  // OWASP Top 10 source
  { name: 'OWASP Top 10', url: 'https://github.com/OWASP/Top10', type: 'github-repo', description: 'OWASP Top 10 web vulns - current and prior versions, methodology' },
  // PenTest Partners blog
  { name: 'PenTest Partners blog', url: 'https://www.pentestpartners.com/security-blog', type: 'agentic-crawl', description: 'PTP security research - IoT, automotive, maritime, broadcast, retail' },
  // pwntools - exploit dev framework
  { name: 'pwntools docs', url: 'https://docs.pwntools.com', type: 'sphinx-docs', description: 'Python pwntools API reference - exploit dev primitives, ROP, shellcode' },
  // Quarkslab - French firm, deep RE
  { name: 'Quarkslab blog', url: 'https://blog.quarkslab.com', type: 'agentic-crawl', description: 'Quarkslab research - RE, crypto, hardware, mobile, vulnerability research' },
  // 0xJs RT cheatsheet
  { name: 'RedTeaming_CheatSheet (0xJs)', url: 'https://github.com/0xJs/RedTeaming_CheatSheet', type: 'github-repo', description: 'Concise red-team cheatsheets - AD, lateral, persistence, evasion' },
  // Rhino Security Labs
  { name: 'Rhino Security Labs', url: 'https://rhinosecuritylabs.com/blog', type: 'agentic-crawl', description: 'Cloud + AWS + AD pentest writeups, Pacu authors' },
  // Shubham Shah personal blog
  { name: 'shubs.io (Shubham Shah)', url: 'https://shubs.io', type: 'agentic-crawl', description: 'Bug bounty deep-dives - auth bypasses, SSRF, file uploads, race conditions' },
  // Sigma - open detection rule format
  { name: 'Sigma rules', url: 'https://github.com/SigmaHQ/sigma', type: 'github-repo', description: 'Generic detection rule format + community rule library (SIEM-portable)' },
  // Star Labs Singapore
  { name: 'Star Labs SG', url: 'https://starlabs.sg/blog', type: 'agentic-crawl', description: 'STAR Labs research - browser/kernel exploitation, n-day, supply-chain' },
  // SWC Registry - smart contract weaknesses
  { name: 'SWC Registry', url: 'https://swcregistry.io', type: 'agentic-crawl', description: 'Smart Contract Weakness Classification (Web3 equivalent of CWE)' },
  // Vulhub - vulnerable docker labs
  { name: 'vulhub', url: 'https://github.com/vulhub/vulhub', type: 'github-repo', description: 'Pre-built Docker images for known CVEs - practice exploitation safely' },
  // watchTowr labs - n-day weaponization
  { name: 'watchTowr blog', url: 'https://blog.watchtowr.com', type: 'agentic-crawl', description: 'watchTowr Labs - n-day weaponization, surface scanning, deep technical RE' },
  // Wireshark wiki - protocol dissection knowledge
  { name: 'Wireshark Wiki', url: 'https://wiki.wireshark.org', type: 'agentic-crawl', description: 'Protocol dissection notes, capture techniques, sample PCAPs per protocol' },
  // WithSecure (former F-Secure) labs
  { name: 'WithSecure Labs', url: 'https://labs.withsecure.com', type: 'agentic-crawl', description: 'WithSecure research - RT TTPs, malware, AD, cloud, mobile' },
  // YARA-Rules curated repo
  { name: 'YARA-Rules', url: 'https://github.com/Yara-Rules/rules', type: 'github-repo', description: 'Community-maintained YARA rule library - malware families, APT, packers' },
  // Trail of Bits' canonical Web3 attack-pattern catalog
  { name: 'Web3 Attacks (crytic)', url: 'https://github.com/crytic/not-so-smart-contracts', type: 'github-repo', description: 'Examples of vulnerable Solidity patterns (re-entrancy, oracle, governance)' },
  // OWASP API Security Top 10
  { name: 'OWASP API Top 10', url: 'https://github.com/OWASP/API-Security', type: 'github-repo', description: 'OWASP REST/GraphQL API Top 10 vulnerability catalog with examples' },
]

// Sorted alphabetically by name (case-insensitive). The original array
// preserves the curation grouping in source for code readers; the sorted
// copy is what the UI renders.
const QUICK_ADD_PRESETS: QuickAdd[] = [...QUICK_ADD_PRESETS_RAW].sort(
  (a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase())
)

const SECTION_PICKER_PROMPT =
  'Optional. This model picks which page of a long resource the agent reads; without one, '
  + 'pages are picked by text match. Cancel saves the resource either way.'

// Asked at most once per page load: the section picker is optional, and a
// person who declined it should not be asked again on every save.
let sectionPickerDeclined = false

export function TradecraftResourceForm({
  userId,
  resource,
  onSave,
  onCancel,
  onDirtyChange,
}: {
  userId: string
  resource: TradecraftResource | null
  onSave: () => void
  onCancel: () => void
  /** Reports unsaved-changes state to the parent (drives the tab-switch guard). */
  onDirtyChange?: (dirty: boolean) => void
}) {
  const isEdit = !!resource?.id
  const [name, setName] = useState(resource?.name || '')
  const [url, setUrl] = useState(resource?.url || '')
  const [githubToken, setGithubToken] = useState(resource?.githubTokenOverride || '')
  const [cacheTtl, setCacheTtl] = useState<number>(resource?.cacheTtlSec ?? 0)
  const [enabled, setEnabled] = useState(resource?.enabled ?? true)
  const [llmModel, setLlmModel] = useState(resource?.llmModel || '')
  const [showToken, setShowToken] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [presetSearch, setPresetSearch] = useState('')
  const { ensureFeatureModel } = useFeatureModelGate()

  // Dirty tracking over the editable fields. Baseline captured from `resource`
  // in the reset effect below (empty for add, resource values for edit).
  const currentValues = useMemo(
    () => ({ name, url, githubToken, cacheTtl, enabled, llmModel }),
    [name, url, githubToken, cacheTtl, enabled, llmModel],
  )
  const { isDirty, setBaseline } = useDirtyState(currentValues)
  // Local-only: the parent /settings page owns the global sidebar/beforeunload
  // guard via onDirtyChange (avoids a duplicate confirm).
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const filteredPresets = useMemo(() => {
    const q = presetSearch.trim().toLowerCase()
    if (!q) return QUICK_ADD_PRESETS
    return QUICK_ADD_PRESETS.filter(p =>
      p.name.toLowerCase().includes(q)
      || p.description.toLowerCase().includes(q)
      || p.type.toLowerCase().includes(q)
    )
  }, [presetSearch])

  useEffect(() => {
    const next = {
      name: resource?.name || '',
      url: resource?.url || '',
      githubToken: resource?.githubTokenOverride || '',
      cacheTtl: resource?.cacheTtlSec ?? 0,
      enabled: resource?.enabled ?? true,
      llmModel: resource?.llmModel || '',
    }
    setName(next.name)
    setUrl(next.url)
    setGithubToken(next.githubToken)
    setCacheTtl(next.cacheTtl)
    setEnabled(next.enabled)
    setLlmModel(next.llmModel)
    // Adopt these loaded values as the dirty baseline (add = empty, edit = resource).
    setBaseline(next)
  }, [resource, setBaseline])

  const handleQuickAdd = (preset: QuickAdd) => {
    setName(preset.name)
    setUrl(preset.url)
  }

  const submit = async () => {
    if (!name.trim() || !url.trim()) {
      setError('Name and URL are required')
      return
    }
    if (!llmModel.trim()) {
      setError('Pick an LLM model. The resource only becomes usable once a model is selected.')
      return
    }
    // The section picker is the user's own model, separate from this
    // resource's. Its answer does not gate the save.
    if (!sectionPickerDeclined) {
      const picked = await ensureFeatureModel('tradecraft_section_picker', { message: SECTION_PICKER_PROMPT })
      if (!picked) sectionPickerDeclined = true
    }
    setSubmitting(true)
    setError('')
    try {
      const body: Record<string, unknown> = {
        name: name.trim(),
        url: url.trim(),
        enabled,
        cacheTtlSec: Number(cacheTtl) || 0,
        llmModel: llmModel.trim(),
      }
      // Type is always auto-detected at verify time; no manual override.
      // Only send the token override when the user typed something real
      // (not the masked placeholder, not empty for an existing resource).
      if (githubToken && !githubToken.startsWith('••••')) {
        body.githubTokenOverride = githubToken
      }
      const path = isEdit
        ? `/api/users/${userId}/tradecraft-resources/${resource!.id}`
        : `/api/users/${userId}/tradecraft-resources`
      const method = isEdit ? 'PUT' : 'POST'
      const resp = await fetch(path, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!resp.ok) throw await readApiError(resp, isEdit ? 'Failed to update the resource' : 'Failed to add the resource')
      setBaseline(currentValues)
      onSave()
    } catch (e: unknown) {
      setError(toApiError(e, isEdit ? 'Failed to update the resource' : 'Failed to add the resource').message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal
      isOpen={true}
      onClose={() => guardedNavigate(onCancel)}
      title={isEdit ? 'Edit Tradecraft Resource' : 'Add Tradecraft Resource'}
      size="default"
      closeOnOverlayClick={false}
      closeOnEscape={true}
    >
      {/*
        Wrapping in a real <form> so submit-on-Enter works and so we can lock
        autoComplete off at the form level. The dummy hidden username
        + readonly password trick blocks Chrome / 1Password from
        offering site-credentials in the GitHub Token field - without it,
        the password manager treats this form as a login page and pollutes
        the token field with a saved password from an unrelated site.
      */}
      <form
        onSubmit={(e) => { e.preventDefault(); submit() }}
        autoComplete="off"
        style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
      >
        <input type="text" name="username" autoComplete="username"
               style={{ display: 'none' }} aria-hidden="true" tabIndex={-1} readOnly />
        <input type="password" name="password" autoComplete="new-password"
               style={{ display: 'none' }} aria-hidden="true" tabIndex={-1} readOnly />

        {!isEdit && (
          <div className="formGroup">
            <label className="formLabel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>
                Quick Add  <span style={{ fontWeight: 400, color: 'var(--text-secondary)', fontSize: '11px' }}>
                  · {filteredPresets.length} of {QUICK_ADD_PRESETS.length} resources
                </span>
              </span>
            </label>
            <div style={{ position: 'relative', marginBottom: '6px' }}>
              <Search
                size={12}
                style={{
                  position: 'absolute', left: '8px', top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-secondary)',
                  pointerEvents: 'none',
                }}
              />
              <input
                type="text"
                className="textInput"
                value={presetSearch}
                onChange={e => setPresetSearch(e.target.value)}
                placeholder="search by name, type (e.g. mkdocs-wiki), or description keyword"
                autoComplete="off"
                spellCheck={false}
                style={{ paddingLeft: '26px', fontSize: '12px' }}
                onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setPresetSearch('') } }}
              />
            </div>
            <div
              role="listbox"
              aria-label="Curated tradecraft resources"
              style={{
                maxHeight: '280px',
                overflowY: 'auto',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '4px',
                background: 'var(--bg-secondary, transparent)',
              }}
            >
              {filteredPresets.length === 0 && (
                <div style={{ padding: '12px', fontSize: '12px', color: 'var(--text-secondary)', textAlign: 'center' }}>
                  No resources match &quot;{presetSearch}&quot;
                </div>
              )}
              {filteredPresets.map(p => (
                <div
                  key={p.name}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '160px 100px 1fr',
                    gap: '8px',
                    alignItems: 'center',
                    padding: '6px 8px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                  onClick={() => handleQuickAdd(p)}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover, rgba(0,0,0,0.04))')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <button
                    type="button"
                    className="secondaryButton"
                    style={{
                      padding: '4px 8px',
                      fontSize: '12px',
                      width: '100%',
                      textAlign: 'left',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                    onClick={(e) => { e.stopPropagation(); handleQuickAdd(p) }}
                    title={`Add ${p.name} (${p.url})`}
                  >
                    {p.name}
                  </button>
                  <span style={{
                    fontSize: '10px',
                    color: 'var(--text-secondary)',
                    padding: '2px 6px',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    textAlign: 'center',
                    fontFamily: 'monospace',
                    whiteSpace: 'nowrap',
                  }}>
                    {p.type}
                  </span>
                  <span style={{
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }} title={p.description}>
                    {p.description}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="formGroup">
          <label className="formLabel formLabelRequired">Name</label>
          <input
            className="textInput"
            name="tc-resource-name"
            autoComplete="off"
            data-1p-ignore="true"
            data-lpignore="true"
            spellCheck={false}
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="HackTricks"
          />
        </div>

        <div className="formGroup">
          <label className="formLabel formLabelRequired">URL</label>
          <input
            className="textInput"
            type="url"
            name="tc-resource-url"
            autoComplete="off"
            data-1p-ignore="true"
            data-lpignore="true"
            spellCheck={false}
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://book.hacktricks.wiki"
          />
        </div>

        <div className="formGroup">
          <label className="formLabel">GitHub Token Override (optional)</label>
          <div className={styles.secretInputWrapper}>
            <input
              className="textInput"
              type={showToken ? 'text' : 'password'}
              name="tc-resource-gh-token"
              autoComplete="new-password"
              data-1p-ignore="true"
              data-lpignore="true"
              spellCheck={false}
              value={githubToken}
              onChange={e => setGithubToken(e.target.value)}
              placeholder="leave blank to use the user-level GitHub token"
            />
            <button
              type="button"
              className={styles.secretToggle}
              onClick={() => setShowToken(s => !s)}
              tabIndex={-1}
              aria-label="toggle visibility"
            >
              {showToken ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </div>

        <div className="formGroup">
          <label className="formLabel">Cache TTL seconds (0 = type default)</label>
          <input
            className="textInput"
            type="number"
            name="tc-resource-cache-ttl"
            autoComplete="off"
            min={0}
            value={cacheTtl}
            onChange={e => setCacheTtl(Number(e.target.value))}
          />
        </div>

        <div className="formGroup">
          <label className="formLabel formLabelRequired">LLM Model</label>
          <ModelPicker
            userId={userId}
            value={llmModel}
            onChange={setLlmModel}
            placeholder="pick the model used to crawl + summarize this resource"
            filter={excludeLoop}
          />
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block', marginTop: '4px' }}>
            Required. Used at verify time (crawl decisions + summary) and at agent runtime. The
            resource is unusable until a model is selected. Pick a small/cheap model - this task
            doesn&apos;t need your main reasoning model.
          </span>
        </div>

        <label className={styles.checkboxLabel}>
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
          <span>Enabled (the agent only sees enabled resources)</span>
        </label>

        {error && <div className={styles.testError}>{error}</div>}

        <div className={styles.formActions}>
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)} disabled={submitting}>
            Cancel
          </button>
          <button type="submit" className="primaryButton" disabled={submitting || !isDirty}>
            {submitting && <Loader2 size={14} className={styles.spin} />}
            {isEdit ? 'Save changes' : 'Add Resource'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
