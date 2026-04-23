'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Play, Loader2, ArrowRight, Upload, FileText, Trash2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import type { GraphInputs, PartialReconParams, UserTargets } from '@/lib/recon-types'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from '../nodeMapping'
import { WORKFLOW_TOOLS } from './workflowDefinition'

interface PartialReconModalProps {
  isOpen: boolean
  toolId: string | null
  onClose: () => void
  onConfirm: (params: PartialReconParams) => void
  projectId?: string
  targetDomain?: string
  subdomainPrefixes?: string[]
  isStarting?: boolean
  userId?: string
}

// --- API key requirements per tool ---
// Each entry maps a tool ID to the API keys it benefits from.
// `key`: the camelCase field name from /api/users/:id/settings
// `label`: human-readable name shown in the warning
// `impact`: what happens without it
interface ApiKeyReq { key: string; label: string; impact: string }

const TOOL_API_KEYS: Record<string, ApiKeyReq[]> = {
  Shodan: [
    { key: 'shodanApiKey', label: 'Shodan', impact: 'Falls back to InternetDB (free) -- no geolocation, banners, or Domain DNS.' },
  ],
  Urlscan: [
    { key: 'urlscanApiKey', label: 'URLScan.io', impact: 'Public results only with lower rate limits.' },
  ],
  Gau: [
    { key: 'urlscanApiKey', label: 'URLScan.io', impact: 'GAU URLScan source will have lower rate limits.' },
  ],
  Uncover: [
    { key: 'shodanApiKey', label: 'Shodan', impact: 'Shodan engine disabled.' },
    { key: 'censysApiToken', label: 'Censys', impact: 'Censys engine disabled.' },
    { key: 'fofaApiKey', label: 'FOFA', impact: 'FOFA engine disabled.' },
    { key: 'zoomEyeApiKey', label: 'ZoomEye', impact: 'ZoomEye engine disabled.' },
    { key: 'netlasApiKey', label: 'Netlas', impact: 'Netlas engine disabled.' },
    { key: 'criminalIpApiKey', label: 'Criminal IP', impact: 'Criminal IP engine disabled.' },
  ],
  OsintEnrichment: [
    { key: 'censysApiToken', label: 'Censys', impact: 'Censys enrichment disabled.' },
    { key: 'fofaApiKey', label: 'FOFA', impact: 'FOFA enrichment disabled.' },
    { key: 'otxApiKey', label: 'OTX', impact: 'OTX limited to public data.' },
    { key: 'netlasApiKey', label: 'Netlas', impact: 'Netlas enrichment disabled.' },
    { key: 'virusTotalApiKey', label: 'VirusTotal', impact: 'VirusTotal enrichment disabled.' },
    { key: 'zoomEyeApiKey', label: 'ZoomEye', impact: 'ZoomEye enrichment disabled.' },
    { key: 'criminalIpApiKey', label: 'Criminal IP', impact: 'Criminal IP enrichment disabled.' },
  ],
  Nuclei: [
    { key: 'nvdApiKey', label: 'NVD', impact: 'CVE lookup rate-limited (no key).' },
    { key: 'vulnersApiKey', label: 'Vulners', impact: 'Vulners CVE enrichment disabled.' },
  ],
}

const TOOL_DESCRIPTIONS: Record<string, string> = {
  SubdomainDiscovery:
    'Discovers subdomains using 5 tools in parallel (crt.sh, HackerTarget, Subfinder, Amass, Knockpy), ' +
    'filters wildcards with Puredns, then resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for each. ' +
    'Results are merged into the existing graph -- duplicates are updated, not recreated.',
  Naabu:
    'Scans discovered IPs and subdomains for open ports using Naabu (Docker-based). ' +
    'Targets are loaded from the graph (subdomains + IPs from prior discovery). ' +
    'You can also provide custom subdomains or IPs below. ' +
    'Port and Service nodes are merged into the existing graph -- duplicates are updated, not recreated.',
  Masscan:
    'High-speed SYN port scanner for large networks using raw SYN packets. ' +
    'Targets are loaded from the graph (IPs from prior discovery). ' +
    'You can also provide custom IPs below. ' +
    'Port and Service nodes are merged into the existing graph -- duplicates are updated, not recreated.',
  Nmap:
    'Runs Nmap service version detection (-sV) and NSE vulnerability scripts on ports already discovered by Naabu. ' +
    'Targets are loaded from the graph (IPs + open ports from prior port scanning). ' +
    'You can also provide custom subdomains or IPs below. ' +
    'Port, Service, Technology, Vulnerability, and CVE nodes are merged into the existing graph.',
  Httpx:
    'Probes HTTP services on discovered ports and subdomains using httpx. ' +
    'Detects live services, technologies, SSL/TLS certificates, and response metadata. ' +
    'Targets are loaded from the graph (IPs + ports from prior scanning, or subdomains on default ports). ' +
    'You can also provide custom subdomains below. ' +
    'BaseURL, Certificate, Technology, and Header nodes are merged into the existing graph.',
  Katana:
    'Crawls discovered BaseURLs using Katana to discover endpoints, parameters, and forms. ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  Hakrawler:
    'Lightweight web crawler that discovers endpoints and links from BaseURLs using Hakrawler (Docker-based). ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  Jsluice:
    'Static analysis of JavaScript files using jsluice (Bishop Fox). Downloads JS files from discovered URLs ' +
    'and extracts hidden API endpoints, paths, query parameters, and secrets (AWS keys, API tokens). ' +
    'Targets are loaded from the graph (BaseURLs + Endpoints from prior crawling). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, Parameter, BaseURL, Secret, and ExternalDomain nodes are merged into the existing graph.',
  Gau:
    'Passive URL discovery from web archives (Wayback Machine, Common Crawl, OTX, URLScan). ' +
    'Queries historical URLs for the target domain and all discovered subdomains without touching the target directly. ' +
    'You can also provide custom subdomains below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  ParamSpider:
    'Passive parameter discovery from the Wayback Machine. ' +
    'Queries historical URLs containing query parameters for the target domain and all discovered subdomains. ' +
    'You can also provide custom subdomains below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  Arjun:
    'Tests ~25,000 common parameter names against discovered endpoints using Arjun. ' +
    'Discovers hidden query/body parameters (debug params, admin functionality, hidden API inputs). ' +
    'Targets are loaded from the graph (BaseURLs + Endpoints from prior resource enumeration). ' +
    'You can also provide custom URLs below. ' +
    'Parameter nodes are merged into the existing graph -- duplicates are updated, not recreated.',
  Ffuf:
    'Directory and file fuzzer that brute-forces paths on BaseURLs using wordlists to discover hidden endpoints. ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  Kiterunner:
    'API endpoint bruteforcing using Kiterunner from Assetnote. Tests Swagger/OpenAPI-derived wordlists against BaseURLs ' +
    'to discover hidden REST API routes (including POST/PUT/DELETE endpoints). ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint and BaseURL nodes are merged into the existing graph.',
  JsRecon:
    'Comprehensive JavaScript reconnaissance scanner. Downloads JS files from discovered URLs ' +
    'and runs 6 analysis modules: secret detection (100+ patterns with live validation), endpoint extraction, ' +
    'source map discovery, dependency confusion checks, DOM sink analysis, and framework detection. ' +
    'Targets are loaded from the graph (BaseURLs + Endpoints from prior crawling). ' +
    'You can also provide custom URLs below. ' +
    'Secret, Endpoint, and JsReconFinding nodes are merged into the existing graph.',
  Nuclei:
    'Template-based vulnerability scanner detecting CVEs, misconfigurations, exposed panels, and web application vulnerabilities (SQLi, XSS, RCE). ' +
    'Targets are loaded from the graph (BaseURLs + Endpoints from prior phases). ' +
    'You can also provide custom URLs below. ' +
    'Vulnerability, CVE, Endpoint, Parameter, MitreData, and Capec nodes are merged into the existing graph.',
  SubdomainTakeover:
    'Layered subdomain takeover detection. Runs Subjack (DNS-first, fingerprints CNAME/NS/MX against known takeover-prone services) and ' +
    'Nuclei with takeover-only templates (-t http/takeovers/ -t dns/) against alive URLs. ' +
    'Findings are deduplicated across tools, scored (confirmed / likely / manual_review), and written as Vulnerability nodes ' +
    'with source="takeover_scan". Targets are loaded from the graph (Subdomains + alive URLs). ' +
    'You can also provide custom subdomains below.',
  GraphqlScan:
    'Active GraphQL security scanner. Discovers GraphQL endpoints from crawled BaseURLs + Endpoints + JS findings, ' +
    'tests for exposed introspection, extracts schema, detects sensitive field exposure, and flags mutation / proxy ' +
    'vulnerabilities. Runs the native scanner + graphql-cop (12 external checks: alias/batch/directive/circular DoS, ' +
    'GraphiQL detection, GET-method CSRF, trace/debug leakage, field suggestions, unhandled errors). ' +
    'You can also provide custom GraphQL endpoint URLs below to test directly (bypasses auto-discovery). ' +
    'Enriches Endpoint nodes with is_graphql + schema metadata and creates Vulnerability nodes.',
  SecurityChecks:
    'Runs custom security checks on discovered infrastructure: Direct IP Access, TLS/SSL certificate expiry, ' +
    'Security Headers (Referrer-Policy, Permissions-Policy, COOP/CORP/COEP), Authentication (HTTPS, cookie flags), ' +
    'DNS Security (SPF, DMARC, DNSSEC, zone transfer), Exposed Services (admin ports, databases), and Application Security. ' +
    'Targets are loaded from the graph (IPs, subdomains, BaseURLs from prior phases). ' +
    'Vulnerability nodes are merged into the existing graph.',
  Shodan:
    'Passive OSINT enrichment using the Shodan API (or free InternetDB fallback). ' +
    'Enriches discovered IPs with geolocation, OS, ISP, open ports, service banners, reverse DNS hostnames, and known CVEs. ' +
    'Targets are loaded from the graph (IPs from prior Subdomain Discovery). ' +
    'Port, Service, Subdomain, ExternalDomain, DNSRecord, Vulnerability, and CVE nodes are merged into the existing graph.',
  Urlscan:
    'Passive OSINT enrichment using URLScan.io historical scan data. ' +
    'Discovers additional subdomains, IPs, ASN info, domain age, TLS certificates, server technologies, and screenshots. ' +
    'Also enriches existing BaseURLs with screenshot URLs and creates Endpoint/Parameter nodes from discovered URL paths. ' +
    'Subdomain, ExternalDomain, IP, Endpoint, and Parameter nodes are merged into the existing graph.',
  Uncover:
    'Multi-engine passive discovery using ProjectDiscovery Uncover. ' +
    'Searches Shodan, Censys, FOFA, ZoomEye, Netlas, CriminalIP, and other engines simultaneously ' +
    'to discover additional IPs, subdomains, open ports, and URLs associated with the target domain. ' +
    'IP, Subdomain, Port, and Endpoint nodes are merged into the existing graph.',
  OsintEnrichment:
    'Passive OSINT enrichment using multiple APIs in parallel: Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, and CriminalIP. ' +
    'Enriches discovered IPs with open ports, services, certificates, threat intelligence, malware associations, DNS records, and vulnerabilities. ' +
    'Targets are loaded from the graph (IPs from prior Subdomain Discovery). Only sub-tools with valid API keys will run. ' +
    'Subdomain, Port, Service, ExternalDomain, DNSRecord, ThreatPulse, Malware, Certificate, Vulnerability, and CVE nodes are merged into the existing graph.',
}

// --- Validation helpers ---

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
const CIDR_V4_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
const CIDR_V6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/
const HOSTNAME_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

function validateIp(value: string): string | null {
  if (IPV4_RE.test(value)) {
    const octets = value.split('.').map(Number)
    if (octets.some(o => o > 255)) return `Invalid IP: ${value}`
    return null
  }
  if (IPV6_RE.test(value)) return null
  if (CIDR_V4_RE.test(value)) {
    const [ip, prefix] = value.split('/')
    const octets = ip.split('.').map(Number)
    if (octets.some(o => o > 255)) return `Invalid CIDR: ${value}`
    const pfx = parseInt(prefix, 10)
    if (pfx < 24 || pfx > 32) return `CIDR prefix must be /24 to /32, got /${pfx}`
    return null
  }
  if (CIDR_V6_RE.test(value)) {
    const prefix = parseInt(value.split('/')[1], 10)
    if (prefix < 120 || prefix > 128) return `IPv6 CIDR prefix must be /120 to /128, got /${prefix}`
    return null
  }
  return `Invalid IP or CIDR: ${value}`
}

function validatePort(value: string): string | null {
  const num = parseInt(value, 10)
  if (isNaN(num) || !Number.isInteger(num)) return `Not a valid port number: ${value}`
  if (num < 1 || num > 65535) return `Port must be 1-65535, got ${num}`
  return null
}

function validateUrl(value: string, projectDomain?: string): string | null {
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return `URL must use http or https: ${value}`
    if (!url.hostname) return `URL has no hostname: ${value}`
    if (projectDomain && !url.hostname.endsWith('.' + projectDomain) && url.hostname !== projectDomain) {
      return `${url.hostname} is out of scope (not a subdomain of ${projectDomain})`
    }
    return null
  } catch {
    return `Invalid URL: ${value}`
  }
}

function validateSubdomain(value: string, projectDomain: string): string | null {
  if (!HOSTNAME_RE.test(value)) return `Invalid hostname: ${value}`
  if (projectDomain && !value.endsWith('.' + projectDomain) && value !== projectDomain) {
    return `${value} is not a subdomain of ${projectDomain}`
  }
  return null
}

function validateLines(text: string, validator: (v: string) => string | null) {
  if (!text.trim()) return { errors: [] as { line: number; error: string }[], validCount: 0 }
  const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
  const errors: { line: number; error: string }[] = []
  let validCount = 0
  lines.forEach((line, i) => {
    const err = validator(line)
    if (err) errors.push({ line: i + 1, error: err })
    else validCount++
  })
  return { errors, validCount }
}

// --- Shared inline styles ---

const textareaStyle = (hasError: boolean) => ({
  width: '100%',
  padding: '8px 10px',
  borderRadius: '6px',
  border: `1px solid ${hasError ? '#ef4444' : 'var(--border-color, #334155)'}`,
  backgroundColor: 'var(--bg-secondary, #1e293b)',
  color: 'var(--text-primary, #e2e8f0)',
  fontSize: '12px',
  fontFamily: 'monospace',
  resize: 'vertical' as const,
})

const labelStyle = { fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '4px' }
const hintStyle = { fontSize: '10px', color: 'var(--text-muted, #64748b)', marginTop: '2px' }
const errorListStyle = { marginTop: '4px', display: 'flex', flexDirection: 'column' as const, gap: '2px' }
const errorLineStyle = { fontSize: '10px', color: '#f87171' }

// --- Component ---

export function PartialReconModal({
  isOpen,
  toolId,
  onClose,
  onConfirm,
  projectId,
  targetDomain = '',
  subdomainPrefixes = [],
  isStarting = false,
  userId,
}: PartialReconModalProps) {
  const [graphInputs, setGraphInputs] = useState<GraphInputs | null>(null)
  const [loadingInputs, setLoadingInputs] = useState(false)
  const [userSettings, setUserSettings] = useState<Record<string, string> | null>(null)
  const [customSubdomains, setCustomSubdomains] = useState('')
  const [customIps, setCustomIps] = useState('')
  const [ipAttachTo, setIpAttachTo] = useState<string | null>(null)
  const [customPorts, setCustomPorts] = useState('')
  const [customUrls, setCustomUrls] = useState('')
  const [urlAttachTo, setUrlAttachTo] = useState<string | null>(null)
  const [includeGraphTargets, setIncludeGraphTargets] = useState(true)

  // Nuclei sub-feature toggles (override project settings)
  const [nucleiCveLookup, setNucleiCveLookup] = useState(true)
  const [nucleiMitre, setNucleiMitre] = useState(true)
  const [nucleiSecurityChecks, setNucleiSecurityChecks] = useState(true)

  // JS file upload state (JsRecon only)
  const [uploadedJsFiles, setUploadedJsFiles] = useState<{ name: string; size: number; uploaded_at: string }[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const jsFileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!isOpen || !toolId || !projectId) return
    setLoadingInputs(true)
    setCustomSubdomains('')
    setCustomIps('')
    setIpAttachTo(null)
    setCustomPorts('')
    setCustomUrls('')
    setUrlAttachTo(null)
    setIncludeGraphTargets(true)
    setNucleiCveLookup(true)
    setNucleiMitre(true)
    setNucleiSecurityChecks(true)
    setUploadedJsFiles([])
    setUploadError(null)
    fetch(`/api/recon/${projectId}/graph-inputs/${toolId}`)
      .then(res => res.ok ? res.json() : null)
      .then((data: GraphInputs | null) => {
        setGraphInputs(data || { domain: targetDomain || null, existing_subdomains_count: 0, existing_ips_count: 0, existing_ports_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
      .catch(() => {
        setGraphInputs({ domain: targetDomain || null, existing_subdomains_count: 0, existing_ips_count: 0, existing_ports_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
    // Fetch existing uploaded JS files for JsRecon
    if (toolId === 'JsRecon') {
      fetch(`/api/js-recon/${projectId}/upload`)
        .then(res => res.ok ? res.json() : null)
        .then(data => setUploadedJsFiles(data?.files || []))
        .catch(() => setUploadedJsFiles([]))
    }
    // Fetch user settings for API key warnings (only for tools that need keys)
    if (userId && TOOL_API_KEYS[toolId]) {
      fetch(`/api/users/${userId}/settings`)
        .then(r => r.ok ? r.json() : null)
        .then(s => setUserSettings(s || {}))
        .catch(() => setUserSettings(null))
    } else {
      setUserSettings(null)
    }
  }, [isOpen, toolId, projectId, targetDomain, userId])

  // JS file upload handlers (JsRecon only)
  const handleJsFileUpload = useCallback(async (file: File) => {
    if (!projectId) return
    setIsUploading(true)
    setUploadError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch(`/api/js-recon/${projectId}/upload`, { method: 'POST', body: formData })
      if (!res.ok) {
        const data = await res.json()
        setUploadError(data.error || 'Upload failed')
        return
      }
      const listRes = await fetch(`/api/js-recon/${projectId}/upload`)
      if (listRes.ok) {
        const data = await listRes.json()
        setUploadedJsFiles(data.files || [])
      }
    } catch {
      setUploadError('Upload failed')
    } finally {
      setIsUploading(false)
      if (jsFileInputRef.current) jsFileInputRef.current.value = ''
    }
  }, [projectId])

  const handleJsFileDelete = useCallback(async (filename: string) => {
    if (!projectId) return
    try {
      await fetch(`/api/js-recon/${projectId}/upload?name=${encodeURIComponent(filename)}`, { method: 'DELETE' })
      const listRes = await fetch(`/api/js-recon/${projectId}/upload`)
      if (listRes.ok) {
        const data = await listRes.json()
        setUploadedJsFiles(data.files || [])
      }
    } catch { /* ignore */ }
  }, [projectId])

  const domain = graphInputs?.domain || targetDomain || ''
  const isPortScanner = toolId === 'Naabu' || toolId === 'Masscan'
  const isNmap = toolId === 'Nmap'
  const isHttpx = toolId === 'Httpx'
  const isNuclei = toolId === 'Nuclei'
  const isGraphql = toolId === 'GraphqlScan'
  const isSecurityChecks = toolId === 'SecurityChecks'
  const isResourceEnum = toolId === 'Katana' || toolId === 'Hakrawler' || toolId === 'Jsluice' || toolId === 'Ffuf' || toolId === 'Kiterunner' || toolId === 'JsRecon' || isNuclei
  const isArjun = toolId === 'Arjun'
  const isGau = toolId === 'Gau'
  const isParamSpider = toolId === 'ParamSpider'
  const isShodan = toolId === 'Shodan'
  const isOsintEnrichment = toolId === 'OsintEnrichment'
  const isSubdomainTakeover = toolId === 'SubdomainTakeover'
  const hasUserInputs = isPortScanner || isNmap || isHttpx || isResourceEnum || isArjun || isGau || isParamSpider || isSecurityChecks || isShodan || isOsintEnrichment || isGraphql || isSubdomainTakeover
  const hasIpInput = isPortScanner || isNmap || isHttpx || isSecurityChecks || isShodan || isOsintEnrichment
  const hasSubdomainInput = toolId === 'Naabu' || isHttpx || isGau || isParamSpider || isSecurityChecks || isSubdomainTakeover
  const hasPortInput = isNmap || isHttpx
  // GraphqlScan's SECTION_INPUT_MAP = [BaseURL, Endpoint]. Per PROMPT.ADD_PARTIAL_RECON.md,
  // BaseURL-accepting tools get a URL textarea; Endpoint is graph-only (never manually entered).
  const hasUrlInput = isResourceEnum || isArjun || isSecurityChecks || isGraphql

  // Subdomain validation
  const subdomainValidation = useMemo(
    () => validateLines(customSubdomains, v => validateSubdomain(v, domain)),
    [customSubdomains, domain],
  )

  // IP validation
  const ipValidation = useMemo(
    () => validateLines(customIps, validateIp),
    [customIps],
  )

  // Port validation (Nmap only)
  const portValidation = useMemo(
    () => validateLines(customPorts, validatePort),
    [customPorts],
  )

  // URL validation (resource enum tools: Katana, Hakrawler) -- must be in project scope
  const urlValidation = useMemo(
    () => validateLines(customUrls, v => validateUrl(v, domain)),
    [customUrls, domain],
  )

  const hasValidationErrors = (hasSubdomainInput && subdomainValidation.errors.length > 0)
    || (hasIpInput && ipValidation.errors.length > 0)
    || (hasPortInput && portValidation.errors.length > 0)
    || (hasUrlInput && urlValidation.errors.length > 0)

  // Compute missing API keys for the current tool
  const missingApiKeys = useMemo(() => {
    if (!toolId || !userSettings || !TOOL_API_KEYS[toolId]) return []
    return TOOL_API_KEYS[toolId].filter(req => !userSettings[req.key])
  }, [toolId, userSettings])

  // Build dropdown options: graph subdomains + custom subdomains (live)
  const attachToOptions = useMemo(() => {
    const graphSubs = graphInputs?.existing_subdomains || []
    const customSubs = customSubdomains
      .split('\n')
      .map(s => s.trim().toLowerCase())
      .filter(s => s && HOSTNAME_RE.test(s) && (s.endsWith('.' + domain) || s === domain))
    // Deduplicate, graph first
    const seen = new Set<string>()
    const options: { value: string; label: string; source: string }[] = []
    for (const s of graphSubs) {
      if (!seen.has(s)) { seen.add(s); options.push({ value: s, label: s, source: 'graph' }) }
    }
    for (const s of customSubs) {
      if (!seen.has(s)) { seen.add(s); options.push({ value: s, label: s, source: 'custom' }) }
    }
    return options
  }, [graphInputs?.existing_subdomains, customSubdomains, domain])

  // Build dropdown options for URL attachment: existing BaseURLs from graph
  const urlAttachToOptions = useMemo(() => {
    const graphBaseUrls = graphInputs?.existing_baseurls || []
    return graphBaseUrls.map(u => ({ value: u, label: u }))
  }, [graphInputs?.existing_baseurls])

  // If selected attach_to was removed from options, reset to null
  useEffect(() => {
    if (ipAttachTo && !attachToOptions.some(o => o.value === ipAttachTo)) {
      setIpAttachTo(null)
    }
  }, [attachToOptions, ipAttachTo])

  useEffect(() => {
    if (urlAttachTo && !urlAttachToOptions.some(o => o.value === urlAttachTo)) {
      setUrlAttachTo(null)
    }
  }, [urlAttachToOptions, urlAttachTo])

  const handleRun = useCallback(() => {
    if (!domain || hasValidationErrors) return

    if (hasUserInputs) {
      const subdomains = hasSubdomainInput ? customSubdomains.split('\n').map(s => s.trim()).filter(Boolean) : []
      const ips = hasIpInput ? customIps.split('\n').map(s => s.trim()).filter(Boolean) : []
      const ports = hasPortInput ? customPorts.split('\n').map(s => s.trim()).filter(Boolean).map(Number).filter(n => n >= 1 && n <= 65535) : []
      const urls = hasUrlInput ? customUrls.split('\n').map(s => s.trim()).filter(Boolean) : []
      const hasCustomInput = subdomains.length || ips.length || ports.length || urls.length
      const userTargets: UserTargets | undefined = hasCustomInput
        ? {
            subdomains, ips, ip_attach_to: ipAttachTo,
            ...(ports.length ? { ports } : {}),
            ...(urls.length ? { urls, url_attach_to: urlAttachTo } : {}),
          }
        : undefined

      // Build Nuclei settings overrides from modal checkboxes
      const nucleiOverrides = isNuclei ? {
        settings_overrides: {
          CVE_LOOKUP_ENABLED: nucleiCveLookup,
          MITRE_ENABLED: nucleiMitre,
          SECURITY_CHECK_ENABLED: nucleiSecurityChecks,
        },
      } : {}

      const params = {
        tool_id: toolId || '',
        graph_inputs: { domain },
        user_inputs: [],
        user_targets: userTargets,
        ...(includeGraphTargets ? {} : { include_graph_targets: false }),
        ...nucleiOverrides,
      }
      console.log('[PartialReconModal] handleRun params:', JSON.stringify(params))
      onConfirm(params)
    } else {
      // Build Nuclei settings overrides from modal checkboxes
      const nucleiOverrides = isNuclei ? {
        settings_overrides: {
          CVE_LOOKUP_ENABLED: nucleiCveLookup,
          MITRE_ENABLED: nucleiMitre,
          SECURITY_CHECK_ENABLED: nucleiSecurityChecks,
        },
      } : {}

      onConfirm({
        tool_id: toolId || '',
        graph_inputs: { domain },
        user_inputs: [],
        ...(includeGraphTargets ? {} : { include_graph_targets: false }),
        ...nucleiOverrides,
      })
    }
  }, [domain, hasValidationErrors, hasUserInputs, hasSubdomainInput, hasIpInput, hasPortInput, hasUrlInput, isNmap, toolId, onConfirm, customSubdomains, customIps, ipAttachTo, customPorts, customUrls, urlAttachTo, includeGraphTargets, isNuclei, nucleiCveLookup, nucleiMitre, nucleiSecurityChecks])

  if (!isOpen || !toolId) return null

  const inputNodeTypes = SECTION_INPUT_MAP[toolId] || []
  const outputNodeTypes = SECTION_NODE_MAP[toolId] || []
  const enrichNodeTypes = SECTION_ENRICH_MAP[toolId] || []
  const hasNoGraphTargets = (isPortScanner && !loadingInputs && (graphInputs?.existing_ips_count ?? 0) === 0)
    || (isNmap && !loadingInputs && (graphInputs?.existing_ports_count ?? 0) === 0)
    || (isHttpx && !loadingInputs && (graphInputs?.existing_ports_count ?? 0) === 0 && (graphInputs?.existing_subdomains_count ?? 0) === 0)
    || (toolId === 'JsRecon' && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0 && (graphInputs?.existing_endpoints_count ?? 0) === 0 && uploadedJsFiles.length === 0)
    || (isNuclei && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0 && (graphInputs?.existing_endpoints_count ?? 0) === 0)
    || (isGraphql && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0 && (graphInputs?.existing_endpoints_count ?? 0) === 0)
    || (isResourceEnum && !isNuclei && toolId !== 'JsRecon' && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0)
    || (isArjun && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0 && (graphInputs?.existing_endpoints_count ?? 0) === 0)
    || (isSecurityChecks && !loadingInputs && (graphInputs?.existing_ips_count ?? 0) === 0 && (graphInputs?.existing_subdomains_count ?? 0) === 0 && (graphInputs?.existing_baseurls_count ?? 0) === 0)
    || (toolId === 'Shodan' && !loadingInputs && (graphInputs?.existing_ips_count ?? 0) === 0)
    || (toolId === 'OsintEnrichment' && !loadingInputs && (graphInputs?.existing_ips_count ?? 0) === 0)
  const hasJsUploads = toolId === 'JsRecon' && uploadedJsFiles.length > 0
  const hasNoCustomTargets = (!hasSubdomainInput || !customSubdomains.trim()) && (!hasIpInput || !customIps.trim()) && !customPorts.trim() && (!hasUrlInput || !customUrls.trim()) && !hasJsUploads
  const noTargetsToScan = hasUserInputs && !isGau && !isParamSpider && !includeGraphTargets && hasNoCustomTargets
  const nmapNoPorts = isNmap && !includeGraphTargets && !customPorts.trim()
  const httpxNoPorts = isHttpx && !includeGraphTargets && !customPorts.trim() && !customSubdomains.trim()
  const resourceEnumNoUrls = isResourceEnum && !includeGraphTargets && !customUrls.trim() && !hasJsUploads
  const arjunNoUrls = isArjun && !includeGraphTargets && !customUrls.trim()
  const securityChecksNoUrls = isSecurityChecks && !includeGraphTargets && !customUrls.trim() && !customSubdomains.trim() && !customIps.trim()
  const shodanNoIps = isShodan && !includeGraphTargets && !customIps.trim()
  const osintNoIps = isOsintEnrichment && !includeGraphTargets && !customIps.trim()

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Partial Recon: ${WORKFLOW_TOOLS.find(t => t.id === toolId)?.label || toolId}`}
      size="default"
      closeOnOverlayClick={false}
      closeOnEscape={false}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Input / Output flow */}
        <div style={{ display: 'flex', alignItems: 'stretch', gap: '12px' }}>
          {/* Input */}
          <div style={{
            flex: 1, padding: '12px 14px', borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#3b82f6', marginBottom: '8px' }}>
              Input
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', marginBottom: '6px' }}>
              {inputNodeTypes.map(nt => (
                <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', fontWeight: 600 }}>{nt}</span>
              ))}
            </div>
            <div style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--text-primary, #e2e8f0)' }}>
              {loadingInputs ? 'Loading...' : isNmap
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_ports_count ?? 0} ports, ${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : isHttpx
                ? `${domain || 'No domain'} (${graphInputs?.existing_subdomains_count ?? 0} subdomains, ${graphInputs?.existing_ports_count ?? 0} ports, ${graphInputs?.existing_baseurls_count ?? 0} existing URLs)`
                : toolId === 'JsRecon'
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs, ${graphInputs?.existing_endpoints_count ?? 0} Endpoints${uploadedJsFiles.length ? `, ${uploadedJsFiles.length} uploaded` : ''})`
                : isNuclei
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs, ${graphInputs?.existing_endpoints_count ?? 0} Endpoints)`
                : isGraphql
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs, ${graphInputs?.existing_endpoints_count ?? 0} Endpoints${graphInputs?.existing_graphql_endpoints_count ? `, ${graphInputs.existing_graphql_endpoints_count} already-flagged GraphQL` : ''})`
                : isResourceEnum
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs)`
                : isArjun
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs, ${graphInputs?.existing_endpoints_count ?? 0} Endpoints)`
                : isSecurityChecks
                ? `${domain || 'No domain'} (${graphInputs?.existing_subdomains_count ?? 0} subdomains, ${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_baseurls_count ?? 0} BaseURLs)`
                : isGau || isParamSpider
                ? `${domain || 'No domain'} (${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : toolId === 'Naabu'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : toolId === 'Masscan'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs)`
                : toolId === 'Shodan'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs)`
                : toolId === 'OsintEnrichment'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : domain || 'No domain configured'}
            </div>
          </div>

          {/* Arrow */}
          <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
            <ArrowRight size={18} style={{ color: 'var(--text-muted, #64748b)' }} />
          </div>

          {/* Output */}
          <div style={{
            flex: 1, padding: '12px 14px', borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#22c55e', marginBottom: '8px' }}>
              Output
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {outputNodeTypes.map(nt => (
                <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', fontWeight: 600 }}>{nt}</span>
              ))}
            </div>
            {enrichNodeTypes.length > 0 && (
              <>
                <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#4ade80', marginTop: '8px', marginBottom: '4px', opacity: 0.7 }}>
                  Enriches
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {enrichNodeTypes.map(nt => (
                    <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(34, 197, 94, 0.08)', color: '#4ade80', fontWeight: 600, borderStyle: 'dashed', border: '1px dashed rgba(34, 197, 94, 0.3)' }}>{nt}</span>
                  ))}
                </div>
              </>
            )}
            <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', marginTop: '6px' }}>
              New nodes merged into graph
            </div>
          </div>
        </div>

        {/* Tools info */}
        <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', lineHeight: '1.6' }}>
          {TOOL_DESCRIPTIONS[toolId] || 'Runs this pipeline phase independently and merges results into the existing graph.'}
        </div>

        {/* API key warning */}
        {missingApiKeys.length > 0 && (
          <div style={{
            fontSize: '11px', color: '#facc15', lineHeight: '1.6', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.2)',
            display: 'flex', flexDirection: 'column', gap: '4px',
          }}>
            <div style={{ fontWeight: 600 }}>
              Missing API {missingApiKeys.length === 1 ? 'key' : 'keys'} -- results may be limited:
            </div>
            {missingApiKeys.map(req => (
              <div key={req.key} style={{ paddingLeft: '8px' }}>
                <span style={{ fontWeight: 600 }}>{req.label}:</span> {req.impact}
              </div>
            ))}
            <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748b)', marginTop: '2px' }}>
              Configure API keys in Global Settings to get full results.
            </div>
          </div>
        )}

        {/* Include graph targets checkbox */}
        {hasUserInputs && (
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={includeGraphTargets}
              onChange={e => setIncludeGraphTargets(e.target.checked)}
              style={{ accentColor: '#3b82f6' }}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-primary, #e2e8f0)' }}>
              Include existing graph targets in scan
            </span>
          </label>
        )}

        {/* No targets warning */}
        {hasNoGraphTargets && includeGraphTargets && hasNoCustomTargets && (
          <div style={{
            fontSize: '11px', color: '#facc15', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.2)',
          }}>
            {isNmap
              ? 'No ports found in graph. Run Naabu first to discover open ports, or provide custom targets below.'
              : isHttpx
              ? 'No subdomains or ports found in graph. Run Subdomain Discovery + Port Scanning first, or provide custom subdomains below.'
              : toolId === 'JsRecon'
              ? 'No BaseURLs or Endpoints found in graph. Run HTTP Probing (Httpx) and Resource Enumeration (Katana/Hakrawler) first, or provide custom URLs below.'
              : isNuclei
              ? 'No BaseURLs or Endpoints found in graph. Run HTTP Probing (Httpx) and Resource Enumeration first, or provide custom URLs below.'
              : isResourceEnum
              ? 'No BaseURLs found in graph. Run HTTP Probing (Httpx) first to discover live URLs, or provide custom URLs below.'
              : isArjun
              ? 'No BaseURLs or Endpoints found in graph. Run Resource Enumeration (Katana/Hakrawler) first, or provide custom URLs below.'
              : isSecurityChecks
              ? 'No IPs, subdomains, or BaseURLs found in graph. Run Subdomain Discovery and HTTP Probing first to populate the graph.'
              : toolId === 'Shodan'
              ? 'No IPs found in graph. Run Subdomain Discovery first to populate IPs, or provide custom IPs below.'
              : toolId === 'OsintEnrichment'
              ? 'No IPs found in graph. Run Subdomain Discovery first to populate IPs for OSINT enrichment.'
              : 'No IPs found in graph. Run Subdomain Discovery first to populate the graph, or provide custom targets below.'}
          </div>
        )}
        {noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Provide custom targets below or enable graph targets to run the scan.
          </div>
        )}
        {nmapNoPorts && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Nmap requires ports to scan. Provide custom ports below or enable graph targets (which include existing ports from Naabu/Masscan).
          </div>
        )}
        {httpxNoPorts && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Httpx requires ports or subdomains to probe. Provide custom ports/IPs, custom subdomains (probed on default ports), or enable graph targets.
          </div>
        )}
        {resourceEnumNoUrls && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            {toolId === 'Jsluice'
              ? 'Jsluice requires URLs to analyze. Provide custom URLs below or enable graph targets (which include existing Endpoints from Katana/Hakrawler).'
              : toolId === 'JsRecon'
              ? 'JS Recon requires URLs to analyze for JavaScript files. Provide custom URLs below or enable graph targets (which include existing BaseURLs + Endpoints).'
              : isNuclei
              ? 'Nuclei requires URLs to scan. Provide custom URLs below or enable graph targets (which include existing BaseURLs + Endpoints from prior phases).'
              : `${toolId} requires URLs to crawl. Provide custom URLs below or enable graph targets (which include existing BaseURLs from Httpx).`}
          </div>
        )}
        {arjunNoUrls && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Arjun requires endpoints to test for parameters. Provide custom URLs below or enable graph targets (which include existing BaseURLs + Endpoints from crawling).
          </div>
        )}
        {securityChecksNoUrls && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Security Checks require targets to scan. Provide custom subdomains, IPs, or URLs below, or enable graph targets.
          </div>
        )}
        {shodanNoIps && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Shodan requires IPs to enrich. Provide custom IPs below or enable graph targets (which include existing IPs from Subdomain Discovery).
          </div>
        )}
        {osintNoIps && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            OSINT Enrichment requires IPs to enrich. Provide custom IPs below or enable graph targets (which include existing IPs from Subdomain Discovery).
          </div>
        )}

        {/* === Section A - Custom Subdomains (only for tools that consume Subdomain) === */}
        {hasSubdomainInput && (
          <div>
            <div style={labelStyle}>Custom subdomains (optional, one per line)</div>
            <textarea
              value={customSubdomains}
              onChange={e => setCustomSubdomains(e.target.value)}
              placeholder={`api.${domain || 'example.com'}\nstaging.${domain || 'example.com'}`}
              rows={2}
              style={textareaStyle(subdomainValidation.errors.length > 0)}
            />
            {subdomainValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {subdomainValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>Will be DNS-resolved and added to the graph as Subdomain nodes</div>
            )}
          </div>
        )}

        {/* === Section B - Custom IPs === */}
        {hasIpInput && (
          <div>
            <div style={labelStyle}>Custom IPs (optional, one per line)</div>
            <textarea
              value={customIps}
              onChange={e => setCustomIps(e.target.value)}
              placeholder={'192.168.1.1\n10.0.0.0/24'}
              rows={2}
              style={textareaStyle(ipValidation.errors.length > 0)}
            />
            {ipValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {ipValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>{isNmap || isHttpx
                ? 'IPv4, IPv6, or CIDR ranges (/24-/32). Will be probed on all ports (graph + custom).'
                : 'IPv4, IPv6, or CIDR ranges (/24-/32)'}</div>
            )}

            {/* Dropdown: associate IPs to subdomain */}
            {customIps.trim() && ipValidation.errors.length === 0 && (
              <div style={{ marginTop: '8px' }}>
                <div style={labelStyle}>Associate IPs to</div>
                <select
                  value={ipAttachTo || ''}
                  onChange={e => setIpAttachTo(e.target.value || null)}
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #334155)',
                    backgroundColor: 'var(--bg-secondary, #1e293b)',
                    color: 'var(--text-primary, #e2e8f0)',
                    fontSize: '12px',
                  }}
                >
                  <option value="">-- Generic (UserInput) --</option>
                  {attachToOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}{opt.source === 'custom' ? ' (new)' : ''}
                    </option>
                  ))}
                </select>
                <div style={hintStyle}>
                  {ipAttachTo
                    ? `IPs will be linked to ${ipAttachTo} via RESOLVES_TO`
                    : 'IPs will be tracked via a UserInput node (no subdomain link)'}
                </div>
              </div>
            )}
          </div>
        )}

        {/* === Section C - Custom Ports (Nmap / Httpx) === */}
        {hasPortInput && (
          <div>
            <div style={labelStyle}>Custom ports (optional, one per line)</div>
            <textarea
              value={customPorts}
              onChange={e => setCustomPorts(e.target.value)}
              placeholder={'8443\n9090\n3000'}
              rows={2}
              style={textareaStyle(portValidation.errors.length > 0)}
            />
            {portValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {portValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>Port numbers 1-65535. Scanned on all target IPs (graph + custom).</div>
            )}
          </div>
        )}

        {/* Httpx default ports info */}
        {isHttpx && (customSubdomains.trim() || customIps.trim()) && !customPorts.trim() && (
          <div style={{
            fontSize: '11px', color: '#60a5fa', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.2)',
          }}>
            No custom ports specified. Custom subdomains and IPs will be probed on default ports (80, 443) only.
            Add custom ports above to probe additional ports.
          </div>
        )}

        {/* === Section D - Custom URLs (resource enum: Katana, Hakrawler) === */}
        {hasUrlInput && (
          <div>
            <div style={labelStyle}>Custom URLs (optional, one per line)</div>
            <textarea
              value={customUrls}
              onChange={e => setCustomUrls(e.target.value)}
              placeholder={isArjun
                ? 'https://example.com/api/users\nhttps://example.com/admin/settings'
                : toolId === 'Jsluice' || toolId === 'JsRecon'
                ? 'https://example.com/assets/app.js\nhttps://cdn.example.com/bundle.min.js'
                : isGraphql
                ? 'https://api.example.com/graphql\nhttps://api.example.com/v1/graphql'
                : 'https://example.com\nhttps://api.example.com:8443'}
              rows={2}
              style={textareaStyle(urlValidation.errors.length > 0)}
            />
            {urlValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {urlValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>{isArjun
                ? 'Full endpoint URLs to test for hidden query/body parameters (e.g. /api/users, /login, /admin/settings).'
                : toolId === 'Jsluice'
                ? 'Full URLs to JS files. Will be downloaded and analyzed for hidden endpoints and secrets.'
                : toolId === 'JsRecon'
                ? 'Full URLs to JS files or pages containing JS. Will be downloaded and analyzed for secrets, endpoints, source maps, and more.'
                : isNuclei
                ? 'Full URLs (http/https). Will be scanned for vulnerabilities, misconfigurations, and CVEs.'
                : isGraphql
                ? 'GraphQL endpoint URLs (e.g. /graphql, /api/graphql). Bypasses auto-discovery and tests these directly via introspection + graphql-cop checks.'
                : 'Full URLs (http/https). Will be crawled to discover endpoints and parameters.'}</div>
            )}

            {/* Dropdown: associate URLs to BaseURL */}
            {customUrls.trim() && urlValidation.errors.length === 0 && (
              <div style={{ marginTop: '8px' }}>
                <div style={labelStyle}>Associate URLs to</div>
                <select
                  value={urlAttachTo || ''}
                  onChange={e => setUrlAttachTo(e.target.value || null)}
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #334155)',
                    backgroundColor: 'var(--bg-secondary, #1e293b)',
                    color: 'var(--text-primary, #e2e8f0)',
                    fontSize: '12px',
                  }}
                >
                  <option value="">-- Generic (UserInput) --</option>
                  {urlAttachToOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
                <div style={hintStyle}>
                  {urlAttachTo
                    ? `Discovered endpoints will be linked to ${urlAttachTo}`
                    : 'URLs will be tracked via a UserInput node (no BaseURL link)'}
                </div>
              </div>
            )}
          </div>
        )}

        {/* === Section E - JS File Upload (JsRecon only) === */}
        {toolId === 'JsRecon' && projectId && (
          <div>
            <div style={labelStyle}>Upload JS files (optional)</div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748b)', marginBottom: '6px' }}>
              Upload .js, .mjs, .map, or .json files directly (from Burp Suite, mobile APKs, DevTools, or authenticated areas).
              These are analyzed alongside any URLs above.
            </div>
            <input
              ref={jsFileInputRef}
              type="file"
              accept=".js,.mjs,.map,.json"
              multiple
              style={{ display: 'none' }}
              onChange={(e) => {
                const files = e.target.files
                if (files) Array.from(files).forEach(f => handleJsFileUpload(f))
              }}
            />
            <button
              type="button"
              onClick={() => jsFileInputRef.current?.click()}
              disabled={isUploading || isStarting}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '5px 10px', borderRadius: '6px', fontSize: '11px',
                border: '1px solid var(--border-color, #334155)',
                backgroundColor: 'var(--bg-secondary, #1e293b)',
                color: 'var(--text-primary, #e2e8f0)',
                cursor: isUploading || isStarting ? 'not-allowed' : 'pointer',
                opacity: isUploading || isStarting ? 0.5 : 1,
              }}
            >
              {isUploading ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Upload size={12} />}
              {isUploading ? ' Uploading...' : ' Upload JS Files'}
            </button>

            {uploadError && (
              <div style={{ fontSize: '10px', color: '#f87171', marginTop: '4px' }}>{uploadError}</div>
            )}

            {uploadedJsFiles.length > 0 && (
              <div style={{ marginTop: '6px', fontSize: '10px', color: 'var(--text-secondary, #94a3b8)' }}>
                <div style={{ marginBottom: '3px' }}>
                  {uploadedJsFiles.length} file(s) uploaded ({(uploadedJsFiles.reduce((sum, f) => sum + f.size, 0) / 1024).toFixed(0)} KB total)
                </div>
                {uploadedJsFiles.map(f => (
                  <div key={f.name} style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '1px 0' }}>
                    <FileText size={10} />
                    <span>{f.name} ({(f.size / 1024).toFixed(1)} KB)</span>
                    <button
                      type="button"
                      onClick={() => handleJsFileDelete(f.name)}
                      style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', padding: '1px', display: 'inline-flex' }}
                      title={`Delete ${f.name}`}
                    >
                      <Trash2 size={10} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Subdomain prefix warning (SubdomainDiscovery only) */}
        {toolId === 'SubdomainDiscovery' && subdomainPrefixes.length > 0 && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            This project has subdomain prefixes locked to <strong>{subdomainPrefixes.join(', ')}</strong>.
            Partial recon ignores this filter and runs full discovery to find all subdomains.
            New subdomains found outside the prefix list will still be added to the graph.
          </div>
        )}

        {/* Nuclei sub-feature toggles */}
        {isNuclei && (
          <div style={{
            display: 'flex', flexDirection: 'column', gap: '6px',
            padding: '10px 12px', borderRadius: '6px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '2px' }}>
              Additional scans (override project settings)
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={nucleiCveLookup} onChange={e => setNucleiCveLookup(e.target.checked)} style={{ accentColor: '#3b82f6' }} />
              <span style={{ fontSize: '12px', color: 'var(--text-primary, #e2e8f0)' }}>CVE Lookup (enrich findings with NVD/Vulners data)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={nucleiMitre} onChange={e => setNucleiMitre(e.target.checked)} style={{ accentColor: '#3b82f6' }} />
              <span style={{ fontSize: '12px', color: 'var(--text-primary, #e2e8f0)' }}>MITRE ATT&CK Mapping (map vulnerabilities to techniques)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={nucleiSecurityChecks} onChange={e => setNucleiSecurityChecks(e.target.checked)} style={{ accentColor: '#3b82f6' }} />
              <span style={{ fontSize: '12px', color: 'var(--text-primary, #e2e8f0)' }}>Security Checks (TLS, headers, direct IP access, DNS)</span>
            </label>
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-color, #334155)' }}>
          <button
            type="button"
            onClick={onClose}
            disabled={isStarting}
            style={{
              padding: '8px 16px', borderRadius: '6px',
              border: '1px solid var(--border-color, #334155)',
              backgroundColor: 'transparent',
              color: 'var(--text-primary, #e2e8f0)',
              cursor: isStarting ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              opacity: isStarting ? 0.5 : 1,
            }}
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleRun}
            disabled={!domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls || arjunNoUrls || securityChecksNoUrls || shodanNoIps || osintNoIps}
            style={{
              padding: '8px 16px', borderRadius: '6px', border: 'none',
              backgroundColor: '#3b82f6', color: '#fff',
              cursor: !domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls || arjunNoUrls || securityChecksNoUrls || shodanNoIps || osintNoIps ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: !domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls || arjunNoUrls || securityChecksNoUrls || shodanNoIps || osintNoIps ? 0.5 : 1,
            }}
          >
            {isStarting ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={14} />}
            {isStarting ? 'Starting...' : 'Run Partial Recon'}
          </button>
        </div>
      </div>
    </Modal>
  )
}
