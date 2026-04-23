/**
 * Unit tests for the Recon Preset system.
 *
 * Tests verify:
 *   - Preset registry structure and lookup
 *   - Secret Miner preset parameters are valid
 *   - Preset merge logic preserves non-recon fields
 *   - Safe merge: missing preset fields fall through to form defaults
 */
import { describe, test, expect } from 'vitest'
import { RECON_PRESETS, getPresetById } from './index'
import { SECRET_MINER } from './presets/secret-miner'
import { API_SECURITY } from './presets/api-security'
import { BUG_BOUNTY_DEEP } from './presets/bug-bounty-deep'
import { BUG_BOUNTY_QUICK } from './presets/bug-bounty-quick'
import { FULL_ACTIVE_SCAN } from './presets/full-active-scan'
import { INFRASTRUCTURE_MAPPER } from './presets/infrastructure-mapper'
import { OSINT_INVESTIGATOR } from './presets/osint-investigator'
import { WEB_APP_PENTESTER } from './presets/web-app-pentester'
import { FULL_MAXIMUM_SCAN } from './presets/full-maximum-scan'
import { FULL_PASSIVE_SCAN } from './presets/full-passive-scan'
import { STEALTH_RECON } from './presets/stealth-recon'
import { SUBDOMAIN_TAKEOVER } from './presets/subdomain-takeover'
import { CVE_HUNTER } from './presets/cve-hunter'
import { DIRECTORY_DISCOVERY } from './presets/directory-discovery'
import { RED_TEAM_OPERATOR } from './presets/red-team-operator'
import { CLOUD_EXPOSURE } from './presets/cloud-exposure'
import { COMPLIANCE_AUDIT } from './presets/compliance-audit'
import { SECRET_HUNTER } from './presets/secret-hunter'
import { PARAMETER_INJECTION } from './presets/parameter-injection'
import { DNS_EMAIL_SECURITY } from './presets/dns-email-security'
import { LARGE_NETWORK } from './presets/large-network'
import type { ReconPreset } from './types'

// ============================================================
// Registry
// ============================================================

describe('RECON_PRESETS registry', () => {
  test('registry is a non-empty array', () => {
    expect(Array.isArray(RECON_PRESETS)).toBe(true)
    expect(RECON_PRESETS.length).toBeGreaterThan(0)
  })

  test('every preset has required fields', () => {
    for (const preset of RECON_PRESETS) {
      expect(preset.id).toBeDefined()
      expect(preset.name).toBeDefined()
      expect(preset.icon).toBeDefined()
      expect(preset.shortDescription).toBeDefined()
      expect(preset.fullDescription).toBeDefined()
      expect(preset.parameters).toBeDefined()
      expect(typeof preset.id).toBe('string')
      expect(typeof preset.name).toBe('string')
      expect(typeof preset.parameters).toBe('object')
    }
  })

  test('preset IDs are unique', () => {
    const ids = RECON_PRESETS.map(p => p.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})

// ============================================================
// getPresetById
// ============================================================

describe('getPresetById', () => {
  test('returns preset for valid ID', () => {
    const preset = getPresetById('secret-miner')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('secret-miner')
    expect(preset!.name).toBe('JS Secret Miner')
  })

  test('returns undefined for unknown ID', () => {
    expect(getPresetById('nonexistent')).toBeUndefined()
  })

  test('returns undefined for empty string', () => {
    expect(getPresetById('')).toBeUndefined()
  })
})

// ============================================================
// Secret Miner preset validation
// ============================================================

describe('JS Secret Miner preset', () => {
  test('has correct id and name', () => {
    expect(SECRET_MINER.id).toBe('secret-miner')
    expect(SECRET_MINER.name).toBe('JS Secret Miner')
  })

  test('enables JS Recon module', () => {
    expect(SECRET_MINER.parameters.jsReconEnabled).toBe(true)
  })

  test('removes port_scan and vuln_scan from scanModules', () => {
    const modules = SECRET_MINER.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('js_recon')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('vuln_scan')
  })

  test('disables port scanning tools', () => {
    expect(SECRET_MINER.parameters.naabuEnabled).toBe(false)
    expect(SECRET_MINER.parameters.nmapEnabled).toBe(false)
    expect(SECRET_MINER.parameters.masscanEnabled).toBe(false)
  })

  test('enables crawling tools with increased depth', () => {
    expect(SECRET_MINER.parameters.katanaEnabled).toBe(true)
    expect(SECRET_MINER.parameters.katanaDepth).toBe(3)
    expect(SECRET_MINER.parameters.katanaMaxUrls).toBe(1000)
    expect(SECRET_MINER.parameters.hakrawlerEnabled).toBe(true)
    expect(SECRET_MINER.parameters.hakrawlerDepth).toBe(3)
  })

  test('enables GAU for historical JS', () => {
    expect(SECRET_MINER.parameters.gauEnabled).toBe(true)
  })

  test('increases jsluice and JS Recon limits', () => {
    expect(SECRET_MINER.parameters.jsluiceMaxFiles).toBe(500)
    expect(SECRET_MINER.parameters.jsReconMaxFiles).toBe(1000)
  })

  test('disables irrelevant tools', () => {
    expect(SECRET_MINER.parameters.ffufEnabled).toBe(false)
    expect(SECRET_MINER.parameters.kiterunnerEnabled).toBe(false)
    expect(SECRET_MINER.parameters.arjunEnabled).toBe(false)
    expect(SECRET_MINER.parameters.paramspiderEnabled).toBe(false)
  })

  test('disables security/vuln modules via master switches', () => {
    expect(SECRET_MINER.parameters.securityCheckEnabled).toBe(false)
    expect(SECRET_MINER.parameters.nucleiEnabled).toBe(false)
    expect(SECRET_MINER.parameters.mitreEnabled).toBe(false)
    expect(SECRET_MINER.parameters.osintEnrichmentEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    // These fields should NOT be in the preset (they would overwrite user input)
    const params = SECRET_MINER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    // Agent settings should not be in recon preset
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    // RoE should not be in recon preset
    expect(params.roeEnabled).toBeUndefined()
    // CypherFix should not be in recon preset
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('fullDescription contains expected section headers', () => {
    expect(SECRET_MINER.fullDescription).toContain('### Pipeline Goal')
    expect(SECRET_MINER.fullDescription).toContain('### Who is this for?')
    expect(SECRET_MINER.fullDescription).toContain('### What it enables')
    expect(SECRET_MINER.fullDescription).toContain('### What it disables')
  })

  test('does not contain em dashes', () => {
    // Em dashes look AI-generated -- project style forbids them
    expect(SECRET_MINER.fullDescription).not.toContain('\u2014')
    expect(SECRET_MINER.shortDescription).not.toContain('\u2014')
  })
})

// ============================================================
// Full Active Scan preset validation
// ============================================================

describe('Full Pipeline - Active Only preset', () => {
  test('has correct id and name', () => {
    expect(FULL_ACTIVE_SCAN.id).toBe('full-active-scan')
    expect(FULL_ACTIVE_SCAN.name).toBe('Full Pipeline - Active Only')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('full-active-scan')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('full-active-scan')
  })

  test('includes all 6 scan modules including js_recon', () => {
    const modules = FULL_ACTIVE_SCAN.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).toContain('js_recon')
    expect(modules).toHaveLength(6)
  })

  // --- Stealth / anonymity explicitly OFF ---
  test('disables stealth mode and Tor', () => {
    expect(FULL_ACTIVE_SCAN.parameters.stealthMode).toBe(false)
    expect(FULL_ACTIVE_SCAN.parameters.useTorForRecon).toBe(false)
  })

  // --- All 3 port scanners enabled ---
  test('enables all three port scanners', () => {
    expect(FULL_ACTIVE_SCAN.parameters.naabuEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.masscanEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nmapEnabled).toBe(true)
  })

  test('naabu uses active SYN scan, not passive InternetDB', () => {
    expect(FULL_ACTIVE_SCAN.parameters.naabuPassiveMode).toBe(false)
    expect(FULL_ACTIVE_SCAN.parameters.naabuScanType).toBe('s')
  })

  test('nmap has version detection and NSE scripts with aggressive timing', () => {
    expect(FULL_ACTIVE_SCAN.parameters.nmapVersionDetection).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nmapScriptScan).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nmapTimingTemplate).toBe('T4')
  })

  test('masscan has high packet rate and banner grabbing', () => {
    expect(FULL_ACTIVE_SCAN.parameters.masscanRate).toBeGreaterThanOrEqual(5000)
    expect(FULL_ACTIVE_SCAN.parameters.masscanBanners).toBe(true)
  })

  // --- HTTP probing: all probes ON ---
  test('enables httpx with all probe flags', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeStatusCode).toBe(true)
    expect(p.httpxProbeContentLength).toBe(true)
    expect(p.httpxProbeContentType).toBe(true)
    expect(p.httpxProbeTitle).toBe(true)
    expect(p.httpxProbeServer).toBe(true)
    expect(p.httpxProbeResponseTime).toBe(true)
    expect(p.httpxProbeWordCount).toBe(true)
    expect(p.httpxProbeLineCount).toBe(true)
    expect(p.httpxProbeTechDetect).toBe(true)
    expect(p.httpxProbeIp).toBe(true)
    expect(p.httpxProbeCname).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
    expect(p.httpxProbeTlsGrab).toBe(true)
    expect(p.httpxProbeFavicon).toBe(true)
    expect(p.httpxProbeJarm).toBe(true)
    expect(p.httpxProbeAsn).toBe(true)
    expect(p.httpxProbeCdn).toBe(true)
    expect(p.httpxIncludeResponse).toBe(true)
    expect(p.httpxIncludeResponseHeaders).toBe(true)
  })

  // --- Banner grabbing enabled ---
  test('enables banner grabbing with increased limits', () => {
    expect(FULL_ACTIVE_SCAN.parameters.bannerGrabEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.bannerGrabThreads).toBeGreaterThanOrEqual(20)
    expect(FULL_ACTIVE_SCAN.parameters.bannerGrabMaxLength).toBeGreaterThanOrEqual(500)
  })

  // --- Wappalyzer enabled ---
  test('enables wappalyzer technology detection', () => {
    expect(FULL_ACTIVE_SCAN.parameters.wappalyzerEnabled).toBe(true)
  })

  // --- Crawlers: deep aggressive settings ---
  test('enables Katana with deep crawl depth and high URL limit', () => {
    expect(FULL_ACTIVE_SCAN.parameters.katanaEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.katanaDepth).toBeGreaterThanOrEqual(4)
    expect(FULL_ACTIVE_SCAN.parameters.katanaMaxUrls).toBeGreaterThanOrEqual(2000)
    expect(FULL_ACTIVE_SCAN.parameters.katanaJsCrawl).toBe(true)
  })

  test('enables Hakrawler with deep crawl depth', () => {
    expect(FULL_ACTIVE_SCAN.parameters.hakrawlerEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.hakrawlerDepth).toBeGreaterThanOrEqual(4)
    expect(FULL_ACTIVE_SCAN.parameters.hakrawlerIncludeSubs).toBe(true)
  })

  // --- Fuzzing & API discovery enabled ---
  test('enables ffuf with recursion', () => {
    expect(FULL_ACTIVE_SCAN.parameters.ffufEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.ffufRecursion).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.ffufRecursionDepth).toBeGreaterThanOrEqual(2)
    expect(FULL_ACTIVE_SCAN.parameters.ffufSmartFuzz).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.ffufAutoCalibrate).toBe(true)
  })

  test('enables Kiterunner with routes-large wordlist', () => {
    expect(FULL_ACTIVE_SCAN.parameters.kiterunnerEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.kiterunnerWordlists).toContain('routes-large')
    expect(FULL_ACTIVE_SCAN.parameters.kiterunnerDetectMethods).toBe(true)
  })

  test('enables Arjun in active mode with all HTTP methods', () => {
    expect(FULL_ACTIVE_SCAN.parameters.arjunEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.arjunPassive).toBe(false)
    const methods = FULL_ACTIVE_SCAN.parameters.arjunMethods!
    expect(methods).toContain('GET')
    expect(methods).toContain('POST')
    expect(methods).toContain('PUT')
    expect(methods).toContain('DELETE')
    expect(methods).toContain('PATCH')
  })

  // --- Nuclei: full DAST + headless + OOB ---
  test('enables Nuclei with DAST, headless, and interactsh', () => {
    expect(FULL_ACTIVE_SCAN.parameters.nucleiEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiDastMode).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiHeadless).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiInteractsh).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiScanAllIps).toBe(true)
  })

  test('nuclei scans all 4 severity levels', () => {
    const sev = FULL_ACTIVE_SCAN.parameters.nucleiSeverity!
    expect(sev).toContain('critical')
    expect(sev).toContain('high')
    expect(sev).toContain('medium')
    expect(sev).toContain('low')
  })

  test('nuclei has aggressive concurrency settings', () => {
    expect(FULL_ACTIVE_SCAN.parameters.nucleiRateLimit).toBeGreaterThanOrEqual(100)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiConcurrency).toBeGreaterThanOrEqual(25)
    expect(FULL_ACTIVE_SCAN.parameters.nucleiBulkSize).toBeGreaterThanOrEqual(25)
  })

  // --- CVE + MITRE enrichment enabled ---
  test('enables CVE lookup and MITRE enrichment', () => {
    expect(FULL_ACTIVE_SCAN.parameters.cveLookupEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.mitreEnabled).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.mitreIncludeCwe).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.mitreIncludeCapec).toBe(true)
    expect(FULL_ACTIVE_SCAN.parameters.mitreEnrichRecon).toBe(true)
  })

  // --- All 28 security checks enabled ---
  test('enables all security checks', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.securityCheckDirectIpHttp).toBe(true)
    expect(p.securityCheckDirectIpHttps).toBe(true)
    expect(p.securityCheckIpApiExposed).toBe(true)
    expect(p.securityCheckWafBypass).toBe(true)
    expect(p.securityCheckTlsExpiringSoon).toBe(true)
    expect(p.securityCheckMissingReferrerPolicy).toBe(true)
    expect(p.securityCheckMissingPermissionsPolicy).toBe(true)
    expect(p.securityCheckMissingCoop).toBe(true)
    expect(p.securityCheckMissingCorp).toBe(true)
    expect(p.securityCheckMissingCoep).toBe(true)
    expect(p.securityCheckCacheControlMissing).toBe(true)
    expect(p.securityCheckLoginNoHttps).toBe(true)
    expect(p.securityCheckSessionNoSecure).toBe(true)
    expect(p.securityCheckSessionNoHttponly).toBe(true)
    expect(p.securityCheckBasicAuthNoTls).toBe(true)
    expect(p.securityCheckSpfMissing).toBe(true)
    expect(p.securityCheckDmarcMissing).toBe(true)
    expect(p.securityCheckDnssecMissing).toBe(true)
    expect(p.securityCheckZoneTransfer).toBe(true)
    expect(p.securityCheckAdminPortExposed).toBe(true)
    expect(p.securityCheckDatabaseExposed).toBe(true)
    expect(p.securityCheckRedisNoAuth).toBe(true)
    expect(p.securityCheckKubernetesApiExposed).toBe(true)
    expect(p.securityCheckSmtpOpenRelay).toBe(true)
    expect(p.securityCheckCspUnsafeInline).toBe(true)
    expect(p.securityCheckInsecureFormAction).toBe(true)
    expect(p.securityCheckNoRateLimiting).toBe(true)
  })

  // --- Subdomain discovery: all tools + brute force ---
  test('enables all subdomain discovery tools with brute force', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    expect(p.subdomainDiscoveryEnabled).toBe(true)
    expect(p.crtshEnabled).toBe(true)
    expect(p.hackerTargetEnabled).toBe(true)
    expect(p.knockpyReconEnabled).toBe(true)
    expect(p.subfinderEnabled).toBe(true)
    expect(p.amassEnabled).toBe(true)
    expect(p.amassActive).toBe(true)
    expect(p.amassBrute).toBe(true)
    expect(p.purednsEnabled).toBe(true)
    expect(p.useBruteforceForSubdomains).toBe(true)
  })

  // --- CORE INVARIANT: every passive source must be OFF ---
  test('disables GAU (passive archive lookups)', () => {
    expect(FULL_ACTIVE_SCAN.parameters.gauEnabled).toBe(false)
  })

  test('disables ParamSpider (passive Wayback parameters)', () => {
    expect(FULL_ACTIVE_SCAN.parameters.paramspiderEnabled).toBe(false)
  })

  test('enables JS Recon with active crawling and all analysis modules', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    expect(p.jsReconEnabled).toBe(true)
    expect(p.jsReconMaxFiles).toBeGreaterThanOrEqual(1000)
    expect(p.jsReconStandaloneCrawlDepth).toBeGreaterThanOrEqual(4)
    expect(p.jsReconValidateKeys).toBe(true)
    expect(p.jsReconExtractEndpoints).toBe(true)
    expect(p.jsReconRegexPatterns).toBe(true)
    expect(p.jsReconSourceMaps).toBe(true)
    expect(p.jsReconDependencyCheck).toBe(true)
    expect(p.jsReconDomSinks).toBe(true)
    expect(p.jsReconFrameworkDetect).toBe(true)
    expect(p.jsReconDevComments).toBe(true)
    expect(p.jsReconIncludeChunks).toBe(true)
    expect(p.jsReconIncludeFrameworkJs).toBe(true)
  })

  test('disables JS Recon archived JS (passive Wayback source)', () => {
    expect(FULL_ACTIVE_SCAN.parameters.jsReconIncludeArchivedJs).toBe(false)
  })

  test('disables OSINT enrichment master switch', () => {
    expect(FULL_ACTIVE_SCAN.parameters.osintEnrichmentEnabled).toBe(false)
  })

  test('disables every individual OSINT provider', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    expect(p.shodanEnabled).toBe(false)
    expect(p.urlscanEnabled).toBe(false)
    expect(p.otxEnabled).toBe(false)
    expect(p.censysEnabled).toBe(false)
    expect(p.fofaEnabled).toBe(false)
    expect(p.netlasEnabled).toBe(false)
    expect(p.virusTotalEnabled).toBe(false)
    expect(p.zoomEyeEnabled).toBe(false)
    expect(p.criminalIpEnabled).toBe(false)
    expect(p.uncoverEnabled).toBe(false)
  })

  // --- No passive-only source should be enabled ---
  test('no passive-only source is enabled', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    const passiveSources = [
      p.gauEnabled,
      p.paramspiderEnabled,
      p.osintEnrichmentEnabled,
      p.shodanEnabled,
      p.urlscanEnabled,
      p.otxEnabled,
      p.censysEnabled,
      p.fofaEnabled,
      p.netlasEnabled,
      p.virusTotalEnabled,
      p.zoomEyeEnabled,
      p.criminalIpEnabled,
      p.uncoverEnabled,
      p.jsReconIncludeArchivedJs,
    ]
    for (const source of passiveSources) {
      expect(source).toBe(false)
    }
  })

  // --- Every active tool should be enabled ---
  test('every active tool is enabled', () => {
    const p = FULL_ACTIVE_SCAN.parameters
    const activeTools = [
      p.naabuEnabled,
      p.masscanEnabled,
      p.nmapEnabled,
      p.httpxEnabled,
      p.bannerGrabEnabled,
      p.katanaEnabled,
      p.hakrawlerEnabled,
      p.ffufEnabled,
      p.kiterunnerEnabled,
      p.arjunEnabled,
      p.nucleiEnabled,
      p.jsluiceEnabled,
      p.jsReconEnabled,
      p.wappalyzerEnabled,
      p.securityCheckEnabled,
      p.cveLookupEnabled,
      p.mitreEnabled,
    ]
    for (const tool of activeTools) {
      expect(tool).toBe(true)
    }
  })

  // --- Safety: no non-recon fields ---
  test('does not contain non-recon fields', () => {
    const params = FULL_ACTIVE_SCAN.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
    expect(params.hydraEnabled).toBeUndefined()
  })

  // --- Description quality ---
  test('fullDescription contains expected section headers', () => {
    expect(FULL_ACTIVE_SCAN.fullDescription).toContain('### Pipeline Goal')
    expect(FULL_ACTIVE_SCAN.fullDescription).toContain('### Who is this for?')
    expect(FULL_ACTIVE_SCAN.fullDescription).toContain('### What it enables')
    expect(FULL_ACTIVE_SCAN.fullDescription).toContain('### What it disables')
    expect(FULL_ACTIVE_SCAN.fullDescription).toContain('### How it works')
  })

  test('does not contain em dashes', () => {
    expect(FULL_ACTIVE_SCAN.fullDescription).not.toContain('\u2014')
    expect(FULL_ACTIVE_SCAN.shortDescription).not.toContain('\u2014')
  })

  // --- Merge behaviour ---
  test('preserves user fields when applied to a form', () => {
    const form = {
      name: 'My Pentest',
      targetDomain: 'target.com',
      description: 'Authorized engagement',
      agentOpenaiModel: 'claude-opus-4-6',
    }
    const merged = { ...form, ...FULL_ACTIVE_SCAN.parameters } as Record<string, unknown>
    expect(merged.name).toBe('My Pentest')
    expect(merged.targetDomain).toBe('target.com')
    expect(merged.description).toBe('Authorized engagement')
    expect(merged.agentOpenaiModel).toBe('claude-opus-4-6')
    // Preset fields applied
    expect(merged.naabuEnabled).toBe(true)
    expect(merged.nucleiDastMode).toBe(true)
    expect(merged.gauEnabled).toBe(false)
  })

  test('overrides previous passive-heavy preset when applied after', () => {
    // Simulate: user applies Secret Miner first, then switches to Full Active
    const form = { name: 'Test' }
    const afterSecretMiner = { ...form, ...SECRET_MINER.parameters }
    const afterFullActive = { ...afterSecretMiner, ...FULL_ACTIVE_SCAN.parameters }
    // Full Active should override Secret Miner's settings
    expect(afterFullActive.naabuEnabled).toBe(true)     // was false in Secret Miner
    expect(afterFullActive.nucleiEnabled).toBe(true)    // was false in Secret Miner
    expect(afterFullActive.gauEnabled).toBe(false)      // was true in Secret Miner
    expect(afterFullActive.jsReconEnabled).toBe(true)   // both enable it
    expect(afterFullActive.ffufEnabled).toBe(true)      // was false in Secret Miner
  })
})

// ============================================================
// Full Passive Scan preset validation
// ============================================================

describe('Full Pipeline - Passive Only preset', () => {
  test('has correct id and name', () => {
    expect(FULL_PASSIVE_SCAN.id).toBe('full-passive-scan')
    expect(FULL_PASSIVE_SCAN.name).toBe('Full Pipeline - Passive Only')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('full-passive-scan')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('full-passive-scan')
  })

  test('includes domain_discovery, port_scan, resource_enum, vuln_scan (Nuclei OFF)', () => {
    // vuln_scan is the gate that lets CVE lookup + MITRE enrichment execute;
    // Nuclei itself is disabled below so nothing active is sent to the target.
    const modules = FULL_PASSIVE_SCAN.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('http_probe')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(4)
  })

  // --- CORE INVARIANT: no tool that sends packets to the target ---
  test('disables httpx (sends HTTP requests to target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.httpxEnabled).toBe(false)
  })

  test('disables all web crawlers (actively crawl target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.katanaEnabled).toBe(false)
    expect(FULL_PASSIVE_SCAN.parameters.hakrawlerEnabled).toBe(false)
  })

  test('disables jsluice (downloads JS files from target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.jsluiceEnabled).toBe(false)
  })

  test('disables JS Recon (crawls and downloads from target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.jsReconEnabled).toBe(false)
  })

  test('disables fuzzing and brute-force tools', () => {
    expect(FULL_PASSIVE_SCAN.parameters.ffufEnabled).toBe(false)
    expect(FULL_PASSIVE_SCAN.parameters.kiterunnerEnabled).toBe(false)
  })

  test('enables Arjun in passive mode only', () => {
    expect(FULL_PASSIVE_SCAN.parameters.arjunEnabled).toBe(true)
    expect(FULL_PASSIVE_SCAN.parameters.arjunPassive).toBe(true)
  })

  test('disables nuclei vulnerability scanning', () => {
    expect(FULL_PASSIVE_SCAN.parameters.nucleiEnabled).toBe(false)
  })

  test('disables security checks (some connect to target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.securityCheckEnabled).toBe(false)
  })

  test('disables active port scanners (Masscan, Nmap)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.masscanEnabled).toBe(false)
    expect(FULL_PASSIVE_SCAN.parameters.nmapEnabled).toBe(false)
  })

  test('disables banner grabbing (connects to target services)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.bannerGrabEnabled).toBe(false)
  })

  test('disables wappalyzer (needs HTTP responses from target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.wappalyzerEnabled).toBe(false)
  })

  test('Amass is in passive mode only (no active, no brute)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.amassEnabled).toBe(true)
    expect(FULL_PASSIVE_SCAN.parameters.amassActive).toBe(false)
    expect(FULL_PASSIVE_SCAN.parameters.amassBrute).toBe(false)
  })

  test('DNS brute force is disabled', () => {
    expect(FULL_PASSIVE_SCAN.parameters.useBruteforceForSubdomains).toBe(false)
  })

  // --- Aggregate: no active tool is enabled ---
  test('no tool that sends packets to the target is enabled in active mode', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    const activeOnlyTools = [
      p.httpxEnabled,
      p.katanaEnabled,
      p.hakrawlerEnabled,
      p.jsluiceEnabled,
      p.jsReconEnabled,
      p.ffufEnabled,
      p.kiterunnerEnabled,
      p.nucleiEnabled,
      p.masscanEnabled,
      p.nmapEnabled,
      p.bannerGrabEnabled,
      p.wappalyzerEnabled,
      p.securityCheckEnabled,
      p.amassActive,
      p.amassBrute,
      p.useBruteforceForSubdomains,
    ]
    for (const tool of activeOnlyTools) {
      expect(tool).toBe(false)
    }
    // Arjun is enabled but forced to passive mode
    expect(p.arjunEnabled).toBe(true)
    expect(p.arjunPassive).toBe(true)
  })

  // --- Naabu passive mode (InternetDB, zero scanning) ---
  test('naabu uses passive InternetDB mode', () => {
    expect(FULL_PASSIVE_SCAN.parameters.naabuEnabled).toBe(true)
    expect(FULL_PASSIVE_SCAN.parameters.naabuPassiveMode).toBe(true)
  })

  // --- Subdomain discovery: all tools enabled at high limits ---
  test('enables all subdomain discovery tools with high limits', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.subdomainDiscoveryEnabled).toBe(true)
    expect(p.crtshEnabled).toBe(true)
    expect(p.hackerTargetEnabled).toBe(true)
    expect(p.knockpyReconEnabled).toBe(true)
    expect(p.subfinderEnabled).toBe(true)
    expect(p.amassEnabled).toBe(true)
    expect(p.purednsEnabled).toBe(true)
    // High result limits
    expect(p.crtshMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.hackerTargetMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.knockpyReconMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.subfinderMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.amassMaxResults).toBeGreaterThanOrEqual(10000)
  })

  // --- WHOIS & DNS ---
  test('enables WHOIS and DNS lookups', () => {
    expect(FULL_PASSIVE_SCAN.parameters.whoisEnabled).toBe(true)
    expect(FULL_PASSIVE_SCAN.parameters.dnsEnabled).toBe(true)
  })

  // --- GAU: all 4 providers at high limits ---
  test('enables GAU with all providers and high URL limit', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauProviders).toContain('wayback')
    expect(p.gauProviders).toContain('commoncrawl')
    expect(p.gauProviders).toContain('otx')
    expect(p.gauProviders).toContain('urlscan')
    expect(p.gauMaxUrls).toBeGreaterThanOrEqual(10000)
  })

  test('GAU URL verification is disabled (would send requests to target)', () => {
    expect(FULL_PASSIVE_SCAN.parameters.gauVerifyUrls).toBe(false)
    expect(FULL_PASSIVE_SCAN.parameters.gauDetectMethods).toBe(false)
  })

  // --- ParamSpider ---
  test('enables ParamSpider for passive parameter mining', () => {
    expect(FULL_PASSIVE_SCAN.parameters.paramspiderEnabled).toBe(true)
  })

  // --- All 10 OSINT providers enabled ---
  test('enables OSINT enrichment master switch', () => {
    expect(FULL_PASSIVE_SCAN.parameters.osintEnrichmentEnabled).toBe(true)
  })

  test('enables all 10 OSINT providers', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.shodanEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(true)
    expect(p.otxEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
    expect(p.fofaEnabled).toBe(true)
    expect(p.netlasEnabled).toBe(true)
    expect(p.virusTotalEnabled).toBe(true)
    expect(p.zoomEyeEnabled).toBe(true)
    expect(p.criminalIpEnabled).toBe(true)
    expect(p.uncoverEnabled).toBe(true)
  })

  test('Shodan has all passive features enabled', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.shodanHostLookup).toBe(true)
    expect(p.shodanReverseDns).toBe(true)
    expect(p.shodanDomainDns).toBe(true)
    expect(p.shodanPassiveCves).toBe(true)
  })

  test('OSINT providers have high result limits', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.urlscanMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.fofaMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.zoomEyeMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.uncoverMaxResults).toBeGreaterThanOrEqual(1000)
  })

  // --- CVE + MITRE (passive lookups against NVD/offline DB) ---
  test('enables CVE lookup and MITRE enrichment', () => {
    const p = FULL_PASSIVE_SCAN.parameters
    expect(p.cveLookupEnabled).toBe(true)
    expect(p.cveLookupMaxCves).toBeGreaterThanOrEqual(50)
    expect(p.mitreEnabled).toBe(true)
    expect(p.mitreIncludeCwe).toBe(true)
    expect(p.mitreIncludeCapec).toBe(true)
  })

  // --- Safety: no non-recon fields ---
  test('does not contain non-recon fields', () => {
    const params = FULL_PASSIVE_SCAN.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
  })

  // --- Description quality ---
  test('fullDescription contains expected section headers', () => {
    expect(FULL_PASSIVE_SCAN.fullDescription).toContain('### Pipeline Goal')
    expect(FULL_PASSIVE_SCAN.fullDescription).toContain('### Who is this for?')
    expect(FULL_PASSIVE_SCAN.fullDescription).toContain('### What it enables')
    expect(FULL_PASSIVE_SCAN.fullDescription).toContain('### What it disables')
    expect(FULL_PASSIVE_SCAN.fullDescription).toContain('### How it works')
  })

  test('does not contain em dashes', () => {
    expect(FULL_PASSIVE_SCAN.fullDescription).not.toContain('\u2014')
    expect(FULL_PASSIVE_SCAN.shortDescription).not.toContain('\u2014')
  })

  // --- Merge: passive overrides active preset ---
  test('overrides active preset when applied after Full Active', () => {
    const form = { name: 'Test' }
    const afterActive = { ...form, ...FULL_ACTIVE_SCAN.parameters }
    const afterPassive = { ...afterActive, ...FULL_PASSIVE_SCAN.parameters }
    // All active tools should now be OFF
    expect(afterPassive.httpxEnabled).toBe(false)
    expect(afterPassive.nucleiEnabled).toBe(false)
    expect(afterPassive.katanaEnabled).toBe(false)
    expect(afterPassive.ffufEnabled).toBe(false)
    expect(afterPassive.masscanEnabled).toBe(false)
    expect(afterPassive.nmapEnabled).toBe(false)
    // Passive sources should be ON
    expect(afterPassive.gauEnabled).toBe(true)
    expect(afterPassive.osintEnrichmentEnabled).toBe(true)
    expect(afterPassive.shodanEnabled).toBe(true)
    expect(afterPassive.naabuPassiveMode).toBe(true)
  })
})

// ============================================================
// Full Maximum Scan preset validation
// ============================================================

describe('Full Pipeline - Maximum preset', () => {
  test('has correct id and name', () => {
    expect(FULL_MAXIMUM_SCAN.id).toBe('full-maximum-scan')
    expect(FULL_MAXIMUM_SCAN.name).toBe('Full Pipeline - Maximum')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('full-maximum-scan')).toBeDefined()
  })

  test('includes all 6 scan modules', () => {
    const modules = FULL_MAXIMUM_SCAN.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).toContain('js_recon')
    expect(modules).toHaveLength(6)
  })

  // --- CORE INVARIANT: every tool must be enabled ---
  test('every tool is enabled', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    const allTools = [
      p.naabuEnabled,
      p.masscanEnabled,
      p.nmapEnabled,
      p.httpxEnabled,
      p.bannerGrabEnabled,
      p.wappalyzerEnabled,
      p.katanaEnabled,
      p.hakrawlerEnabled,
      p.gauEnabled,
      p.paramspiderEnabled,
      p.jsluiceEnabled,
      p.jsReconEnabled,
      p.ffufEnabled,
      p.kiterunnerEnabled,
      p.arjunEnabled,
      p.nucleiEnabled,
      p.securityCheckEnabled,
      p.cveLookupEnabled,
      p.mitreEnabled,
      p.osintEnrichmentEnabled,
      p.shodanEnabled,
      p.urlscanEnabled,
      p.otxEnabled,
      p.censysEnabled,
      p.fofaEnabled,
      p.netlasEnabled,
      p.virusTotalEnabled,
      p.zoomEyeEnabled,
      p.criminalIpEnabled,
      p.uncoverEnabled,
    ]
    for (const tool of allTools) {
      expect(tool).toBe(true)
    }
  })

  // --- Parameters must be higher than defaults ---
  test('subdomain tools have high result limits', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.crtshMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.hackerTargetMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.subfinderMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.amassMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.knockpyReconMaxResults).toBeGreaterThanOrEqual(10000)
  })

  test('Amass uses active mode with brute force', () => {
    expect(FULL_MAXIMUM_SCAN.parameters.amassActive).toBe(true)
    expect(FULL_MAXIMUM_SCAN.parameters.amassBrute).toBe(true)
    expect(FULL_MAXIMUM_SCAN.parameters.useBruteforceForSubdomains).toBe(true)
  })

  test('port scanners have aggressive settings', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.naabuPassiveMode).toBe(false)
    expect(p.naabuScanType).toBe('s')
    expect(p.masscanRate).toBeGreaterThanOrEqual(10000)
    expect(p.nmapTimingTemplate).toBe('T4')
    expect(p.nmapVersionDetection).toBe(true)
    expect(p.nmapScriptScan).toBe(true)
  })

  test('crawlers have high depth and URL limits', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.katanaDepth).toBeGreaterThanOrEqual(5)
    expect(p.katanaMaxUrls).toBeGreaterThanOrEqual(5000)
    expect(p.hakrawlerDepth).toBeGreaterThanOrEqual(5)
    expect(p.hakrawlerMaxUrls).toBeGreaterThanOrEqual(2000)
  })

  test('GAU has all providers and high URL limit', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.gauProviders).toContain('wayback')
    expect(p.gauProviders).toContain('commoncrawl')
    expect(p.gauProviders).toContain('otx')
    expect(p.gauProviders).toContain('urlscan')
    expect(p.gauMaxUrls).toBeGreaterThanOrEqual(10000)
    expect(p.gauVerifyUrls).toBe(true)
    expect(p.gauDetectMethods).toBe(true)
  })

  test('JS analysis has high file limits', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.jsluiceMaxFiles).toBeGreaterThanOrEqual(1000)
    expect(p.jsReconMaxFiles).toBeGreaterThanOrEqual(2000)
    expect(p.jsReconStandaloneCrawlDepth).toBeGreaterThanOrEqual(5)
    expect(p.jsReconIncludeArchivedJs).toBe(true)
  })

  test('ffuf has deep recursion', () => {
    expect(FULL_MAXIMUM_SCAN.parameters.ffufRecursion).toBe(true)
    expect(FULL_MAXIMUM_SCAN.parameters.ffufRecursionDepth).toBeGreaterThanOrEqual(3)
  })

  test('Arjun uses all HTTP methods with high endpoints limit', () => {
    const methods = FULL_MAXIMUM_SCAN.parameters.arjunMethods!
    expect(methods).toHaveLength(5)
    expect(FULL_MAXIMUM_SCAN.parameters.arjunMaxEndpoints).toBeGreaterThanOrEqual(200)
  })

  test('Nuclei has DAST, headless, interactsh, and high concurrency', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.nucleiDastMode).toBe(true)
    expect(p.nucleiHeadless).toBe(true)
    expect(p.nucleiInteractsh).toBe(true)
    expect(p.nucleiScanAllIps).toBe(true)
    expect(p.nucleiRateLimit).toBeGreaterThanOrEqual(200)
    expect(p.nucleiConcurrency).toBeGreaterThanOrEqual(75)
  })

  test('OSINT providers have high result limits', () => {
    const p = FULL_MAXIMUM_SCAN.parameters
    expect(p.urlscanMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.fofaMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.zoomEyeMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.uncoverMaxResults).toBeGreaterThanOrEqual(1000)
  })

  test('CVE lookup has high max per service', () => {
    expect(FULL_MAXIMUM_SCAN.parameters.cveLookupMaxCves).toBeGreaterThanOrEqual(50)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = FULL_MAXIMUM_SCAN.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
  })

  test('fullDescription contains expected section headers', () => {
    expect(FULL_MAXIMUM_SCAN.fullDescription).toContain('### Pipeline Goal')
    expect(FULL_MAXIMUM_SCAN.fullDescription).toContain('### Who is this for?')
    expect(FULL_MAXIMUM_SCAN.fullDescription).toContain('### What it enables')
    expect(FULL_MAXIMUM_SCAN.fullDescription).toContain('### What it disables')
  })

  test('does not contain em dashes', () => {
    expect(FULL_MAXIMUM_SCAN.fullDescription).not.toContain('\u2014')
    expect(FULL_MAXIMUM_SCAN.shortDescription).not.toContain('\u2014')
  })

  // --- This preset must be a superset of both active and passive ---
  test('enables everything that Full Active enables', () => {
    const max = FULL_MAXIMUM_SCAN.parameters
    const active = FULL_ACTIVE_SCAN.parameters
    // All active tools enabled in Full Active must also be enabled in Maximum
    expect(max.naabuEnabled).toBe(active.naabuEnabled)
    expect(max.masscanEnabled).toBe(active.masscanEnabled)
    expect(max.nmapEnabled).toBe(active.nmapEnabled)
    expect(max.katanaEnabled).toBe(active.katanaEnabled)
    expect(max.ffufEnabled).toBe(active.ffufEnabled)
    expect(max.nucleiEnabled).toBe(active.nucleiEnabled)
  })

  test('enables everything that Full Passive enables', () => {
    const max = FULL_MAXIMUM_SCAN.parameters
    const passive = FULL_PASSIVE_SCAN.parameters
    // All passive sources enabled in Full Passive must also be enabled in Maximum
    expect(max.gauEnabled).toBe(passive.gauEnabled)
    expect(max.osintEnrichmentEnabled).toBe(passive.osintEnrichmentEnabled)
    expect(max.shodanEnabled).toBe(passive.shodanEnabled)
    expect(max.censysEnabled).toBe(passive.censysEnabled)
    expect(max.virusTotalEnabled).toBe(passive.virusTotalEnabled)
  })
})

// ============================================================
// Bug Bounty Quick preset validation
// ============================================================

describe('Bug Bounty - Quick Wins preset', () => {
  test('has correct id and name', () => {
    expect(BUG_BOUNTY_QUICK.id).toBe('bug-bounty-quick')
    expect(BUG_BOUNTY_QUICK.name).toBe('Bug Bounty - Quick Wins')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('bug-bounty-quick')).toBeDefined()
  })

  // --- Speed-optimized module selection ---
  test('skips port_scan and js_recon modules for speed', () => {
    const modules = BUG_BOUNTY_QUICK.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(4)
  })

  // --- Fast tools enabled ---
  test('enables subdomain discovery with all tools', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.subdomainDiscoveryEnabled).toBe(true)
    expect(p.crtshEnabled).toBe(true)
    expect(p.hackerTargetEnabled).toBe(true)
    expect(p.knockpyReconEnabled).toBe(true)
    expect(p.subfinderEnabled).toBe(true)
    expect(p.amassEnabled).toBe(true)
  })

  test('Amass runs in passive mode only (no brute force for speed)', () => {
    expect(BUG_BOUNTY_QUICK.parameters.amassActive).toBe(false)
    expect(BUG_BOUNTY_QUICK.parameters.amassBrute).toBe(false)
    expect(BUG_BOUNTY_QUICK.parameters.useBruteforceForSubdomains).toBe(false)
  })

  test('enables httpx with essential probes only', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeStatusCode).toBe(true)
    expect(p.httpxProbeTitle).toBe(true)
    expect(p.httpxProbeTechDetect).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
    // Heavy probes disabled for speed
    expect(p.httpxProbeJarm).toBe(false)
    expect(p.httpxProbeFavicon).toBe(false)
    expect(p.httpxProbeAsn).toBe(false)
    expect(p.httpxProbeCdn).toBe(false)
    expect(p.httpxIncludeResponse).toBe(false)
    expect(p.httpxIncludeResponseHeaders).toBe(false)
  })

  test('enables Katana with shallow depth for speed', () => {
    expect(BUG_BOUNTY_QUICK.parameters.katanaEnabled).toBe(true)
    expect(BUG_BOUNTY_QUICK.parameters.katanaDepth).toBe(1)
    expect(BUG_BOUNTY_QUICK.parameters.katanaMaxUrls).toBeLessThanOrEqual(200)
  })

  test('enables jsluice with low file cap', () => {
    expect(BUG_BOUNTY_QUICK.parameters.jsluiceEnabled).toBe(true)
    expect(BUG_BOUNTY_QUICK.parameters.jsluiceMaxFiles).toBeLessThanOrEqual(50)
    expect(BUG_BOUNTY_QUICK.parameters.jsluiceExtractSecrets).toBe(true)
  })

  test('enables Nuclei with critical+high only for quick wins', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiSeverity).toContain('critical')
    expect(p.nucleiSeverity).toContain('high')
    expect(p.nucleiSeverity).not.toContain('medium')
    expect(p.nucleiSeverity).not.toContain('low')
    expect(p.nucleiDastMode).toBe(true)
    expect(p.nucleiHeadless).toBe(false)
  })

  test('enables security checks for header/TLS quick wins', () => {
    expect(BUG_BOUNTY_QUICK.parameters.securityCheckEnabled).toBe(true)
  })

  // --- Slow tools disabled ---
  test('disables all port scanners', () => {
    expect(BUG_BOUNTY_QUICK.parameters.naabuEnabled).toBe(false)
    expect(BUG_BOUNTY_QUICK.parameters.masscanEnabled).toBe(false)
    expect(BUG_BOUNTY_QUICK.parameters.nmapEnabled).toBe(false)
  })

  test('disables slow enumeration tools', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
  })

  test('disables all OSINT and enrichment', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = BUG_BOUNTY_QUICK.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(BUG_BOUNTY_QUICK.fullDescription).not.toContain('\u2014')
    expect(BUG_BOUNTY_QUICK.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(BUG_BOUNTY_QUICK.fullDescription).toContain('### Pipeline Goal')
    expect(BUG_BOUNTY_QUICK.fullDescription).toContain('### Who is this for?')
    expect(BUG_BOUNTY_QUICK.fullDescription).toContain('### What it enables')
    expect(BUG_BOUNTY_QUICK.fullDescription).toContain('### What it disables')
  })

  // --- Speed invariants: parameters must be at or below defaults ---
  test('Nuclei is configured for speed over thoroughness', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    expect(p.nucleiHeadless).toBe(false)
    expect(p.nucleiScanAllIps).toBe(false)
    expect(p.nucleiRetries).toBeLessThanOrEqual(1)
    expect(p.nucleiRateLimit).toBeGreaterThanOrEqual(100)
    expect(p.nucleiConcurrency).toBeGreaterThanOrEqual(25)
  })

  test('Katana timeout is capped for speed', () => {
    expect(BUG_BOUNTY_QUICK.parameters.katanaTimeout).toBeLessThanOrEqual(600)
  })

  test('all parameters stay within quick-scan budget', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    // Crawl depth and URL limits must be minimal
    expect(p.katanaDepth).toBeLessThanOrEqual(1)
    expect(p.katanaMaxUrls).toBeLessThanOrEqual(200)
    expect(p.jsluiceMaxFiles).toBeLessThanOrEqual(50)
    // No slow brute-forcing
    expect(p.amassActive).toBe(false)
    expect(p.amassBrute).toBe(false)
    expect(p.useBruteforceForSubdomains).toBe(false)
  })

  test('only enables tools that produce direct vulnerability findings', () => {
    const p = BUG_BOUNTY_QUICK.parameters
    // Tools that find vulnerabilities directly
    expect(p.nucleiEnabled).toBe(true)
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.jsluiceExtractSecrets).toBe(true)
    // Tools that only enrich/classify (no direct findings) are off
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
  })
})

// ============================================================
// Bug Bounty Deep Dive preset validation
// ============================================================

describe('Bug Bounty - Deep Dive preset', () => {
  test('has correct id and name', () => {
    expect(BUG_BOUNTY_DEEP.id).toBe('bug-bounty-deep')
    expect(BUG_BOUNTY_DEEP.name).toBe('Bug Bounty - Deep Dive')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('bug-bounty-deep')).toBeDefined()
  })

  test('includes 5 modules with js_recon but no port_scan', () => {
    const modules = BUG_BOUNTY_DEEP.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).toContain('js_recon')
    expect(modules).not.toContain('port_scan')
    expect(modules).toHaveLength(5)
  })

  // --- Deeper than Quick, more conservative than Full Active ---
  test('crawlers go deeper than Bug Bounty Quick', () => {
    expect(BUG_BOUNTY_DEEP.parameters.katanaDepth).toBeGreaterThan(BUG_BOUNTY_QUICK.parameters.katanaDepth!)
    expect(BUG_BOUNTY_DEEP.parameters.katanaMaxUrls).toBeGreaterThan(BUG_BOUNTY_QUICK.parameters.katanaMaxUrls!)
  })

  test('Nuclei covers all severities unlike Quick preset', () => {
    const sev = BUG_BOUNTY_DEEP.parameters.nucleiSeverity!
    expect(sev).toContain('critical')
    expect(sev).toContain('high')
    expect(sev).toContain('medium')
    expect(sev).toContain('low')
  })

  // --- Deep crawling enabled ---
  test('enables Katana with deep crawl and JS crawling', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaDepth).toBeGreaterThanOrEqual(3)
    expect(p.katanaMaxUrls).toBeGreaterThanOrEqual(1500)
    expect(p.katanaJsCrawl).toBe(true)
  })

  test('enables Hakrawler for complementary crawling', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.hakrawlerEnabled).toBe(true)
    expect(p.hakrawlerDepth).toBeGreaterThanOrEqual(3)
    expect(p.hakrawlerIncludeSubs).toBe(true)
  })

  test('enables GAU with all providers for historical URLs', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauProviders).toContain('wayback')
    expect(p.gauProviders).toContain('commoncrawl')
    expect(p.gauMaxUrls).toBeGreaterThanOrEqual(5000)
    expect(p.gauVerifyUrls).toBe(true)
  })

  // --- JS analysis enabled ---
  test('enables jsluice with moderate file limit', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.jsluiceEnabled).toBe(true)
    expect(p.jsluiceMaxFiles).toBeGreaterThanOrEqual(300)
    expect(p.jsluiceExtractSecrets).toBe(true)
  })

  test('enables JS Recon with full analysis suite', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.jsReconEnabled).toBe(true)
    expect(p.jsReconMaxFiles).toBeGreaterThanOrEqual(800)
    expect(p.jsReconSourceMaps).toBe(true)
    expect(p.jsReconDomSinks).toBe(true)
    expect(p.jsReconDependencyCheck).toBe(true)
    expect(p.jsReconValidateKeys).toBe(true)
    expect(p.jsReconDevComments).toBe(true)
  })

  // --- Parameter discovery but no brute-force ---
  test('enables Arjun for parameter discovery', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.arjunEnabled).toBe(true)
    expect(p.arjunMethods).toContain('GET')
    expect(p.arjunMethods).toContain('POST')
    expect(p.arjunPassive).toBe(false)
  })

  // --- Noisy brute-force tools disabled to avoid IP bans ---
  test('disables noisy brute-force tools', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.amassActive).toBe(false)
    expect(p.amassBrute).toBe(false)
  })

  // --- Port scanning disabled (web-focused) ---
  test('disables all port scanners', () => {
    expect(BUG_BOUNTY_DEEP.parameters.naabuEnabled).toBe(false)
    expect(BUG_BOUNTY_DEEP.parameters.masscanEnabled).toBe(false)
    expect(BUG_BOUNTY_DEEP.parameters.nmapEnabled).toBe(false)
  })

  // --- OSINT disabled (not bounty-relevant) ---
  test('disables all OSINT enrichment', () => {
    expect(BUG_BOUNTY_DEEP.parameters.osintEnrichmentEnabled).toBe(false)
  })

  // --- CVE + MITRE enabled (unlike Quick) ---
  test('enables CVE lookup and MITRE enrichment', () => {
    expect(BUG_BOUNTY_DEEP.parameters.cveLookupEnabled).toBe(true)
    expect(BUG_BOUNTY_DEEP.parameters.mitreEnabled).toBe(true)
  })

  // --- Moderate rate limiting to avoid bans ---
  test('uses moderate rate limits to avoid WAF blocks', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.katanaRateLimit).toBeLessThanOrEqual(50)
    expect(p.httpxRateLimit).toBeLessThanOrEqual(50)
    expect(p.nucleiRateLimit).toBeLessThanOrEqual(100)
  })

  // --- Nuclei: thorough but not headless ---
  test('Nuclei uses DAST and Interactsh but not headless', () => {
    const p = BUG_BOUNTY_DEEP.parameters
    expect(p.nucleiDastMode).toBe(true)
    expect(p.nucleiInteractsh).toBe(true)
    expect(p.nucleiHeadless).toBe(false)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = BUG_BOUNTY_DEEP.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(BUG_BOUNTY_DEEP.fullDescription).not.toContain('\u2014')
    expect(BUG_BOUNTY_DEEP.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(BUG_BOUNTY_DEEP.fullDescription).toContain('### Pipeline Goal')
    expect(BUG_BOUNTY_DEEP.fullDescription).toContain('### Who is this for?')
    expect(BUG_BOUNTY_DEEP.fullDescription).toContain('### What it enables')
    expect(BUG_BOUNTY_DEEP.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// API Security Audit preset validation
// ============================================================

describe('API Security Audit preset', () => {
  test('has correct id and name', () => {
    expect(API_SECURITY.id).toBe('api-security')
    expect(API_SECURITY.name).toBe('API Security Audit')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('api-security')).toBeDefined()
  })

  test('includes 5 modules with port_scan (for non-standard API ports)', () => {
    const modules = API_SECURITY.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(5)
  })

  // --- API discovery triad: Kiterunner + Arjun + ffuf ---
  test('enables Kiterunner with routes-large wordlist and method detection', () => {
    const p = API_SECURITY.parameters
    expect(p.kiterunnerEnabled).toBe(true)
    expect(p.kiterunnerWordlists).toContain('routes-large')
    expect(p.kiterunnerDetectMethods).toBe(true)
    expect(p.kiterunnerBruteforceMethods).toContain('POST')
    expect(p.kiterunnerBruteforceMethods).toContain('PUT')
    expect(p.kiterunnerBruteforceMethods).toContain('DELETE')
    expect(p.kiterunnerBruteforceMethods).toContain('PATCH')
  })

  test('enables Arjun with all 5 HTTP methods for parameter discovery', () => {
    const p = API_SECURITY.parameters
    expect(p.arjunEnabled).toBe(true)
    expect(p.arjunPassive).toBe(false)
    const methods = p.arjunMethods!
    expect(methods).toContain('GET')
    expect(methods).toContain('POST')
    expect(methods).toContain('PUT')
    expect(methods).toContain('DELETE')
    expect(methods).toContain('PATCH')
    expect(p.arjunMaxEndpoints).toBeGreaterThanOrEqual(150)
  })

  test('enables ffuf with API-specific extensions', () => {
    const p = API_SECURITY.parameters
    expect(p.ffufEnabled).toBe(true)
    expect(p.ffufSmartFuzz).toBe(true)
    expect(p.ffufAutoCalibrate).toBe(true)
    const exts = p.ffufExtensions!
    expect(exts).toContain('.json')
    expect(exts).toContain('.xml')
    expect(exts).toContain('.graphql')
    expect(exts).toContain('.yaml')
  })

  // --- Supporting tools ---
  test('enables Katana with JS crawl for API endpoint discovery in frontend', () => {
    expect(API_SECURITY.parameters.katanaEnabled).toBe(true)
    expect(API_SECURITY.parameters.katanaJsCrawl).toBe(true)
  })

  test('enables jsluice for API endpoint extraction from JS', () => {
    expect(API_SECURITY.parameters.jsluiceEnabled).toBe(true)
    expect(API_SECURITY.parameters.jsluiceExtractUrls).toBe(true)
  })

  test('enables httpx with response capture for API detection', () => {
    expect(API_SECURITY.parameters.httpxEnabled).toBe(true)
    expect(API_SECURITY.parameters.httpxIncludeResponse).toBe(true)
    expect(API_SECURITY.parameters.httpxIncludeResponseHeaders).toBe(true)
  })

  test('enables Nuclei with DAST and Interactsh for API vuln testing', () => {
    const p = API_SECURITY.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiDastMode).toBe(true)
    expect(p.nucleiInteractsh).toBe(true)
  })

  // --- Non-API tools disabled ---
  test('disables tools not relevant to API testing', () => {
    const p = API_SECURITY.parameters
    // Naabu is ON with scoped API ports (Apollo/Hasura/Node/Flask) so httpx sees non-standard ports
    expect(p.naabuEnabled).toBe(true)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
  })

  test('Naabu scoped to common API ports (4000/3000/8080/etc.)', () => {
    const p = API_SECURITY.parameters as Record<string, unknown>
    const ports = p.naabuCustomPorts as string
    expect(ports).toMatch(/4000/)
    expect(ports).toMatch(/3000/)
    expect(ports).toMatch(/8080/)
    expect(ports).toMatch(/8443/)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = API_SECURITY.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(API_SECURITY.fullDescription).not.toContain('\u2014')
    expect(API_SECURITY.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(API_SECURITY.fullDescription).toContain('### Pipeline Goal')
    expect(API_SECURITY.fullDescription).toContain('### Who is this for?')
    expect(API_SECURITY.fullDescription).toContain('### What it enables')
    expect(API_SECURITY.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// Infrastructure Mapper preset validation
// ============================================================

describe('Infrastructure Mapper preset', () => {
  test('has correct id and name', () => {
    expect(INFRASTRUCTURE_MAPPER.id).toBe('infrastructure-mapper')
    expect(INFRASTRUCTURE_MAPPER.name).toBe('Infrastructure Mapper')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('infrastructure-mapper')).toBeDefined()
  })

  test('includes domain_discovery, port_scan, http_probe, vuln_scan (Nuclei OFF)', () => {
    // vuln_scan is the gate that lets CVE lookup + MITRE enrichment + 27
    // security checks execute. Nuclei itself is disabled (this preset maps
    // infrastructure, not vuln-tests it).
    const modules = INFRASTRUCTURE_MAPPER.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('resource_enum')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(4)
  })

  // --- All 3 port scanners enabled ---
  test('enables all three port scanners', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.naabuEnabled).toBe(true)
    expect(p.masscanEnabled).toBe(true)
    expect(p.nmapEnabled).toBe(true)
  })

  test('Naabu uses active SYN scan', () => {
    expect(INFRASTRUCTURE_MAPPER.parameters.naabuPassiveMode).toBe(false)
    expect(INFRASTRUCTURE_MAPPER.parameters.naabuScanType).toBe('s')
  })

  test('Nmap has version detection and NSE vuln scripts with T4 timing', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.nmapVersionDetection).toBe(true)
    expect(p.nmapScriptScan).toBe(true)
    expect(p.nmapTimingTemplate).toBe('T4')
  })

  test('Masscan has high packet rate', () => {
    expect(INFRASTRUCTURE_MAPPER.parameters.masscanRate).toBeGreaterThanOrEqual(5000)
    expect(INFRASTRUCTURE_MAPPER.parameters.masscanBanners).toBe(true)
  })

  // --- Banner grabbing for non-HTTP services ---
  test('enables banner grabbing with high threads and large buffer', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.bannerGrabEnabled).toBe(true)
    expect(p.bannerGrabThreads).toBeGreaterThanOrEqual(30)
    expect(p.bannerGrabMaxLength).toBeGreaterThanOrEqual(1500)
  })

  // --- httpx with full probes for web services ---
  test('enables httpx with full fingerprinting probes', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeTechDetect).toBe(true)
    expect(p.httpxProbeJarm).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
    expect(p.httpxProbeAsn).toBe(true)
    expect(p.httpxProbeCdn).toBe(true)
  })

  // --- Infrastructure OSINT: Shodan + Censys only ---
  test('enables Shodan with host lookup and passive CVEs', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.shodanHostLookup).toBe(true)
    expect(p.shodanReverseDns).toBe(true)
    expect(p.shodanPassiveCves).toBe(true)
  })

  test('enables Censys for host context', () => {
    expect(INFRASTRUCTURE_MAPPER.parameters.censysEnabled).toBe(true)
  })

  test('disables non-infrastructure OSINT providers', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.urlscanEnabled).toBe(false)
    expect(p.otxEnabled).toBe(false)
    expect(p.fofaEnabled).toBe(false)
    expect(p.netlasEnabled).toBe(false)
    expect(p.virusTotalEnabled).toBe(false)
    expect(p.zoomEyeEnabled).toBe(false)
    expect(p.criminalIpEnabled).toBe(false)
    expect(p.uncoverEnabled).toBe(false)
  })

  // --- CVE + MITRE for vulnerability mapping ---
  test('enables CVE lookup with high max per service', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.cveLookupEnabled).toBe(true)
    expect(p.cveLookupMaxCves).toBeGreaterThanOrEqual(40)
  })

  test('enables MITRE enrichment', () => {
    expect(INFRASTRUCTURE_MAPPER.parameters.mitreEnabled).toBe(true)
    expect(INFRASTRUCTURE_MAPPER.parameters.mitreIncludeCwe).toBe(true)
    expect(INFRASTRUCTURE_MAPPER.parameters.mitreIncludeCapec).toBe(true)
  })

  // --- All web-layer tools disabled ---
  test('disables all web crawling and fuzzing tools', () => {
    const p = INFRASTRUCTURE_MAPPER.parameters
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.nucleiEnabled).toBe(false)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = INFRASTRUCTURE_MAPPER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(INFRASTRUCTURE_MAPPER.fullDescription).not.toContain('\u2014')
    expect(INFRASTRUCTURE_MAPPER.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(INFRASTRUCTURE_MAPPER.fullDescription).toContain('### Pipeline Goal')
    expect(INFRASTRUCTURE_MAPPER.fullDescription).toContain('### Who is this for?')
    expect(INFRASTRUCTURE_MAPPER.fullDescription).toContain('### What it enables')
    expect(INFRASTRUCTURE_MAPPER.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// OSINT Investigator preset validation
// ============================================================

describe('OSINT Investigator preset', () => {
  test('has correct id and name', () => {
    expect(OSINT_INVESTIGATOR.id).toBe('osint-investigator')
    expect(OSINT_INVESTIGATOR.name).toBe('OSINT Investigator')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('osint-investigator')).toBeDefined()
  })

  test('includes domain_discovery, port_scan, resource_enum, vuln_scan (Nuclei OFF)', () => {
    // vuln_scan is the gate that lets CVE lookup + MITRE enrichment execute;
    // Nuclei itself is disabled below so nothing active is sent to the target.
    const modules = OSINT_INVESTIGATOR.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('http_probe')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(4)
  })

  // --- All 10 OSINT providers enabled at max ---
  test('enables all 10 OSINT providers', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(true)
    expect(p.otxEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
    expect(p.fofaEnabled).toBe(true)
    expect(p.netlasEnabled).toBe(true)
    expect(p.virusTotalEnabled).toBe(true)
    expect(p.zoomEyeEnabled).toBe(true)
    expect(p.criminalIpEnabled).toBe(true)
    expect(p.uncoverEnabled).toBe(true)
  })

  test('Shodan has all features enabled including domain DNS', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.shodanHostLookup).toBe(true)
    expect(p.shodanReverseDns).toBe(true)
    expect(p.shodanDomainDns).toBe(true)
    expect(p.shodanPassiveCves).toBe(true)
  })

  test('OSINT providers have maximum result limits', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.urlscanMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.fofaMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.zoomEyeMaxResults).toBeGreaterThanOrEqual(5000)
    expect(p.uncoverMaxResults).toBeGreaterThanOrEqual(1000)
  })

  // --- Passive archive discovery ---
  test('enables GAU with all providers and high limits', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauProviders).toHaveLength(4)
    expect(p.gauMaxUrls).toBeGreaterThanOrEqual(10000)
  })

  test('GAU verification disabled (would send requests to target)', () => {
    expect(OSINT_INVESTIGATOR.parameters.gauVerifyUrls).toBe(false)
    expect(OSINT_INVESTIGATOR.parameters.gauDetectMethods).toBe(false)
  })

  test('enables ParamSpider and Arjun passive mode', () => {
    expect(OSINT_INVESTIGATOR.parameters.paramspiderEnabled).toBe(true)
    expect(OSINT_INVESTIGATOR.parameters.arjunEnabled).toBe(true)
    expect(OSINT_INVESTIGATOR.parameters.arjunPassive).toBe(true)
  })

  // --- Subdomain discovery at max ---
  test('enables all subdomain tools with high limits', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.subdomainDiscoveryEnabled).toBe(true)
    expect(p.crtshMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.subfinderMaxResults).toBeGreaterThanOrEqual(10000)
    expect(p.amassMaxResults).toBeGreaterThanOrEqual(10000)
  })

  // --- Naabu passive only ---
  test('Naabu uses passive InternetDB mode', () => {
    expect(OSINT_INVESTIGATOR.parameters.naabuEnabled).toBe(true)
    expect(OSINT_INVESTIGATOR.parameters.naabuPassiveMode).toBe(true)
  })

  // --- No active tool that touches the target ---
  test('disables all tools that send packets to the target', () => {
    const p = OSINT_INVESTIGATOR.parameters
    expect(p.httpxEnabled).toBe(false)
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.nucleiEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
    expect(p.amassActive).toBe(false)
    expect(p.amassBrute).toBe(false)
  })

  // --- CVE + MITRE ---
  test('enables CVE lookup and MITRE enrichment', () => {
    expect(OSINT_INVESTIGATOR.parameters.cveLookupEnabled).toBe(true)
    expect(OSINT_INVESTIGATOR.parameters.cveLookupMaxCves).toBeGreaterThanOrEqual(50)
    expect(OSINT_INVESTIGATOR.parameters.mitreEnabled).toBe(true)
  })

  // --- Difference from Full Passive: OSINT Investigator is purely about intelligence ---
  test('has same OSINT coverage as Full Passive preset', () => {
    // Both should enable all 11 providers
    expect(OSINT_INVESTIGATOR.parameters.osintEnrichmentEnabled)
      .toBe(FULL_PASSIVE_SCAN.parameters.osintEnrichmentEnabled)
    expect(OSINT_INVESTIGATOR.parameters.shodanEnabled)
      .toBe(FULL_PASSIVE_SCAN.parameters.shodanEnabled)
    expect(OSINT_INVESTIGATOR.parameters.censysEnabled)
      .toBe(FULL_PASSIVE_SCAN.parameters.censysEnabled)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = OSINT_INVESTIGATOR.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(OSINT_INVESTIGATOR.fullDescription).not.toContain('\u2014')
    expect(OSINT_INVESTIGATOR.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(OSINT_INVESTIGATOR.fullDescription).toContain('### Pipeline Goal')
    expect(OSINT_INVESTIGATOR.fullDescription).toContain('### Who is this for?')
    expect(OSINT_INVESTIGATOR.fullDescription).toContain('### What it enables')
    expect(OSINT_INVESTIGATOR.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// Web App Pentester preset validation
// ============================================================

describe('Web App Pentester preset', () => {
  test('has correct id and name', () => {
    expect(WEB_APP_PENTESTER.id).toBe('web-app-pentester')
    expect(WEB_APP_PENTESTER.name).toBe('Web App Pentester')
  })

  test('is findable by getPresetById', () => {
    expect(getPresetById('web-app-pentester')).toBeDefined()
  })

  test('includes 4 web-focused modules, no port_scan or js_recon', () => {
    const modules = WEB_APP_PENTESTER.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('js_recon')
    expect(modules).toHaveLength(4)
  })

  // --- Deep crawling from multiple engines ---
  test('enables Katana with deep crawl', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaDepth).toBeGreaterThanOrEqual(4)
    expect(p.katanaMaxUrls).toBeGreaterThanOrEqual(2000)
    expect(p.katanaJsCrawl).toBe(true)
  })

  test('enables Hakrawler with deep crawl', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.hakrawlerEnabled).toBe(true)
    expect(p.hakrawlerDepth).toBeGreaterThanOrEqual(4)
  })

  test('enables GAU and ParamSpider for historical endpoints', () => {
    expect(WEB_APP_PENTESTER.parameters.gauEnabled).toBe(true)
    expect(WEB_APP_PENTESTER.parameters.paramspiderEnabled).toBe(true)
  })

  // --- ffuf with web-specific extensions and recursion ---
  test('enables ffuf with recursion and web extensions', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.ffufEnabled).toBe(true)
    expect(p.ffufRecursion).toBe(true)
    expect(p.ffufRecursionDepth).toBeGreaterThanOrEqual(2)
    expect(p.ffufSmartFuzz).toBe(true)
    const exts = p.ffufExtensions!
    expect(exts).toContain('.php')
    expect(exts).toContain('.asp')
    expect(exts).toContain('.aspx')
    expect(exts).toContain('.jsp')
    expect(exts).toContain('.bak')
    expect(exts).toContain('.old')
    expect(exts).toContain('.config')
  })

  // --- Parameter discovery ---
  test('enables Arjun with all HTTP methods', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.arjunEnabled).toBe(true)
    expect(p.arjunPassive).toBe(false)
    expect(p.arjunMethods).toHaveLength(5)
  })

  // --- Nuclei DAST ---
  test('enables Nuclei with all severities and DAST', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiDastMode).toBe(true)
    expect(p.nucleiInteractsh).toBe(true)
    expect(p.nucleiSeverity).toHaveLength(4)
  })

  // --- Web fingerprinting ---
  test('enables httpx with all probes and Wappalyzer', () => {
    expect(WEB_APP_PENTESTER.parameters.httpxEnabled).toBe(true)
    expect(WEB_APP_PENTESTER.parameters.httpxIncludeResponse).toBe(true)
    expect(WEB_APP_PENTESTER.parameters.wappalyzerEnabled).toBe(true)
  })

  // --- Non-web tools disabled ---
  test('disables network-layer tools', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.naabuEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
  })

  test('disables Kiterunner, JS Recon, OSINT, CVE lookup', () => {
    const p = WEB_APP_PENTESTER.parameters
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
  })

  // --- Differentiator: ffuf extensions vs API Security preset ---
  test('uses web extensions not API extensions (differs from API Security)', () => {
    const webExts = WEB_APP_PENTESTER.parameters.ffufExtensions!
    const apiExts = API_SECURITY.parameters.ffufExtensions!
    // Web preset has .php, .bak etc; API preset has .json, .graphql etc
    expect(webExts).toContain('.php')
    expect(webExts).toContain('.bak')
    expect(apiExts).toContain('.json')
    expect(apiExts).toContain('.graphql')
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = WEB_APP_PENTESTER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(WEB_APP_PENTESTER.fullDescription).not.toContain('\u2014')
    expect(WEB_APP_PENTESTER.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(WEB_APP_PENTESTER.fullDescription).toContain('### Pipeline Goal')
    expect(WEB_APP_PENTESTER.fullDescription).toContain('### Who is this for?')
    expect(WEB_APP_PENTESTER.fullDescription).toContain('### What it enables')
    expect(WEB_APP_PENTESTER.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// Stealth Recon preset validation
// ============================================================

describe('Stealth Recon preset', () => {
  test('has correct id and name', () => {
    expect(STEALTH_RECON.id).toBe('stealth-recon')
    expect(STEALTH_RECON.name).toBe('Stealth Recon')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('stealth-recon')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('stealth-recon')
  })

  test('enables stealth mode and Tor routing', () => {
    expect(STEALTH_RECON.parameters.stealthMode).toBe(true)
    expect(STEALTH_RECON.parameters.useTorForRecon).toBe(true)
  })

  test('enables Naabu in passive mode', () => {
    expect(STEALTH_RECON.parameters.naabuEnabled).toBe(true)
    expect(STEALTH_RECON.parameters.naabuPassiveMode).toBe(true)
  })

  test('httpx is throttled (1 thread, rate limit 2)', () => {
    const p = STEALTH_RECON.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxThreads).toBe(1)
    expect(p.httpxRateLimit).toBe(2)
  })

  test('Katana is throttled (depth 1, maxUrls 50, jsCrawl false)', () => {
    const p = STEALTH_RECON.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaDepth).toBe(1)
    expect(p.katanaMaxUrls).toBe(50)
    expect(p.katanaJsCrawl).toBe(false)
  })

  test('Nuclei is throttled (rateLimit 5, concurrency 2, no DAST, no Interactsh)', () => {
    const p = STEALTH_RECON.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiRateLimit).toBe(5)
    expect(p.nucleiConcurrency).toBe(2)
    expect(p.nucleiDastMode).toBe(false)
    expect(p.nucleiInteractsh).toBe(false)
  })

  test('nucleiExcludeTags contains dos, fuzz, and intrusive', () => {
    const tags = STEALTH_RECON.parameters.nucleiExcludeTags!
    expect(tags).toContain('dos')
    expect(tags).toContain('fuzz')
    expect(tags).toContain('intrusive')
  })

  test('GAU enabled with verification disabled', () => {
    const p = STEALTH_RECON.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauVerifyUrls).toBe(false)
  })

  test('Arjun in passive mode', () => {
    expect(STEALTH_RECON.parameters.arjunEnabled).toBe(true)
    expect(STEALTH_RECON.parameters.arjunPassive).toBe(true)
  })

  test('disables noisy tools: masscan, nmap, hakrawler, ffuf, kiterunner, jsRecon, bannerGrab, wappalyzer, securityCheck', () => {
    const p = STEALTH_RECON.parameters
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
  })

  test('all OSINT providers enabled', () => {
    const p = STEALTH_RECON.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(true)
    expect(p.otxEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
    expect(p.fofaEnabled).toBe(true)
    expect(p.netlasEnabled).toBe(true)
    expect(p.virusTotalEnabled).toBe(true)
    expect(p.zoomEyeEnabled).toBe(true)
    expect(p.criminalIpEnabled).toBe(true)
    expect(p.uncoverEnabled).toBe(true)
  })

  test('does not contain non-recon fields', () => {
    const params = STEALTH_RECON.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(STEALTH_RECON.fullDescription).not.toContain('\u2014')
    expect(STEALTH_RECON.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(STEALTH_RECON.fullDescription).toContain('### Pipeline Goal')
    expect(STEALTH_RECON.fullDescription).toContain('### Who is this for?')
    expect(STEALTH_RECON.fullDescription).toContain('### What it enables')
    expect(STEALTH_RECON.fullDescription).toContain('### What it disables')
  })
})

// ============================================================
// CVE Hunter
// ============================================================

describe('CVE_HUNTER preset', () => {
  test('has correct id and name', () => {
    expect(CVE_HUNTER.id).toBe('cve-hunter')
    expect(CVE_HUNTER.name).toBe('CVE Hunter')
  })

  test('is findable by getPresetById', () => {
    const found = getPresetById('cve-hunter')
    expect(found).toBeDefined()
    expect(found!.name).toBe('CVE Hunter')
  })

  test('scan modules include domain_discovery, port_scan, http_probe, vuln_scan', () => {
    const modules = CVE_HUNTER.parameters.scanModules as string[]
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('vuln_scan')
  })

  test('scan modules do NOT include resource_enum or js_recon', () => {
    const modules = CVE_HUNTER.parameters.scanModules as string[]
    expect(modules).not.toContain('resource_enum')
    expect(modules).not.toContain('js_recon')
  })

  test('Naabu enabled with active SYN scan', () => {
    expect(CVE_HUNTER.parameters.naabuEnabled).toBe(true)
    expect(CVE_HUNTER.parameters.naabuPassiveMode).toBe(false)
    expect(CVE_HUNTER.parameters.naabuScanType).toBe('s')
  })

  test('Nmap enabled with version detection and NSE scripts, T4 timing', () => {
    expect(CVE_HUNTER.parameters.nmapEnabled).toBe(true)
    expect(CVE_HUNTER.parameters.nmapVersionDetection).toBe(true)
    expect(CVE_HUNTER.parameters.nmapScriptScan).toBe(true)
    expect(CVE_HUNTER.parameters.nmapTimingTemplate).toBe('T4')
  })

  test('Nuclei enabled with all 4 severities, scanAllIps, autoUpdateTemplates', () => {
    expect(CVE_HUNTER.parameters.nucleiEnabled).toBe(true)
    const sev = CVE_HUNTER.parameters.nucleiSeverity as string[]
    expect(sev).toContain('critical')
    expect(sev).toContain('high')
    expect(sev).toContain('medium')
    expect(sev).toContain('low')
    expect(sev).toHaveLength(4)
    expect(CVE_HUNTER.parameters.nucleiScanAllIps).toBe(true)
    expect(CVE_HUNTER.parameters.nucleiAutoUpdateTemplates).toBe(true)
  })

  test('CVE lookup enabled with maxCves >= 50', () => {
    expect(CVE_HUNTER.parameters.cveLookupEnabled).toBe(true)
    expect(CVE_HUNTER.parameters.cveLookupMaxCves).toBeGreaterThanOrEqual(50)
  })

  test('MITRE enabled with CWE and CAPEC', () => {
    expect(CVE_HUNTER.parameters.mitreEnabled).toBe(true)
    expect(CVE_HUNTER.parameters.mitreIncludeCwe).toBe(true)
    expect(CVE_HUNTER.parameters.mitreIncludeCapec).toBe(true)
  })

  test('Shodan enabled with passive CVEs', () => {
    expect(CVE_HUNTER.parameters.shodanEnabled).toBe(true)
    expect(CVE_HUNTER.parameters.shodanPassiveCves).toBe(true)
  })

  test('banner grabbing enabled', () => {
    expect(CVE_HUNTER.parameters.bannerGrabEnabled).toBe(true)
  })

  test('crawlers, fuzzers, JS tools, GAU, ParamSpider, Masscan all disabled', () => {
    expect(CVE_HUNTER.parameters.katanaEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.hakrawlerEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.ffufEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.kiterunnerEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.jsluiceEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.jsReconEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.gauEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.paramspiderEnabled).toBe(false)
    expect(CVE_HUNTER.parameters.masscanEnabled).toBe(false)
  })

  // --- Safety ---
  test('does not contain non-recon fields', () => {
    const params = CVE_HUNTER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(CVE_HUNTER.fullDescription).not.toContain('\u2014')
    expect(CVE_HUNTER.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(CVE_HUNTER.fullDescription).toContain('### Pipeline Goal')
    expect(CVE_HUNTER.fullDescription).toContain('### Who is this for?')
    expect(CVE_HUNTER.fullDescription).toContain('### What it enables')
    expect(CVE_HUNTER.fullDescription).toContain('### What it disables')
    expect(CVE_HUNTER.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Subdomain Takeover Hunter preset validation
// ============================================================

describe('Subdomain Takeover Hunter preset', () => {
  test('has correct id and name', () => {
    expect(SUBDOMAIN_TAKEOVER.id).toBe('subdomain-takeover')
    expect(SUBDOMAIN_TAKEOVER.name).toBe('Subdomain Takeover Hunter')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('subdomain-takeover')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('subdomain-takeover')
  })

  test('scan modules include domain_discovery, http_probe, resource_enum, vuln_scan', () => {
    // resource_enum is required so GAU (passive historical subdomain data) runs.
    // All other resource_enum tools (Katana, Hakrawler, ffuf, Kiterunner, Arjun,
    // jsluice, ParamSpider) are explicitly disabled below -- only GAU fires.
    const modules = SUBDOMAIN_TAKEOVER.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('js_recon')
  })

  test('all subdomain tools enabled at 10000 max', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.crtshEnabled).toBe(true)
    expect(p.crtshMaxResults).toBe(10000)
    expect(p.hackerTargetEnabled).toBe(true)
    expect(p.hackerTargetMaxResults).toBe(10000)
    expect(p.knockpyReconEnabled).toBe(true)
    expect(p.knockpyReconMaxResults).toBe(10000)
    expect(p.subfinderEnabled).toBe(true)
    expect(p.subfinderMaxResults).toBe(10000)
    expect(p.amassEnabled).toBe(true)
    expect(p.amassMaxResults).toBe(10000)
    expect(p.purednsEnabled).toBe(true)
  })

  test('amass active and brute-force enabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.amassActive).toBe(true)
    expect(SUBDOMAIN_TAKEOVER.parameters.amassBrute).toBe(true)
    expect(SUBDOMAIN_TAKEOVER.parameters.useBruteforceForSubdomains).toBe(true)
  })

  test('httpx enabled with CNAME probe (key for dangling CNAME detection)', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeCname).toBe(true)
    expect(p.httpxProbeStatusCode).toBe(true)
    expect(p.httpxProbeIp).toBe(true)
    expect(p.httpxFollowRedirects).toBe(true)
  })

  test('full Nuclei scanner disabled (dedicated takeover module covers it)', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.nucleiEnabled).toBe(false)
  })

  test('dedicated takeover module enabled with every subjack check', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.subdomainTakeoverEnabled).toBe(true)
    expect(p.subjackEnabled).toBe(true)
    expect(p.subjackSsl).toBe(true)
    expect(p.subjackAll).toBe(true)
    expect(p.subjackCheckNs).toBe(true)
    expect(p.subjackCheckAr).toBe(true)
    expect(p.subjackCheckMail).toBe(true)
    expect(p.subjackThreads).toBe(20)
    expect(p.nucleiTakeoversEnabled).toBe(true)
  })

  test('takeover scoring is aggressive (threshold 40, severity full range, auto-publish on)', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.takeoverConfidenceThreshold).toBe(40)
    expect(p.takeoverSeverity).toEqual(['critical', 'high', 'medium', 'low'])
    expect(p.takeoverManualReviewAutoPublish).toBe(true)
    expect(p.takeoverRateLimit).toBe(100)
  })

  test('GAU historical URL mining enabled for additional subdomain discovery', () => {
    const p = SUBDOMAIN_TAKEOVER.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauProviders).toEqual(['wayback', 'commoncrawl', 'otx', 'urlscan'])
  })

  test('roundtrips through Zod schema without losing keys', async () => {
    const { reconPresetSchema } = await import('../recon-preset-schema')
    const result = reconPresetSchema.safeParse(SUBDOMAIN_TAKEOVER.parameters)
    expect(result.success).toBe(true)
    expect(result.data!.subdomainTakeoverEnabled).toBe(true)
    expect(result.data!.subjackCheckAr).toBe(true)
    expect(result.data!.takeoverConfidenceThreshold).toBe(40)
    expect(result.data!.takeoverManualReviewAutoPublish).toBe(true)
    expect(result.data!.gauEnabled).toBe(true)
  })

  test('port scanners disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.naabuEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.nmapEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.masscanEnabled).toBe(false)
  })

  test('crawlers disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.katanaEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.hakrawlerEnabled).toBe(false)
  })

  test('fuzzers disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.ffufEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.kiterunnerEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.arjunEnabled).toBe(false)
  })

  test('JS tools disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.jsluiceEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.jsReconEnabled).toBe(false)
  })

  test('OSINT disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.osintEnrichmentEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.shodanEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.censysEnabled).toBe(false)
  })

  test('security checks disabled', () => {
    expect(SUBDOMAIN_TAKEOVER.parameters.securityCheckEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.cveLookupEnabled).toBe(false)
    expect(SUBDOMAIN_TAKEOVER.parameters.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = SUBDOMAIN_TAKEOVER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(SUBDOMAIN_TAKEOVER.fullDescription).not.toContain('\u2014')
    expect(SUBDOMAIN_TAKEOVER.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(SUBDOMAIN_TAKEOVER.fullDescription).toContain('### Pipeline Goal')
    expect(SUBDOMAIN_TAKEOVER.fullDescription).toContain('### Who is this for?')
    expect(SUBDOMAIN_TAKEOVER.fullDescription).toContain('### What it enables')
    expect(SUBDOMAIN_TAKEOVER.fullDescription).toContain('### What it disables')
    expect(SUBDOMAIN_TAKEOVER.fullDescription).toContain('### How the layered scanner works')
  })
})

// ============================================================
// Directory & Content Discovery preset validation
// ============================================================

describe('Directory & Content Discovery preset', () => {
  test('has correct id and name', () => {
    expect(DIRECTORY_DISCOVERY.id).toBe('directory-discovery')
    expect(DIRECTORY_DISCOVERY.name).toBe('Directory & Content Discovery')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('directory-discovery')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('directory-discovery')
  })

  test('scanModules include discovery, http_probe, resource_enum but not port_scan, vuln_scan, js_recon', () => {
    const modules = DIRECTORY_DISCOVERY.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('vuln_scan')
    expect(modules).not.toContain('js_recon')
  })

  test('ffuf enabled with recursion depth 3 and many extensions', () => {
    expect(DIRECTORY_DISCOVERY.parameters.ffufEnabled).toBe(true)
    expect(DIRECTORY_DISCOVERY.parameters.ffufRecursionDepth).toBe(3)
    const extensions = DIRECTORY_DISCOVERY.parameters.ffufExtensions as string[]
    expect(extensions).toContain('.php')
    expect(extensions).toContain('.bak')
    expect(extensions).toContain('.env')
    expect(extensions).toContain('.sql')
    expect(extensions).toContain('.zip')
  })

  test('Kiterunner enabled with routes-large', () => {
    expect(DIRECTORY_DISCOVERY.parameters.kiterunnerEnabled).toBe(true)
    const wordlists = DIRECTORY_DISCOVERY.parameters.kiterunnerWordlists as string[]
    expect(wordlists).toContain('routes-large')
  })

  test('Katana depth 4 and Hakrawler depth 4', () => {
    expect(DIRECTORY_DISCOVERY.parameters.katanaEnabled).toBe(true)
    expect(DIRECTORY_DISCOVERY.parameters.katanaDepth).toBe(4)
    expect(DIRECTORY_DISCOVERY.parameters.hakrawlerEnabled).toBe(true)
    expect(DIRECTORY_DISCOVERY.parameters.hakrawlerDepth).toBe(4)
  })

  test('GAU enabled with all providers', () => {
    expect(DIRECTORY_DISCOVERY.parameters.gauEnabled).toBe(true)
    const providers = DIRECTORY_DISCOVERY.parameters.gauProviders as string[]
    expect(providers).toContain('wayback')
    expect(providers).toContain('commoncrawl')
    expect(providers).toContain('otx')
    expect(providers).toContain('urlscan')
  })

  test('jsluice enabled', () => {
    expect(DIRECTORY_DISCOVERY.parameters.jsluiceEnabled).toBe(true)
  })

  test('disables port scanning, vuln scanning, OSINT, and irrelevant tools', () => {
    expect(DIRECTORY_DISCOVERY.parameters.naabuEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.masscanEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.nmapEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.arjunEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.paramspiderEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.nucleiEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.jsReconEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.bannerGrabEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.wappalyzerEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.securityCheckEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.osintEnrichmentEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.cveLookupEnabled).toBe(false)
    expect(DIRECTORY_DISCOVERY.parameters.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = DIRECTORY_DISCOVERY.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(DIRECTORY_DISCOVERY.fullDescription).not.toContain('\u2014')
    expect(DIRECTORY_DISCOVERY.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(DIRECTORY_DISCOVERY.fullDescription).toContain('### Pipeline Goal')
    expect(DIRECTORY_DISCOVERY.fullDescription).toContain('### Who is this for?')
    expect(DIRECTORY_DISCOVERY.fullDescription).toContain('### What it enables')
    expect(DIRECTORY_DISCOVERY.fullDescription).toContain('### What it disables')
    expect(DIRECTORY_DISCOVERY.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Red Team Operator preset validation
// ============================================================

describe('Red Team Operator preset', () => {
  test('has correct id and name', () => {
    expect(RED_TEAM_OPERATOR.id).toBe('red-team-operator')
    expect(RED_TEAM_OPERATOR.name).toBe('Red Team Operator')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('red-team-operator')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('red-team-operator')
  })

  test('routes all traffic through Tor', () => {
    expect(RED_TEAM_OPERATOR.parameters.useTorForRecon).toBe(true)
  })

  test('Naabu uses connect scan (not passive, not SYN)', () => {
    expect(RED_TEAM_OPERATOR.parameters.naabuEnabled).toBe(true)
    expect(RED_TEAM_OPERATOR.parameters.naabuPassiveMode).toBe(false)
    expect(RED_TEAM_OPERATOR.parameters.naabuScanType).toBe('c')
  })

  test('httpx is throttled with limited probes', () => {
    const p = RED_TEAM_OPERATOR.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxThreads).toBe(3)
    expect(p.httpxRateLimit).toBe(5)
    expect(p.httpxProbeJarm).toBe(false)
    expect(p.httpxProbeFavicon).toBe(false)
    expect(p.httpxProbeAsn).toBe(false)
    expect(p.httpxProbeCdn).toBe(false)
  })

  test('Katana is throttled with shallow crawl', () => {
    const p = RED_TEAM_OPERATOR.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaDepth).toBe(1)
    expect(p.katanaMaxUrls).toBe(100)
    expect(p.katanaRateLimit).toBe(5)
    expect(p.katanaJsCrawl).toBe(false)
  })

  test('Nuclei is critical-only with low concurrency and exclude tags', () => {
    const p = RED_TEAM_OPERATOR.parameters
    expect(p.nucleiEnabled).toBe(true)
    const sev = p.nucleiSeverity as string[]
    expect(sev).toEqual(['critical'])
    expect(p.nucleiConcurrency).toBe(3)
    expect(p.nucleiDastMode).toBe(false)
    expect(p.nucleiInteractsh).toBe(false)
    const tags = p.nucleiExcludeTags as string[]
    expect(tags).toContain('dos')
    expect(tags).toContain('fuzz')
    expect(tags).toContain('intrusive')
  })

  test('GAU enabled with verify disabled', () => {
    expect(RED_TEAM_OPERATOR.parameters.gauEnabled).toBe(true)
    expect(RED_TEAM_OPERATOR.parameters.gauVerifyUrls).toBe(false)
  })

  test('Arjun is passive', () => {
    expect(RED_TEAM_OPERATOR.parameters.arjunEnabled).toBe(true)
    expect(RED_TEAM_OPERATOR.parameters.arjunPassive).toBe(true)
  })

  test('OSINT enrichment enabled with Shodan, URLScan, OTX, Censys', () => {
    const p = RED_TEAM_OPERATOR.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(true)
    expect(p.otxEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
  })

  test('disables noisy and brute-force tools', () => {
    const p = RED_TEAM_OPERATOR.parameters
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = RED_TEAM_OPERATOR.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(RED_TEAM_OPERATOR.fullDescription).not.toContain('\u2014')
    expect(RED_TEAM_OPERATOR.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(RED_TEAM_OPERATOR.fullDescription).toContain('### Pipeline Goal')
    expect(RED_TEAM_OPERATOR.fullDescription).toContain('### Who is this for?')
    expect(RED_TEAM_OPERATOR.fullDescription).toContain('### What it enables')
    expect(RED_TEAM_OPERATOR.fullDescription).toContain('### What it disables')
    expect(RED_TEAM_OPERATOR.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Cloud & External Exposure preset validation
// ============================================================

describe('Cloud & External Exposure preset', () => {
  test('has correct id and name', () => {
    expect(CLOUD_EXPOSURE.id).toBe('cloud-exposure')
    expect(CLOUD_EXPOSURE.name).toBe('Cloud & External Exposure')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('cloud-exposure')
    expect(preset).toBeDefined()
    expect(preset!.name).toBe('Cloud & External Exposure')
  })

  test('scan modules include domain_discovery, port_scan, http_probe, vuln_scan', () => {
    const modules = CLOUD_EXPOSURE.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('resource_enum')
    expect(modules).not.toContain('js_recon')
  })

  test('Naabu enabled with custom cloud ports', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.naabuEnabled).toBe(true)
    expect(p.naabuCustomPorts).toContain('6443')
    expect(p.naabuCustomPorts).toContain('10250')
    expect(p.naabuCustomPorts).toContain('9200')
    expect(p.naabuCustomPorts).toContain('27017')
  })

  test('Nmap enabled with version detection and scripts', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.nmapEnabled).toBe(true)
    expect(p.nmapVersionDetection).toBe(true)
    expect(p.nmapScriptScan).toBe(true)
  })

  test('httpx with ASN, CDN, TLS probes all true', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeAsn).toBe(true)
    expect(p.httpxProbeCdn).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
    expect(p.httpxProbeTlsGrab).toBe(true)
    expect(p.httpxProbeJarm).toBe(true)
  })

  test('all OSINT providers enabled', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(true)
    expect(p.otxEnabled).toBe(true)
    expect(p.fofaEnabled).toBe(true)
    expect(p.netlasEnabled).toBe(true)
    expect(p.virusTotalEnabled).toBe(true)
    expect(p.zoomEyeEnabled).toBe(true)
    expect(p.criminalIpEnabled).toBe(true)
    expect(p.uncoverEnabled).toBe(true)
  })

  test('security checks all enabled, especially cloud-related', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.securityCheckKubernetesApiExposed).toBe(true)
    expect(p.securityCheckDatabaseExposed).toBe(true)
    expect(p.securityCheckAdminPortExposed).toBe(true)
    expect(p.securityCheckRedisNoAuth).toBe(true)
    expect(p.securityCheckDirectIpHttp).toBe(true)
    expect(p.securityCheckDirectIpHttps).toBe(true)
    expect(p.securityCheckIpApiExposed).toBe(true)
    expect(p.securityCheckWafBypass).toBe(true)
  })

  test('Nuclei enabled with interactsh', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiInteractsh).toBe(true)
    expect(p.nucleiSeverity).toEqual(['critical', 'high', 'medium'])
  })

  test('CVE and MITRE enabled', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.cveLookupEnabled).toBe(true)
    expect(p.mitreEnabled).toBe(true)
    expect(p.mitreIncludeCwe).toBe(true)
    expect(p.mitreIncludeCapec).toBe(true)
  })

  test('web crawlers and fuzzers disabled', () => {
    const p = CLOUD_EXPOSURE.parameters
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = CLOUD_EXPOSURE.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(CLOUD_EXPOSURE.fullDescription).not.toContain('\u2014')
    expect(CLOUD_EXPOSURE.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(CLOUD_EXPOSURE.fullDescription).toContain('### Pipeline Goal')
    expect(CLOUD_EXPOSURE.fullDescription).toContain('### Who is this for?')
    expect(CLOUD_EXPOSURE.fullDescription).toContain('### What it enables')
    expect(CLOUD_EXPOSURE.fullDescription).toContain('### What it disables')
    expect(CLOUD_EXPOSURE.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Compliance & Header Audit preset validation
// ============================================================

describe('Compliance & Header Audit preset', () => {
  test('has correct id and name', () => {
    expect(COMPLIANCE_AUDIT.id).toBe('compliance-audit')
    expect(COMPLIANCE_AUDIT.name).toBe('Compliance & Header Audit')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('compliance-audit')
    expect(preset).toBeDefined()
    expect(preset!.name).toBe('Compliance & Header Audit')
  })

  test('scan modules include domain_discovery, http_probe, vuln_scan only', () => {
    const modules = COMPLIANCE_AUDIT.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('port_scan')
    expect(modules).not.toContain('resource_enum')
    expect(modules).not.toContain('js_recon')
  })

  test('httpx all header probes enabled', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeStatusCode).toBe(true)
    expect(p.httpxProbeContentLength).toBe(true)
    expect(p.httpxProbeContentType).toBe(true)
    expect(p.httpxProbeTitle).toBe(true)
    expect(p.httpxProbeServer).toBe(true)
    expect(p.httpxProbeResponseTime).toBe(true)
    expect(p.httpxProbeWordCount).toBe(true)
    expect(p.httpxProbeLineCount).toBe(true)
    expect(p.httpxProbeTechDetect).toBe(true)
    expect(p.httpxProbeIp).toBe(true)
    expect(p.httpxProbeCname).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
    expect(p.httpxProbeTlsGrab).toBe(true)
    expect(p.httpxProbeFavicon).toBe(true)
    expect(p.httpxProbeJarm).toBe(true)
    expect(p.httpxProbeAsn).toBe(true)
    expect(p.httpxProbeCdn).toBe(true)
  })

  test('httpxIncludeResponseHeaders true', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.httpxIncludeResponseHeaders).toBe(true)
    expect(p.httpxIncludeResponse).toBe(false)
  })

  test('Wappalyzer enabled', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.wappalyzerEnabled).toBe(true)
    expect(p.wappalyzerMinConfidence).toBe(30)
    expect(p.wappalyzerAutoUpdate).toBe(true)
  })

  test('all 27 security checks enabled', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.securityCheckDirectIpHttp).toBe(true)
    expect(p.securityCheckDirectIpHttps).toBe(true)
    expect(p.securityCheckIpApiExposed).toBe(true)
    expect(p.securityCheckWafBypass).toBe(true)
    expect(p.securityCheckTlsExpiringSoon).toBe(true)
    expect(p.securityCheckMissingReferrerPolicy).toBe(true)
    expect(p.securityCheckMissingPermissionsPolicy).toBe(true)
    expect(p.securityCheckMissingCoop).toBe(true)
    expect(p.securityCheckMissingCorp).toBe(true)
    expect(p.securityCheckMissingCoep).toBe(true)
    expect(p.securityCheckCacheControlMissing).toBe(true)
    expect(p.securityCheckLoginNoHttps).toBe(true)
    expect(p.securityCheckSessionNoSecure).toBe(true)
    expect(p.securityCheckSessionNoHttponly).toBe(true)
    expect(p.securityCheckBasicAuthNoTls).toBe(true)
    expect(p.securityCheckSpfMissing).toBe(true)
    expect(p.securityCheckDmarcMissing).toBe(true)
    expect(p.securityCheckDnssecMissing).toBe(true)
    expect(p.securityCheckZoneTransfer).toBe(true)
    expect(p.securityCheckAdminPortExposed).toBe(true)
    expect(p.securityCheckDatabaseExposed).toBe(true)
    expect(p.securityCheckRedisNoAuth).toBe(true)
    expect(p.securityCheckKubernetesApiExposed).toBe(true)
    expect(p.securityCheckSmtpOpenRelay).toBe(true)
    expect(p.securityCheckCspUnsafeInline).toBe(true)
    expect(p.securityCheckInsecureFormAction).toBe(true)
    expect(p.securityCheckNoRateLimiting).toBe(true)
  })

  test('Nuclei enabled with misconfig focus, no DAST, no interactsh', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiDastMode).toBe(false)
    expect(p.nucleiInteractsh).toBe(false)
    expect(p.nucleiHeadless).toBe(false)
    expect(p.nucleiSeverity).toEqual(['critical', 'high', 'medium'])
    expect(p.nucleiTags).toEqual(['misconfig', 'exposure'])
  })

  test('all port scanners disabled', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.naabuEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
  })

  test('crawlers, fuzzers, JS tools, OSINT, CVE, MITRE all disabled', () => {
    const p = COMPLIANCE_AUDIT.parameters
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.shodanEnabled).toBe(false)
    expect(p.censysEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = COMPLIANCE_AUDIT.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(COMPLIANCE_AUDIT.fullDescription).not.toContain('\u2014')
    expect(COMPLIANCE_AUDIT.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(COMPLIANCE_AUDIT.fullDescription).toContain('### Pipeline Goal')
    expect(COMPLIANCE_AUDIT.fullDescription).toContain('### Who is this for?')
    expect(COMPLIANCE_AUDIT.fullDescription).toContain('### What it enables')
    expect(COMPLIANCE_AUDIT.fullDescription).toContain('### What it disables')
    expect(COMPLIANCE_AUDIT.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Secret & Credential Hunter preset validation
// ============================================================

describe('Secret & Credential Hunter preset', () => {
  test('has correct id and name', () => {
    expect(SECRET_HUNTER.id).toBe('secret-hunter')
    expect(SECRET_HUNTER.name).toBe('Secret & Credential Hunter')
  })

  test('getPresetById returns it', () => {
    const preset = getPresetById('secret-hunter')
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('secret-hunter')
    expect(preset!.name).toBe('Secret & Credential Hunter')
  })

  test('scanModules includes js_recon', () => {
    const modules = SECRET_HUNTER.parameters.scanModules!
    expect(modules).toContain('js_recon')
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('resource_enum')
    expect(modules).toContain('vuln_scan')
  })

  test('JS Recon fully enabled with maxFiles >= 2000, validateKeys, sourceMaps, all analysis modules', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.jsReconEnabled).toBe(true)
    expect(p.jsReconMaxFiles).toBeGreaterThanOrEqual(2000)
    expect(p.jsReconValidateKeys).toBe(true)
    expect(p.jsReconSourceMaps).toBe(true)
    expect(p.jsReconExtractEndpoints).toBe(true)
    expect(p.jsReconRegexPatterns).toBe(true)
    expect(p.jsReconDependencyCheck).toBe(true)
    expect(p.jsReconDomSinks).toBe(true)
    expect(p.jsReconFrameworkDetect).toBe(true)
    expect(p.jsReconDevComments).toBe(true)
    expect(p.jsReconIncludeChunks).toBe(true)
    expect(p.jsReconIncludeFrameworkJs).toBe(true)
    expect(p.jsReconIncludeArchivedJs).toBe(true)
  })

  test('jsluice enabled with maxFiles >= 1000, extractSecrets true', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.jsluiceEnabled).toBe(true)
    expect(p.jsluiceMaxFiles).toBeGreaterThanOrEqual(1000)
    expect(p.jsluiceExtractSecrets).toBe(true)
  })

  test('ffuf with sensitive extensions (.env, .config, .yml, .bak, .key, .pem)', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.ffufEnabled).toBe(true)
    const exts = p.ffufExtensions as string[]
    expect(exts).toContain('.env')
    expect(exts).toContain('.config')
    expect(exts).toContain('.yml')
    expect(exts).toContain('.bak')
    expect(exts).toContain('.key')
    expect(exts).toContain('.pem')
  })

  test('Katana depth 3 with JS crawl', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaDepth).toBe(3)
    expect(p.katanaJsCrawl).toBe(true)
  })

  test('Hakrawler enabled', () => {
    expect(SECRET_HUNTER.parameters.hakrawlerEnabled).toBe(true)
  })

  test('GAU enabled', () => {
    expect(SECRET_HUNTER.parameters.gauEnabled).toBe(true)
  })

  test('Nuclei with exposure/token tags', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.nucleiEnabled).toBe(true)
    const tags = p.nucleiTags as string[]
    expect(tags).toContain('exposure')
    expect(tags).toContain('token')
  })

  test('disables port scanners, kiterunner, arjun, paramspider, bannerGrab, wappalyzer, securityCheck, osint, cveLookup, mitre', () => {
    const p = SECRET_HUNTER.parameters
    expect(p.naabuEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = SECRET_HUNTER.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(SECRET_HUNTER.fullDescription).not.toContain('\u2014')
    expect(SECRET_HUNTER.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(SECRET_HUNTER.fullDescription).toContain('### Pipeline Goal')
    expect(SECRET_HUNTER.fullDescription).toContain('### Who is this for?')
    expect(SECRET_HUNTER.fullDescription).toContain('### What it enables')
    expect(SECRET_HUNTER.fullDescription).toContain('### What it disables')
    expect(SECRET_HUNTER.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Parameter & Injection Surface preset
// ============================================================

describe('Parameter & Injection Surface preset', () => {
  test('has correct id and name', () => {
    expect(PARAMETER_INJECTION.id).toBe('parameter-injection')
    expect(PARAMETER_INJECTION.name).toBe('Parameter & Injection Surface')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('parameter-injection')
    expect(preset).toBeDefined()
    expect(preset!.name).toBe('Parameter & Injection Surface')
  })

  test('enables domain_discovery, http_probe, resource_enum, vuln_scan modules', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.scanModules).toEqual(['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'])
  })

  test('Arjun enabled with all 5 methods and maxEndpoints >= 200', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.arjunEnabled).toBe(true)
    expect(p.arjunMethods).toEqual(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    expect(p.arjunMaxEndpoints).toBeGreaterThanOrEqual(200)
  })

  test('Katana enabled with paramsOnly true', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.katanaEnabled).toBe(true)
    expect(p.katanaParamsOnly).toBe(true)
  })

  test('ParamSpider enabled', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.paramspiderEnabled).toBe(true)
  })

  test('GAU enabled with verify and method detection', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.gauEnabled).toBe(true)
    expect(p.gauVerifyUrls).toBe(true)
    expect(p.gauDetectMethods).toBe(true)
  })

  test('jsluice enabled with extractUrls true', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.jsluiceEnabled).toBe(true)
    expect(p.jsluiceExtractUrls).toBe(true)
  })

  test('Nuclei DAST mode with injection tags', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.nucleiEnabled).toBe(true)
    expect(p.nucleiDastMode).toBe(true)
    const tags = p.nucleiTags as string[]
    expect(tags).toContain('sqli')
    expect(tags).toContain('xss')
    expect(tags).toContain('ssrf')
    expect(tags).toContain('injection')
  })

  test('disables port scanners, hakrawler, ffuf, kiterunner, jsRecon, bannerGrab, wappalyzer, securityCheck, osint, cveLookup, mitre', () => {
    const p = PARAMETER_INJECTION.parameters
    expect(p.naabuEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.bannerGrabEnabled).toBe(false)
    expect(p.wappalyzerEnabled).toBe(false)
    expect(p.securityCheckEnabled).toBe(false)
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const keys = Object.keys(PARAMETER_INJECTION.parameters)
    const nonReconFields = ['name', 'targetDomain', 'description', 'userId', 'projectId']
    for (const field of nonReconFields) {
      expect(keys).not.toContain(field)
    }
  })

  test('fullDescription does not contain em dashes', () => {
    expect(PARAMETER_INJECTION.fullDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(PARAMETER_INJECTION.fullDescription).toContain('### Pipeline Goal')
    expect(PARAMETER_INJECTION.fullDescription).toContain('### Who is this for?')
    expect(PARAMETER_INJECTION.fullDescription).toContain('### What it enables')
    expect(PARAMETER_INJECTION.fullDescription).toContain('### What it disables')
    expect(PARAMETER_INJECTION.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Network Perimeter - Large Scale preset validation
// ============================================================

describe('Network Perimeter - Large Scale preset', () => {
  test('has correct id and name', () => {
    expect(LARGE_NETWORK.id).toBe('large-network')
    expect(LARGE_NETWORK.name).toBe('Network Perimeter - Large Scale')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('large-network')
    expect(preset).toBeDefined()
    expect(preset!.name).toBe('Network Perimeter - Large Scale')
  })

  test('scan modules include domain_discovery, port_scan, http_probe, vuln_scan (Nuclei OFF)', () => {
    // vuln_scan is the gate that lets CVE lookup + MITRE enrichment + security
    // checks execute. Nuclei itself is disabled (this preset maps infrastructure,
    // not vuln-tests it).
    const modules = LARGE_NETWORK.parameters.scanModules!
    expect(modules).toContain('domain_discovery')
    expect(modules).toContain('port_scan')
    expect(modules).toContain('http_probe')
    expect(modules).toContain('vuln_scan')
    expect(modules).not.toContain('resource_enum')
    expect(modules).not.toContain('js_recon')
  })

  test('Naabu enabled with high rate and threads', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.naabuEnabled).toBe(true)
    expect(p.naabuRateLimit).toBeGreaterThanOrEqual(1500)
    expect(p.naabuThreads).toBeGreaterThanOrEqual(50)
    expect(p.naabuScanType).toBe('s')
    expect(p.naabuVerifyPorts).toBe(true)
  })

  test('Masscan enabled with rate >= 10000', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.masscanEnabled).toBe(true)
    expect(p.masscanRate).toBeGreaterThanOrEqual(10000)
    expect(p.masscanBanners).toBe(true)
  })

  test('Nmap with version detection, scripts, T4', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.nmapEnabled).toBe(true)
    expect(p.nmapVersionDetection).toBe(true)
    expect(p.nmapScriptScan).toBe(true)
    expect(p.nmapTimingTemplate).toBe('T4')
  })

  test('Banner grabbing enabled with high threads', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.bannerGrabEnabled).toBe(true)
    expect(p.bannerGrabThreads).toBeGreaterThanOrEqual(40)
  })

  test('httpx enabled with ASN, CDN, JARM probes', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.httpxEnabled).toBe(true)
    expect(p.httpxProbeAsn).toBe(true)
    expect(p.httpxProbeCdn).toBe(true)
    expect(p.httpxProbeJarm).toBe(true)
    expect(p.httpxProbeTlsInfo).toBe(true)
  })

  test('Shodan + Censys enabled, other OSINT disabled', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.censysEnabled).toBe(true)
    expect(p.urlscanEnabled).toBe(false)
    expect(p.otxEnabled).toBe(false)
    expect(p.fofaEnabled).toBe(false)
    expect(p.netlasEnabled).toBe(false)
    expect(p.virusTotalEnabled).toBe(false)
    expect(p.zoomEyeEnabled).toBe(false)
    expect(p.criminalIpEnabled).toBe(false)
    expect(p.uncoverEnabled).toBe(false)
  })

  test('CVE + MITRE enabled', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.cveLookupEnabled).toBe(true)
    expect(p.cveLookupMaxCves).toBe(40)
    expect(p.mitreEnabled).toBe(true)
    expect(p.mitreIncludeCwe).toBe(true)
    expect(p.mitreIncludeCapec).toBe(true)
  })

  test('Security checks enabled', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.securityCheckMaxWorkers).toBe(20)
    expect(p.securityCheckAdminPortExposed).toBe(true)
    expect(p.securityCheckDatabaseExposed).toBe(true)
    expect(p.securityCheckKubernetesApiExposed).toBe(true)
  })

  test('web crawlers, fuzzers, JS analysis, and nuclei all disabled', () => {
    const p = LARGE_NETWORK.parameters
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.nucleiEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = LARGE_NETWORK.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(LARGE_NETWORK.fullDescription).not.toContain('\u2014')
    expect(LARGE_NETWORK.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(LARGE_NETWORK.fullDescription).toContain('### Pipeline Goal')
    expect(LARGE_NETWORK.fullDescription).toContain('### Who is this for?')
    expect(LARGE_NETWORK.fullDescription).toContain('### What it enables')
    expect(LARGE_NETWORK.fullDescription).toContain('### What it disables')
    expect(LARGE_NETWORK.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// DNS & Email Security preset validation
// ============================================================

describe('DNS & Email Security preset', () => {
  test('has correct id and name', () => {
    expect(DNS_EMAIL_SECURITY.id).toBe('dns-email-security')
    expect(DNS_EMAIL_SECURITY.name).toBe('DNS & Email Security')
  })

  test('is findable by getPresetById', () => {
    const preset = getPresetById('dns-email-security')
    expect(preset).toBeDefined()
    expect(preset!.name).toBe('DNS & Email Security')
  })

  test('scanModules contains domain_discovery and vuln_scan (Nuclei OFF)', () => {
    // vuln_scan is the gate that lets SPF/DMARC/DNSSEC/zone-transfer/SMTP security
    // checks execute. Nuclei itself is disabled below so no active vuln scanning fires.
    const modules = DNS_EMAIL_SECURITY.parameters.scanModules!
    expect(modules).toEqual(['domain_discovery', 'vuln_scan'])
  })

  test('all subdomain tools enabled at 10000 max, amass active+brute, bruteforce enabled', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.subdomainDiscoveryEnabled).toBe(true)
    expect(p.crtshEnabled).toBe(true)
    expect(p.crtshMaxResults).toBe(10000)
    expect(p.hackerTargetEnabled).toBe(true)
    expect(p.hackerTargetMaxResults).toBe(10000)
    expect(p.knockpyReconEnabled).toBe(true)
    expect(p.knockpyReconMaxResults).toBe(10000)
    expect(p.subfinderEnabled).toBe(true)
    expect(p.subfinderMaxResults).toBe(10000)
    expect(p.amassEnabled).toBe(true)
    expect(p.amassActive).toBe(true)
    expect(p.amassBrute).toBe(true)
    expect(p.amassMaxResults).toBe(10000)
    expect(p.purednsEnabled).toBe(true)
    expect(p.useBruteforceForSubdomains).toBe(true)
  })

  test('whoisEnabled and dnsEnabled are true', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.whoisEnabled).toBe(true)
    expect(p.dnsEnabled).toBe(true)
  })

  test('security checks enabled with DNS/email checks', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.securityCheckEnabled).toBe(true)
    expect(p.securityCheckSpfMissing).toBe(true)
    expect(p.securityCheckDmarcMissing).toBe(true)
    expect(p.securityCheckDnssecMissing).toBe(true)
    expect(p.securityCheckZoneTransfer).toBe(true)
    expect(p.securityCheckSmtpOpenRelay).toBe(true)
  })

  test('HTTP/web security checks disabled', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.securityCheckDirectIpHttp).toBe(false)
    expect(p.securityCheckWafBypass).toBe(false)
    expect(p.securityCheckLoginNoHttps).toBe(false)
    expect(p.securityCheckSessionNoSecure).toBe(false)
  })

  test('Shodan enabled with domainDns and reverseDns', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.osintEnrichmentEnabled).toBe(true)
    expect(p.shodanEnabled).toBe(true)
    expect(p.shodanDomainDns).toBe(true)
    expect(p.shodanReverseDns).toBe(true)
  })

  test('httpx, port scanners, crawlers, fuzzers, JS tools, nuclei, cveLookup, mitre all disabled', () => {
    const p = DNS_EMAIL_SECURITY.parameters
    expect(p.httpxEnabled).toBe(false)
    expect(p.naabuEnabled).toBe(false)
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
    expect(p.katanaEnabled).toBe(false)
    expect(p.hakrawlerEnabled).toBe(false)
    expect(p.gauEnabled).toBe(false)
    expect(p.paramspiderEnabled).toBe(false)
    expect(p.jsluiceEnabled).toBe(false)
    expect(p.jsReconEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.arjunEnabled).toBe(false)
    expect(p.nucleiEnabled).toBe(false)
    expect(p.cveLookupEnabled).toBe(false)
    expect(p.mitreEnabled).toBe(false)
  })

  test('does not contain non-recon fields', () => {
    const params = DNS_EMAIL_SECURITY.parameters as Record<string, unknown>
    expect(params.name).toBeUndefined()
    expect(params.description).toBeUndefined()
    expect(params.targetDomain).toBeUndefined()
    expect(params.subdomainList).toBeUndefined()
    expect(params.ipMode).toBeUndefined()
    expect(params.targetIps).toBeUndefined()
    expect(params.agentOpenaiModel).toBeUndefined()
    expect(params.agentMaxIterations).toBeUndefined()
    expect(params.roeEnabled).toBeUndefined()
    expect(params.cypherfixRequireApproval).toBeUndefined()
  })

  test('does not contain em dashes', () => {
    expect(DNS_EMAIL_SECURITY.fullDescription).not.toContain('\u2014')
    expect(DNS_EMAIL_SECURITY.shortDescription).not.toContain('\u2014')
  })

  test('fullDescription contains expected section headers', () => {
    expect(DNS_EMAIL_SECURITY.fullDescription).toContain('### Pipeline Goal')
    expect(DNS_EMAIL_SECURITY.fullDescription).toContain('### Who is this for?')
    expect(DNS_EMAIL_SECURITY.fullDescription).toContain('### What it enables')
    expect(DNS_EMAIL_SECURITY.fullDescription).toContain('### What it disables')
    expect(DNS_EMAIL_SECURITY.fullDescription).toContain('### How it works')
  })
})

// ============================================================
// Merge logic simulation
// ============================================================

describe('Preset merge logic', () => {
  // Simulate the merge that happens in ProjectForm.tsx applyPreset()
  function simulateApplyPreset(
    currentForm: Record<string, unknown>,
    preset: ReconPreset
  ): Record<string, unknown> {
    // This mirrors: setFormData(prev => ({ ...prev, ...preset.parameters }))
    return { ...currentForm, ...preset.parameters }
  }

  test('preserves user-entered name and targetDomain', () => {
    const currentForm = {
      name: 'My Project',
      targetDomain: 'example.com',
      description: 'Test project',
      naabuEnabled: true,
      katanaDepth: 2,
    }
    const result = simulateApplyPreset(currentForm, SECRET_MINER)
    // User fields preserved
    expect(result.name).toBe('My Project')
    expect(result.targetDomain).toBe('example.com')
    expect(result.description).toBe('Test project')
    // Preset fields applied
    expect(result.naabuEnabled).toBe(false)
    expect(result.katanaDepth).toBe(3)
  })

  test('preserves agent settings not in preset', () => {
    const currentForm = {
      name: 'Test',
      agentOpenaiModel: 'claude-opus-4-6',
      agentMaxIterations: 50,
      naabuEnabled: true,
    }
    const result = simulateApplyPreset(currentForm, SECRET_MINER)
    expect(result.agentOpenaiModel).toBe('claude-opus-4-6')
    expect(result.agentMaxIterations).toBe(50)
  })

  test('preset overrides existing recon values', () => {
    const currentForm = {
      name: 'Test',
      katanaDepth: 1,
      katanaMaxUrls: 100,
      jsReconEnabled: false,
      gauEnabled: false,
    }
    const result = simulateApplyPreset(currentForm, SECRET_MINER)
    expect(result.katanaDepth).toBe(3)
    expect(result.katanaMaxUrls).toBe(1000)
    expect(result.jsReconEnabled).toBe(true)
    expect(result.gauEnabled).toBe(true)
  })

  test('fields not in preset remain unchanged', () => {
    const currentForm = {
      name: 'Test',
      httpxThreads: 100,
      httpxTimeout: 15,
    }
    const result = simulateApplyPreset(currentForm, SECRET_MINER)
    // httpxThreads is not in SECRET_MINER.parameters, so it stays
    expect(result.httpxThreads).toBe(100)
    expect(result.httpxTimeout).toBe(15)
  })

  test('applying same preset twice is idempotent', () => {
    const currentForm = {
      name: 'Test',
      targetDomain: 'example.com',
      naabuEnabled: true,
    }
    const first = simulateApplyPreset(currentForm, SECRET_MINER)
    const second = simulateApplyPreset(first, SECRET_MINER)
    expect(second).toEqual(first)
  })
})

// ============================================================
// Cross-cutting system-wide validation
// ============================================================

describe('Preset system integrity', () => {
  test('registry contains exactly 22 presets', () => {
    expect(RECON_PRESETS).toHaveLength(22)
  })

  test('every preset has all required fields with correct types', () => {
    for (const preset of RECON_PRESETS) {
      expect(typeof preset.id).toBe('string')
      expect(preset.id.length).toBeGreaterThan(0)
      expect(typeof preset.name).toBe('string')
      expect(preset.name.length).toBeGreaterThan(0)
      expect(typeof preset.icon).toBe('string')
      expect(typeof preset.shortDescription).toBe('string')
      expect(preset.shortDescription.length).toBeGreaterThan(0)
      expect(typeof preset.fullDescription).toBe('string')
      expect(preset.fullDescription.length).toBeGreaterThan(0)
      expect(typeof preset.parameters).toBe('object')
      expect(Object.keys(preset.parameters).length).toBeGreaterThan(0)
    }
  })

  test('all preset IDs are unique', () => {
    const ids = RECON_PRESETS.map(p => p.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  test('all preset names are unique', () => {
    const names = RECON_PRESETS.map(p => p.name)
    expect(new Set(names).size).toBe(names.length)
  })

  test('every preset is findable by getPresetById', () => {
    for (const preset of RECON_PRESETS) {
      const found = getPresetById(preset.id)
      expect(found).toBeDefined()
      expect(found!.id).toBe(preset.id)
    }
  })

  test('no preset contains em dashes in any text field', () => {
    for (const preset of RECON_PRESETS) {
      expect(preset.shortDescription).not.toContain('\u2014')
      expect(preset.fullDescription).not.toContain('\u2014')
      expect(preset.name).not.toContain('\u2014')
    }
  })

  test('every preset fullDescription has all required section headers', () => {
    const requiredHeaders = ['### Pipeline Goal', '### Who is this for?', '### What it enables', '### What it disables']
    for (const preset of RECON_PRESETS) {
      for (const header of requiredHeaders) {
        expect(preset.fullDescription).toContain(header)
      }
    }
  })

  test('no preset overrides user-input fields (name, targetDomain, etc.)', () => {
    const forbiddenKeys = [
      'name', 'description', 'targetDomain', 'subdomainList', 'ipMode', 'targetIps',
      'agentOpenaiModel', 'agentMaxIterations', 'agentInformationalSystemPrompt',
      'agentExplSystemPrompt', 'agentPostExplSystemPrompt',
      'roeEnabled', 'roeRawText', 'roeClientName',
      'cypherfixRequireApproval', 'cypherfixGithubToken',
      'hydraEnabled', 'hydraThreads',
    ]
    for (const preset of RECON_PRESETS) {
      const params = preset.parameters as Record<string, unknown>
      for (const key of forbiddenKeys) {
        expect(params[key]).toBeUndefined()
      }
    }
  })

  test('every preset with scanModules sets a valid array', () => {
    const validModules = ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon']
    for (const preset of RECON_PRESETS) {
      const modules = preset.parameters.scanModules
      if (modules) {
        expect(Array.isArray(modules)).toBe(true)
        for (const mod of modules) {
          expect(validModules).toContain(mod)
        }
      }
    }
  })

  test('applying any preset preserves user fields', () => {
    const userForm = {
      name: 'My Project',
      targetDomain: 'example.com',
      description: 'Test',
      agentOpenaiModel: 'claude-opus-4-6',
    }
    for (const preset of RECON_PRESETS) {
      const merged = { ...userForm, ...preset.parameters } as Record<string, unknown>
      expect(merged.name).toBe('My Project')
      expect(merged.targetDomain).toBe('example.com')
      expect(merged.description).toBe('Test')
      expect(merged.agentOpenaiModel).toBe('claude-opus-4-6')
    }
  })

  test('applying any preset twice is idempotent', () => {
    const form = { name: 'Test', targetDomain: 'example.com' }
    for (const preset of RECON_PRESETS) {
      const first = { ...form, ...preset.parameters }
      const second = { ...first, ...preset.parameters }
      expect(second).toEqual(first)
    }
  })

  test('every preset with image field points to a valid SVG path', () => {
    for (const preset of RECON_PRESETS) {
      if (preset.image) {
        expect(preset.image).toMatch(/^\/preset-[\w-]+\.svg$/)
      }
    }
  })
})

// ============================================================
// GraphQL Security Scanner preset decisions (Phase 1 §8.3)
// ============================================================

describe('GraphQL Security Scanner preset coverage', () => {
  const get = (id: string) => RECON_PRESETS.find(p => p.id === id)

  // GraphQL enables only when: preset mission needs it AND crawlers are ON
  // (Katana/Hakrawler provide Endpoints for GraphQL discovery to enrich).
  const EXPECTED_ENABLED = [
    'api-security', 'web-app-pentester', 'bug-bounty-deep',
    'full-active-scan', 'full-maximum-scan',
    'parameter-injection',
    'secret-miner',         // JS crawl finds /graphql endpoints embedded in SPA bundles
  ]

  // All 14 "OFF" presets MUST explicitly set graphqlSecurityEnabled: false (not just
  // omit it). Reason: preset-apply is a shallow merge ({...form, ...preset.parameters}),
  // so switching from a GraphQL-enabled preset to one that merely OMITS the key leaves
  // the toggle stuck ON. Explicit false is required for correct preset transitions.
  const EXPLICITLY_DISABLED = [
    'bug-bounty-quick', 'red-team-operator', 'stealth-recon',
    'compliance-audit', 'cve-hunter',
    'cloud-exposure', 'dns-email-security', 'full-passive-scan',
    'infrastructure-mapper', 'large-network', 'osint-investigator',
    'subdomain-takeover', 'secret-hunter',
    'directory-discovery',  // descriptions promise "no vuln scanning" -- GraphQL scan is vuln scanning
  ]

  test.each(EXPECTED_ENABLED)('%s enables graphqlSecurityEnabled', (id) => {
    const preset = get(id)
    expect(preset).toBeDefined()
    const p = preset!.parameters as Record<string, unknown>
    expect(p.graphqlSecurityEnabled).toBe(true)
  })

  test.each(EXPLICITLY_DISABLED)('%s explicitly sets graphqlSecurityEnabled: false (for clean switching)', (id) => {
    const preset = get(id)
    expect(preset).toBeDefined()
    const p = preset!.parameters as Record<string, unknown>
    // Must be explicit false, NOT undefined -- required so shallow-merge resets the
    // toggle when switching from a GraphQL-enabled preset.
    expect(p.graphqlSecurityEnabled).toBe(false)
    expect(p.graphqlCopEnabled).toBe(false)
  })

  test('switching from graphql-recon to a disabled preset resets graphqlSecurityEnabled', () => {
    const graphqlOn = RECON_PRESETS.find(p => p.id === 'graphql-recon')!.parameters
    const form = { name: 'test', ...graphqlOn } as Record<string, unknown>
    expect(form.graphqlSecurityEnabled).toBe(true)

    for (const id of EXPLICITLY_DISABLED) {
      const disabledParams = RECON_PRESETS.find(p => p.id === id)!.parameters
      const merged = { ...form, ...disabledParams } as Record<string, unknown>
      expect(merged.graphqlSecurityEnabled).toBe(false)
      expect(merged.graphqlCopEnabled).toBe(false)
    }
  })

  test('secret-miner enables graphql with introspection + read-only checks', () => {
    const p = get('secret-miner')!.parameters as Record<string, unknown>
    expect(p.graphqlSecurityEnabled).toBe(true)
    expect(p.graphqlIntrospectionTest).toBe(true)
  })

  test('full-maximum-scan turns everything on with elevated mutation cap', () => {
    const p = get('full-maximum-scan')!.parameters as Record<string, unknown>
  })
})

// ============================================================
// graphql-cop preset coverage (Phase 2 §17.7)
// ============================================================

describe('graphql-cop preset coverage', () => {
  const get = (id: string) => RECON_PRESETS.find(p => p.id === id)

  // graphql-cop enables 1:1 with graphqlSecurityEnabled
  const EXPECTED_COP_ENABLED = [
    'api-security', 'web-app-pentester', 'bug-bounty-deep',
    'full-active-scan', 'full-maximum-scan',
    'parameter-injection',
    'secret-miner',
  ]

  test.each(EXPECTED_COP_ENABLED)('%s enables graphqlCopEnabled', (id) => {
    const preset = get(id)
    expect(preset).toBeDefined()
    const p = preset!.parameters as Record<string, unknown>
    expect(p.graphqlCopEnabled).toBe(true)
  })

  test('full-maximum-scan enables graphql-cop introspection for cross-validation', () => {
    const p = get('full-maximum-scan')!.parameters as Record<string, unknown>
    expect(p.graphqlCopEnabled).toBe(true)
    expect(p.graphqlCopTestIntrospection).toBe(true)
  })

  test('bug-bounty-deep enables graphql-cop with DoS probes OFF (avoid-IP-ban mission)', () => {
    // The preset promises "balanced to avoid IP bans" and "moderate concurrency to
    // stay under WAF thresholds" -- incompatible with graphql-cop's four DoS probes
    // which default-on.
    const p = get('bug-bounty-deep')!.parameters as Record<string, unknown>
    expect(p.graphqlCopEnabled).toBe(true)
    expect(p.graphqlCopTestAliasOverloading).toBe(false)
    expect(p.graphqlCopTestBatchQuery).toBe(false)
    expect(p.graphqlCopTestDirectiveOverloading).toBe(false)
    expect(p.graphqlCopTestCircularIntrospection).toBe(false)
  })

  test('secret-miner skips DoS probes (read-only focus)', () => {
    const p = get('secret-miner')!.parameters as Record<string, unknown>
    expect(p.graphqlCopTestAliasOverloading).toBe(false)
    expect(p.graphqlCopTestBatchQuery).toBe(false)
    expect(p.graphqlCopTestDirectiveOverloading).toBe(false)
    expect(p.graphqlCopTestCircularIntrospection).toBe(false)
  })
})

// ============================================================
// GraphQL Recon preset (dedicated GraphQL-focused preset)
// ============================================================

describe('GraphQL Recon preset', () => {
  const preset = RECON_PRESETS.find(p => p.id === 'graphql-recon')

  test('is registered in RECON_PRESETS', () => {
    expect(preset).toBeDefined()
    expect(preset!.id).toBe('graphql-recon')
    expect(preset!.name).toBe('GraphQL Recon')
  })

  test('has a graphql-themed SVG image', () => {
    expect(preset!.image).toBe('/preset-graphql.svg')
  })

  test('has substantive descriptions', () => {
    expect(preset!.shortDescription.length).toBeGreaterThan(50)
    expect(preset!.fullDescription.length).toBeGreaterThan(500)
    expect(preset!.fullDescription).toContain('GraphQL')
    expect(preset!.fullDescription).toContain('introspection')
  })

  test('enables both native GraphQL scanner AND graphql-cop', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.graphqlSecurityEnabled).toBe(true)
    expect(p.graphqlCopEnabled).toBe(true)
  })

  test('native scanner runs with full coverage (mutations + proxy + safe mode off)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.graphqlIntrospectionTest).toBe(true)
  })

  test('graphql-cop runs with cross-validation (introspection ON) + all DoS probes', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.graphqlCopTestIntrospection).toBe(true)  // cross-validate with native
    expect(p.graphqlCopTestAliasOverloading).toBe(true)
    expect(p.graphqlCopTestBatchQuery).toBe(true)
    expect(p.graphqlCopTestDirectiveOverloading).toBe(true)
    expect(p.graphqlCopTestCircularIntrospection).toBe(true)
  })

  test('enables JS Recon for SPA GraphQL endpoint extraction', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.jsReconEnabled).toBe(true)
    expect(p.jsReconExtractEndpoints).toBe(true)
    expect(p.jsReconSourceMaps).toBe(true)
    expect(p.jsReconFrameworkDetect).toBe(true)
  })

  test('enables Naabu with scoped API ports (non-standard GraphQL ports like 4000/3000/8080)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.naabuEnabled).toBe(true)
    // Must include Apollo (4000), Hasura (8080), Flask (5000), DVGA (5013), alt-HTTPS (8443)
    const ports = p.naabuCustomPorts as string
    expect(ports).toMatch(/4000/)
    expect(ports).toMatch(/5013/)
    expect(ports).toMatch(/8080/)
    expect(ports).toMatch(/8443/)
    // Heavy scanners stay off
    expect(p.masscanEnabled).toBe(false)
    expect(p.nmapEnabled).toBe(false)
  })

  test('scanModules includes port_scan (required for Naabu to run)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.scanModules).toContain('port_scan')
  })

  test('enables MITRE for CVE-to-ATT&CK mapping of Nuclei findings', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.mitreEnabled).toBe(true)
  })

  test('GAU has verify + method detection + dead-endpoint filtering enabled', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.gauVerifyUrls).toBe(true)
    expect(p.gauDetectMethods).toBe(true)
    expect(p.gauFilterDeadEndpoints).toBe(true)
  })

  test('Wappalyzer enabled (detects Apollo/Hasura/graphql-yoga for better targeting)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.wappalyzerEnabled).toBe(true)
  })

  test('Knockpy disabled (brute-force subdomain, marginal GraphQL ROI)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.knockpyReconEnabled).toBe(false)
  })

  test('Nuclei tags include csrf + injection beyond framework CVEs', () => {
    const p = preset!.parameters as Record<string, unknown>
    const tags = p.nucleiTags as string[]
    expect(tags).toContain('graphql')
    expect(tags).toContain('apollo')
    expect(tags).toContain('hasura')
    expect(tags).toContain('csrf')
    expect(tags).toContain('injection')
  })

  test('disables Kiterunner and ffuf (GraphQL paths are known patterns)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.kiterunnerEnabled).toBe(false)
    expect(p.ffufEnabled).toBe(false)
  })

  test('enables crawlers + historical URL sources (find JS-referenced endpoints)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.katanaEnabled).toBe(true)
    expect(p.hakrawlerEnabled).toBe(true)
    expect(p.gauEnabled).toBe(true)
    expect(p.paramspiderEnabled).toBe(true)
    expect(p.jsluiceEnabled).toBe(true)
  })

  test('disables all OSINT enrichment (not GraphQL-relevant)', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.osintEnrichmentEnabled).toBe(false)
    expect(p.shodanEnabled).toBe(false)
    expect(p.urlscanEnabled).toBe(false)
    expect(p.otxEnabled).toBe(false)
    expect(p.censysEnabled).toBe(false)
  })

  test('Nuclei uses GraphQL-specific tags', () => {
    const p = preset!.parameters as Record<string, unknown>
    expect(p.nucleiEnabled).toBe(true)
    const tags = p.nucleiTags as string[]
    expect(tags).toContain('graphql')
    expect(tags).toContain('apollo')
    expect(tags).toContain('hasura')
  })

  test('roundtrips through Zod schema without losing keys', async () => {
    const { reconPresetSchema } = await import('../recon-preset-schema')
    const result = reconPresetSchema.safeParse(preset!.parameters)
    expect(result.success).toBe(true)
    // Critical GraphQL keys must survive validation
    expect(result.data!.graphqlSecurityEnabled).toBe(true)
    expect(result.data!.graphqlCopEnabled).toBe(true)
    expect(result.data!.jsReconEnabled).toBe(true)
  })

  test('has unique ID (not colliding with existing presets)', () => {
    const ids = RECON_PRESETS.map(p => p.id)
    const uniqueIds = new Set(ids)
    expect(uniqueIds.size).toBe(ids.length)
  })

  test('is included in the registry (current count: 22)', () => {
    expect(RECON_PRESETS.length).toBe(22)
  })
})
