/**
 * Unit tests for report template — focuses on:
 * - Dynamic TOC numbering
 * - Conditional section rendering (empty data returns '')
 * - HTML escaping / XSS prevention
 * - Section ID consistency between TOC and rendered sections
 */

import { describe, test, expect } from 'vitest'
import { generateReportHtml } from './reportTemplate'
import type { ReportData } from './reportData'

// ── Minimal mock ReportData ─────────────────────────────────────────────

function makeReportData(overrides: Partial<ReportData> = {}): ReportData {
  return {
    project: {
      id: 'test-id',
      name: 'Test Project',
      targetDomain: 'example.com',
      createdAt: new Date(),
      updatedAt: new Date(),
      userId: 'user1',
      status: 'active',
      targetType: 'domain',
      description: null,
      githubTarget: null,
      excludeTargets: null,
      settings: null,
      roeEngagementType: null,
      roeClientName: null,
      roeStartDate: null,
      roeEndDate: null,
      roeScopeDescription: null,
      roePrimaryContact: null,
      roeRulesOfEngagement: null,
    } as any,
    remediations: [],
    generatedAt: '2026-04-03T00:00:00.000Z',
    graphOverview: {
      totalNodes: 0,
      nodeCounts: [],
      subdomainStats: { total: 0, resolved: 0, uniqueIps: 0 },
      endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
      certificateHealth: { total: 0, expired: 0, expiringSoon: 0 },
      infrastructureStats: { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
      subdomainMappings: [],
      ipMappings: [],
    },
    attackSurface: {
      services: [],
      ports: [],
      technologies: [],
      dnsRecords: [],
      securityHeaders: [],
      endpointCategories: [],
      parameterAnalysis: [],
    },
    vulnerabilities: {
      severityDistribution: [],
      findings: [],
      cvssHistogram: [],
      cveSeverity: [],
      gvmRemediation: [],
    },
    cveIntelligence: {
      cveChains: [],
      exploits: [],
      githubSecrets: { repos: 0, secrets: 0, sensitiveFiles: 0 },
    },
    trufflehog: {
      totalFindings: 0,
      verifiedFindings: 0,
      repositories: 0,
      findings: [],
    },
    secrets: {
      total: 0,
      bySeverity: [],
      bySource: [],
      byType: [],
      findings: [],
    },
    jsRecon: {
      totalFindings: 0,
      bySeverity: [],
      byType: [],
      findings: [],
    },
    graphqlScan: {
      totalFindings: 0,
      endpointsTested: 0,
      introspectionEnabled: 0,
      bySeverity: [],
      byType: [],
      endpoints: [],
      findings: [],
    },
    otx: {
      totalPulses: 0,
      totalMalware: 0,
      enrichedIps: 0,
      adversaries: [],
      pulses: [],
      malware: [],
    },
    attackChains: {
      chains: [],
      exploitSuccesses: [],
      topFindings: [],
      totalChainFindings: 0,
    },
    metrics: {
      riskScore: 0,
      riskLabel: 'Minimal',
      totalVulnerabilities: 0,
      totalRemediations: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      exploitableCount: 0,
      totalCves: 0,
      cveCriticalCount: 0,
      cveHighCount: 0,
      cveMediumCount: 0,
      cveLowCount: 0,
      cvssAverage: 0,
      attackSurfaceSize: 0,
      secretsExposed: 0,
    },
    ...overrides,
  }
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('Report Template Generation', () => {
  test('generates valid HTML with minimal data', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('</html>')
    expect(html).toContain('Test Project')
    expect(html).toContain('example.com')
  })

  test('contains core sections in TOC', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).toContain('Executive Summary')
    expect(html).toContain('Scope &amp; Methodology')
    expect(html).toContain('Risk Summary')
    expect(html).toContain('Findings')
    expect(html).toContain('Attack Surface')
    expect(html).toContain('CVE Intelligence')
    expect(html).toContain('Recommendations')
    expect(html).toContain('Appendix')
  })
})

describe('Conditional Section Rendering', () => {
  test('TruffleHog section NOT rendered when no findings', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="trufflehog"')
  })

  test('TruffleHog section rendered when findings exist', () => {
    const data = makeReportData({
      trufflehog: {
        totalFindings: 3,
        verifiedFindings: 1,
        repositories: 2,
        findings: [
          { detectorName: 'AWS', verified: true, redacted: 'AKIA...', repository: 'org/repo', file: '.env', commit: 'abc123', line: 5, link: null },
          { detectorName: 'GitHub', verified: false, redacted: 'ghp_...', repository: 'org/repo', file: 'config.js', commit: 'def456', line: 10, link: null },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="trufflehog"')
    expect(html).toContain('TruffleHog Findings')
    expect(html).toContain('VERIFIED')
    expect(html).toContain('AWS')
    expect(html).toContain('AKIA...')
  })

  test('Secrets section NOT rendered when total=0', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="secrets"')
  })

  test('Secrets section rendered when secrets exist', () => {
    const data = makeReportData({
      secrets: {
        total: 2,
        bySeverity: [{ severity: 'high', count: 2 }],
        bySource: [{ source: 'js_recon', count: 2 }],
        byType: [{ secretType: 'AWSAccessKey', count: 2 }],
        findings: [
          { secretType: 'AWSAccessKey', severity: 'high', source: 'js_recon', sourceUrl: 'https://example.com/app.js', sample: 'AKIA2E...', validationStatus: 'validated', confidence: 'high', keyType: 'cloud' },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="secrets"')
    expect(html).toContain('Secret Detection')
    expect(html).toContain('AWSAccessKey')
    expect(html).toContain('validated')
  })

  test('JS Recon section NOT rendered when no findings', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="js-recon"')
  })

  test('JS Recon section rendered when findings exist', () => {
    const data = makeReportData({
      jsRecon: {
        totalFindings: 1,
        bySeverity: [{ severity: 'high', count: 1 }],
        byType: [{ findingType: 'dependency_confusion', count: 1 }],
        findings: [
          { findingType: 'dependency_confusion', severity: 'high', confidence: 'high', title: 'Private npm package exposed', detail: null, evidence: '@internal/utils', sourceUrl: 'https://example.com/bundle.js' },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="js-recon"')
    expect(html).toContain('JavaScript Reconnaissance')
    expect(html).toContain('dependency confusion')
    expect(html).toContain('Private npm package exposed')
  })

  test('OTX section NOT rendered when no pulses or malware', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="otx"')
  })

  // ============================================================================
  // GraphQL Security section (Phase 1 §7)
  // ============================================================================
  test('GraphQL section NOT rendered with zero endpoints and zero findings', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="graphql-scan"')
    expect(html).not.toContain('GraphQL Security')
  })

  test('GraphQL section rendered when an endpoint was tested even without findings', () => {
    const data = makeReportData({
      graphqlScan: {
        totalFindings: 0,
        endpointsTested: 2,
        introspectionEnabled: 1,
        bySeverity: [],
        byType: [],
        endpoints: [
          { url: 'https://api.target.com/graphql', introspectionEnabled: true, schemaExtracted: true, queriesCount: 23, mutationsCount: 8, subscriptionsCount: 2, schemaHash: 'sha256:abc1234567890def' },
          { url: 'https://api.target.com/v1/graphql', introspectionEnabled: false, schemaExtracted: false, queriesCount: 0, mutationsCount: 0, subscriptionsCount: 0, schemaHash: null },
        ],
        findings: [],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="graphql-scan"')
    expect(html).toContain('GraphQL Security')
    expect(html).toContain('https://api.target.com/graphql')
    expect(html).toContain('YES')      // introspection enabled badge
  })

  test('GraphQL section renders findings table when vulnerabilities present', () => {
    const data = makeReportData({
      graphqlScan: {
        totalFindings: 2,
        endpointsTested: 1,
        introspectionEnabled: 1,
        bySeverity: [{ severity: 'medium', count: 1 }, { severity: 'high', count: 1 }],
        byType: [
          { vulnerabilityType: 'graphql_introspection_enabled', count: 1 },
          { vulnerabilityType: 'graphql_sensitive_data_exposure', count: 1 },
        ],
        endpoints: [
          { url: 'https://api.target.com/graphql', introspectionEnabled: true, schemaExtracted: true, queriesCount: 23, mutationsCount: 8, subscriptionsCount: 0, schemaHash: 'sha256:abc' },
        ],
        findings: [
          { endpoint: 'https://api.target.com/graphql', vulnerabilityType: 'graphql_introspection_enabled', severity: 'medium', source: 'graphql_scan', title: 'GraphQL Introspection Enabled', description: null, evidence: null, curlVerify: null },
          { endpoint: 'https://api.target.com/graphql', vulnerabilityType: 'graphql_sensitive_data_exposure', severity: 'high', source: 'graphql_scan', title: 'Sensitive Fields Exposed', description: null, evidence: null, curlVerify: null },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="graphql-scan"')
    expect(html).toContain('graphql introspection enabled')
    expect(html).toContain('graphql sensitive data exposure')
    expect(html).toContain('GraphQL Introspection Enabled')
    expect(html).toContain('Sensitive Fields Exposed')
    // By Severity table should reflect counts
    expect(html).toMatch(/<h3>By Severity<\/h3>[\s\S]*medium/)
  })

  test('GraphQL section does not render tested-endpoints table when none tested', () => {
    const data = makeReportData({
      graphqlScan: {
        totalFindings: 0,
        endpointsTested: 0,
        introspectionEnabled: 0,
        bySeverity: [],
        byType: [],
        endpoints: [],
        findings: [],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('id="graphql-scan"')
  })

  test('OTX section rendered when pulses exist', () => {
    const data = makeReportData({
      otx: {
        totalPulses: 2,
        totalMalware: 1,
        enrichedIps: 3,
        adversaries: ['APT28', 'Lazarus Group'],
        pulses: [
          { name: 'APT28 C2 Infrastructure', adversary: 'APT28', malwareFamilies: ['Sofacy'], attackIds: ['T1566'], tlp: 'green', targetedCountries: ['US'], ipAddress: '1.2.3.4' },
        ],
        malware: [
          { hash: 'abc123def456', hashType: 'sha256', fileType: 'pe32', fileName: 'backdoor.exe', source: 'otx', ipAddress: '1.2.3.4' },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('id="otx"')
    expect(html).toContain('OTX Threat Intelligence')
    expect(html).toContain('APT28')
    expect(html).toContain('Lazarus Group')
    expect(html).toContain('Sofacy')
    expect(html).toContain('T1566')
    expect(html).toContain('abc123def456')
  })

  test('GitHub Secrets section NOT rendered when empty', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="github-secrets"')
  })

  test('Attack Chains section NOT rendered when empty', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).not.toContain('id="attack-chains"')
  })
})

describe('Dynamic TOC Numbering', () => {
  test('TOC numbers are sequential with no conditional sections', () => {
    const html = generateReportHtml(makeReportData(), null)
    // Core sections only: 1-7 fixed, then Recommendations=8, Appendix=9
    expect(html).toContain('1. Executive Summary')
    expect(html).toContain('2. Scope &amp; Methodology')
    expect(html).toContain('7. CVE Intelligence')
    expect(html).toContain('8. Recommendations')
    expect(html).toContain('9. Appendix')
  })

  test('TOC numbers shift when conditional sections are present', () => {
    const data = makeReportData({
      trufflehog: { totalFindings: 1, verifiedFindings: 0, repositories: 1, findings: [] },
      jsRecon: { totalFindings: 1, bySeverity: [], byType: [], findings: [] },
      otx: { totalPulses: 1, totalMalware: 0, enrichedIps: 0, adversaries: [], pulses: [], malware: [] },
    })
    const html = generateReportHtml(data, null)
    // Core: 1-7, then TruffleHog=8, JS Recon=9, OTX=10, Recommendations=11, Appendix=12
    expect(html).toContain('8. TruffleHog Findings')
    expect(html).toContain('9. JavaScript Reconnaissance')
    expect(html).toContain('10. OTX Threat Intelligence')
    expect(html).toContain('11. Recommendations')
    expect(html).toContain('12. Appendix')
  })

  test('all conditional sections appear in TOC when data present', () => {
    const data = makeReportData({
      cveIntelligence: {
        cveChains: [],
        exploits: [],
        githubSecrets: { repos: 1, secrets: 3, sensitiveFiles: 1 },
      },
      trufflehog: { totalFindings: 2, verifiedFindings: 1, repositories: 1, findings: [] },
      secrets: { total: 5, bySeverity: [], bySource: [], byType: [], findings: [] },
      jsRecon: { totalFindings: 3, bySeverity: [], byType: [], findings: [] },
      otx: { totalPulses: 2, totalMalware: 1, enrichedIps: 0, adversaries: [], pulses: [], malware: [] },
      attackChains: {
        chains: [{ title: 'Test', status: 'completed', steps: 3, findings: 1, failures: 0 }],
        exploitSuccesses: [],
        topFindings: [],
        totalChainFindings: 1,
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).toContain('GitHub Secrets')
    expect(html).toContain('TruffleHog Findings')
    expect(html).toContain('Secret Detection')
    expect(html).toContain('JavaScript Reconnaissance')
    expect(html).toContain('OTX Threat Intelligence')
    expect(html).toContain('Attack Chains')
    // Verify Appendix is last
    const appendixMatch = html.match(/(\d+)\. Appendix/)
    expect(appendixMatch).not.toBeNull()
    expect(Number(appendixMatch![1])).toBe(15) // 7 core + 6 conditional + Recommendations + Appendix
  })
})

describe('HTML Escaping / XSS Prevention', () => {
  test('XSS in project name is escaped', () => {
    const data = makeReportData()
    ;(data.project as any).name = '<script>alert("xss")</script>'
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('<script>alert("xss")</script>')
    expect(html).toContain('&lt;script&gt;')
  })

  test('XSS in trufflehog detector name is escaped', () => {
    const data = makeReportData({
      trufflehog: {
        totalFindings: 1,
        verifiedFindings: 0,
        repositories: 1,
        findings: [
          { detectorName: '<img onerror=alert(1)>', verified: false, redacted: null, repository: null, file: null, commit: null, line: null, link: null },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('<img onerror=alert(1)>')
    expect(html).toContain('&lt;img onerror=alert(1)&gt;')
  })

  test('XSS in secret sample is escaped', () => {
    const data = makeReportData({
      secrets: {
        total: 1,
        bySeverity: [{ severity: 'high', count: 1 }],
        bySource: [{ source: 'js_recon', count: 1 }],
        byType: [{ secretType: 'test', count: 1 }],
        findings: [
          { secretType: 'test', severity: 'high', source: 'js_recon', sourceUrl: null, sample: '"><script>alert(1)</script>', validationStatus: null, confidence: null, keyType: null },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('"><script>alert(1)</script>')
  })

  test('XSS in OTX adversary name is escaped', () => {
    const data = makeReportData({
      otx: {
        totalPulses: 1, totalMalware: 0, enrichedIps: 0,
        adversaries: ['<script>steal()</script>'],
        pulses: [{ name: 'test', adversary: '<script>steal()</script>', malwareFamilies: [], attackIds: [], tlp: null, targetedCountries: [], ipAddress: null }],
        malware: [],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('<script>steal()</script>')
  })

  test('XSS in JS Recon title is escaped', () => {
    const data = makeReportData({
      jsRecon: {
        totalFindings: 1,
        bySeverity: [{ severity: 'high', count: 1 }],
        byType: [{ findingType: 'dom_sink', count: 1 }],
        findings: [
          { findingType: 'dom_sink', severity: 'high', confidence: 'high', title: '<img src=x onerror=alert(1)>', detail: null, evidence: null, sourceUrl: null },
        ],
      },
    })
    const html = generateReportHtml(data, null)
    expect(html).not.toContain('<img src=x onerror=alert(1)>')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })
})

describe('Section ID Consistency', () => {
  test('TOC section IDs match rendered section IDs', () => {
    const data = makeReportData({
      cveIntelligence: {
        cveChains: [],
        exploits: [],
        githubSecrets: { repos: 1, secrets: 1, sensitiveFiles: 0 },
      },
      trufflehog: { totalFindings: 1, verifiedFindings: 0, repositories: 1, findings: [{ detectorName: 'test', verified: false, redacted: null, repository: null, file: null, commit: null, line: null, link: null }] },
      secrets: { total: 1, bySeverity: [], bySource: [], byType: [], findings: [{ secretType: 'test', severity: 'high', source: 'test', sourceUrl: null, sample: null, validationStatus: null, confidence: null, keyType: null }] },
      jsRecon: { totalFindings: 1, bySeverity: [], byType: [], findings: [{ findingType: 'test', severity: 'high', confidence: null, title: 'test', detail: null, evidence: null, sourceUrl: null }] },
      otx: { totalPulses: 1, totalMalware: 0, enrichedIps: 0, adversaries: [], pulses: [{ name: 'test', adversary: null, malwareFamilies: [], attackIds: [], tlp: null, targetedCountries: [], ipAddress: null }], malware: [] },
      attackChains: {
        chains: [{ title: 'test', status: 'completed', steps: 1, findings: 0, failures: 0 }],
        exploitSuccesses: [], topFindings: [], totalChainFindings: 0,
      },
    })
    const html = generateReportHtml(data, null)

    // Every TOC href should have a matching rendered section id
    const tocHrefs = [...html.matchAll(/href="#([^"]+)"/g)].map(m => m[1])
    const sectionIds = [...html.matchAll(/id="([^"]+)"/g)].map(m => m[1])

    for (const href of tocHrefs) {
      expect(sectionIds).toContain(href)
    }
  })
})

describe('Appendix Tools Table', () => {
  test('lists new tools in appendix', () => {
    const html = generateReportHtml(makeReportData(), null)
    expect(html).toContain('TruffleHog')
    expect(html).toContain('jsluice')
    expect(html).toContain('JS Recon')
    expect(html).toContain('AlienVault OTX')
  })
})
