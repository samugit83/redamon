import { describe, expect, it } from 'vitest'
import { evaluateCompliance, evidenceFromReportData, normalizeFrameworkIds } from './index'
import type { ComplianceEvidenceSnapshot } from './types'
import { generateReportHtml } from '@/lib/report/reportTemplate'
import type { ReportData } from '@/lib/report/reportData'

function emptyEvidence(overrides: Partial<ComplianceEvidenceSnapshot> = {}): ComplianceEvidenceSnapshot {
  return {
    isIpOnlyMode: false,
    roeForbiddenCategories: [],
    totalVulnerabilities: 0,
    criticalHighVulns: 0,
    mediumVulns: 0,
    cveTotal: 0,
    cveCriticalHigh: 0,
    tlsCertificatesScanned: 0,
    tlsExpiredOrMismatched: 0,
    tlsSelfSigned: 0,
    secretsExposed: 0,
    trufflehogScanned: false,
    trufflehogFindings: 0,
    githubSecretHuntScanned: false,
    githubSecretFindings: 0,
    supplyChainScanned: false,
    supplyChainMaliciousOrSuspicious: 0,
    graphqlScanned: false,
    graphqlFindings: 0,
    webCachePoisonFindings: 0,
    jsReconScanned: false,
    jsReconFindings: 0,
    aiSurfaceScanned: false,
    aiSurfaceFindings: 0,
    attackSurfaceSize: 0,
    hasReconNodes: false,
    hasVulnScanEvidence: false,
    remediationsTotal: 0,
    ...overrides,
  }
}

function minimalReportData(roeComplianceFrameworks: string[] = []): ReportData {
  return {
    project: {
      id: 'proj-1',
      name: 'Test App',
      targetDomain: 'example.test',
      ipMode: false,
      targetIps: [],
      subdomainList: [],
      roeEnabled: roeComplianceFrameworks.length > 0,
      roeComplianceFrameworks,
    } as unknown as ReportData['project'],
    remediations: [],
    generatedAt: '2026-11-27T00:00:00.000Z',
    coverageLimitations: [],
    graphOverview: {
      totalNodes: 10,
      nodeCounts: [],
      suppressedCount: 0,
      suppressedByPeople: 0,
      suppressedByMultiMute: 0,
      suppressedByAgents: 0,
      suppressedByRules: 0,
      suppressedRules: [],
      judged: { personFalsePositive: 0, resolved: 0, aiFlagged: 0 },
      subdomainStats: { total: 0, resolved: 0, uniqueIps: 0 },
      endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
      certificateHealth: { total: 0, expired: 0, expiringSoon: 0, selfSigned: 0, mismatched: 0 },
      infrastructureStats: { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
      subdomainMappings: [],
      ipMappings: [],
    } as unknown as ReportData['graphOverview'],
    attackSurface: {
      services: [],
      ports: [],
      technologies: [],
      baseUrls: [],
      endpoints: [],
      parameters: [],
      headers: [],
      dnsRecords: [],
      securityHeaders: [],
      endpointCategories: [],
      parameterAnalysis: [],
    } as unknown as ReportData['attackSurface'],
    vulnerabilities: {
      severityDistribution: [],
      cvssHistogram: [],
      cveSeverity: [],
      gvmRemediation: [],
      findings: [],
    } as unknown as ReportData['vulnerabilities'],
    cveIntelligence: {
      cveChains: [],
      exploits: [],
      mitreCount: 0,
      capecCount: 0,
      githubSecrets: { repos: 0, secrets: 0, sensitiveFiles: 0 },
    } as unknown as ReportData['cveIntelligence'],
    githubSecrets: {
      reposScanned: 0,
      totalSecrets: 0,
      totalSensitiveFiles: 0,
      findings: [],
    } as unknown as ReportData['githubSecrets'],
    trufflehog: {
      totalFindings: 0,
      verifiedFindings: 0,
      sources: [],
      findings: [],
    } as unknown as ReportData['trufflehog'],
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
    supplyChain: {
      totalPackages: 0,
      maliciousCount: 0,
      suspiciousCount: 0,
      byEcosystem: [],
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
    vhostSni: {
      totalFindings: 0,
      ipsTested: 0,
      candidatesTested: 0,
      anomaliesL7: 0,
      anomaliesL4: 0,
      reverseProxiesDetected: 0,
      bySeverity: [],
      byLayer: [],
      byType: [],
      findings: [],
    },
    tlsx: {
      totalCertificates: 2,
      expired: 1,
      selfSigned: 0,
      mismatched: 0,
      wildcard: 0,
      expiringSoon: 0,
      topIssuers: [],
      findings: [],
    },
    webCachePoison: {
      totalFindings: 0,
      confirmed: 0,
      strong: 0,
      bySeverity: [],
      byImpact: [],
      findings: [],
    },
    aiSurface: {
      totalAiEndpoints: 0,
      ragIngestEndpoints: 0,
      promptInjectableParams: 0,
      mcpServers: 0,
      mcpPoisoningFindings: 0,
      vectorDbs: 0,
      modelFamilies: [],
      byInterfaceType: [],
      findings: [],
      attackFindings: [],
      attackToolsRun: [],
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
      riskScore: 10,
      riskLabel: 'Low',
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
      attackSurfaceSize: 5,
      secretsExposed: 0,
    },
  }
}

describe('compliance framework mapping', () => {
  it('normalizes RoE framework aliases into canonical IDs without duplicates', () => {
    expect(
      normalizeFrameworkIds(['PCI-DSS', 'PCI DSS 4.0', 'OWASP ASVS', 'NIST-CSF-2.0', 'unknown-std'])
    ).toEqual(['pci_dss_4_0', 'owasp_asvs_4_0', 'nist_csf_2_0'])
  })

  it('never marks un-run scanners as pass (reports no_evidence instead)', () => {
    const report = evaluateCompliance(emptyEvidence(), ['pci_dss_4_0', 'owasp_asvs_4_0', 'nist_csf_2_0'])
    for (const fw of report.frameworks) {
      expect(fw.counts.pass).toBe(0)
      expect(fw.counts.fail).toBe(0)
      expect(fw.counts.no_evidence).toBe(fw.totalControls)
    }
  })

  it('does not read recon nodes as evidence that a vulnerability scan ran', () => {
    const data = minimalReportData(['PCI-DSS'])
    data.metrics.totalVulnerabilities = 0
    data.metrics.totalRemediations = 0
    data.metrics.criticalCount = 0
    data.metrics.highCount = 0
    data.vulnerabilities = { ...data.vulnerabilities, severityDistribution: [] } as ReportData['vulnerabilities']
    data.graphOverview = { ...data.graphOverview, totalNodes: 250 } as ReportData['graphOverview']
    const ev = evidenceFromReportData(data)
    expect(ev.hasReconNodes).toBe(true)
    expect(ev.hasVulnScanEvidence).toBe(false)
    const vulnControl = evaluateCompliance(ev, ['pci_dss_4_0']).frameworks[0].controls.find(c => c.id === 'pci_11_3_2')
    expect(vulnControl?.status).toBe('no_evidence')
  })

  it('marks controls out_of_scope for IP-only non-HTTP assessments', () => {
    const report = evaluateCompliance(
      emptyEvidence({ isIpOnlyMode: true, attackSurfaceSize: 0 }),
      ['pci_dss_4_0', 'owasp_asvs_4_0']
    )
    const pciWeb = report.frameworks[0].controls.find(c => c.id === 'pci_6_2_4')
    const asvsWeb = report.frameworks[1].controls.find(c => c.id === 'asvs_v13_1')
    expect(pciWeb?.status).toBe('out_of_scope')
    expect(asvsWeb?.status).toBe('out_of_scope')
  })

  it('marks pass only when scan evidence exists with 0 findings, and fail when findings exist', () => {
    const ev = emptyEvidence({
      tlsCertificatesScanned: 3,
      tlsExpiredOrMismatched: 0,
      tlsSelfSigned: 0,
      supplyChainScanned: true,
      supplyChainMaliciousOrSuspicious: 2,
      trufflehogScanned: true,
      trufflehogFindings: 0,
      hasReconNodes: true,
      hasVulnScanEvidence: true,
      criticalHighVulns: 0,
    })
    const report = evaluateCompliance(ev, ['pci_dss_4_0'])
    const byId = Object.fromEntries(report.frameworks[0].controls.map(c => [c.id, c]))
    expect(byId.pci_4_2_1.status).toBe('pass')
    expect(byId.pci_8_6_1.status).toBe('pass')
    expect(byId.pci_11_3_2.status).toBe('pass')
    expect(byId.pci_6_3_2.status).toBe('fail')
    expect(byId.pci_6_3_2.findingCount).toBe(2)
  })

  it('omits compliance section from HTML report when roeComplianceFrameworks is empty, and renders it when configured', () => {
    const withoutCompliance = generateReportHtml(minimalReportData([]), null)
    expect(withoutCompliance).not.toContain('id="compliance-mapping"')

    const withCompliance = generateReportHtml(minimalReportData(['PCI-DSS 4.0', 'NIST CSF']), null)
    expect(withCompliance).toContain('id="compliance-mapping"')
    expect(withCompliance).toContain('Compliance Framework Mapping')
    expect(withCompliance).toContain('PCI DSS 4.0')
    expect(withCompliance).toContain('NIST CSF 2.0')
    expect(withCompliance).toContain('FAIL')
    expect(withCompliance).toContain('NO EVIDENCE')
  })

  it('extracts evidence snapshot accurately from ReportData', () => {
    const snap = evidenceFromReportData(minimalReportData(['PCI-DSS']))
    expect(snap.tlsCertificatesScanned).toBe(2)
    expect(snap.tlsExpiredOrMismatched).toBe(1)
    expect(snap.hasReconNodes).toBe(true)
  })
})
