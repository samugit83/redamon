import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { gatherReportData } from '@/lib/report/reportData'
import { generateReportHtml, type LLMNarratives } from '@/lib/report/reportTemplate'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import path from 'path'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

const REPORT_OUTPUT_PATH = process.env.REPORT_OUTPUT_PATH || '/data/reports'
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** GET /api/projects/{id}/reports - List all reports for a project */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const reports = await prisma.report.findMany({
      where: { projectId: id },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        title: true,
        filename: true,
        fileSize: true,
        format: true,
        metrics: true,
        hasNarratives: true,
        createdAt: true,
      },
    })
    return NextResponse.json(reports)
  } catch (error) {
    console.error('List reports failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list reports' },
      { status: 500 }
    )
  }
}

/** POST /api/projects/{id}/reports - Generate a new report */
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    // 1. Gather all data from Neo4j + PostgreSQL
    const reportData = await gatherReportData(id)

    // 2. Request LLM narratives from the agent service (with fallback)
    let narratives: LLMNarratives | null = null
    try {
      const condensed = condenseForAgent(reportData)
      const resp = await fetch(`${AGENT_API_URL}/api/report/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: condensed }),
        signal: AbortSignal.timeout(300_000), // 5 min timeout
      })
      if (resp.ok) {
        narratives = await resp.json() as LLMNarratives
      } else {
        console.warn(`Report narratives failed (${resp.status}): ${await resp.text()}`)
      }
    } catch (err) {
      console.warn('Agent unavailable for report narratives, generating without:', err)
    }

    // 3. Generate HTML
    const html = generateReportHtml(reportData, narratives)

    // 4. Write to disk
    if (!existsSync(REPORT_OUTPUT_PATH)) {
      mkdirSync(REPORT_OUTPUT_PATH, { recursive: true })
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19)
    const safeName = reportData.project.name.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 40)
    const filename = `report_${safeName}_${timestamp}.html`
    const filePath = path.join(REPORT_OUTPUT_PATH, filename)
    const htmlBuffer = Buffer.from(html, 'utf-8')
    writeFileSync(filePath, htmlBuffer)

    // 5. Save metadata to DB
    const report = await prisma.report.create({
      data: {
        projectId: id,
        title: `Pentest Report - ${reportData.project.targetDomain || reportData.project.name}`,
        filename,
        filePath,
        fileSize: htmlBuffer.length,
        format: 'html',
        hasNarratives: narratives !== null,
        metrics: {
          riskScore: reportData.metrics.riskScore,
          riskLabel: reportData.metrics.riskLabel,
          totalVulnerabilities: reportData.metrics.totalVulnerabilities,
          totalCves: reportData.metrics.totalCves,
          criticalCount: reportData.metrics.criticalCount,
          highCount: reportData.metrics.highCount,
          mediumCount: reportData.metrics.mediumCount,
          lowCount: reportData.metrics.lowCount,
          cveCriticalCount: reportData.metrics.cveCriticalCount,
          cveHighCount: reportData.metrics.cveHighCount,
          cveMediumCount: reportData.metrics.cveMediumCount,
          cveLowCount: reportData.metrics.cveLowCount,
          totalRemediations: reportData.metrics.totalRemediations,
          exploitableCount: reportData.metrics.exploitableCount,
        },
      },
    })

    return NextResponse.json(report, { status: 201 })
  } catch (error) {
    console.error('Generate report failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Report generation failed' },
      { status: 500 }
    )
  }
}

/** Condense ReportData into a smaller payload for the LLM summarizer.
 *  Sends ALL CVEs, findings, exploits, and remediations so the LLM can
 *  produce a comprehensive triage in the recommendations section. */
function condenseForAgent(data: ReturnType<typeof gatherReportData> extends Promise<infer T> ? T : never) {
  // Deduplicate ALL CVE chains by CVE ID
  const seenCves = new Set<string>()
  const allChains = data.cveIntelligence.cveChains
    .filter(c => {
      if (!c.cveId || seenCves.has(c.cveId)) return false
      seenCves.add(c.cveId)
      return true
    })
    .map(c => ({
      tech: c.tech, techVersion: c.techVersion,
      cveId: c.cveId, cvss: c.cvss, cveSeverity: c.cveSeverity,
      cweId: c.cweId, cweName: c.cweName,
      capecId: c.capecId, capecName: c.capecName,
    }))

  return {
    project: {
      name: data.project.name,
      targetDomain: data.project.targetDomain,
      roeEngagementType: (data.project as any).roeEngagementType,
      roeClientName: (data.project as any).roeClientName,
    },
    metrics: data.metrics,
    graphOverview: {
      totalNodes: data.graphOverview.totalNodes,
      subdomainStats: data.graphOverview.subdomainStats,
      endpointCoverage: data.graphOverview.endpointCoverage,
      certificateHealth: data.graphOverview.certificateHealth,
      infrastructureStats: data.graphOverview.infrastructureStats,
    },
    attackSurface: {
      technologies: data.attackSurface.technologies,
      services: data.attackSurface.services,
      ports: data.attackSurface.ports,
      securityHeaders: data.attackSurface.securityHeaders,
      parameterAnalysis: data.attackSurface.parameterAnalysis,
    },
    vulnerabilities: {
      severityDistribution: data.vulnerabilities.severityDistribution,
      cvssHistogram: data.vulnerabilities.cvssHistogram,
      findings: data.vulnerabilities.findings.map(f => ({
        name: f.name,
        severity: f.severity,
        findingSource: f.findingSource,
        target: f.target || f.host,
        category: f.category,
        cvssScore: f.cvssScore,
      })),
    },
    cveIntelligence: {
      exploits: data.cveIntelligence.exploits.map(e => ({
        name: e.name,
        cvssScore: e.cvssScore,
        cveIds: e.cveIds,
        cisaKev: e.cisaKev,
        targetIp: e.targetIp,
      })),
      githubSecrets: data.cveIntelligence.githubSecrets,
      cveChains: allChains,
    },
    attackChains: {
      chains: data.attackChains.chains,
      exploitSuccesses: data.attackChains.exploitSuccesses.map(e => ({
        title: e.title,
        targetIp: e.targetIp,
        attackType: e.attackType,
        cveIds: e.cveIds,
        module: e.module,
        evidence: e.evidence,
      })),
    },
    remediations: data.remediations.map(r => ({
      title: r.title,
      severity: r.severity,
      category: r.category,
      solution: r.solution,
      cveIds: r.cveIds,
      cweIds: r.cweIds,
      exploitAvailable: r.exploitAvailable,
      cisaKev: r.cisaKev,
      status: r.status,
      cvssScore: r.cvssScore,
      affectedAssets: r.affectedAssets,
    })),
    trufflehog: {
      totalFindings: data.trufflehog.totalFindings,
      verifiedFindings: data.trufflehog.verifiedFindings,
      repositories: data.trufflehog.repositories,
      findings: data.trufflehog.findings.slice(0, 20).map(f => ({
        detectorName: f.detectorName,
        verified: f.verified,
        repository: f.repository,
        file: f.file,
      })),
    },
    secrets: {
      total: data.secrets.total,
      bySeverity: data.secrets.bySeverity,
      bySource: data.secrets.bySource,
      byType: data.secrets.byType,
    },
    jsRecon: {
      totalFindings: data.jsRecon.totalFindings,
      bySeverity: data.jsRecon.bySeverity,
      byType: data.jsRecon.byType,
      findings: data.jsRecon.findings.slice(0, 20).map(f => ({
        title: f.title,
        severity: f.severity,
        findingType: f.findingType,
        confidence: f.confidence,
      })),
    },
    supplyChain: {
      totalPackages: data.supplyChain.totalPackages,
      maliciousCount: data.supplyChain.maliciousCount,
      suspiciousCount: data.supplyChain.suspiciousCount,
      byEcosystem: data.supplyChain.byEcosystem,
      // Malicious first (the query already orders that way), capped for the LLM.
      findings: data.supplyChain.findings.slice(0, 20).map(f => ({
        name: f.name,
        version: f.version,
        ecosystem: f.ecosystem,
        verdict: f.verdict,
        advisoryId: f.advisoryId,
        severity: f.severity,
      })),
    },
    graphqlScan: {
      totalFindings: data.graphqlScan.totalFindings,
      endpointsTested: data.graphqlScan.endpointsTested,
      introspectionEnabled: data.graphqlScan.introspectionEnabled,
      bySeverity: data.graphqlScan.bySeverity,
      byType: data.graphqlScan.byType,
      topFindings: data.graphqlScan.findings.slice(0, 15).map(f => ({
        title: f.title,
        severity: f.severity,
        vulnerabilityType: f.vulnerabilityType,
        source: f.source,   // 'graphql_scan' vs 'graphql_cop' - helps LLM narrate differently
        endpoint: f.endpoint,
      })),
    },
    vhostSni: {
      totalFindings: data.vhostSni.totalFindings,
      ipsTested: data.vhostSni.ipsTested,
      anomaliesL7: data.vhostSni.anomaliesL7,
      anomaliesL4: data.vhostSni.anomaliesL4,
      reverseProxiesDetected: data.vhostSni.reverseProxiesDetected,
      bySeverity: data.vhostSni.bySeverity,
      byLayer: data.vhostSni.byLayer,
      byType: data.vhostSni.byType,
      topFindings: data.vhostSni.findings.slice(0, 15).map(f => ({
        hostname: f.hostname,
        severity: f.severity,
        layer: f.layer,
        type: f.type,
        target: f.ip ? `${f.ip}${f.port ? ':' + f.port : ''}` : null,
        internalPatternMatch: f.internalPatternMatch,
      })),
    },
    tlsx: {
      totalCertificates: data.tlsx.totalCertificates,
      expired: data.tlsx.expired,
      expiringSoon: data.tlsx.expiringSoon,
      selfSigned: data.tlsx.selfSigned,
      mismatched: data.tlsx.mismatched,
      wildcard: data.tlsx.wildcard,
      topIssuers: data.tlsx.topIssuers.slice(0, 10),
      notableCerts: data.tlsx.findings
        .filter(f => f.expired || f.selfSigned || f.mismatched)
        .slice(0, 15)
        .map(f => ({
          subjectCn: f.subjectCn,
          issuer: f.issuer,
          expired: f.expired,
          selfSigned: f.selfSigned,
          mismatched: f.mismatched,
          source: f.source,
        })),
    },
    webCachePoison: {
      totalFindings: data.webCachePoison.totalFindings,
      confirmed: data.webCachePoison.confirmed,
      strong: data.webCachePoison.strong,
      bySeverity: data.webCachePoison.bySeverity,
      byImpact: data.webCachePoison.byImpact,
      topFindings: data.webCachePoison.findings.slice(0, 15).map(f => ({
        endpoint: f.endpoint,
        severity: f.severity,
        vector: f.cacheHeader || f.cacheParam || null,
        impact: f.cacheImpact,
        technique: f.cacheTechnique,
        confidenceTier: f.confidenceTier,
        confidence: f.confidence,
      })),
    },
    aiSurface: {
      totalAiEndpoints: data.aiSurface.totalAiEndpoints,
      ragIngestEndpoints: data.aiSurface.ragIngestEndpoints,
      promptInjectableParams: data.aiSurface.promptInjectableParams,
      mcpServers: data.aiSurface.mcpServers,
      mcpPoisoningFindings: data.aiSurface.mcpPoisoningFindings,
      vectorDbs: data.aiSurface.vectorDbs,
      modelFamilies: data.aiSurface.modelFamilies,
      byInterfaceType: data.aiSurface.byInterfaceType,
      // Top 15 endpoints for the LLM's narrative (full 50 stay in the HTML report)
      sampleEndpoints: data.aiSurface.findings.slice(0, 15).map(f => ({
        baseUrl: f.baseUrl,
        path: f.path,
        interfaceType: f.interfaceType,
        isRagIngest: f.isRagIngest,
        promptInjectableParams: f.promptInjectableParams,
      })),
      // CONFIRMED attack findings (garak/pyrit/giskard/promptfoo), corroborated
      // across tools - the highest-signal AI evidence for the narrative (§9).
      attackToolsRun: data.aiSurface.attackToolsRun,
      attackFindings: data.aiSurface.attackFindings.slice(0, 25).map(f => ({
        owaspLlmId: f.owaspLlmId,
        attack: f.attackChip,
        target: f.target,
        foundBy: f.sources,
        maxAsr: f.maxAsr,
        trials: f.totalTrials,
        severity: f.severity,
        evidence: (f.evidence || '').slice(0, 160),
      })),
    },
    otx: {
      totalPulses: data.otx.totalPulses,
      totalMalware: data.otx.totalMalware,
      enrichedIps: data.otx.enrichedIps,
      adversaries: data.otx.adversaries,
      pulses: data.otx.pulses.slice(0, 15).map(p => ({
        name: p.name,
        adversary: p.adversary,
        malwareFamilies: p.malwareFamilies,
        attackIds: p.attackIds,
      })),
    },
  }
}
