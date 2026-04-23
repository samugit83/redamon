/**
 * Report Data Layer — gathers all Neo4j graph + PostgreSQL data for report generation.
 * Reuses query patterns from analytics routes but runs them in a single session.
 */

import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'
import type { Project, Remediation } from '@prisma/client'

// ── Helpers ──────────────────────────────────────────────────────────────────

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/** Run a query function with its own Neo4j session, auto-closing when done. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function withSession<T>(fn: (session: any) => Promise<T>): Promise<T> {
  const session = getSession()
  try {
    return await fn(session)
  } finally {
    await session.close()
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface VulnFinding {
  name: string
  severity: string
  source: string
  category: string | null
  cvssScore: number | null
  matchedAt: string | null
  host: string | null
  targetIp: string | null
  targetPort: number | null
  target: string | null
  parentType: string | null
  endpointPath: string | null
  paramName: string | null
  findingSource: string
}

export interface CveChain {
  tech: string
  techVersion: string | null
  cveId: string
  cvss: number | null
  cveSeverity: string | null
  cweId: string | null
  cweName: string | null
  capecId: string | null
  capecName: string | null
  capecSeverity: string | null
}

export interface ExploitRecord {
  name: string
  severity: string
  targetIp: string | null
  targetPort: number | null
  cvssScore: number | null
  cisaKev: boolean | null
  evidence: string | null
  cveIds: string[]
}

export interface AttackChainSummary {
  title: string
  status: string
  steps: number
  findings: number
  failures: number
}

export interface ExploitSuccess {
  title: string
  targetIp: string | null
  targetPort: number | null
  module: string | null
  evidence: string | null
  attackType: string | null
  cveIds: string[]
}

export interface TrufflehogFindingRecord {
  detectorName: string
  verified: boolean
  redacted: string | null
  repository: string | null
  file: string | null
  commit: string | null
  line: number | null
  link: string | null
}

export interface SecretRecord {
  secretType: string
  severity: string
  source: string
  sourceUrl: string | null
  sample: string | null
  validationStatus: string | null
  confidence: string | null
  keyType: string | null
}

export interface JsReconFindingRecord {
  findingType: string
  severity: string
  confidence: string | null
  title: string
  detail: string | null
  evidence: string | null
  sourceUrl: string | null
}

export interface GraphqlFindingRecord {
  endpoint: string
  vulnerabilityType: string   // native: 'graphql_introspection_enabled' | 'graphql_sensitive_data_exposure'
                              // graphql-cop: 'graphql_alias_overloading', 'graphql_batch_query_allowed', etc.
  severity: string
  source: 'graphql_scan' | 'graphql_cop' | string
  title: string
  description: string | null
  evidence: string | null     // JSON blob
  curlVerify: string | null   // graphql-cop cURL reproducer (extracted from evidence JSON)
}

export interface GraphqlEndpointRecord {
  url: string
  introspectionEnabled: boolean
  schemaExtracted: boolean
  queriesCount: number
  mutationsCount: number
  subscriptionsCount: number
  schemaHash: string | null
}

export interface ThreatPulseRecord {
  name: string
  adversary: string | null
  malwareFamilies: string[]
  attackIds: string[]
  tlp: string | null
  targetedCountries: string[]
  ipAddress: string | null
}

export interface MalwareRecord {
  hash: string
  hashType: string | null
  fileType: string | null
  fileName: string | null
  source: string | null
  ipAddress: string | null
}

export interface SubdomainMapping {
  subdomain: string
  ips: { address: string; version: string | null; isCdn: boolean; cdnName: string | null }[]
  openPorts: number
}

export interface IpMapping {
  ip: string
  version: string | null
  isCdn: boolean
  cdnName: string | null
  asn: string | null
  hostnames: string[]
  openPorts: number
}

export interface ReportData {
  project: Project
  remediations: Remediation[]
  generatedAt: string

  // Graph Overview
  graphOverview: {
    totalNodes: number
    nodeCounts: { label: string; count: number }[]
    subdomainStats: { total: number; resolved: number; uniqueIps: number }
    endpointCoverage: { baseUrls: number; endpoints: number; parameters: number }
    certificateHealth: { total: number; expired: number; expiringSoon: number }
    infrastructureStats: {
      totalIps: number; ipv4: number; ipv6: number
      cdnCount: number; uniqueAsns: number; uniqueCdns: number
    }
    subdomainMappings: SubdomainMapping[]
    ipMappings: IpMapping[]
  }

  // Attack Surface
  attackSurface: {
    services: { service: string; port: number; count: number }[]
    ports: { port: number; protocol: string; count: number }[]
    technologies: { name: string; version: string | null; cveCount: number }[]
    dnsRecords: { type: string; count: number }[]
    securityHeaders: { name: string; isSecurity: boolean; count: number }[]
    endpointCategories: { category: string; count: number }[]
    parameterAnalysis: { position: string; total: number; injectable: number }[]
  }

  // Vulnerabilities
  vulnerabilities: {
    severityDistribution: { severity: string; count: number }[]
    findings: VulnFinding[]
    cvssHistogram: { bucket: number; count: number }[]
    cveSeverity: { severity: string; count: number }[]
    gvmRemediation: { status: string; count: number }[]
  }

  // CVE Intelligence
  cveIntelligence: {
    cveChains: CveChain[]
    exploits: ExploitRecord[]
    githubSecrets: { repos: number; secrets: number; sensitiveFiles: number }
  }

  // TruffleHog
  trufflehog: {
    totalFindings: number
    verifiedFindings: number
    repositories: number
    findings: TrufflehogFindingRecord[]
  }

  // Secrets (generic, from jsluice / js_recon / etc.)
  secrets: {
    total: number
    bySeverity: { severity: string; count: number }[]
    bySource: { source: string; count: number }[]
    byType: { secretType: string; count: number }[]
    findings: SecretRecord[]
  }

  // JS Recon
  jsRecon: {
    totalFindings: number
    bySeverity: { severity: string; count: number }[]
    byType: { findingType: string; count: number }[]
    findings: JsReconFindingRecord[]
  }

  // GraphQL Security Scanner
  graphqlScan: {
    totalFindings: number
    endpointsTested: number
    introspectionEnabled: number
    bySeverity: { severity: string; count: number }[]
    byType: { vulnerabilityType: string; count: number }[]
    endpoints: GraphqlEndpointRecord[]
    findings: GraphqlFindingRecord[]
  }

  // OTX Threat Intelligence
  otx: {
    totalPulses: number
    totalMalware: number
    enrichedIps: number
    adversaries: string[]
    pulses: ThreatPulseRecord[]
    malware: MalwareRecord[]
  }

  // Attack Chains
  attackChains: {
    chains: AttackChainSummary[]
    exploitSuccesses: ExploitSuccess[]
    topFindings: {
      title: string; severity: string; findingType: string
      evidence: string | null; targetHost: string | null
    }[]
    totalChainFindings: number
  }

  // Fireteam (multi-agent) deployments
  fireteams?: {
    totalFireteams: number
    totalMembers: number
    totalFindings: number
    deployments: {
      fireteamIdKey: string
      iteration: number
      planRationale: string
      startedAt: string
      completedAt: string | null
      wallClockSeconds: number | null
      statusCounts: Record<string, number> | null
      status: string
      members: {
        memberIdKey: string
        name: string
        task: string
        skills: string[]
        status: string
        completionReason: string | null
        iterationsUsed: number
        tokensUsed: number
        findingsCount: number
        wallClockSeconds: number | null
        errorMessage: string | null
      }[]
    }[]
  }

  // Computed Metrics
  metrics: {
    riskScore: number        // 0–100 weighted score (same formula as Insights gauge)
    riskLabel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal'
    totalVulnerabilities: number
    totalRemediations: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
    exploitableCount: number
    totalCves: number
    cveCriticalCount: number
    cveHighCount: number
    cveMediumCount: number
    cveLowCount: number
    cvssAverage: number
    attackSurfaceSize: number
    secretsExposed: number
  }
}

// ── Main Data Gathering ─────────────────────────────────────────────────────

export async function gatherReportData(projectId: string): Promise<ReportData> {
  // Fetch PostgreSQL data
  const [project, remediations] = await Promise.all([
    prisma.project.findUniqueOrThrow({ where: { id: projectId } }),
    prisma.remediation.findMany({
      where: { projectId },
      orderBy: [{ priority: 'desc' }, { severity: 'asc' }],
    }),
  ])

  // Fetch all Neo4j data — each query group gets its own session
  // (Neo4j doesn't allow concurrent queries on a single session)
  const [
    graphOverview,
    attackSurface,
    vulnData,
    cveIntelligence,
    attackChainData,
    trufflehogData,
    secretsData,
    jsReconData,
    graphqlData,
    otxData,
  ] = await Promise.all([
    withSession(s => queryGraphOverview(s, projectId)),
    withSession(s => queryAttackSurface(s, projectId)),
    withSession(s => queryVulnerabilities(s, projectId)),
    withSession(s => queryCveIntelligence(s, projectId)),
    withSession(s => queryAttackChains(s, projectId)),
    withSession(s => queryTrufflehog(s, projectId)),
    withSession(s => querySecrets(s, projectId)),
    withSession(s => queryJsRecon(s, projectId)),
    withSession(s => queryGraphql(s, projectId)),
    withSession(s => queryOtx(s, projectId)),
  ])

  // Compute metrics
    const totalVulns = vulnData.severityDistribution.reduce((s: number, d: { count: number }) => s + d.count, 0)
    const bySev: Record<string, number> = Object.fromEntries(vulnData.severityDistribution.map((d: { severity: string; count: number }) => [d.severity, d.count]))
    const criticalCount = (bySev['critical'] || 0)
    const highCount = (bySev['high'] || 0)
    const mediumCount = (bySev['medium'] || 0)
    const lowCount = (bySev['low'] || 0)

    // Count unique CVEs from cveChains
    const uniqueCveIds = new Set<string>()
    const cveCvssScores: number[] = []
    for (const c of cveIntelligence.cveChains) {
      if (c.cveId && !uniqueCveIds.has(c.cveId)) {
        uniqueCveIds.add(c.cveId)
        if (c.cvss != null && c.cvss > 0) cveCvssScores.push(c.cvss)
      }
    }
    const totalCves = uniqueCveIds.size

    // CVE severity counts — derive from CVSS scores in cveChains (c.severity is often unset on nodes)
    let cveCriticalCount = 0, cveHighCount = 0, cveMediumCount = 0, cveLowCount = 0
    const countedCves = new Set<string>()
    for (const c of cveIntelligence.cveChains) {
      if (!c.cveId || countedCves.has(c.cveId)) continue
      countedCves.add(c.cveId)
      const score = c.cvss ?? 0
      if (score >= 9) cveCriticalCount++
      else if (score >= 7) cveHighCount++
      else if (score >= 4) cveMediumCount++
      else cveLowCount++
    }

    // Avg CVSS: combine Vulnerability.cvss_score + unique CVE.cvss scores
    const vulnCvss = vulnData.findings
      .map((f: { cvssScore: number | null }) => f.cvssScore)
      .filter((s: number | null): s is number => s != null && s > 0)
    const allCvss = [...vulnCvss, ...cveCvssScores]
    const cvssAverage = allCvss.length > 0
      ? allCvss.reduce((a: number, b: number) => a + b, 0) / allCvss.length
      : 0

    const totalParams = attackSurface.parameterAnalysis.reduce((s: number, p: { total: number }) => s + p.total, 0)
    const injectableParams = attackSurface.parameterAnalysis.reduce((s: number, p: { injectable: number }) => s + p.injectable, 0)

    // Risk Score 0–100 (same weighted formula as Insights RiskScoreGauge)
    const sevWeight = (s: string) => {
      switch (s?.toLowerCase()) {
        case 'critical': return 40; case 'high': return 20
        case 'medium': return 5; case 'low': return 1; default: return 0
      }
    }
    const vulnScore = vulnData.severityDistribution.reduce((sum: number, d: { count: number; severity: string }) => sum + d.count * sevWeight(d.severity), 0)
    const cveScore = cveCriticalCount * sevWeight('critical') + cveHighCount * sevWeight('high') + cveMediumCount * sevWeight('medium') + cveLowCount * sevWeight('low')
    const gvmExploitScore = cveIntelligence.exploits.length * 100
    const kevScore = cveIntelligence.exploits.filter((e: { cisaKev: boolean | null }) => e.cisaKev).length * 120
    const chainExploitScore = attackChainData.exploitSuccesses.length * 100
    const chainFindingsScore = attackChainData.topFindings.reduce((sum: number, f: { severity: string }) => sum + sevWeight(f.severity), 0)
    const cvesWithCapec = new Set(cveIntelligence.cveChains.filter((c: { capecId: string | null }) => c.capecId).map((c: { cveId: string }) => c.cveId)).size
    const capecScore = cvesWithCapec * 15
    const secretsScore = (cveIntelligence.githubSecrets.secrets + secretsData.total) * 60
    const sensitiveFilesScore = cveIntelligence.githubSecrets.sensitiveFiles * 30
    const trufflehogScore = trufflehogData.verifiedFindings * 80 + (trufflehogData.totalFindings - trufflehogData.verifiedFindings) * 30
    const jsReconScore = jsReconData.bySeverity
      .filter((d: { severity: string; count: number }) => d.severity === 'critical' || d.severity === 'high')
      .reduce((sum: number, d: { severity: string; count: number }) => sum + d.count, 0) * 40
    const graphqlScore = graphqlData.bySeverity.reduce((sum: number, d: { severity: string; count: number }) => {
      const w = d.severity === 'critical' ? 60 : d.severity === 'high' ? 30 : d.severity === 'medium' ? 10 : d.severity === 'low' ? 3 : 1
      return sum + d.count * w
    }, 0)
    const otxScore = otxData.totalPulses * 20 + otxData.totalMalware * 50
    const injectableScore = injectableParams * 25
    const expiredCertScore = graphOverview.certificateHealth.expired * 10
    // Missing security headers penalty
    const SEC_HEADERS = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options']
    let missingHeaderScore = 0
    const totalBaseUrls = graphOverview.endpointCoverage.baseUrls
    if (totalBaseUrls > 0) {
      const headerMap = new Map<string, number>(attackSurface.securityHeaders.map((h: { name: string; count: number }) => [h.name.toLowerCase(), h.count] as [string, number]))
      for (const hdr of SEC_HEADERS) {
        const coverage = (headerMap.get(hdr) || 0) / totalBaseUrls
        missingHeaderScore += Math.round((1 - Math.min(coverage, 1)) * 5)
      }
    }
    const rawRisk = vulnScore + cveScore + gvmExploitScore + kevScore
      + chainExploitScore + chainFindingsScore + capecScore
      + secretsScore + sensitiveFilesScore + injectableScore
      + expiredCertScore + missingHeaderScore
      + trufflehogScore + jsReconScore + graphqlScore + otxScore
    const riskScore = Math.min(100, Math.round(15 * Math.log(rawRisk + 1)))
    const riskLabel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal' =
      riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High'
      : riskScore >= 40 ? 'Medium' : riskScore >= 20 ? 'Low' : 'Minimal'

    // Fireteam (multi-agent) deployments, keyed by this project's conversations.
    // Authoritative findings-per-member come from Neo4j ChainFinding rows
    // filtered by fireteam_id + source_agent — Postgres findingsCount may be
    // stale (fire-and-forget writes).
    let fireteamsBlock: ReportData['fireteams'] = undefined
    try {
      const conversations = await prisma.conversation.findMany({
        where: { projectId },
        select: { id: true },
      })
      const convIds = conversations.map(c => c.id)
      if (convIds.length > 0) {
        const ftRows = await prisma.fireteam.findMany({
          where: { parentConversationId: { in: convIds } },
          include: { members: { orderBy: { startedAt: 'asc' } } },
          orderBy: { startedAt: 'asc' },
        })
        if (ftRows.length > 0) {
          // Count ChainFinding rows in Neo4j by (fireteam_id, source_agent)
          // and use those as authoritative per-member findings.
          const ftKeys = ftRows.map(f => f.fireteamIdKey)
          const ftSession = getSession()
          let authoritativeCounts: Map<string, number> = new Map()
          try {
            const ftFindingsRes = await ftSession.run(
              `
              MATCH (f:ChainFinding)
              WHERE f.project_id = $pid AND f.fireteam_id IN $ftKeys
              RETURN f.fireteam_id AS ft, f.source_agent AS member, count(f) AS n
              `,
              { pid: projectId, ftKeys },
            )
            for (const r of ftFindingsRes.records) {
              const key = `${r.get('ft')}::${r.get('member')}`
              authoritativeCounts.set(key, Number(r.get('n')))
            }
          } catch (e) {
            console.warn('[report] fireteam findings Neo4j query failed:', e)
          } finally {
            await ftSession.close()
          }
          const counted = (ftKey: string, memberName: string, fallback: number): number => {
            const n = authoritativeCounts.get(`${ftKey}::${memberName}`)
            return n !== undefined ? n : fallback
          }

          const totalFindingsNeo4j = Array.from(authoritativeCounts.values()).reduce((a, b) => a + b, 0)
          const totalFindingsPostgres = ftRows.reduce(
            (n, f) => n + f.members.reduce((mn, m) => mn + (m.findingsCount ?? 0), 0),
            0,
          )
          fireteamsBlock = {
            totalFireteams: ftRows.length,
            totalMembers: ftRows.reduce((n, f) => n + f.members.length, 0),
            totalFindings: totalFindingsNeo4j > 0 ? totalFindingsNeo4j : totalFindingsPostgres,
            deployments: ftRows.map(f => ({
              fireteamIdKey: f.fireteamIdKey,
              iteration: f.iteration,
              planRationale: f.planRationale ?? '',
              startedAt: f.startedAt.toISOString(),
              completedAt: f.completedAt ? f.completedAt.toISOString() : null,
              wallClockSeconds: f.wallClockSeconds ?? null,
              statusCounts: (f.statusCounts as Record<string, number> | null) ?? null,
              status: f.status,
              members: f.members.map(m => ({
                memberIdKey: m.memberIdKey,
                name: m.name,
                task: m.task,
                skills: m.skills,
                status: m.status,
                completionReason: m.completionReason,
                iterationsUsed: m.iterationsUsed,
                tokensUsed: m.tokensUsed,
                findingsCount: counted(f.fireteamIdKey, m.name, m.findingsCount),
                wallClockSeconds: m.wallClockSeconds ?? null,
                errorMessage: m.errorMessage,
              })),
            })),
          }
        }
      }
    } catch (e) {
      console.warn('[report] fireteam fetch failed:', e)
    }

    return {
      project,
      remediations,
      generatedAt: new Date().toISOString(),
      graphOverview,
      attackSurface,
      vulnerabilities: vulnData,
      cveIntelligence,
      trufflehog: trufflehogData,
      secrets: secretsData,
      jsRecon: jsReconData,
      graphqlScan: graphqlData,
      otx: otxData,
      attackChains: attackChainData,
      fireteams: fireteamsBlock,
      metrics: {
        riskScore,
        riskLabel,
        totalVulnerabilities: totalVulns,
        totalRemediations: remediations.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        totalCves,
        cveCriticalCount,
        cveHighCount,
        cveMediumCount,
        cveLowCount,
        exploitableCount: cveIntelligence.exploits.length + attackChainData.exploitSuccesses.length,
        cvssAverage: Math.round(cvssAverage * 10) / 10,
        attackSurfaceSize: graphOverview.endpointCoverage.endpoints + totalParams,
        secretsExposed: cveIntelligence.githubSecrets.secrets + cveIntelligence.githubSecrets.sensitiveFiles + secretsData.total + trufflehogData.totalFindings,
      },
    }
}

// ── Neo4j Query Functions ───────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryGraphOverview(session: any, pid: string) {
  const nodeRes = await session.run(
    `MATCH (n {project_id: $pid}) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC`,
    { pid }
  )
  const subRes = await session.run(
    `MATCH (s:Subdomain {project_id: $pid})
     OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
     RETURN count(DISTINCT s) AS total,
            count(DISTINCT CASE WHEN i IS NOT NULL THEN s END) AS resolved,
            count(DISTINCT i) AS uniqueIps`,
    { pid }
  )
  const epRes = await session.run(
    `MATCH (b:BaseURL {project_id: $pid})
     OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint)
     OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
     RETURN count(DISTINCT b) AS baseUrls, count(DISTINCT e) AS endpoints, count(DISTINCT p) AS parameters`,
    { pid }
  )
  const certRes = await session.run(
    `OPTIONAL MATCH (:BaseURL {project_id: $pid})-[:HAS_CERTIFICATE]->(c:Certificate)
     RETURN count(c) AS total,
            count(CASE WHEN c.not_after < datetime() THEN 1 END) AS expired,
            count(CASE WHEN c.not_after >= datetime() AND c.not_after < datetime() + duration('P30D') THEN 1 END) AS expiringSoon`,
    { pid }
  )
  const infraRes = await session.run(
    `MATCH (ip:IP {project_id: $pid})
     RETURN count(ip) AS total,
            count(CASE WHEN ip.version = 'ipv4' THEN 1 END) AS ipv4,
            count(CASE WHEN ip.version = 'ipv6' THEN 1 END) AS ipv6,
            count(CASE WHEN ip.is_cdn = true THEN 1 END) AS cdnCount,
            count(DISTINCT CASE WHEN ip.asn IS NOT NULL THEN ip.asn END) AS uniqueAsns,
            count(DISTINCT CASE WHEN ip.cdn_name IS NOT NULL THEN ip.cdn_name END) AS uniqueCdns`,
    { pid }
  )

  // Subdomain → IP detail mapping
  const subDetailRes = await session.run(
    `MATCH (s:Subdomain {project_id: $pid})
     OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
     OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)
     RETURN s.name AS subdomain,
            collect(DISTINCT {address: ip.address, version: ip.version, isCdn: ip.is_cdn, cdnName: ip.cdn_name}) AS ips,
            count(DISTINCT port) AS openPorts
     ORDER BY subdomain`,
    { pid }
  )
  // IP → hostname detail mapping
  const ipDetailRes = await session.run(
    `MATCH (ip:IP {project_id: $pid})
     OPTIONAL MATCH (s:Subdomain {project_id: $pid})-[:RESOLVES_TO]->(ip)
     OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)
     RETURN ip.address AS ip, ip.version AS version, ip.is_cdn AS isCdn,
            ip.cdn_name AS cdnName, ip.asn AS asn,
            collect(DISTINCT s.name) AS hostnames,
            count(DISTINCT port) AS openPorts
     ORDER BY ip`,
    { pid }
  )

  const nodeCounts = nodeRes.records.map((r: any) => ({
    label: r.get('label') as string,
    count: toNum(r.get('count')),
  }))

  const subRec = subRes.records[0]
  const epRec = epRes.records[0]
  const certRec = certRes.records[0]
  const infraRec = infraRes.records[0]

  const subdomainMappings: SubdomainMapping[] = subDetailRes.records.map((r: any) => ({
    subdomain: r.get('subdomain') as string,
    ips: (r.get('ips') as any[]).filter((ip: any) => ip.address != null).map((ip: any) => ({
      address: ip.address as string,
      version: ip.version as string | null,
      isCdn: ip.isCdn === true,
      cdnName: ip.cdnName as string | null,
    })),
    openPorts: toNum(r.get('openPorts')),
  }))

  const ipMappings: IpMapping[] = ipDetailRes.records.map((r: any) => ({
    ip: r.get('ip') as string,
    version: r.get('version') as string | null,
    isCdn: r.get('isCdn') === true,
    cdnName: r.get('cdnName') as string | null,
    asn: r.get('asn') as string | null,
    hostnames: (r.get('hostnames') as any[]).filter((h: any) => h != null),
    openPorts: toNum(r.get('openPorts')),
  }))

  return {
    totalNodes: nodeCounts.reduce((s: number, n: { count: number }) => s + n.count, 0),
    nodeCounts,
    subdomainStats: subRec
      ? { total: toNum(subRec.get('total')), resolved: toNum(subRec.get('resolved')), uniqueIps: toNum(subRec.get('uniqueIps')) }
      : { total: 0, resolved: 0, uniqueIps: 0 },
    endpointCoverage: epRec
      ? { baseUrls: toNum(epRec.get('baseUrls')), endpoints: toNum(epRec.get('endpoints')), parameters: toNum(epRec.get('parameters')) }
      : { baseUrls: 0, endpoints: 0, parameters: 0 },
    certificateHealth: certRec
      ? { total: toNum(certRec.get('total')), expired: toNum(certRec.get('expired')), expiringSoon: toNum(certRec.get('expiringSoon')) }
      : { total: 0, expired: 0, expiringSoon: 0 },
    infrastructureStats: infraRec
      ? {
          totalIps: toNum(infraRec.get('total')),
          ipv4: toNum(infraRec.get('ipv4')),
          ipv6: toNum(infraRec.get('ipv6')),
          cdnCount: toNum(infraRec.get('cdnCount')),
          uniqueAsns: toNum(infraRec.get('uniqueAsns')),
          uniqueCdns: toNum(infraRec.get('uniqueCdns')),
        }
      : { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
    subdomainMappings,
    ipMappings,
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryAttackSurface(session: any, pid: string) {
  const svcRes = await session.run(
    `MATCH (:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
     RETURN s.name AS service, p.number AS port, count(DISTINCT p) AS count
     ORDER BY count DESC LIMIT 25`,
    { pid }
  )
  const portRes = await session.run(
    `MATCH (:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)
     RETURN p.number AS port, p.protocol AS protocol, count(p) AS count
     ORDER BY count DESC LIMIT 25`,
    { pid }
  )
  const techRes = await session.run(
    `MATCH (:BaseURL {project_id: $pid})-[:USES_TECHNOLOGY]->(t:Technology)
     OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE)
     RETURN t.name AS name, t.version AS version, count(DISTINCT c) AS cveCount
     ORDER BY cveCount DESC, name ASC`,
    { pid }
  )
  const dnsRes = await session.run(
    `MATCH (:Subdomain {project_id: $pid})-[:HAS_DNS_RECORD]->(d:DNSRecord)
     RETURN d.type AS type, count(d) AS count ORDER BY count DESC`,
    { pid }
  )
  const secHdrRes = await session.run(
    `MATCH (:BaseURL {project_id: $pid})-[:HAS_HEADER]->(h:Header)
     RETURN h.name AS name, COALESCE(h.is_security_header, false) AS isSecurity, count(h) AS count
     ORDER BY count DESC`,
    { pid }
  )
  const epCatRes = await session.run(
    `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
     RETURN COALESCE(e.category, 'other') AS category, count(e) AS count ORDER BY count DESC`,
    { pid }
  )
  const paramRes = await session.run(
    `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter)
     RETURN COALESCE(p.position, 'unknown') AS position,
            count(p) AS total,
            count(CASE WHEN p.is_injectable = true THEN 1 END) AS injectable
     ORDER BY total DESC`,
    { pid }
  )

  return {
    services: svcRes.records.map((r: any) => ({
      service: (r.get('service') as string) || 'unknown',
      port: toNum(r.get('port')),
      count: toNum(r.get('count')),
    })),
    ports: portRes.records.map((r: any) => ({
      port: toNum(r.get('port')),
      protocol: (r.get('protocol') as string) || 'tcp',
      count: toNum(r.get('count')),
    })),
    technologies: techRes.records.map((r: any) => ({
      name: (r.get('name') as string) || 'Unknown',
      version: r.get('version') as string | null,
      cveCount: toNum(r.get('cveCount')),
    })),
    dnsRecords: dnsRes.records.map((r: any) => ({
      type: (r.get('type') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    securityHeaders: secHdrRes.records.map((r: any) => ({
      name: (r.get('name') as string) || 'unknown',
      isSecurity: r.get('isSecurity') as boolean,
      count: toNum(r.get('count')),
    })),
    endpointCategories: epCatRes.records.map((r: any) => ({
      category: (r.get('category') as string) || 'other',
      count: toNum(r.get('count')),
    })),
    parameterAnalysis: paramRes.records.map((r: any) => ({
      position: (r.get('position') as string) || 'unknown',
      total: toNum(r.get('total')),
      injectable: toNum(r.get('injectable')),
    })),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryVulnerabilities(session: any, pid: string) {
  const sevRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid})
     RETURN v.severity AS severity, count(v) AS count`,
    { pid }
  )
  const findingsRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid})
     OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
     OPTIONAL MATCH (v)-[:FOUND_AT]->(ep:Endpoint)
     OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(param:Parameter)
     WITH v,
          COALESCE(parent.address, parent.url, parent.name, parent.domain, ep.baseurl) AS target,
          labels(parent)[0] AS parentType,
          ep.path AS endpointPath,
          param.name AS paramName,
          CASE WHEN v.source = 'takeover_scan' THEN 'Subdomain Takeover'
               WHEN ep IS NOT NULL THEN 'DAST'
               WHEN v.source = 'gvm' THEN 'GVM'
               WHEN v.source = 'nuclei' THEN 'Nuclei'
               ELSE 'Security Check' END AS findingSource
     RETURN v.name AS name, v.severity AS severity, v.source AS source,
            v.category AS category, v.cvss_score AS cvssScore,
            v.matched_at AS matchedAt, v.host AS host,
            v.target_ip AS targetIp, v.target_port AS targetPort,
            target, parentType, endpointPath, paramName, findingSource
     ORDER BY CASE v.severity
       WHEN 'critical' THEN 0 WHEN 'high' THEN 1
       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
    { pid }
  )
  const cvssRes = await session.run(
    `MATCH (:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
     WITH toFloat(c.cvss) AS score WHERE score IS NOT NULL
     RETURN floor(score) AS bucket, count(*) AS count ORDER BY bucket`,
    { pid }
  )
  const cveSevRes = await session.run(
    `MATCH (:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
     RETURN c.severity AS severity, count(DISTINCT c) AS count`,
    { pid }
  )
  const gvmRemRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid, source: 'gvm'})
     RETURN CASE WHEN v.remediated = true THEN 'Remediated' ELSE 'Open' END AS status,
            count(v) AS count`,
    { pid }
  )

  return {
    severityDistribution: sevRes.records.map((r: any) => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    findings: findingsRes.records.map((r: any) => ({
      name: (r.get('name') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'unknown',
      source: (r.get('source') as string) || 'unknown',
      category: r.get('category') as string | null,
      cvssScore: r.get('cvssScore') as number | null,
      matchedAt: r.get('matchedAt') as string | null,
      host: r.get('host') as string | null,
      targetIp: r.get('targetIp') as string | null,
      targetPort: r.get('targetPort') != null ? toNum(r.get('targetPort')) : null,
      target: r.get('target') as string | null,
      parentType: r.get('parentType') as string | null,
      endpointPath: r.get('endpointPath') as string | null,
      paramName: r.get('paramName') as string | null,
      findingSource: (r.get('findingSource') as string) || 'Unknown',
    })),
    cvssHistogram: cvssRes.records.map((r: any) => ({
      bucket: toNum(r.get('bucket')),
      count: toNum(r.get('count')),
    })),
    cveSeverity: cveSevRes.records.map((r: any) => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    gvmRemediation: gvmRemRes.records.map((r: any) => ({
      status: (r.get('status') as string) || 'Open',
      count: toNum(r.get('count')),
    })),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryCveIntelligence(session: any, pid: string) {
  const chainRes = await session.run(
    `MATCH (t:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
     OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
     OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
     RETURN t.name AS tech, t.version AS techVersion,
            c.id AS cveId, c.cvss AS cvss, c.severity AS cveSeverity,
            m.cwe_id AS cweId, m.cwe_name AS cweName,
            cap.capec_id AS capecId, cap.name AS capecName, cap.severity AS capecSeverity
     ORDER BY c.cvss DESC`,
    { pid }
  )
  const exploitRes = await session.run(
    `MATCH (ex:ExploitGvm {project_id: $pid})
     OPTIONAL MATCH (ex)-[:EXPLOITED_CVE]->(c:CVE)
     RETURN ex.name AS name, ex.severity AS severity, ex.target_ip AS targetIp,
            ex.target_port AS targetPort, ex.cvss_score AS cvssScore,
            ex.cisa_kev AS cisaKev, ex.evidence AS evidence,
            collect(c.id) AS cveIds
     ORDER BY ex.cvss_score DESC`,
    { pid }
  )
  const ghRes = await session.run(
    `OPTIONAL MATCH (d:Domain {project_id: $pid})-[:HAS_GITHUB_HUNT]->()-[:HAS_REPOSITORY]->(r:GithubRepository)
     OPTIONAL MATCH (r)-[:HAS_PATH]->()-[:CONTAINS_SECRET]->(sec:GithubSecret)
     OPTIONAL MATCH (r)-[:HAS_PATH]->()-[:CONTAINS_SENSITIVE_FILE]->(sf:GithubSensitiveFile)
     RETURN count(DISTINCT r) AS repos, count(DISTINCT sec) AS secrets, count(DISTINCT sf) AS sensitiveFiles`,
    { pid }
  )

  const ghRec = ghRes.records[0]

  return {
    cveChains: chainRes.records.map((r: any) => ({
      tech: (r.get('tech') as string) || 'Unknown',
      techVersion: r.get('techVersion') as string | null,
      cveId: (r.get('cveId') as string) || '',
      cvss: r.get('cvss') as number | null,
      cveSeverity: r.get('cveSeverity') as string | null,
      cweId: r.get('cweId') as string | null,
      cweName: r.get('cweName') as string | null,
      capecId: r.get('capecId') as string | null,
      capecName: r.get('capecName') as string | null,
      capecSeverity: r.get('capecSeverity') as string | null,
    })),
    exploits: exploitRes.records.map((r: any) => ({
      name: (r.get('name') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'critical',
      targetIp: r.get('targetIp') as string | null,
      targetPort: r.get('targetPort') != null ? toNum(r.get('targetPort')) : null,
      cvssScore: r.get('cvssScore') as number | null,
      cisaKev: r.get('cisaKev') as boolean | null,
      evidence: r.get('evidence') as string | null,
      cveIds: r.get('cveIds') as string[],
    })),
    githubSecrets: ghRec
      ? { repos: toNum(ghRec.get('repos')), secrets: toNum(ghRec.get('secrets')), sensitiveFiles: toNum(ghRec.get('sensitiveFiles')) }
      : { repos: 0, secrets: 0, sensitiveFiles: 0 },
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryAttackChains(session: any, pid: string) {
  const chainsRes = await session.run(
    `MATCH (ac:AttackChain {project_id: $pid})
     OPTIONAL MATCH (step:ChainStep {chain_id: ac.chain_id})
     WITH ac, collect(step) AS allSteps
     UNWIND CASE WHEN size(allSteps) = 0 THEN [null] ELSE allSteps END AS step
     OPTIONAL MATCH (step)-[:PRODUCED]->(f:ChainFinding)
     WITH ac, step, count(f) AS sf
     OPTIONAL MATCH (step)-[:FAILED_WITH]->(fail:ChainFailure)
     WITH ac, step, sf, count(fail) AS sfl
     RETURN ac.title AS title, ac.status AS status,
            count(step) AS steps, sum(sf) AS findings, sum(sfl) AS failures`,
    { pid }
  )
  const exploitRes = await session.run(
    `MATCH (f:ChainFinding {project_id: $pid})
     WHERE f.finding_type IN ['exploit_success', 'access_gained', 'privilege_escalation', 'credential_found', 'data_exfiltration', 'lateral_movement', 'persistence_established', 'denial_of_service_success', 'social_engineering_success', 'remote_code_execution', 'session_hijacked']
     OPTIONAL MATCH (f)-[:FINDING_RELATES_CVE]->(cve:CVE)
     WITH f, collect(cve.id) AS cveIds
     RETURN f.title AS title, f.target_ip AS targetIp, f.target_port AS targetPort,
            f.metasploit_module AS module,
            f.evidence AS evidence, f.attack_type AS attackType, f.finding_type AS findingType, cveIds
     ORDER BY f.created_at DESC`,
    { pid }
  )
  const topRes = await session.run(
    `MATCH (f:ChainFinding {project_id: $pid})
     OPTIONAL MATCH (f)-[:FOUND_ON]->(target)
     WITH f, COALESCE(target.address, target.name) AS targetHost
     RETURN f.title AS title, f.severity AS severity, f.finding_type AS findingType,
            f.evidence AS evidence, targetHost
     ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
     LIMIT 20`,
    { pid }
  )
  const countRes = await session.run(
    `MATCH (f:ChainFinding {project_id: $pid}) RETURN count(f) AS total`,
    { pid }
  )

  return {
    chains: chainsRes.records
      .filter((r: any) => r.get('title'))
      .map((r: any) => ({
        title: (r.get('title') as string) || 'Untitled',
        status: (r.get('status') as string) || 'unknown',
        steps: toNum(r.get('steps')),
        findings: toNum(r.get('findings')),
        failures: toNum(r.get('failures')),
      })),
    exploitSuccesses: exploitRes.records.map((r: any) => ({
      title: (r.get('title') as string) || 'Untitled',
      targetIp: r.get('targetIp') as string | null,
      targetPort: toNum(r.get('targetPort')) || null,
      module: r.get('module') as string | null,
      evidence: r.get('evidence') as string | null,
      attackType: r.get('attackType') as string | null,
      cveIds: (r.get('cveIds') as string[]) || [],
    })),
    topFindings: topRes.records.map((r: any) => ({
      title: (r.get('title') as string) || 'Untitled',
      severity: (r.get('severity') as string) || 'unknown',
      findingType: (r.get('findingType') as string) || 'unknown',
      evidence: r.get('evidence') as string | null,
      targetHost: r.get('targetHost') as string | null,
    })),
    totalChainFindings: toNum(countRes.records[0]?.get('total')),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryTrufflehog(session: any, pid: string) {
  const summaryRes = await session.run(
    `OPTIONAL MATCH (d:Domain {project_id: $pid})-[:HAS_TRUFFLEHOG_SCAN]->(ts:TrufflehogScan)
     OPTIONAL MATCH (ts)-[:HAS_REPOSITORY]->(tr:TrufflehogRepository)
     OPTIONAL MATCH (tr)-[:HAS_FINDING]->(tf:TrufflehogFinding)
     RETURN count(DISTINCT tf) AS total,
            count(DISTINCT CASE WHEN tf.verified = true THEN tf END) AS verified,
            count(DISTINCT tr) AS repos`,
    { pid }
  )
  const findingsRes = await session.run(
    `MATCH (d:Domain {project_id: $pid})-[:HAS_TRUFFLEHOG_SCAN]->()-[:HAS_REPOSITORY]->(tr:TrufflehogRepository)-[:HAS_FINDING]->(tf:TrufflehogFinding)
     RETURN tf.detector_name AS detectorName, tf.verified AS verified,
            tf.redacted AS redacted, tr.name AS repository,
            tf.file AS file, tf.commit AS commit,
            tf.line AS line, tf.link AS link
     ORDER BY CASE WHEN tf.verified = true THEN 0 ELSE 1 END, tf.detector_name
     LIMIT 50`,
    { pid }
  )

  const sumRec = summaryRes.records[0]
  return {
    totalFindings: sumRec ? toNum(sumRec.get('total')) : 0,
    verifiedFindings: sumRec ? toNum(sumRec.get('verified')) : 0,
    repositories: sumRec ? toNum(sumRec.get('repos')) : 0,
    findings: findingsRes.records.map((r: any) => ({
      detectorName: (r.get('detectorName') as string) || 'Unknown',
      verified: r.get('verified') === true,
      redacted: r.get('redacted') as string | null,
      repository: r.get('repository') as string | null,
      file: r.get('file') as string | null,
      commit: r.get('commit') as string | null,
      line: r.get('line') != null ? toNum(r.get('line')) : null,
      link: r.get('link') as string | null,
    })),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function querySecrets(session: any, pid: string) {
  const totalRes = await session.run(
    `MATCH (s:Secret {project_id: $pid})
     RETURN count(s) AS total`,
    { pid }
  )
  const bySevRes = await session.run(
    `MATCH (s:Secret {project_id: $pid})
     RETURN s.severity AS severity, count(s) AS count ORDER BY count DESC`,
    { pid }
  )
  const bySrcRes = await session.run(
    `MATCH (s:Secret {project_id: $pid})
     RETURN s.source AS source, count(s) AS count ORDER BY count DESC`,
    { pid }
  )
  const byTypeRes = await session.run(
    `MATCH (s:Secret {project_id: $pid})
     RETURN s.secret_type AS secretType, count(s) AS count ORDER BY count DESC LIMIT 20`,
    { pid }
  )
  const findingsRes = await session.run(
    `MATCH (s:Secret {project_id: $pid})
     RETURN s.secret_type AS secretType, s.severity AS severity,
            s.source AS source, s.source_url AS sourceUrl,
            s.sample AS sample, s.validation_status AS validationStatus,
            s.confidence AS confidence, s.key_type AS keyType
     ORDER BY CASE s.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
     LIMIT 50`,
    { pid }
  )

  return {
    total: toNum(totalRes.records[0]?.get('total')),
    bySeverity: bySevRes.records.map((r: any) => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    bySource: bySrcRes.records.map((r: any) => ({
      source: (r.get('source') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    byType: byTypeRes.records.map((r: any) => ({
      secretType: (r.get('secretType') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    findings: findingsRes.records.map((r: any) => ({
      secretType: (r.get('secretType') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'unknown',
      source: (r.get('source') as string) || 'unknown',
      sourceUrl: r.get('sourceUrl') as string | null,
      sample: r.get('sample') as string | null,
      validationStatus: r.get('validationStatus') as string | null,
      confidence: r.get('confidence') as string | null,
      keyType: r.get('keyType') as string | null,
    })),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryJsRecon(session: any, pid: string) {
  const bySevRes = await session.run(
    `MATCH (jf:JsReconFinding {project_id: $pid})
     RETURN jf.severity AS severity, count(jf) AS count ORDER BY count DESC`,
    { pid }
  )
  const byTypeRes = await session.run(
    `MATCH (jf:JsReconFinding {project_id: $pid})
     RETURN jf.finding_type AS findingType, count(jf) AS count ORDER BY count DESC`,
    { pid }
  )
  const findingsRes = await session.run(
    `MATCH (jf:JsReconFinding {project_id: $pid})
     RETURN jf.finding_type AS findingType, jf.severity AS severity,
            jf.confidence AS confidence, jf.title AS title,
            jf.detail AS detail, jf.evidence AS evidence,
            jf.source_url AS sourceUrl
     ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
     LIMIT 50`,
    { pid }
  )

  const totalFindings = bySevRes.records.reduce((s: number, r: any) => s + toNum(r.get('count')), 0)

  return {
    totalFindings,
    bySeverity: bySevRes.records.map((r: any) => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    byType: byTypeRes.records.map((r: any) => ({
      findingType: (r.get('findingType') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    findings: findingsRes.records.map((r: any) => ({
      findingType: (r.get('findingType') as string) || 'unknown',
      severity: (r.get('severity') as string) || 'unknown',
      confidence: r.get('confidence') as string | null,
      title: (r.get('title') as string) || 'Untitled',
      detail: r.get('detail') as string | null,
      evidence: r.get('evidence') as string | null,
      sourceUrl: r.get('sourceUrl') as string | null,
    })),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryGraphql(session: any, pid: string) {
  const endpointsRes = await session.run(
    `MATCH (e:Endpoint {project_id: $pid, is_graphql: true})
     RETURN e.full_url AS url,
            coalesce(e.graphql_introspection_enabled, false) AS introspectionEnabled,
            coalesce(e.graphql_schema_extracted, false) AS schemaExtracted,
            coalesce(e.graphql_queries_count, 0) AS queriesCount,
            coalesce(e.graphql_mutations_count, 0) AS mutationsCount,
            coalesce(e.graphql_subscriptions_count, 0) AS subscriptionsCount,
            e.graphql_schema_hash AS schemaHash
     ORDER BY introspectionEnabled DESC, queriesCount DESC
     LIMIT 50`,
    { pid }
  )
  const bySevRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid}) WHERE v.source IN ['graphql_scan', 'graphql_cop']
     RETURN v.severity AS severity, count(v) AS count ORDER BY count DESC`,
    { pid }
  )
  const byTypeRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid}) WHERE v.source IN ['graphql_scan', 'graphql_cop']
     RETURN v.vulnerability_type AS vulnerabilityType, count(v) AS count ORDER BY count DESC`,
    { pid }
  )
  const findingsRes = await session.run(
    `MATCH (v:Vulnerability {project_id: $pid}) WHERE v.source IN ['graphql_scan', 'graphql_cop']
     OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)
     RETURN coalesce(e.full_url, v.endpoint, '') AS endpoint,
            v.vulnerability_type AS vulnerabilityType,
            v.severity AS severity,
            v.source AS source,
            coalesce(v.title, v.name) AS title,
            v.description AS description,
            v.evidence AS evidence
     ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
     LIMIT 50`,
    { pid }
  )

  const endpoints: GraphqlEndpointRecord[] = endpointsRes.records.map((r: any) => ({
    url: (r.get('url') as string) || '',
    introspectionEnabled: !!r.get('introspectionEnabled'),
    schemaExtracted: !!r.get('schemaExtracted'),
    queriesCount: toNum(r.get('queriesCount')),
    mutationsCount: toNum(r.get('mutationsCount')),
    subscriptionsCount: toNum(r.get('subscriptionsCount')),
    schemaHash: r.get('schemaHash') as string | null,
  }))
  const totalFindings = bySevRes.records.reduce((s: number, r: any) => s + toNum(r.get('count')), 0)

  return {
    totalFindings,
    endpointsTested: endpoints.length,
    introspectionEnabled: endpoints.filter(e => e.introspectionEnabled).length,
    bySeverity: bySevRes.records.map((r: any) => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    byType: byTypeRes.records.map((r: any) => ({
      vulnerabilityType: (r.get('vulnerabilityType') as string) || 'unknown',
      count: toNum(r.get('count')),
    })),
    endpoints,
    findings: findingsRes.records.map((r: any) => {
      const evidence = r.get('evidence') as string | null
      // Extract the graphql-cop cURL reproducer from the evidence JSON if present.
      let curlVerify: string | null = null
      if (evidence) {
        try {
          const parsed = JSON.parse(evidence)
          if (parsed && typeof parsed.curl_verify === 'string') {
            curlVerify = parsed.curl_verify
          }
        } catch { /* evidence isn't valid JSON; leave curlVerify null */ }
      }
      return {
        endpoint: (r.get('endpoint') as string) || '',
        vulnerabilityType: (r.get('vulnerabilityType') as string) || 'unknown',
        severity: (r.get('severity') as string) || 'unknown',
        source: (r.get('source') as string) || 'graphql_scan',
        title: (r.get('title') as string) || 'GraphQL Finding',
        description: r.get('description') as string | null,
        evidence,
        curlVerify,
      }
    }),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function queryOtx(session: any, pid: string) {
  const pulseRes = await session.run(
    `MATCH (ip:IP {project_id: $pid})-[:APPEARS_IN_PULSE]->(tp:ThreatPulse)
     RETURN tp.name AS name, tp.adversary AS adversary,
            tp.malware_families AS malwareFamilies,
            tp.attack_ids AS attackIds, tp.tlp AS tlp,
            tp.targeted_countries AS targetedCountries,
            ip.address AS indicator
     UNION
     MATCH (d:Domain {project_id: $pid})-[:APPEARS_IN_PULSE]->(tp:ThreatPulse)
     RETURN tp.name AS name, tp.adversary AS adversary,
            tp.malware_families AS malwareFamilies,
            tp.attack_ids AS attackIds, tp.tlp AS tlp,
            tp.targeted_countries AS targetedCountries,
            d.domain AS indicator
     ORDER BY name
     LIMIT 30`,
    { pid }
  )
  const malwareRes = await session.run(
    `MATCH (ip:IP {project_id: $pid})-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)
     RETURN m.hash AS hash, m.hash_type AS hashType,
            m.file_type AS fileType, m.file_name AS fileName,
            m.source AS source, ip.address AS indicator
     UNION
     MATCH (d:Domain {project_id: $pid})-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)
     RETURN m.hash AS hash, m.hash_type AS hashType,
            m.file_type AS fileType, m.file_name AS fileName,
            m.source AS source, d.domain AS indicator
     LIMIT 30`,
    { pid }
  )
  const enrichedRes = await session.run(
    `MATCH (ip:IP {project_id: $pid})
     WHERE ip.otx_enriched = true
     RETURN count(ip) AS enrichedIps`,
    { pid }
  )

  const pulses = pulseRes.records.map((r: any) => ({
    name: (r.get('name') as string) || 'Unknown',
    adversary: r.get('adversary') as string | null,
    malwareFamilies: (r.get('malwareFamilies') as string[]) || [],
    attackIds: (r.get('attackIds') as string[]) || [],
    tlp: r.get('tlp') as string | null,
    targetedCountries: (r.get('targetedCountries') as string[]) || [],
    ipAddress: r.get('indicator') as string | null,
  }))

  const adversaryList: string[] = []
  for (const p of pulses) {
    if (p.adversary && !adversaryList.includes(p.adversary)) adversaryList.push(p.adversary)
  }
  const adversaries = adversaryList

  return {
    totalPulses: pulses.length,
    totalMalware: malwareRes.records.length,
    enrichedIps: toNum(enrichedRes.records[0]?.get('enrichedIps')),
    adversaries,
    pulses,
    malware: malwareRes.records.map((r: any) => ({
      hash: (r.get('hash') as string) || '',
      hashType: r.get('hashType') as string | null,
      fileType: r.get('fileType') as string | null,
      fileName: r.get('fileName') as string | null,
      source: r.get('source') as string | null,
      ipAddress: r.get('indicator') as string | null,
    })),
  }
}
