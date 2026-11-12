import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted, agentCandidateConfirmedOrNA } from '@/lib/graphMute'
import { queryJudgedFindings, reportCountable } from '@/lib/triage/reportable'
import { inSeverityBreakdown, queryDispositionSummary } from '@/lib/triage/disposition'
import { githubSecretCounts, githubSecretCountsCypher } from '@/lib/secrets/githubSecretCounts'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Q1: Vulnerability severity distribution, as the report's: what scanners
    // claimed about reportable and candidate findings.
    const sevResult = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE ${notMuted('v')} AND ${reportCountable('v')} AND ${agentCandidateConfirmedOrNA('v')}
         AND ${inSeverityBreakdown('v')}
       RETURN v.severity AS severity, count(v) AS count`,
      { pid: projectId }
    )
    const severityDistribution = sevResult.records.map(r => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q2: Top vulnerability types
    const typesResult = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE ${notMuted('v')} AND ${reportCountable('v')} AND ${agentCandidateConfirmedOrNA('v')}
       RETURN v.name AS name, v.severity AS severity, v.source AS source, count(v) AS count
       ORDER BY count DESC LIMIT 20`,
      { pid: projectId }
    )
    const vulnTypes = typesResult.records.map(r => ({
      name: (r.get('name') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'unknown',
      source: (r.get('source') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q3: Security findings with full context - traces ALL vulnerability connection paths
    // Covers: HAS_VULNERABILITY (from IP/BaseURL/Subdomain/Domain), FOUND_AT (DAST→Endpoint)
    const findingsResult = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE ${notMuted('v')} AND ${reportCountable('v')} AND ${agentCandidateConfirmedOrNA('v')}
       OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
       OPTIONAL MATCH (v)-[:FOUND_AT]->(ep:Endpoint)
       OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(param:Parameter)
       WITH v,
            COALESCE(parent.address, parent.url, parent.name, parent.domain, ep.baseurl) AS target,
            labels(parent)[0] AS parentType,
            ep.path AS endpointPath,
            param.name AS paramName,
            CASE WHEN ep IS NOT NULL THEN 'DAST'
                 WHEN v.source = 'gvm' THEN 'GVM'
                 WHEN v.source = 'nuclei' THEN 'Nuclei'
                 ELSE 'Security Check' END AS findingSource
       RETURN v.name AS name,
              v.severity AS severity,
              v.source AS source,
              v.category AS category,
              v.cvss_score AS cvssScore,
              v.matched_at AS matchedAt,
              v.host AS host,
              v.target_ip AS targetIp,
              v.target_port AS targetPort,
              target,
              parentType,
              endpointPath,
              paramName,
              findingSource
       ORDER BY CASE v.severity
         WHEN 'critical' THEN 0 WHEN 'high' THEN 1
         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
      { pid: projectId }
    )
    const findings = findingsResult.records.map(r => ({
      name: (r.get('name') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'unknown',
      source: (r.get('source') as string) || 'unknown',
      category: r.get('category') as string | null,
      // A score stored as INTEGER arrives as a driver Integer, not a number; the
      // Insights cards call .toFixed() on it.
      cvssScore: r.get('cvssScore') != null ? toNum(r.get('cvssScore')) : null,
      matchedAt: r.get('matchedAt') as string | null,
      host: r.get('host') as string | null,
      targetIp: r.get('targetIp') as string | null,
      targetPort: r.get('targetPort') != null ? toNum(r.get('targetPort')) : null,
      target: r.get('target') as string | null,
      parentType: r.get('parentType') as string | null,
      endpointPath: r.get('endpointPath') as string | null,
      paramName: r.get('paramName') as string | null,
      findingSource: (r.get('findingSource') as string) || 'Unknown',
    }))

    // Q4: CVSS histogram from CVEs
    const cvssResult = await session.run(
      `MATCH (:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
       WITH toFloat(c.cvss) AS score WHERE score IS NOT NULL
       RETURN floor(score) AS bucket, count(*) AS count ORDER BY bucket`,
      { pid: projectId }
    )
    const cvssHistogram = cvssResult.records.map(r => ({
      bucket: toNum(r.get('bucket')),
      count: toNum(r.get('count')),
    }))

    // Q5: CVE severity breakdown
    const cveSevResult = await session.run(
      `MATCH (:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
       RETURN c.severity AS severity, count(DISTINCT c) AS count`,
      { pid: projectId }
    )
    const cveSeverity = cveSevResult.records.map(r => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q6: Technology → CVE → CWE → CAPEC chain (the danger chain)
    const chainResult = await session.run(
      `MATCH (t:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
       OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
       OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
       RETURN t.name AS tech, t.version AS techVersion,
              c.id AS cveId, c.cvss AS cvss, c.severity AS cveSeverity,
              m.cwe_id AS cweId, m.cwe_name AS cweName,
              cap.capec_id AS capecId, cap.name AS capecName, cap.severity AS capecSeverity
       ORDER BY c.cvss DESC`,
      { pid: projectId }
    )
    const cveChains = chainResult.records.map(r => ({
      tech: (r.get('tech') as string) || 'Unknown',
      techVersion: r.get('techVersion') as string | null,
      cveId: (r.get('cveId') as string) || '',
      cvss: r.get('cvss') != null ? toNum(r.get('cvss')) : null,
      cveSeverity: r.get('cveSeverity') as string | null,
      cweId: r.get('cweId') as string | null,
      cweName: r.get('cweName') as string | null,
      capecId: r.get('capecId') as string | null,
      capecName: r.get('capecName') as string | null,
      capecSeverity: r.get('capecSeverity') as string | null,
    }))

    // Q7: Confirmed exploits (ExploitGvm)
    const exploitResult = await session.run(
      `MATCH (ex:ExploitGvm {project_id: $pid})
       WHERE ${notMuted('ex')} AND ${reportCountable('ex')}
       OPTIONAL MATCH (ex)-[:EXPLOITED_CVE]->(c:CVE)
       RETURN ex.name AS name, ex.severity AS severity, ex.target_ip AS targetIp,
              ex.target_port AS targetPort, ex.cvss_score AS cvssScore,
              ex.cisa_kev AS cisaKev, ex.evidence AS evidence,
              collect(c.id) AS cveIds
       ORDER BY ex.cvss_score DESC`,
      { pid: projectId }
    )
    const exploits = exploitResult.records.map(r => ({
      name: (r.get('name') as string) || 'Unknown',
      severity: (r.get('severity') as string) || 'critical',
      targetIp: r.get('targetIp') as string | null,
      targetPort: r.get('targetPort') != null ? toNum(r.get('targetPort')) : null,
      cvssScore: r.get('cvssScore') != null ? toNum(r.get('cvssScore')) : null,
      cisaKev: r.get('cisaKev') as boolean | null,
      evidence: r.get('evidence') as string | null,
      cveIds: r.get('cveIds') as string[],
    }))

    // Q8: GitHub secrets summary, as the report counts it: a key that is
    // public by design is counted apart, never as an exposed secret.
    const ghResult = await session.run(githubSecretCountsCypher(), { pid: projectId })
    const githubSecrets = githubSecretCounts(ghResult.records[0])

    // Q9: GVM remediation status
    const remResult = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid, source: 'gvm'})
       WHERE ${notMuted('v')} AND ${reportCountable('v')}
       RETURN CASE WHEN v.remediated = true THEN 'Remediated' ELSE 'Open' END AS status,
              count(v) AS count`,
      { pid: projectId }
    )
    const gvmRemediation = remResult.records.map(r => ({
      status: (r.get('status') as string) || 'Open',
      count: toNum(r.get('count')),
    }))

    // Findings the board set aside, for the "not counted above" lines.
    const judged = await queryJudgedFindings(session, projectId)
    const disposition = await queryDispositionSummary(session, projectId)

    return NextResponse.json({
      disposition,
      severityDistribution,
      vulnTypes,
      findings,
      cvssHistogram,
      cveSeverity,
      cveChains,
      exploits,
      githubSecrets,
      gvmRemediation,
      judged,
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Analytics vulnerabilities error' })
  } finally {
    await session.close()
  }
}
