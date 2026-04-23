import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getSession()
  try {
    // Q1: Chain summary
    const chainsResult = await session.run(
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
      { pid: projectId }
    )
    const chains = chainsResult.records
      .filter(r => r.get('title'))
      .map(r => ({
        title: (r.get('title') as string) || 'Untitled',
        status: (r.get('status') as string) || 'unknown',
        steps: toNum(r.get('steps')),
        findings: toNum(r.get('findings')),
        failures: toNum(r.get('failures')),
      }))

    // Q2: Tool usage
    const toolResult = await session.run(
      `MATCH (step:ChainStep {project_id: $pid})
       RETURN step.tool_name AS tool, count(step) AS uses,
              count(CASE WHEN step.success = true THEN 1 END) AS successes
       ORDER BY uses DESC`,
      { pid: projectId }
    )
    const chainToolUsage = toolResult.records
      .filter(r => r.get('tool'))
      .map(r => ({
        tool: (r.get('tool') as string) || 'unknown',
        uses: toNum(r.get('uses')),
        successes: toNum(r.get('successes')),
      }))

    // Q3: Chain success rate
    const successResult = await session.run(
      `MATCH (ac:AttackChain {project_id: $pid})
       RETURN ac.status AS status, count(ac) AS count`,
      { pid: projectId }
    )
    const chainSuccessRate = successResult.records.map(r => ({
      status: (r.get('status') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q4: Findings by type
    const findTypeResult = await session.run(
      `MATCH (f:ChainFinding {project_id: $pid})
       RETURN f.finding_type AS findingType, count(f) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const findingsByType = findTypeResult.records.map(r => ({
      findingType: (r.get('findingType') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q5: Findings by severity
    const findSevResult = await session.run(
      `MATCH (f:ChainFinding {project_id: $pid})
       RETURN f.severity AS severity, count(f) AS count`,
      { pid: projectId }
    )
    const findingsBySeverity = findSevResult.records.map(r => ({
      severity: (r.get('severity') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q6: Phase progression
    const phaseResult = await session.run(
      `MATCH (s:ChainStep {project_id: $pid})
       RETURN s.phase AS phase, count(s) AS totalSteps,
              count(CASE WHEN s.success = true THEN 1 END) AS successSteps
       ORDER BY CASE s.phase WHEN 'informational' THEN 0 WHEN 'exploitation' THEN 1 WHEN 'post_exploitation' THEN 2 ELSE 3 END`,
      { pid: projectId }
    )
    const phaseProgression = phaseResult.records.map(r => ({
      phase: (r.get('phase') as string) || 'unknown',
      totalSteps: toNum(r.get('totalSteps')),
      successSteps: toNum(r.get('successSteps')),
    }))

    // Q7: Goal/outcome findings detail (exploit successes + all attack objectives achieved)
    const exploitResult = await session.run(
      `MATCH (f:ChainFinding {project_id: $pid})
       WHERE f.finding_type IN ['exploit_success', 'access_gained', 'privilege_escalation', 'credential_found', 'data_exfiltration', 'lateral_movement', 'persistence_established', 'denial_of_service_success', 'social_engineering_success', 'remote_code_execution', 'session_hijacked']
       OPTIONAL MATCH (f)-[:FINDING_RELATES_CVE]->(cve:CVE)
       WITH f, collect(cve.id) AS cveIds
       RETURN f.title AS title, f.target_ip AS targetIp, f.target_port AS targetPort,
              f.metasploit_module AS module, f.payload AS payload,
              f.evidence AS evidence, f.attack_type AS attackType, f.finding_type AS findingType, cveIds
       ORDER BY f.created_at DESC`,
      { pid: projectId }
    )
    const exploitSuccesses = exploitResult.records.map(r => ({
      title: (r.get('title') as string) || 'Untitled',
      targetIp: r.get('targetIp') as string | null,
      targetPort: toNum(r.get('targetPort')) || null,
      module: r.get('module') as string | null,
      payload: r.get('payload') as string | null,
      evidence: r.get('evidence') as string | null,
      attackType: r.get('attackType') as string | null,
      cveIds: (r.get('cveIds') as string[]) || [],
    }))

    // Q8: Top findings
    const topResult = await session.run(
      `MATCH (f:ChainFinding {project_id: $pid})
       OPTIONAL MATCH (f)-[:FOUND_ON]->(target)
       WITH f, COALESCE(target.address, target.name) AS targetHost
       RETURN f.title AS title, f.severity AS severity, f.finding_type AS findingType,
              f.evidence AS evidence, f.confidence AS confidence, f.phase AS phase,
              targetHost
       ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
       LIMIT 20`,
      { pid: projectId }
    )
    const topFindings = topResult.records.map(r => ({
      title: (r.get('title') as string) || 'Untitled',
      severity: (r.get('severity') as string) || 'unknown',
      findingType: (r.get('findingType') as string) || 'unknown',
      evidence: r.get('evidence') as string | null,
      confidence: toNum(r.get('confidence')) || null,
      phase: r.get('phase') as string | null,
      targetHost: r.get('targetHost') as string | null,
    }))

    // Q9: Failures by type
    const failResult = await session.run(
      `MATCH (fl:ChainFailure {project_id: $pid})
       RETURN fl.failure_type AS failureType, count(fl) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const failuresByType = failResult.records.map(r => ({
      failureType: (r.get('failureType') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q10: Decisions breakdown
    const decResult = await session.run(
      `MATCH (d:ChainDecision {project_id: $pid})
       RETURN d.decision_type AS decisionType, count(*) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const decisions = decResult.records.map(r => ({
      decisionType: (r.get('decisionType') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q11: ExploitGvm list
    const gvmResult = await session.run(
      `MATCH (ex:ExploitGvm {project_id: $pid})
       OPTIONAL MATCH (ex)-[:EXPLOITED_CVE]->(c:CVE)
       WITH ex, collect(c.id) AS cveIds
       RETURN ex.name AS name, ex.target_ip AS targetIp, ex.target_port AS targetPort,
              ex.cvss_score AS cvssScore, ex.evidence AS evidence,
              ex.cisa_kev AS cisaKev, ex.family AS family, cveIds
       ORDER BY ex.cvss_score DESC`,
      { pid: projectId }
    )
    const gvmExploits = gvmResult.records.map(r => ({
      name: (r.get('name') as string) || 'Untitled',
      targetIp: r.get('targetIp') as string | null,
      targetPort: toNum(r.get('targetPort')) || null,
      cvssScore: typeof r.get('cvssScore') === 'number' ? r.get('cvssScore') as number : null,
      evidence: r.get('evidence') as string | null,
      cisaKev: r.get('cisaKev') as boolean | null,
      family: r.get('family') as string | null,
      cveIds: (r.get('cveIds') as string[]) || [],
    }))

    // Q12: Targets attacked
    const targetResult = await session.run(
      `MATCH (s:ChainStep {project_id: $pid})-[:STEP_TARGETED]->(target)
       RETURN COALESCE(target.address, target.name) AS targetHost,
              labels(target)[0] AS targetType,
              count(s) AS attackCount,
              count(CASE WHEN s.success = true THEN 1 END) AS successCount
       ORDER BY attackCount DESC
       LIMIT 15`,
      { pid: projectId }
    )
    const targetsAttacked = targetResult.records
      .filter(r => r.get('targetHost'))
      .map(r => ({
        targetHost: (r.get('targetHost') as string) || 'unknown',
        targetType: r.get('targetType') as string | null,
        attackCount: toNum(r.get('attackCount')),
        successCount: toNum(r.get('successCount')),
      }))

    // Q13: Attack execution flow — Target → Tool → FindingType → Severity
    // Returns individual rows for Sankey visualization of real attack paths
    const flowResult = await session.run(
      `MATCH (s:ChainStep {project_id: $pid})-[:PRODUCED]->(f:ChainFinding)
       WHERE s.tool_name IS NOT NULL
       OPTIONAL MATCH (s)-[:STEP_TARGETED]->(target)
       WHERE target:IP OR target:Subdomain
       WITH COALESCE(
         CASE WHEN target:IP THEN target.address ELSE target.name END,
         f.target_host,
         'unknown'
       ) AS target,
       s.tool_name AS tool,
       f.finding_type AS findingType,
       f.severity AS severity
       RETURN target, tool, findingType, severity
       UNION ALL
       MATCH (ex:ExploitGvm {project_id: $pid})
       RETURN COALESCE(ex.target_ip, 'unknown') AS target,
              'openvas' AS tool,
              'exploit_success' AS findingType,
              'critical' AS severity`,
      { pid: projectId }
    )
    const attackFlowRows = flowResult.records.map(r => ({
      target: (r.get('target') as string) || 'unknown',
      tool: (r.get('tool') as string) || 'unknown',
      findingType: (r.get('findingType') as string) || 'unknown',
      severity: (r.get('severity') as string) || 'unknown',
    }))

    return NextResponse.json({
      chains,
      chainToolUsage,
      chainSuccessRate,
      findingsByType,
      findingsBySeverity,
      phaseProgression,
      exploitSuccesses,
      topFindings,
      failuresByType,
      decisions,
      gvmExploits,
      targetsAttacked,
      attackFlowRows,
    })
  } catch (error) {
    console.error('Analytics attack-chains error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
