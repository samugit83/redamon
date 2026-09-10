import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { corroborateAttackFindings, type RawAttackRow } from '@/lib/report/aiAttackFindings'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/**
 * "AI Risk (LLM)" offensive view - the attackable AI findings, mapped to
 * OWASP-LLM / MITRE ATLAS: MCP tool poisoning, prompt-injectable parameters,
 * RAG ingestion sinks, exposed runtimes/gateways, and unauthenticated MCP.
 */
export async function GET(request: NextRequest) {
  const pid = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(pid || '')
  if (__denied) return __denied
  if (!pid) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })

  const session = getGraphSession()
  try {
    // --- MCP tool-poisoning / exfiltration / annotation findings ---
    const findings = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid, source: 'ai_surface_recon'})
       WHERE ${notMuted('v')}
       OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)
       RETURN v.severity AS severity, v.type AS type, v.name AS name,
              v.ai_owasp_llm_id AS owasp, v.ai_atlas_technique AS atlas,
              v.ai_payload_class AS payloadClass, v.evidence AS evidence, v.id AS findingId,
              coalesce(e.baseurl, '') AS baseUrl, e.path AS endpointPath,
              v.updated_at AS updatedAt
       ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT ${rowCap()}`,
      { pid })

    // --- Prompt-injectable parameters ---
    const params = await session.run(
      `MATCH (p:Parameter {project_id: $pid}) WHERE p.is_ai_prompt_injectable = true
       OPTIONAL MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p)
       RETURN p.name AS name, coalesce(e.path, p.endpoint_path) AS endpointPath,
              coalesce(e.baseurl, p.baseurl) AS baseUrl,
              p.ai_tool_arg_path AS toolArgPath, p.position AS position,
              p.updated_at AS updatedAt
       ORDER BY p.name LIMIT ${rowCap()}`,
      { pid })

    // --- RAG ingestion points (indirect-prompt-injection vectors) ---
    const rag = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.is_ai_rag_ingest = true
       RETURN ep.baseurl AS baseUrl, ep.path AS path, ep.method AS method,
              ep.ai_interface_type AS interfaceType, ep.updated_at AS updatedAt
       ORDER BY ep.baseurl, ep.path LIMIT ${rowCap()}`,
      { pid })

    // --- Exposed AI runtimes / gateways ---
    const exposed = await session.run(
      `MATCH (t:Technology {project_id: $pid}) WHERE t.category IN ['ai-runtime','ai-proxy']
       OPTIONAL MATCH (p:Port)-[:HAS_TECHNOLOGY]->(t)
       OPTIONAL MATCH (ip:IP)-[:HAS_PORT]->(p)
       WITH t, [hp IN collect(DISTINCT (ip.address + ':' + toString(p.number))) WHERE hp <> ':'] AS hostPorts
       RETURN t.name AS name, t.category AS category, t.version AS version, hostPorts AS exposedOn,
              t.updated_at AS updatedAt
       ORDER BY t.category, t.name LIMIT ${rowCap()}`,
      { pid })

    // --- Unauthenticated MCP servers ---
    const unauth = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid})
       WHERE ep.ai_interface_type = 'mcp' AND coalesce(ep.ai_mcp_auth_required, false) = false
       RETURN ep.baseurl AS baseUrl, ep.path AS path, ep.ai_mcp_server_name AS serverName,
              ep.ai_mcp_tool_count AS toolCount, ep.updated_at AS updatedAt
       ORDER BY ep.baseurl LIMIT ${rowCap()}`,
      { pid })

    // --- Tested vulnerabilities (garak/pyrit/giskard/promptfoo), corroborated
    // across tools by (OWASP-LLM id, target) - the confirmed AI attack findings.
    // Queried LAST so the earlier sheets' query order stays stable. ---
    const tested = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE v.source IN ['garak', 'pyrit', 'giskard', 'promptfoo']
         AND ${notMuted('v')}
       OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
       // One row per finding even when it has several parents (Endpoint + IP);
       // prefer the most specific parent so corroboration isn't double-counted.
       WITH v, parent
       ORDER BY (CASE WHEN parent IS NULL THEN 3
                      WHEN 'Endpoint' IN labels(parent) THEN 0
                      WHEN 'BaseURL' IN labels(parent) THEN 1
                      ELSE 2 END)
       WITH v, head(collect(parent)) AS parent
       RETURN v.source AS source, v.severity AS severity, v.type AS type,
              v.ai_owasp_llm_id AS owaspLlmId, v.ai_asr AS asr, v.ai_trials AS trials,
              v.ai_payload_class AS payloadClass, v.ai_transcript_ref AS transcriptRef,
              v.evidence AS evidence, v.ai_probe_pack_version AS probePackVersion,
              coalesce(parent.baseurl, parent.url, parent.name, v.ai_target_url) AS target,
              parent.path AS endpointPath, v.updated_at AS updatedAt
       ORDER BY v.ai_asr DESC LIMIT ${rowCap()}`,
      { pid })
    const rawTested: RawAttackRow[] = tested.records.map((r: { get: (k: string) => unknown }) => ({
      source: (r.get('source') as string) || '', severity: (r.get('severity') as string) || 'info',
      type: (r.get('type') as string) || null, owaspLlmId: (r.get('owaspLlmId') as string) || null,
      asr: toNum(r.get('asr')), trials: toNum(r.get('trials')),
      payloadClass: (r.get('payloadClass') as string) || null,
      transcriptRef: (r.get('transcriptRef') as string) || null,
      evidence: (r.get('evidence') as string) || null,
      probePackVersion: (r.get('probePackVersion') as string) || null,
      target: (r.get('target') as string) || null, endpointPath: (r.get('endpointPath') as string) || null,
      updatedAt: r.get('updatedAt') ?? null,
    }))

    const sheets = {
      testedVulns: corroborateAttackFindings(rawTested).map(f => ({
        severity: f.severity,
        owasp: f.owaspLlmId,
        attack: f.attackChip,
        target: f.target + (f.endpointPath || ''),
        foundBy: f.sources,
        asr: f.maxAsr != null ? `${Math.round(f.maxAsr * 100)}%` : '-',
        trials: f.totalTrials,
        evidence: f.evidence,
        updatedAt: f.updatedAt ?? null,
      })),
      findings: findings.records.map((r: { get: (key: string) => unknown }) => ({
        severity: r.get('severity'), type: r.get('type'), name: r.get('name'),
        owasp: r.get('owasp'), atlas: r.get('atlas'), payloadClass: r.get('payloadClass'),
        evidence: r.get('evidence'), findingId: r.get('findingId'),
        baseUrl: r.get('baseUrl'), endpointPath: r.get('endpointPath'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      injectableParams: params.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), endpointPath: r.get('endpointPath'), baseUrl: r.get('baseUrl'),
        toolArgPath: r.get('toolArgPath'), position: r.get('position'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      ragPoints: rag.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), method: r.get('method'),
        interfaceType: r.get('interfaceType'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      exposedRuntimes: exposed.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), category: r.get('category'), version: r.get('version'),
        exposedOn: (r.get('exposedOn') as string[]) || [],
        updatedAt: r.get('updatedAt') ?? null,
      })),
      unauthenticatedMcp: unauth.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), serverName: r.get('serverName'),
        toolCount: toNum(r.get('toolCount')),
        updatedAt: r.get('updatedAt') ?? null,
      })),
    }

    return NextResponse.json({
      sheets,
      meta: {
        testedVulns: sheets.testedVulns.length,
        findings: sheets.findings.length,
        injectableParams: sheets.injectableParams.length,
        ragPoints: sheets.ragPoints.length,
        exposedRuntimes: sheets.exposedRuntimes.length,
        unauthenticatedMcp: sheets.unauthenticatedMcp.length,
      },
    })
  } catch (error) {
    console.error('Red-zone aiRisk error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' }, { status: 500 })
  } finally {
    await session.close()
  }
}
