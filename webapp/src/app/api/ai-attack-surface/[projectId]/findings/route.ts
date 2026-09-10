import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

// GET /api/ai-attack-surface/{projectId}/findings
// The normalized Vulnerability findings written by the attack tools (§7),
// grouped-ready by OWASP-LLM id, with ASR/trials/transcript ref.
const AI_ATTACK_SOURCES = ['garak', 'pyrit', 'giskard', 'promptfoo']

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  const session = getGraphSession()
  try {
    const res = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE v.source IN $sources AND ${notMuted('v')}
       OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
       // A finding can have several parents (e.g. Endpoint + IP). Collapse to ONE
       // row per finding, preferring the most specific parent (Endpoint), so it
       // is never duplicated in the table.
       WITH v, parent
       ORDER BY (CASE WHEN parent IS NULL THEN 3
                      WHEN 'Endpoint' IN labels(parent) THEN 0
                      WHEN 'BaseURL' IN labels(parent) THEN 1
                      ELSE 2 END)
       WITH v, head(collect(parent)) AS parent
       ORDER BY v.ai_asr DESC, v.severity
       RETURN v.id AS id, v.source AS source, v.name AS name, v.severity AS severity,
              v.type AS type, v.ai_owasp_llm_id AS owaspLlmId, v.ai_asr AS asr,
              v.ai_trials AS trials, v.ai_payload_class AS payloadClass,
              v.ai_oracle_kind AS oracleKind, v.ai_atlas_technique AS atlasTechnique,
              v.ai_probe_pack_version AS probePackVersion, v.ai_transcript_ref AS transcriptRef,
              v.evidence AS evidence, v.description AS description,
              head([l IN labels(parent) WHERE l <> 'Vulnerability']) AS targetType,
              // Prefer the linked node; fall back to the URL stored on the
              // finding so custom (off-graph) targets still show a target.
              coalesce(parent.baseurl, parent.url, parent.name, v.ai_target_url) AS target,
              parent.path AS endpointPath,
              v.updated_at AS updatedAt
       LIMIT 2000`,
      { pid: projectId, sources: AI_ATTACK_SOURCES },
    )
    const findings = res.records.map((r: { get: (k: string) => unknown }) => ({
      id: r.get('id'),
      source: r.get('source'),
      name: r.get('name'),
      severity: r.get('severity'),
      type: r.get('type'),
      owaspLlmId: r.get('owaspLlmId'),
      asr: typeof r.get('asr') === 'number' ? (r.get('asr') as number) : toNum(r.get('asr')),
      trials: toNum(r.get('trials')),
      payloadClass: r.get('payloadClass'),
      oracleKind: r.get('oracleKind'),
      atlasTechnique: r.get('atlasTechnique'),
      probePackVersion: r.get('probePackVersion'),
      transcriptRef: r.get('transcriptRef'),
      evidence: r.get('evidence'),
      description: r.get('description'),
      targetType: r.get('targetType'),
      target: r.get('target'),
      endpointPath: r.get('endpointPath'),
      updatedAt: r.get('updatedAt') ?? null,
    }))
    return NextResponse.json({ findings, count: findings.length })
  } catch (error) {
    console.error('AI Attack Surface findings error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed', findings: [] },
      { status: 500 },
    )
  } finally {
    await session.close()
  }
}
