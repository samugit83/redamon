import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { withRouteErrors } from '@/lib/routeErrors'
import { graphTriage } from '@/lib/triageClient'
import { liveRuleMutedBy } from '@/lib/nodeFilters/model'
import { MULTI_BATCH_PATTERN } from '@/lib/multiMute'
import {
  annotateMutedFacets,
  annotateMutedRow,
  loadMutedRuleDoc,
  MUTED_TOKEN_PATTERN,
} from '@/lib/nodeFilters/mutedAnnotate'

/**
 * GET /api/triage/muted?projectId= - the Muted Nodes table, one page at a time.
 *
 * The ONE endpoint in the product that returns suppressed findings. It is
 * explicitly non-agent: the agent's Cypher chokepoint refuses any query that
 * even names the `Muted` label, and nothing here is reachable from it.
 *
 * Query: offset, limit (default 50), label, mutedVia (person | multi | mcp |
 * rule | deleted_rule), rule (an exact muted_by), token (an MCP token prefix,
 * one token's mutes, or a Multi mute batch id, one batch's), search, order
 * (recent | person_first), facets=1 for the per-kind, per-rule and per-token
 * counts.
 *
 * Rule mutes are annotated from the project's rule document here, server-side:
 * `rule_name` for a rule that still exists, `rule_deleted` for one that does not.
 */
const MUTED_PAGE_DEFAULT = 50
/** Export reads the whole filtered view in one request. */
const MUTED_PAGE_MAX = 5000

const MUTED_VIA = new Set(['person', 'multi', 'mcp', 'rule', 'deleted_rule'])
const ORDERS = new Set(['recent', 'person_first'])

function intParam(raw: string | null, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(raw ?? '', 10)
  if (!Number.isFinite(n)) return fallback
  return Math.max(min, Math.min(max, n))
}

// The ownership check reads Postgres; a failure there would otherwise be
// Next's empty-bodied 500.
export const GET = withRouteErrors('Could not load the muted nodes', async (request: NextRequest) => {
  const q = request.nextUrl.searchParams
  const auth = await requirePermission(request, 'triage:read', { projectId: q.get('projectId') })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const mutedVia = q.get('mutedVia')
  const order = q.get('order')
  const doc = await loadMutedRuleDoc(caller.projectId)
  const token = q.get('token')

  const extra: Record<string, unknown> = {
    offset: intParam(q.get('offset'), 0, 0, 10_000_000),
    limit: intParam(q.get('limit'), MUTED_PAGE_DEFAULT, 1, MUTED_PAGE_MAX),
    label: q.get('label') || undefined,
    muted_via: mutedVia && MUTED_VIA.has(mutedVia) ? mutedVia : undefined,
    rule: q.get('rule')?.slice(0, 200) || undefined,
    search: q.get('search')?.slice(0, 200) || undefined,
    order: order && ORDERS.has(order) ? order : undefined,
    // Dropped, not refused, when it is neither: the agent refuses one.
    token: token && (MUTED_TOKEN_PATTERN.test(token) || MULTI_BATCH_PATTERN.test(token)) ? token : undefined,
  }
  if (extra.muted_via === 'deleted_rule') extra.live_rules = liveRuleMutedBy(doc)

  const list = await graphTriage('list_muted', caller, extra)
  if (list.status !== 200) return NextResponse.json(list.body, { status: list.status })

  const rows = Array.isArray(list.body.findings) ? list.body.findings : []
  const findings = rows.map((row: Record<string, unknown>) => annotateMutedRow(doc, row))

  const out: Record<string, unknown> = {
    findings,
    total: typeof list.body.total === 'number' ? list.body.total : findings.length,
    offset: extra.offset,
    limit: extra.limit,
  }

  if (q.get('facets') === '1') {
    const facets = await graphTriage('muted_facets', caller)
    if (facets.status === 200) out.facets = annotateMutedFacets(doc, facets.body)
  }
  return NextResponse.json(out)
})
