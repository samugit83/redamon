import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { listFindings, triageFacets } from '@/lib/triage/actions'
import { actionErrorResponse, parseBoardFilters } from '@/lib/triage/http'
import { latestPublishedRunId, latestRunIdFrom } from '@/lib/triageRun'

/**
 * GET /api/triage/findings?projectId=&decidedBy=&reviewedVia=&reviewCurrent=
 *
 * The Priority Board: findings in triage scope, muted excluded, with the
 * filters applied in the graph before the cap (so `total` is exact), the
 * uncapped `facets` behind the filter menu, and `latestRunId` - the run whose
 * results the board shows, which marks a row "not in the latest run". A project
 * imported without its runs falls back to the run id of its most recently
 * triaged finding.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const auth = await requirePermission(request, 'triage:read', { projectId: params.get('projectId') })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  const filters = parseBoardFilters(params)
  if (filters instanceof NextResponse) return filters

  try {
    const [page, facets, published] = await Promise.all([
      listFindings(caller, { filters, channel: 'app' }),
      triageFacets(caller, 'app'),
      latestPublishedRunId(caller.projectId).catch(() => null),
    ])
    return NextResponse.json({
      findings: page.findings,
      total: page.total,
      // Display only: the filters still apply server-side without them.
      ...(facets ? { facets } : {}),
      latestRunId: published ?? latestRunIdFrom(page.findings),
    })
  } catch (err) {
    return actionErrorResponse(err)
  }
}
