import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { readFinding } from '@/lib/triage/actions'
import { actionErrorResponse, parseFindingRef } from '@/lib/triage/http'

/**
 * GET /api/triage/finding?projectId=&findingId=&label= - everything behind one
 * finding's place on the Priority Board: the result, the rules, the review, the
 * decision, the detector and the group. The detail panel's source.
 *
 * A muted finding, a wrong id and another project's id all answer 404.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const auth = await requirePermission(request, 'triage:read', { projectId: params.get('projectId') })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  const ref = parseFindingRef(params.get('findingId'), params.get('label'))
  if (ref instanceof NextResponse) return ref
  try {
    return NextResponse.json(await readFinding(caller, ref.findingId, ref.label, 'app'))
  } catch (err) {
    return actionErrorResponse(err)
  }
}
