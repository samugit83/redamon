import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { readEvidence } from '@/lib/triage/actions'
import { actionErrorResponse, parseFindingRef } from '@/lib/triage/http'

/**
 * GET /api/triage/evidence?projectId=&findingId=&label= - the evidence a
 * reviewer reads for one finding: normalised, secret shapes redacted, capped.
 * The same bundle MCP `get_finding_evidence` returns and the built-in review
 * is shown. It is scanner output, so the panel renders it as untrusted text.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const auth = await requirePermission(request, 'triage:read', { projectId: params.get('projectId') })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  const ref = parseFindingRef(params.get('findingId'), params.get('label'))
  if (ref instanceof NextResponse) return ref
  try {
    return NextResponse.json(await readEvidence(caller, ref.findingId, ref.label, 'app'))
  } catch (err) {
    return actionErrorResponse(err)
  }
}
