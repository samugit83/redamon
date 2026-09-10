import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'

/** GET /api/triage/findings?projectId= - findings in triage scope, muted excluded. */
export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  return callGraphTriage('list_findings', caller)
}
