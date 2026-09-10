import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'

/**
 * GET /api/triage/muted?projectId= - the Muted table.
 *
 * The ONE endpoint in the product that returns suppressed findings. It is
 * explicitly non-agent: the agent's Cypher chokepoint refuses any query that
 * even names the `Muted` label, and nothing here is reachable from it.
 */
export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  return callGraphTriage('list_muted', caller)
}
