/**
 * GET /api/projects/[id]/node-filters/status — what the Mute Rules tab badges.
 *
 * { armed, mode, activeRules, activeKinds, runningApply }. Fetched on load, after
 * Save and Apply, and when the project changes.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { nodeFilterStatus } from '@/lib/nodeFilters/server'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await requirePermission(request, 'triage:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  return NextResponse.json(await nodeFilterStatus(caller.projectId))
}
