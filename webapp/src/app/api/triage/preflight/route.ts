/**
 * GET /api/triage/preflight?projectId= — what the confirm dialog needs to say.
 *
 * The dialog exists because a triage run is not free and not invisible: it
 * spends LLM budget, replaces the board's order, rewrites the fix list, and
 * blocks version activation while it works. An operator should be told all of
 * that with THIS project's numbers in it, not with a generic warning.
 *
 * So this answers four questions in one call:
 *   how much is in scope, and how much of it is new since the last run;
 *   when the last run was, and with which model;
 *   which model reviews it: the owner's "Triage review" model from Models by
 *     feature. A review budget above 0 with no model answers `model_required`
 *     (the dialog opens the model picker); budget 0 needs no model at all;
 *   whether anything is BLOCKING a run right now.
 *
 * Guarded by `requireProjectOwner`, the strict owner check the mute routes use.
 * The logic lives in `lib/triage/preflight.ts`, shared with MCP `get_triage_status`.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner } from '@/lib/triageClient'
import { featureModelErrorResponse } from '@/lib/featureModels'
import { computePreflight } from '@/lib/triage/preflight'
import { withRouteErrors } from '@/lib/routeErrors'

// A Prisma or lock-table failure used to escape as Next's empty-bodied 500,
// which the dialog could only report as "could not be checked".
export const GET = withRouteErrors('The project could not be checked.', async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller

  const preflight = await computePreflight(caller, 'app')
  if (!preflight) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  if (preflight.modelRequired) return featureModelErrorResponse('model_required', 'triage')
  return NextResponse.json(preflight)
})
