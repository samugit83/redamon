/**
 * POST /api/navigator/projects/:projectId/threads/:threadId/stop: ends the answer being written on
 * the person's thread; the relay saves the partial answer as `stopped`.
 */
import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requirePermission } from '@/lib/authz/guards'
import { navigatorContext } from '@/lib/navigator/access'
import { navigatorError, navigatorJson, isNavigatorId } from '@/lib/navigator/responses'
import { findOwnedThread } from '@/lib/navigator/threads'
import { navigatorRuns } from '@/lib/navigator/runRegistry'

type Ctx = { params: Promise<{ projectId: string; threadId: string }> }

export const POST = withRouteErrors('Could not stop the AI Navigator answer', async (request: NextRequest, { params }: Ctx) => {
  const { projectId, threadId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) return nav
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const thread = await findOwnedThread(nav.personId, nav.projectId, threadId)
  if (!thread) return navigatorError('not_found', 404)
  return navigatorJson({ stopped: navigatorRuns().abortThread(thread.id) > 0 })
})
