/**
 * GET /api/navigator/projects/:projectId/threads: the person's own AI Navigator conversations on the
 * project, newest first (D13: never anyone else's). The project's expired threads are purged first.
 */
import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { navigatorContext } from '@/lib/navigator/access'
import { navigatorJson, isNavigatorId, navigatorError } from '@/lib/navigator/responses'
import { listThreads } from '@/lib/navigator/threads'
import { purgeProjectThreads } from '@/lib/navigator/retention'

type Ctx = { params: Promise<{ projectId: string }> }

export const GET = withRouteErrors('Could not list the AI Navigator conversations', async (request: NextRequest, { params }: Ctx) => {
  const { projectId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) return nav
  try {
    await purgeProjectThreads(nav.projectId)
  } catch (err) {
    console.warn(`[navigator] lazy purge failed project=${nav.projectId} code=${(err as { code?: string })?.code ?? 'error'}`)
  }
  return navigatorJson({ threads: await listThreads(nav.personId, nav.projectId) })
})
