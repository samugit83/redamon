/**
 * GET /api/navigator/projects/:projectId/threads/:threadId[?before=<seq>]: one of the person's
 * conversations, 50 messages a page. DELETE removes it, stopping a live answer on it first.
 * A thread that does not exist, is another person's or another project's is the same 404.
 */
import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requirePermission } from '@/lib/authz/guards'
import { navigatorContext } from '@/lib/navigator/access'
import { navigatorError, navigatorJson, NO_STORE, isNavigatorId } from '@/lib/navigator/responses'
import { deleteThread, findOwnedThread, readThreadPage } from '@/lib/navigator/threads'
import { navigatorRuns } from '@/lib/navigator/runRegistry'

type Ctx = { params: Promise<{ projectId: string; threadId: string }> }

export const GET = withRouteErrors('Could not read the AI Navigator conversation', async (request: NextRequest, { params }: Ctx) => {
  const { projectId, threadId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) return nav
  const thread = await findOwnedThread(nav.personId, nav.projectId, threadId)
  if (!thread) return navigatorError('not_found', 404)
  const raw = request.nextUrl.searchParams.get('before')
  const before = raw && /^\d{1,6}$/.test(raw) ? Number(raw) : undefined
  const page = await readThreadPage(thread.id, before)
  const live = navigatorRuns().liveForThread(thread.id)
  return navigatorJson({
    thread: { id: thread.id, title: thread.title, lastMessageAt: thread.lastMessageAt, running: live !== null },
    ...page,
  })
})

export const DELETE = withRouteErrors('Could not delete the AI Navigator conversation', async (request: NextRequest, { params }: Ctx) => {
  const { projectId, threadId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) return nav
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const thread = await findOwnedThread(nav.personId, nav.projectId, threadId)
  if (!thread) return navigatorError('not_found', 404)
  navigatorRuns().abortThread(thread.id)
  await deleteThread(thread.id)
  return new NextResponse(null, { status: 204, headers: NO_STORE })
})
