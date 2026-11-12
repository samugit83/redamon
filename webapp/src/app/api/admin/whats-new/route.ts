import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin, type Session } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { actingAsUserId } from '@/lib/userAudit'
import { sessionActor } from '@/lib/auditActor'
import { dismissWhatsNew, whatsNewState } from '@/lib/authz/updateReview'

/**
 * The one-time "What changed in this update" card of each admin (HD-32). GET answers
 * whether this admin dismissed it, whether it applies to this install, and the members whose
 * saved stdio MCP servers no longer load; POST `{action: 'dismiss'}` records the dismissal.
 */

async function admin(): Promise<Session | NextResponse> {
  const session = await requireAdmin()
  if (session instanceof NextResponse && session.status === 403) {
    return NextResponse.json(
      { error: 'Only an administrator reads the update notes.', code: 'forbidden', permission: 'users:assign_permissions' },
      { status: 403 },
    )
  }
  return session
}

export const GET = withRouteErrors('Could not read the update notes', async () => {
  const session = await admin()
  if (session instanceof NextResponse) return session
  return NextResponse.json(await whatsNewState(session.userId))
})

export const POST = withRouteErrors('Could not dismiss the update notes', async (request: NextRequest) => {
  const session = await admin()
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  if (parsed.body.action !== 'dismiss') {
    return NextResponse.json({ error: 'action must be dismiss.', code: 'invalid_action' }, { status: 400 })
  }
  const { changed } = await dismissWhatsNew({
    actorId: session.userId, actingAsUserId: await actingAsUserId(request, session), actorEmail: sessionActor(session).email,
  })
  return NextResponse.json({ dismissed: true, changed })
})
