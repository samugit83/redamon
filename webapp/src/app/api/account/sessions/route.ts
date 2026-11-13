import { NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { sessionDeviceId } from '@/lib/authz/deviceSessions'
import { listDeviceSessions } from '@/lib/authz/deviceSessionAdmin'

/**
 * GET /api/account/sessions (step 6.10, GV-17, UI-09): the signed-in account's device sessions for
 * My account → Sessions, the asking browser marked `current`. The real signed-in account, never one
 * an admin is acting as. Governance switch only (404 without it, nothing read).
 */
export const GET = withRouteErrors('Could not read your sessions', async () => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const sessions = await listDeviceSessions(session.userId, { currentId: sessionDeviceId(session) })
  return NextResponse.json({ sessions: sessions ?? [] }, { headers: { 'Cache-Control': 'no-store' } })
})
