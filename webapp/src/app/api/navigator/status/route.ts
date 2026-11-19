/**
 * GET /api/navigator/status: whether Root's AI Navigator switch is on (D15), for the launcher.
 * Signed in, no permission and no project: it says only whether the instance switch is on.
 */
import { NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { navigatorEnabled } from '@/lib/navigator/switch'
import { navigatorJson } from '@/lib/navigator/responses'

export const GET = withRouteErrors('Could not read the AI Navigator status', async () => {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  return navigatorJson({ enabled: await navigatorEnabled() })
})
