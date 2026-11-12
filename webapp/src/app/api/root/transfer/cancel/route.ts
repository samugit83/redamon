import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { transferForbidden, withdrawRootTransfer } from '@/lib/authz/rootTransfer'

/**
 * POST `{}`: withdraw a pending Root transfer offer (step 2.6, ID-07): Root cancels it, or its
 * recipient declines it; audited `root.transfer_cancelled` / `root.transfer_declined`. Nothing
 * pending for Root answers `{withdrawn: false}`. Identity switch only (404 without it).
 */
export const POST = withRouteErrors('Could not withdraw the Root transfer', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return transferForbidden(session)
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return withdrawRootTransfer(request, session)
})
