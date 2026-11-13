import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { transfersForAccount, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

/**
 * GET /api/projects/transfers (step 5.12, SH-15): what the header's banners show the account: the
 * ownership transfer offers made to it on projects it still shares, the offers it made, and the settings
 * a transfer to it cleared, not yet dismissed. The effective user's own; write sharing in force only (404
 * otherwise, nothing read).
 */
export const GET = withRouteErrors('Could not list your ownership transfers', async (_request: NextRequest) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  if (!(await writeSharingInForce())) return routeNotFound()
  return NextResponse.json(await transfersForAccount(eff.userId))
})
