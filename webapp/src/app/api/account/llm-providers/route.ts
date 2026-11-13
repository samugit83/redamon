import { NextResponse } from 'next/server'
import { getEffectiveUser } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { entitledProviderSummaries, instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'

/**
 * GET /api/account/llm-providers (step 6.11, GV-15): the instance LLM providers an administrator made
 * available to the account through a permission set it holds, by name and kind only (no key, no
 * endpoint, no header), for Global Settings and the new-project check. The effective user's (the
 * account an admin acts as, whose models the pickers list). 404 with RBAC_GOVERNANCE_ENABLED off.
 */
export const GET = withRouteErrors('Could not read the instance LLM providers', async () => {
  if (!instanceProvidersInForce()) return routeNotFound()
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return NextResponse.json({ providers: await entitledProviderSummaries(eff.userId) }, { headers: { 'Cache-Control': 'no-store' } })
})
