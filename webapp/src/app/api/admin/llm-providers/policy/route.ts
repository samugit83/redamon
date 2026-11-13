import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { changePolicy } from '@/lib/instanceProviders/admin'
import { instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'
import { confirmedRootWriter, providerRouteError } from '@/lib/instanceProviders/routeGate'

/**
 * PUT `{byoLlmForbidden, stepUpPassword}` (step 6.11): whether accounts lacking self:llm_providers
 * also lose the agent's use of the providers they added themselves (the permission already hides
 * the list, the add and their models). The confirmed Root with its password, same-origin JSON;
 * 404 with RBAC_GOVERNANCE_ENABLED off. GET /api/admin/llm-providers reads it.
 */
export async function PUT(request: NextRequest) {
  try {
    if (!instanceProvidersInForce()) return routeNotFound()
    const session = await requireSession({ fresh: true })
    if (session instanceof NextResponse) return session
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const refused = await confirmedRootWriter(request, session, parsed.body)
    if (refused) return refused
    return await changePolicy(request, session, parsed.body)
  } catch (error) {
    return providerRouteError(error, 'Could not change the instance LLM provider policy')
  }
}
