import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { adminView, createProvider } from '@/lib/instanceProviders/admin'
import { instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'
import { confirmedRootReader, confirmedRootWriter, providerRouteError } from '@/lib/instanceProviders/routeGate'

/**
 * Instance LLM providers (step 6.11, GV-15): providers the confirmed Root adds for the whole instance
 * and assigns to permission sets (lib/instanceProviders/admin.ts). With RBAC_GOVERNANCE_ENABLED off
 * they are neither offered nor resolved, and this route does not exist (404).
 *
 * GET: every provider with its secrets masked and its sets, the sets an assignment may name, and
 * `byoLlmForbidden`; the confirmed Root only (403 root_only).
 * POST `{providerType, name, ..., setIds, stepUpPassword}`: a new provider; the confirmed Root with its
 * password, same-origin JSON.
 */
export async function GET() {
  try {
    if (!instanceProvidersInForce()) return routeNotFound()
    const session = await requireSession()
    if (session instanceof NextResponse) return session
    const refused = await confirmedRootReader(session)
    if (refused) return refused
    return NextResponse.json(await adminView(), { headers: { 'Cache-Control': 'no-store' } })
  } catch (error) {
    return providerRouteError(error, 'Could not read the instance LLM providers')
  }
}

export async function POST(request: NextRequest) {
  try {
    if (!instanceProvidersInForce()) return routeNotFound()
    const session = await requireSession({ fresh: true })
    if (session instanceof NextResponse) return session
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const refused = await confirmedRootWriter(request, session, parsed.body)
    if (refused) return refused
    return await createProvider(request, session, parsed.body)
  } catch (error) {
    return providerRouteError(error, 'Could not add the instance LLM provider')
  }
}
