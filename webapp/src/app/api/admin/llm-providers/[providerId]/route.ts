import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { deleteProvider, updateProvider } from '@/lib/instanceProviders/admin'
import { instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'
import { confirmedRootWriter, providerRouteError } from '@/lib/instanceProviders/routeGate'

type Params = { params: Promise<{ providerId: string }> }

/**
 * One instance LLM provider (step 6.11, GV-15). 404 with RBAC_GOVERNANCE_ENABLED off.
 *
 * PUT `{..., setIds?, stepUpPassword}`: its settings, and its sets exactly `setIds` when sent; a masked
 * secret keeps the stored one, a new endpoint or kind needs the secrets typed again (HD-24).
 * DELETE `{stepUpPassword}`: the provider and its assignments; a project on one of its models then
 * fails closed in the agent (instance_provider_unavailable).
 * Each is the confirmed Root's with its password, same-origin JSON.
 */
export async function PUT(request: NextRequest, { params }: Params) {
  try {
    if (!instanceProvidersInForce()) return routeNotFound()
    const session = await requireSession({ fresh: true })
    if (session instanceof NextResponse) return session
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const refused = await confirmedRootWriter(request, session, parsed.body)
    if (refused) return refused
    const { providerId } = await params
    return await updateProvider(request, session, providerId, parsed.body)
  } catch (error) {
    return providerRouteError(error, 'Could not change the instance LLM provider')
  }
}

export async function DELETE(request: NextRequest, { params }: Params) {
  try {
    if (!instanceProvidersInForce()) return routeNotFound()
    const session = await requireSession({ fresh: true })
    if (session instanceof NextResponse) return session
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const refused = await confirmedRootWriter(request, session, parsed.body)
    if (refused) return refused
    const { providerId } = await params
    return await deleteProvider(request, session, providerId)
  } catch (error) {
    return providerRouteError(error, 'Could not delete the instance LLM provider')
  }
}
