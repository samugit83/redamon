import { NextResponse, type NextRequest } from 'next/server'
import type { Session } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireRootPower, rootOnlyRefusal, rootStanding } from '@/lib/authz/rootPowers'
import { InstanceProvidersNotReady } from './store'

/**
 * The Root rule of the instance providers' routes (step 6.11): `instance:settings` is Root-only, so
 * the confirmed Root reads them (403 `root_only` for anyone else, an unconfirmed Root told why) and
 * changes them with its own password (step-up, ID-25). The routes check the switch, the session
 * and the origin before these.
 */
export const ROOT_ONLY = 'Only Root manages the instance LLM providers.'

export async function confirmedRootReader(session: Session): Promise<NextResponse | null> {
  const standing = await rootStanding(session.userId)
  return standing === 'confirmed' ? null : rootOnlyRefusal(standing, ROOT_ONLY)
}

export function confirmedRootWriter(request: NextRequest, session: Session, body: Record<string, unknown>): Promise<NextResponse | null> {
  return requireRootPower(request, session, body.stepUpPassword, ROOT_ONLY)
}

/** A write before the provider tables exist answers 503 `instance_providers_not_ready`; anything else the coded 500. */
export function providerRouteError(err: unknown, message: string): NextResponse {
  if (err instanceof InstanceProvidersNotReady) {
    console.warn(`[rbac] ${err.code}: ${message}`)
    return NextResponse.json({ error: err.message, code: err.code }, { status: 503 })
  }
  return internalError(err, message)
}
