/**
 * MCP personal access tokens: list and mint.
 *
 * Minting is judged on the REAL login identity (`getSession`), never on
 * `getEffectiveUser`. The settings page derives its userId from ProjectProvider,
 * which for an admin is their act-as target; using the effective user would let
 * an admin silently mint a long-lived credential on someone else's account,
 * usable with no further authentication and indistinguishable from that user's
 * own actions. Admins included: there is no act-as path to minting.
 *
 * Listing keeps the admin bypass so an admin can audit tokens during an
 * incident. Revoking is a safe privilege; minting is not.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, requireUserAccess } from '@/lib/session'
import { checkStepUp } from '@/lib/authz/stepUp'
import { writeAudit } from '@/lib/audit'
import {
  generateToken,
  resolveExpiry,
  sanitizeTokenName,
  validateScopes,
} from '@/lib/mcpAuth'
import { validateProfile } from '@/lib/mcp/profiles'
import { internalError, withRouteErrors } from '@/lib/routeErrors'
import { agentInTheLoopEnabled } from '@/lib/agentInTheLoop'

interface RouteParams {
  params: Promise<{ id: string }>
}

const LIST_SELECT = {
  id: true,
  name: true,
  tokenPrefix: true,
  scopes: true,
  profile: true,
  lastUsedAt: true,
  expiresAt: true,
  revokedAt: true,
  createdAt: true,
} as const

export const GET = withRouteErrors('Could not load tokens', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const denied = await requireUserAccess(request, id)
  if (denied) return denied

  try {
    const tokens = await prisma.mcpAccessToken.findMany({
      where: { userId: id },
      select: LIST_SELECT,
      orderBy: { createdAt: 'desc' },
    })
    // Expired and revoked rows stay visible: "why did my agent stop working" is
    // the common support question, and hiding the answer makes it harder.
    // The browser cannot read the deployment's switches; the token UI needs this one.
    return NextResponse.json({ tokens, features: { agentInTheLoop: agentInTheLoopEnabled() } })
  } catch (error) {
    return internalError(error, 'Could not load tokens', { log: '[mcp-tokens] list failed' })
  }
})

export const POST = withRouteErrors('Could not create the token', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const session = await getSession()
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  // Self-only, on the REAL identity. Not requireUserAccess: that carries the
  // admin bypass, which must not extend to minting.
  if (session.userId !== id) {
    return NextResponse.json(
      { error: 'A token can only be created by its own user, signed in as themselves.' },
      { status: 403 }
    )
  }

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const name = sanitizeTokenName(body.name)
  if (!name) return NextResponse.json({ error: 'A token name is required' }, { status: 400 })

  const scopeResult = validateScopes(body.scopes)
  if ('error' in scopeResult) {
    return NextResponse.json({ error: scopeResult.error }, { status: 400 })
  }
  // Rejected rather than coerced, exactly like an unknown scope: the profile is
  // the operator's stated intent for this credential, and quietly storing a
  // different one labels the token as a job nobody chose.
  const profileResult = validateProfile(body.profile)
  if ('error' in profileResult) {
    return NextResponse.json({ error: profileResult.error }, { status: 400 })
  }
  const expiryResult = resolveExpiry(body.expiresInDays ?? null)
  if ('error' in expiryResult) {
    return NextResponse.json({ error: expiryResult.error }, { status: 400 })
  }

  // Step-up: a stolen 7-day session cookie must not silently become a
  // credential that outlives logout and password changes. The helper throttles
  // it with the login limiter, keyed on this (self-only) owner. This route keeps
  // the answers its clients know: 401 for a missing or wrong password, 429 locked.
  const proof = await checkStepUp(request, body.password)
  if (proof.outcome === 'locked') {
    return NextResponse.json(
      { error: `Too many incorrect passwords. Try again in ${proof.retryAfterSeconds}s.` },
      { status: 429 }
    )
  }
  if (proof.outcome !== 'ok') {
    return NextResponse.json({ error: 'Password is incorrect' }, { status: 401 })
  }

  try {
    const { plaintext, hash, prefix } = generateToken()
    const created = await prisma.mcpAccessToken.create({
      data: {
        userId: id,
        name,
        tokenPrefix: prefix,
        tokenHash: hash,
        scopes: scopeResult.scopes,
        profile: profileResult.profile,
        expiresAt: expiryResult.expiresAt,
      },
      select: LIST_SELECT,
    })

    await writeAudit({
      actorId: session.userId,
      action: 'mcp-token.create',
      targetType: 'mcpAccessToken',
      targetId: created.id,
      after: {
        tokenPrefix: prefix, name, scopes: scopeResult.scopes,
        profile: profileResult.profile, expiresAt: expiryResult.expiresAt,
      },
      source: 'ui',
    })

    // The ONLY time the plaintext is returned. `no-store` is set here rather
    // than relied on from nginx: a plain `docker compose up` has no nginx.
    return NextResponse.json(
      { token: created, plaintext },
      { status: 201, headers: { 'Cache-Control': 'no-store' } }
    )
  } catch (error) {
    return internalError(error, 'Could not create the token', { log: '[mcp-tokens] create failed' })
  }
})
