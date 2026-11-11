/**
 * MCP personal access tokens: edit and delete.
 *
 * PATCH changes a token's name, profile, scopes and expiry. The hash and the
 * owner are never mutable, and a revoked token keeps its capability frozen (only
 * its labels can change): restoring access means minting a new token.
 *
 * The rule an edit is judged by is DIRECTION, not field:
 *  - a change that NARROWS the token's capability (drop a scope, earlier expiry,
 *    "expire now") is open to an admin on another account, exactly like DELETE
 *    below: taking power away is a safe privilege during an incident, and both are
 *    audited with the real admin as the actor (HD-23's one exception). A profile
 *    switch riding along is allowed with it: the profile is a label, never an
 *    authorization input, and switching it in the UI re-ticks the scopes.
 *  - a rename or a profile change on its own is the account's write rule
 *    (requireAccountWrite): needs no step-up, but an admin cannot do it to
 *    another account.
 *  - a change that WIDENS it (add a scope, later or no expiry, reviving an
 *    expired token) gets the mint's step-up: self-only on the REAL identity,
 *    password re-confirmed, same limiter. Otherwise a stolen session cookie
 *    could upgrade an existing token into the credential it cannot mint.
 *
 * Scopes and expiry are re-read on every MCP call, so an edit takes effect on
 * the agent's next call.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, requireUserAccess } from '@/lib/session'
import { checkStepUp } from '@/lib/authz/stepUp'
import { writeAudit } from '@/lib/audit'
import {
  isTokenWidening,
  resolveExpiryChange,
  sanitizeTokenName,
  validateScopes,
  type McpScope,
} from '@/lib/mcpAuth'
import { validateProfile, type ProfileId } from '@/lib/mcp/profiles'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; tokenId: string }>
}

const SELECT = {
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

/** Load the token, 404ing unless it belongs to the user in the path. */
async function loadOwned(userId: string, tokenId: string) {
  const token = await prisma.mcpAccessToken.findUnique({
    where: { id: tokenId },
    select: { ...SELECT, userId: true },
  })
  if (!token || token.userId !== userId) return null
  return token
}

const sameScopes = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every(s => b.includes(s))

const sameExpiry = (a: Date | null, b: Date | null) =>
  (a === null && b === null) || (a !== null && b !== null && a.getTime() === b.getTime())

export const PATCH = withRouteErrors('Could not update the token', async (request: NextRequest, { params }: RouteParams) => {
  const { id, tokenId } = await params
  // The read rule lets an admin reach another account's token to narrow it; every
  // other edit is checked against the write rule below, once its direction is known.
  const denied = await requireUserAccess(request, id, { mode: 'read' })
  if (denied) return denied

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const data: {
    name?: string
    scopes?: McpScope[]
    profile?: ProfileId | null
    expiresAt?: Date | null
  } = {}

  if ('name' in body) {
    const name = sanitizeTokenName(body.name)
    if (!name) return NextResponse.json({ error: 'A token name is required' }, { status: 400 })
    if (name !== existing.name) data.name = name
  }
  if ('scopes' in body) {
    const scopeResult = validateScopes(body.scopes)
    if ('error' in scopeResult) {
      return NextResponse.json({ error: scopeResult.error }, { status: 400 })
    }
    if (!sameScopes(scopeResult.scopes, existing.scopes)) data.scopes = scopeResult.scopes
  }
  if ('profile' in body) {
    const profileResult = validateProfile(body.profile)
    if ('error' in profileResult) {
      return NextResponse.json({ error: profileResult.error }, { status: 400 })
    }
    if (profileResult.profile !== existing.profile) data.profile = profileResult.profile
  }
  if ('expiry' in body) {
    const expiryResult = resolveExpiryChange(body.expiry)
    if ('error' in expiryResult) {
      return NextResponse.json({ error: expiryResult.error }, { status: 400 })
    }
    if (!sameExpiry(expiryResult.expiresAt, existing.expiresAt)) data.expiresAt = expiryResult.expiresAt
  }

  if (!('name' in body) && !('scopes' in body) && !('expiry' in body) && !('profile' in body)) {
    return NextResponse.json({ error: 'Nothing to change' }, { status: 400 })
  }
  if (Object.keys(data).length === 0) {
    const token = Object.fromEntries(
      Object.keys(SELECT).map(k => [k, existing[k as keyof typeof SELECT]])
    )
    return NextResponse.json({ token })
  }

  // A profile is deliberately NOT capability-changing: it grants nothing, so it
  // needs no password and is allowed on a revoked token, exactly like a rename.
  const changesCapability = 'scopes' in data || 'expiresAt' in data
  if (changesCapability && existing.revokedAt) {
    return NextResponse.json(
      { error: 'A revoked token can only be renamed. Create a new token to restore access.' },
      { status: 409 }
    )
  }

  const after = {
    scopes: data.scopes ?? existing.scopes,
    expiresAt: 'expiresAt' in data ? data.expiresAt ?? null : existing.expiresAt,
  }
  const widened = changesCapability && isTokenWidening(existing, after)
  const narrowsOnly = changesCapability && !widened && !('name' in data)
  if (!narrowsOnly && !widened) {
    const writeDenied = await requireUserAccess(request, id, { mode: 'write' })
    if (writeDenied) return writeDenied
  }
  const session = await getSession()

  if (widened) {
    // Judged on the REAL identity, like minting: requireUserAccess above
    // carries the admin bypass, which must not extend to adding power.
    if (!session || session.userId !== id) {
      return NextResponse.json(
        {
          error:
            'Only the token owner, signed in as themselves, can add a permission or extend the ' +
            'expiry. You can still remove permissions, shorten the expiry or revoke it.',
        },
        { status: 403 }
      )
    }
    // The shared step-up: one attempt budget with the mint and every other
    // step-up route. This route keeps its own answers (401 + passwordRequired).
    const proof = await checkStepUp(request, body.password)
    if (proof.outcome === 'locked') {
      return NextResponse.json(
        { error: `Too many incorrect passwords. Try again in ${proof.retryAfterSeconds}s.` },
        { status: 429 }
      )
    }
    if (proof.outcome === 'missing') {
      return NextResponse.json(
        {
          error: 'Adding a permission or extending the expiry needs your password.',
          passwordRequired: true,
        },
        { status: 401 }
      )
    }
    if (proof.outcome === 'wrong') {
      return NextResponse.json(
        { error: 'Password is incorrect', passwordRequired: true },
        { status: 401 }
      )
    }
  }

  try {
    const updated = await prisma.mcpAccessToken.update({
      where: { id: tokenId },
      data,
      select: SELECT,
    })

    // A profile change is recorded as an update, not a rename: it does not
    // change what the token may do, but it restates what it is FOR, and an
    // incident reader needs the before/after of that alongside the scope diff.
    const renameOnly = !changesCapability && !('profile' in data)
    await writeAudit({
      actorId: session?.userId ?? null,
      action: renameOnly ? 'mcp-token.rename' : 'mcp-token.update',
      targetType: 'mcpAccessToken',
      targetId: tokenId,
      before: renameOnly
        ? { name: existing.name, tokenPrefix: existing.tokenPrefix }
        : {
            name: existing.name, tokenPrefix: existing.tokenPrefix,
            scopes: existing.scopes, profile: existing.profile,
            expiresAt: existing.expiresAt,
          },
      after: renameOnly
        ? { name: updated.name, tokenPrefix: existing.tokenPrefix }
        : {
            name: updated.name, tokenPrefix: existing.tokenPrefix,
            scopes: updated.scopes, profile: updated.profile,
            expiresAt: updated.expiresAt,
            widened, ownerId: id,
          },
      source: 'ui',
    })
    return NextResponse.json({ token: updated })
  } catch (error) {
    return internalError(error, 'Could not update the token', { log: '[mcp-tokens] update failed' })
  }
})

export const DELETE = withRouteErrors('Could not delete the token', async (request: NextRequest, { params }: RouteParams) => {
  const { id, tokenId } = await params
  // The read rule on purpose: an admin revokes another account's token during an
  // incident (HD-23's one exception). The audit row names the real admin.
  const denied = await requireUserAccess(request, id, { mode: 'read' })
  if (denied) return denied

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // A hard delete: the row goes, and with it the token's only capability record,
  // so an agent presenting it gets the same answer as one presenting a string
  // that was never minted. `resolveMcpToken` looks a token up by hash, so a
  // missing row denies it as surely as a revoked one.
  //
  // The audit row below is what survives. It is written in a separate table the
  // delete cannot reach, so "this prefix existed, and who removed it when"
  // outlives the credential itself - which is the part an incident review needs
  // and the part the row on screen was never the right home for.
  try {
    await prisma.mcpAccessToken.delete({ where: { id: tokenId } })
    const session = await getSession()
    await writeAudit({
      actorId: session?.userId ?? null,
      action: 'mcp-token.delete',
      targetType: 'mcpAccessToken',
      targetId: tokenId,
      before: {
        tokenPrefix: existing.tokenPrefix,
        name: existing.name,
        ownerId: id,
        scopes: existing.scopes,
        createdAt: existing.createdAt,
        lastUsedAt: existing.lastUsedAt,
        expiresAt: existing.expiresAt,
        revokedAt: existing.revokedAt,
      },
      source: 'ui',
    })
    return NextResponse.json({ deleted: true, token: existing })
  } catch (error) {
    return internalError(error, 'Could not delete the token', { log: '[mcp-tokens] delete failed' })
  }
})
