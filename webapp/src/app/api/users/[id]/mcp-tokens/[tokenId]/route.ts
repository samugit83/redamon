/**
 * MCP personal access tokens: edit and delete.
 *
 * PATCH changes a token's name, profile, scopes and expiry. The hash and the
 * owner are never mutable, and a revoked token keeps its capability frozen (only
 * its labels can change): restoring access means minting a new token.
 *
 * The rule an edit is judged by is DIRECTION, not field:
 *  - a change that NARROWS the token's capability (drop a scope, earlier expiry,
 *    "expire now") is open on another account to whoever holds users:revoke_sessions
 *    (every admin with the permissions switch off), exactly like DELETE below: taking
 *    power away is a safe privilege during an incident, and both are audited with the
 *    real admin as the actor (HD-23's one exception), except on Root's tokens
 *    (identity switch on: `root_protected`, as DELETE). A profile
 *    switch riding along is allowed with it: the profile is a label, never an
 *    authorization input, and switching it in the UI re-ticks the scopes.
 *  - a rename or a profile change on its own is the account's write rule
 *    (requireAccountWrite): needs no step-up, but an admin cannot do it to
 *    another account.
 *  - a change that WIDENS it (add a scope, later or no expiry, reviving an
 *    expired token) gets the mint's step-up: self-only on the REAL identity,
 *    password re-confirmed, same limiter. Otherwise a stolen session cookie
 *    could upgrade an existing token into the credential it cannot mint. A scope
 *    it adds must be one the owner may grant, as at mint (permissions switch on).
 *
 * With RBAC_SHARING_ENABLED on, the opt-in to shared projects and its allowlist
 * are capability too (step 4.10): opting in, emptying the allowlist or naming a
 * new project widens; opting out or naming fewer narrows. With the switch off
 * neither is read from a body or shown, as before (DV-30).
 *
 * Scopes and expiry are re-read on every MCP call, so an edit takes effect on
 * the agent's next call.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, requireUserAccess } from '@/lib/session'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { checkStepUp } from '@/lib/authz/stepUp'
import { writeAudit } from '@/lib/audit'
import {
  isTokenWidening,
  resolveExpiryChange,
  sanitizeTokenName,
  validateScopes,
  validateSharedReach,
  type McpScope,
} from '@/lib/mcpAuth'
import { rbacFlags } from '@/lib/authz/flags'
import { validateProfile, type ProfileId } from '@/lib/mcp/profiles'
import { internalError, withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rootTokensRefusal } from '@/lib/authz/rootProtection'
import { ownsRow } from '@/lib/authz/rowOwner'
import { scopeGrantRefusal } from '@/lib/mcp/scopePermissions'

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

const SHARED_REACH_SELECT = { includeSharedProjects: true, projectAllowlist: true } as const

/** The token row as the screen reads it; the shared-project opt-in only with the sharing switch on. */
function tokenSelect(): typeof SELECT & Partial<typeof SHARED_REACH_SELECT> {
  return rbacFlags().sharing ? { ...SELECT, ...SHARED_REACH_SELECT } : SELECT
}

/** Load the token, 404ing unless it belongs to the user in the path. */
async function loadOwned(userId: string, tokenId: string) {
  const token = await prisma.mcpAccessToken.findUnique({
    where: { id: tokenId },
    select: { ...tokenSelect(), userId: true },
  })
  if (!token || !ownsRow({ userId }, token.userId)) return null
  return token
}

const sameScopes = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every(s => b.includes(s))

const sameExpiry = (a: Date | null, b: Date | null) =>
  (a === null && b === null) || (a !== null && b !== null && a.getTime() === b.getTime())

const sameIds = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every(s => b.includes(s))

export const PATCH = withRouteErrors('Could not update the token', async (request: NextRequest, { params }: RouteParams) => {
  const { id, tokenId } = await params
  // The revoke rule lets a revoker reach another account's token to narrow it; every
  // other edit is checked against the write rule below, once its direction is known.
  const denied = await requireUserAccess(request, id, { mode: 'revoke' }) ?? await rootTokensRefusal(request, id, 'edit_mcp_token')
  if (denied) return denied

  // Same-origin JSON whatever the identity switch (ID-26, step 2.12).
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const body = parsed.body

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const data: {
    name?: string
    scopes?: McpScope[]
    profile?: ProfileId | null
    expiresAt?: Date | null
    includeSharedProjects?: boolean
    projectAllowlist?: string[]
  } = {}
  const sharing = rbacFlags().sharing
  const touchesReach = sharing && ('includeSharedProjects' in body || 'projectAllowlist' in body)

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

  if (touchesReach) {
    // A field left out keeps its stored value, so an edit can change one of the two alone.
    const reach = validateSharedReach(
      'includeSharedProjects' in body ? body.includeSharedProjects : existing.includeSharedProjects,
      'projectAllowlist' in body ? body.projectAllowlist : existing.projectAllowlist,
    )
    if ('error' in reach) return NextResponse.json({ error: reach.error }, { status: 400 })
    if (reach.includeSharedProjects !== (existing.includeSharedProjects === true)) data.includeSharedProjects = reach.includeSharedProjects
    if (!sameIds(reach.projectAllowlist, existing.projectAllowlist ?? [])) data.projectAllowlist = reach.projectAllowlist
  }

  if (!('name' in body) && !('scopes' in body) && !('expiry' in body) && !('profile' in body) && !touchesReach) {
    return NextResponse.json({ error: 'Nothing to change' }, { status: 400 })
  }
  if (Object.keys(data).length === 0) {
    const token = Object.fromEntries(
      Object.keys(tokenSelect()).map(k => [k, existing[k as keyof typeof existing]])
    )
    return NextResponse.json({ token })
  }

  // A profile is deliberately NOT capability-changing: it grants nothing, so it
  // needs no password and is allowed on a revoked token, exactly like a rename.
  const changesReach = 'includeSharedProjects' in data || 'projectAllowlist' in data
  const changesCapability = 'scopes' in data || 'expiresAt' in data || changesReach
  if (changesCapability && existing.revokedAt) {
    return NextResponse.json(
      { error: 'A revoked token can only be renamed. Create a new token to restore access.' },
      { status: 409 }
    )
  }

  const after = {
    scopes: data.scopes ?? existing.scopes,
    expiresAt: 'expiresAt' in data ? data.expiresAt ?? null : existing.expiresAt,
    includeSharedProjects: data.includeSharedProjects ?? existing.includeSharedProjects,
    projectAllowlist: data.projectAllowlist ?? existing.projectAllowlist,
  }
  const widened = changesCapability && isTokenWidening(existing, after)
  const narrowsOnly = changesCapability && !widened && !('name' in data)
  if (!narrowsOnly && !widened) {
    const writeDenied = await requireUserAccess(request, id, { mode: 'write' })
    if (writeDenied) return writeDenied
  }
  const session = await getSession()

  if (widened) {
    // Judged on the REAL identity, like minting: the revoke rule above lets a
    // revoker in on another account, which must not extend to adding power.
    if (!session || session.userId !== id) {
      return NextResponse.json(
        {
          error:
            'Only the token owner, signed in as themselves, can add a permission, extend the ' +
            'expiry or open it to more shared projects. You can still remove permissions, shorten ' +
            'the expiry or revoke it.',
        },
        { status: 403 }
      )
    }
    // Adding power is the mint's permission (self:mcp_tokens, fresh); taking it away never asks it.
    const refused = await requireSelfPermission(request, id, 'self:mcp_tokens', { fresh: true })
    if (refused) return refused
    // Only the scopes it adds: one already on the token stays capped on every call.
    const ungrantable = await scopeGrantRefusal(id, (data.scopes ?? []).filter(s => !existing.scopes.includes(s)))
    if (ungrantable) return NextResponse.json(ungrantable, { status: 403 })
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
          error: changesReach && !('scopes' in data) && !('expiresAt' in data)
            ? 'Opening a token to projects shared with you needs your password.'
            : 'Adding a permission or extending the expiry needs your password.',
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
      select: tokenSelect(),
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
            ...(changesReach ? { includeSharedProjects: existing.includeSharedProjects, projectAllowlist: existing.projectAllowlist } : {}),
          },
      after: renameOnly
        ? { name: updated.name, tokenPrefix: existing.tokenPrefix }
        : {
            name: updated.name, tokenPrefix: existing.tokenPrefix,
            scopes: updated.scopes, profile: updated.profile,
            expiresAt: updated.expiresAt,
            ...(changesReach ? { includeSharedProjects: after.includeSharedProjects, projectAllowlist: after.projectAllowlist } : {}),
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
  // A revoker deletes another account's token during an incident (HD-23's one exception),
  // never Root's. The audit row names the real admin.
  const denied = await requireUserAccess(request, id, { mode: 'revoke' }) ?? await rootTokensRefusal(request, id, 'delete_mcp_token')
  if (denied) return denied
  // No body to check: a browser form cannot send a DELETE.
  if (!sameOrigin(request)) return crossOriginResponse(request)

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
