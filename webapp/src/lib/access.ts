import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getEffectiveUser, EffectiveUser } from './session'
import { projectAccess } from './authz/projectAccess'
import { ownsRow, rowOwnerFilter } from './authz/rowOwner'

/**
 * Per-user authorization guards (BOLA remediation).
 *
 * Every data route must scope reads/writes to the caller's EFFECTIVE user
 * (see getEffectiveUser): a standard user to their own id, an admin to their own
 * id unless they are simulating another user. These helpers turn "which user is
 * this?" (identity) into "may this user touch this resource?" (authorization).
 *
 * Ownership is always enforced: ACCESS_ENFORCE, which once allowed a log-only rollout,
 * is ignored with one warning per process (PE-24).
 *
 * Anti-enumeration: a cross-user resource is reported as 404 (not 403) so the
 * distinction "exists but not yours" vs "does not exist" cannot be used to
 * enumerate other users' project/conversation ids (repo convention).
 *
 * Secret-exposure routes (A2) use requireUserAccess, which answers 403 instead.
 *
 * The helpers keep their signatures and answers, and ask the policy (T1): a project through
 * `projectAccess()`, a per-user row (a preset, a conversation) through `ownsRow()`.
 */

let ignoredWarned = false

/**
 * Always true. ACCESS_ENFORCE once turned ownership into a log-only check; it is read only to
 * tell an operator who still sets it that it is ignored.
 */
export function accessEnforced(): boolean {
  if (!ignoredWarned && (process.env.ACCESS_ENFORCE ?? '').trim() !== '') {
    ignoredWarned = true
    console.warn('[rbac] access_enforce_ignored: ACCESS_ENFORCE is set but ignored; ownership is always enforced')
  }
  return true
}

/** Tests only. */
export function resetAccessEnforceWarningForTests(): void {
  ignoredWarned = false
}

/** The answer to a resource of another user: 404, as for one that does not exist (anti-enumeration). */
function ownershipDenied(): NextResponse {
  accessEnforced()
  return NextResponse.json({ error: 'Not found' }, { status: 404 })
}

/** Resolve the effective user, or a 401 NextResponse the caller must return. */
export async function requireEffectiveUser(): Promise<EffectiveUser | NextResponse> {
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return eff
}

/** Owner check answering 403 (not the anti-enumeration 404) unless eff owns ownerId. */
export function assertOwnerStrict(eff: EffectiveUser, ownerId: string): NextResponse | null {
  if (ownsRow(eff, ownerId)) return null
  return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
}

/** Owner check for a per-user row: null when eff owns it, else 404. */
export function assertOwner(eff: EffectiveUser, ownerId: string): NextResponse | null {
  if (ownsRow(eff, ownerId)) return null
  return ownershipDenied()
}

/** Prisma where-fragment scoping a list query to the effective user. */
export function ownerScope(eff: EffectiveUser): { userId: string } {
  return rowOwnerFilter(eff)
}

/**
 * One-call guard for project-scoped routes: resolve the effective user and verify
 * they own `projectId`. Returns a 401/404 NextResponse to return, or null when
 * access is allowed. Convenience wrapper over requireEffectiveUser +
 * requireProjectAccess for the many scan/analytics `[projectId]` routes.
 */
export async function guardProject(projectId: string): Promise<NextResponse | null> {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return access
  return null
}

/**
 * Verify the effective user may reach a Project (`projectAccess()`: today its owner): 404 when
 * the project does not exist or is another user's. On success returns the project's id + owner.
 */
export async function requireProjectAccess(
  eff: EffectiveUser,
  projectId: string
): Promise<{ project: { id: string; userId: string } } | NextResponse> {
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }
  const access = await projectAccess(eff, projectId)
  if (!access) return ownershipDenied()
  return { project: { id: access.project.id, userId: access.project.userId } }
}

/**
 * Guard a resource that is owned via its parent Project (Report, Remediation,
 * GraphView, ...). `loadProjectId` returns the resource's projectId (or null when
 * the resource does not exist). Verifies the effective user owns that project.
 */
export async function requireProjectScopedResource(
  eff: EffectiveUser,
  loadProjectId: () => Promise<string | null | undefined>,
): Promise<{ ok: true } | NextResponse> {
  const projectId = await loadProjectId()
  if (!projectId) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return access
  return { ok: true }
}

/** Load a Conversation (which carries a direct userId) and verify ownership: 404 when absent or another user's. */
export async function requireConversationAccess(
  eff: EffectiveUser,
  conversationId: string
): Promise<{ conversation: { id: string; userId: string; projectId: string } } | NextResponse> {
  const conversation = await prisma.conversation.findUnique({
    where: { id: conversationId },
    select: { id: true, userId: true, projectId: true },
  })
  if (!conversation) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  if (!ownsRow(eff, conversation.userId)) return ownershipDenied()
  return { conversation }
}

/**
 * Load a Conversation by its (unique) sessionId and verify ownership: 404 when absent or
 * another user's. Used by the by-session/* routes.
 */
export async function requireConversationAccessBySession(
  eff: EffectiveUser,
  sessionId: string
): Promise<{ conversation: { id: string; userId: string; projectId: string } } | NextResponse> {
  const conversation = await prisma.conversation.findUnique({
    where: { sessionId },
    select: { id: true, userId: true, projectId: true },
  })
  if (!conversation) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  if (!ownsRow(eff, conversation.userId)) return ownershipDenied()
  return { conversation }
}
