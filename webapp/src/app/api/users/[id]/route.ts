import { NextRequest, NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import { projectTargetLabel } from '@/lib/projectSummary'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { teardownProject } from '@/lib/projectTeardown'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { normalizeEmail, emailTakenByAnother } from '@/lib/authz/accountEmail'
import { requireStepUp } from '@/lib/authz/stepUp'
import { LAST_ADMIN_REFUSAL, withLastAdminGuard } from '@/lib/authz/adminSet'
import { userAuditEntry, writeUserAudit, type UserAuditFields } from '@/lib/userAudit'
import { writeAuditTx } from '@/lib/audit'
import { invalidatePrincipal } from '@/lib/authz/principal'
import { rootProtectedAnswer, rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { rbacFlags } from '@/lib/authz/flags'
import { lockedInstanceRoot } from '@/lib/authz/root'
import { requireRootPower, rootOnlyRefusal } from '@/lib/authz/rootPowers'
import { emailChangedNotice, withNotice } from '@/lib/authz/accountNotices'
import { now } from '@/lib/authz/clock'
import type { RootGuardRefusal } from '@/lib/authz/adminSet'
import type { Session } from '@/lib/session'

interface RouteParams {
  params: Promise<{ id: string }>
}

const EMAIL_TAKEN = { error: 'A user with this email already exists', code: 'email_taken' } as const
const ACCOUNT_CHANGED = {
  error: 'The account changed while this request ran. Reload it and try again.',
  code: 'account_changed',
} as const

/** Thrown inside the write's transaction when the address moved since it was read: all rolls back. */
class AccountChanged extends Error {
  constructor() {
    super('account changed')
    this.name = 'AccountChanged'
  }
}

const USER_SELECT = {
  id: true,
  name: true,
  email: true,
  role: true,
  defaultAgentModel: true,
  defaultAiPipelineModel: true,
  createdAt: true,
  updatedAt: true,
} as const

type AuditedFields = { name?: string | null; email?: string | null; role?: string | null }

/**
 * `user.update` (name, email) and `user.role_changed`, each only for the fields this
 * request wrote that really changed. The remembered model defaults are preferences
 * the project form saves often, not account administration: no row. A role change that
 * raised the session version (identity switch on) records the new version. With
 * `emailRow` (identity switch on, step 2.11) a changed email has its own
 * `user.email_changed` row instead of a field of `user.update`.
 */
function userEditRows(
  id: string,
  written: Record<string, string>,
  before: AuditedFields | null,
  after: AuditedFields & { sessionVersion?: number },
  { emailRow = false }: { emailRow?: boolean } = {},
): UserAuditFields[] {
  const changed = (k: keyof AuditedFields) => k in written && (before?.[k] ?? null) !== (after[k] ?? null)
  const fields = (emailRow ? ['name'] as const : ['name', 'email'] as const).filter(changed)
  const rows: UserAuditFields[] = []
  if (fields.length > 0) {
    rows.push({
      action: 'user.update',
      targetId: id,
      before: Object.fromEntries(fields.map(k => [k, before?.[k] ?? null])),
      after: Object.fromEntries(fields.map(k => [k, after[k] ?? null])),
    })
  }
  if (emailRow && changed('email')) {
    rows.push({ action: 'user.email_changed', targetId: id, before: { email: before?.email ?? null }, after: { email: after.email ?? null } })
  }
  if (changed('role')) {
    rows.push({
      action: 'user.role_changed',
      targetId: id,
      before: { role: before?.role ?? null },
      after: { role: after.role ?? null, ...(after.sessionVersion !== undefined ? { sessionVersion: after.sessionVersion } : {}) },
    })
  }
  return rows
}

async function auditUserEdit(
  request: NextRequest,
  session: Session,
  id: string,
  written: Record<string, string>,
  before: AuditedFields | null,
  after: AuditedFields,
): Promise<void> {
  for (const row of userEditRows(id, written, before, after)) await writeUserAudit(request, session, row)
}

/**
 * Identity switch on: the guard's transaction also takes the Root lock and reads the Root
 * again, so a Root chosen or moved since this request's check is never demoted or deleted;
 * `needsRoot` when the action is Root's power (step 2.6), which is checked again there too.
 */
function rootRecheck(session: { userId: string }, needsRoot = false) {
  return rbacFlags().identity ? { root: { actorId: session.userId, needsRoot } } : {}
}

const ROOT_ONLY_EDIT = 'Only Root can make an admin, or change, demote or delete another admin account.'

/** The answer to a write the Root re-check refused inside its transaction. */
async function rootGuardAnswer(
  request: NextRequest, session: Session, id: string, refused: RootGuardRefusal, attempted: 'role_change' | 'edit' | 'delete',
): Promise<NextResponse> {
  if (refused === 'root_only') return rootOnlyRefusal('none', ROOT_ONLY_EDIT)
  return rootProtectedAnswer(request, session, id, attempted)
}

/** What the browser gets: never the session version. */
function publicUser<T extends { sessionVersion?: number }>(user: T): Omit<T, 'sessionVersion'> {
  const { sessionVersion: _sessionVersion, ...rest } = user
  return rest
}

/**
 * PUT with the identity switch on (step 2.6, ID-03, PE-08, T5). Promoting a member, and any
 * change to another admin's account, is the confirmed Root's power with its password; an admin
 * acts on members and on its own account (its own demotion included, under the last-admin
 * rule). A role change raises the account's session version in the same transaction as the role
 * and its audit rows (written fail closed), so the role a cookie was signed for never outlives
 * it; the transaction holds the Root lock and checks Root again.
 *
 * The sign-in email (step 2.11, ID-30, ID-25): changing one's own takes the current password,
 * an admin changing a member's takes the admin's own (another admin's is Root's, above). Only
 * then is the address checked against the other accounts, so a cookie without the password
 * learns nothing about which addresses exist. The change, its `user.email_changed` row and a
 * notice to the account commit together.
 */
async function updateWithIdentity(
  request: NextRequest, session: Session, id: string, data: Record<string, string>,
  { stepUpPassword, currentPassword }: { stepUpPassword: unknown; currentPassword: unknown },
): Promise<NextResponse> {
  const target = await prisma.user.findUnique({ where: { id }, select: { role: true, email: true } })
  if (!target) return NextResponse.json({ error: 'User not found' }, { status: 404 })
  const self = id === session.userId
  const roleChange = 'role' in data && data.role !== target.role
  const emailChange = 'email' in data && data.email !== target.email
  const otherAdmin = !self && target.role === 'admin'
  const needsRoot = otherAdmin || (roleChange && data.role === 'admin')
  if (needsRoot) {
    const refusal = await requireRootPower(request, session, stepUpPassword, ROOT_ONLY_EDIT)
    if (refusal) return refusal
  } else if (emailChange) {
    const refusal = await requireStepUp(request, self ? currentPassword : stepUpPassword)
    if (refusal) return refusal
  }
  if (emailChange && await emailTakenByAnother(data.email, id)) {
    return NextResponse.json(EMAIL_TAKEN, { status: 409 })
  }
  const select = { ...USER_SELECT, sessionVersion: true } as const
  const attempted = roleChange ? 'role_change' : 'edit'

  if (!roleChange && !needsRoot && !emailChange) {
    const before = ('name' in data || 'email' in data)
      ? await prisma.user.findUnique({ where: { id }, select: { name: true, email: true, role: true } })
      : null
    const user = await prisma.user.update({ where: { id }, data, select: USER_SELECT })
    invalidatePrincipal(id)
    await auditUserEdit(request, session, id, data, before, user)
    return NextResponse.json(user)
  }

  const writeEdit = async (tx: Prisma.TransactionClient, before: AuditedFields | null) => {
    const bump = 'role' in data && data.role !== before?.role
    const fields = (bump ? { ...data, sessionVersion: { increment: 1 } } : { ...data }) as Prisma.UserUpdateInput
    let user
    if (emailChange) {
      // Conditional on the address read here: another change in between refuses this one.
      const held = await tx.user.findUnique({ where: { id }, select: { email: true, pendingNotices: true } })
      if (!held) throw new AccountChanged()
      const actor = await tx.user.findUnique({ where: { id: session.userId }, select: { name: true, email: true } })
      const by = { id: session.userId, name: actor?.name ?? '', email: actor?.email ?? '' }
      const notice = emailChangedNotice({ by, at: now(), from: held.email, to: data.email, self })
      fields.pendingNotices = withNotice(held.pendingNotices, notice) as unknown as Prisma.InputJsonValue
      const moved = await tx.user.updateMany({ where: { id, email: held.email }, data: fields as Prisma.UserUpdateManyMutationInput })
      if (moved.count !== 1) throw new AccountChanged()
      user = await tx.user.findUnique({ where: { id }, select })
      if (!user) throw new AccountChanged()
    } else {
      user = await tx.user.update({ where: { id }, data: fields, select })
    }
    for (const row of userEditRows(id, data, before, bump ? user : publicUser(user), { emailRow: true })) {
      await writeAuditTx(tx, await userAuditEntry(request, session, row))
    }
    return user
  }

  try {
    if (roleChange && data.role === 'standard') {
      const result = await withLastAdminGuard(id, (tx, before) => writeEdit(tx, before), rootRecheck(session, needsRoot))
      if (!result.ok) {
        if (result.refused) return rootGuardAnswer(request, session, id, result.refused, attempted)
        return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
      }
      invalidatePrincipal(id)
      return NextResponse.json(publicUser(result.value))
    }

    type Outcome = { refused: RootGuardRefusal } | { missing: true } | { user: Awaited<ReturnType<typeof writeEdit>> }
    const result = await prisma.$transaction(async (tx): Promise<Outcome> => {
      const root = await lockedInstanceRoot(tx)
      if (root && root.userId === id && id !== session.userId) return { refused: 'root_protected' }
      if (needsRoot && !(root && root.userId === session.userId && root.confirmed)) return { refused: 'root_only' }
      const before = await tx.user.findUnique({ where: { id }, select: { name: true, email: true, role: true } })
      if (!before) return { missing: true }
      return { user: await writeEdit(tx, before) }
    })
    if ('refused' in result) return rootGuardAnswer(request, session, id, result.refused, attempted)
    if ('missing' in result) return NextResponse.json({ error: 'User not found' }, { status: 404 })
    invalidatePrincipal(id)
    return NextResponse.json(publicUser(result.user))
  } catch (err) {
    if (err instanceof AccountChanged) return NextResponse.json(ACCOUNT_CHANGED, { status: 409 })
    throw err
  }
}

/** Another admin's account changes hands only with the acting admin's own password. */
async function isAnotherAdmin(sessionUserId: string, targetId: string): Promise<boolean> {
  if (sessionUserId === targetId) return false
  const target = await prisma.user.findUnique({ where: { id: targetId }, select: { role: true } })
  return target?.role === 'admin'
}

// GET /api/users/[id] - Get user by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Check permissions: admin or internal can view any user, standard can only view self
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      if (session.role !== 'admin' && session.userId !== id) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        defaultAgentModel: true,
        defaultAiPipelineModel: true,
        createdAt: true,
        updatedAt: true,
        projects: {
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            name: true,
            targetDomain: true,
            ipMode: true,
            targetIps: true,
            subdomainList: true,
            domainBatchMode: true,
            domainBatchHosts: true,
            createdAt: true,
            updatedAt: true
          }
        }
      }
    })

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // A batch has no targetDomain: each project row carries its scope label.
    return NextResponse.json({
      ...user,
      projects: user.projects.map(({ ipMode, targetIps, subdomainList, domainBatchMode, domainBatchHosts, ...p }) => ({
        ...p,
        targetLabel: projectTargetLabel({ ...p, ipMode, targetIps, subdomainList, domainBatchMode, domainBatchHosts }),
      })),
    })
  } catch (error) {
    return internalError(error, 'Failed to fetch user')
  }
}

// PUT /api/users/[id] - Update user
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Check permissions. S2/E2: internal-key no longer bypasses -- updating a
    // user (esp. role escalation) requires a real session.
    const session = await getSession({ fresh: true })
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Same-origin JSON whatever the identity switch (ID-26, step 2.12).
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const body = parsed.body as {
      name?: string; email?: unknown; role?: unknown; defaultAgentModel?: unknown
      defaultAiPipelineModel?: unknown; stepUpPassword?: unknown; currentPassword?: unknown
    }
    const { name, email, role, defaultAgentModel, defaultAiPipelineModel, stepUpPassword } = body

    // Standard users can only update their own name/email
    if (session.role !== 'admin' && session.userId !== id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Only admin can change roles
    if (role && session.role !== 'admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Identity switch on: nobody else edits Root, and Root keeps the admin role.
    const demotion = role === 'standard'
    const rootRefusal = await rootProtectedRefusal(request, session, id, demotion ? 'role_change' : 'edit', { self: demotion })
    if (rootRefusal) return rootRefusal

    const data: Record<string, string> = {}
    if (name) data.name = name
    if (typeof email === 'string' && email) data.email = normalizeEmail(email)
    if (role === 'admin' || role === 'standard') data.role = role
    // Remembered model choices, used to pre-fill the next new project.
    if (isLoopModel(defaultAgentModel) || isLoopModel(defaultAiPipelineModel)) {
      return NextResponse.json(
        { error: 'Agent in the Loop cannot be a default model; pick it per project.', code: 'loop_model_not_allowed' },
        { status: 400 },
      )
    }
    if (typeof defaultAgentModel === 'string') data.defaultAgentModel = defaultAgentModel
    if (typeof defaultAiPipelineModel === 'string') data.defaultAiPipelineModel = defaultAiPipelineModel

    // With the identity switch on the address is checked after the password it takes (step 2.11).
    if (rbacFlags().identity) {
      return await updateWithIdentity(request, session, id, data, { stepUpPassword, currentPassword: body?.currentPassword })
    }

    // Another account may hold the address in other capitals (stored before
    // emails were lowercased), which the unique index cannot see.
    if (data.email && await emailTakenByAnother(data.email, id)) {
      return NextResponse.json(EMAIL_TAKEN, { status: 409 })
    }

    if (data.role !== 'standard') {
      const before = ('name' in data || 'email' in data || 'role' in data)
        ? await prisma.user.findUnique({ where: { id }, select: { name: true, email: true, role: true } })
        : null
      const user = await prisma.user.update({ where: { id }, data, select: USER_SELECT })
      invalidatePrincipal(id)
      await auditUserEdit(request, session, id, data, before, user)
      return NextResponse.json(user)
    }

    // A demotion, the actor's own included: never of the last admin with a password.
    if (await isAnotherAdmin(session.userId, id)) {
      const refusal = await requireStepUp(request, stepUpPassword)
      if (refusal) return refusal
    }
    const result = await withLastAdminGuard(id, async (tx, before) => ({
      before,
      user: await tx.user.update({ where: { id }, data, select: USER_SELECT }),
    }), rootRecheck(session))
    if (!result.ok) {
      if (result.refused) return rootGuardAnswer(request, session, id, result.refused, 'role_change')
      return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
    }
    invalidatePrincipal(id)
    await auditUserEdit(request, session, id, data, result.value.before, result.value.user)
    return NextResponse.json(result.value.user)
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') {
      return NextResponse.json(EMAIL_TAKEN, { status: 409 })
    }

    return internalError(error, 'Failed to update user')
  }
}

// DELETE /api/users/[id] - Delete user (admin only)
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // S2/E2: deleting a user requires an admin session; no internal bypass.
    const session = await getSession({ fresh: true })
    if (!session || session.role !== 'admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }
    // Whatever the identity switch (ID-26, step 2.12). No JSON check: a member's DELETE has no
    // body, and a browser form cannot send a DELETE.
    if (!sameOrigin(request)) return crossOriginResponse(request)

    // Prevent self-deletion
    if (session.userId === id) {
      return NextResponse.json(
        { error: 'Cannot delete your own account' },
        { status: 400 }
      )
    }

    // Self-deletion is refused above, so an admin target is another admin.
    const target = await prisma.user.findUnique({ where: { id }, select: { email: true, role: true } })
    // Before the step-up and the teardown: a refused deletion tears nothing down.
    const rootRefusal = await rootProtectedRefusal(request, session, id, 'delete')
    if (rootRefusal) return rootRefusal
    const targetIsAdmin = target?.role === 'admin'
    // Identity switch on: deleting an admin is the confirmed Root's power (step 2.6).
    const rootPower = targetIsAdmin && rbacFlags().identity
    if (targetIsAdmin) {
      const body = await request.json().catch(() => null)
      const refusal = rootPower
        ? await requireRootPower(request, session, body?.stepUpPassword, 'Only Root can delete an admin account.')
        : await requireStepUp(request, body?.stepUpPassword)
      if (refusal) return refusal
    }

    // The teardown below cannot be undone, so a deletion the last-admin rule
    // refuses is refused before it; the delete itself checks again under the lock.
    if (targetIsAdmin) {
      const allowed = await withLastAdminGuard(id, async () => undefined, rootRecheck(session, rootPower))
      if (!allowed.ok) {
        if (allowed.refused) return rootGuardAnswer(request, session, id, allowed.refused, 'delete')
        return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
      }
    }

    // Each project goes through the project-delete teardown first (HD-11): the
    // cascade alone leaves its graph, files, workspace and running work behind, and
    // a project holding an authorization record refuses it (the key is Restrict).
    const projects = await prisma.project.findMany({
      where: { userId: id }, select: { id: true, userId: true }, orderBy: { createdAt: 'asc' },
    })
    const auditBefore = { email: target?.email ?? null, role: target?.role ?? null, ownedProjectCount: projects.length }
    const projectsDeleted: string[] = []
    for (const project of projects) {
      const result = await teardownProject(project, { actorUserId: session.userId, archiveReason: 'user_deleted' })
      if (result.ok) {
        projectsDeleted.push(project.id)
        continue
      }
      // Its owner deleted it meanwhile, through the project route's own teardown.
      if (result.code === 'project_not_found') continue
      console.error(`[rbac] user-delete teardown failed project=${project.id} step=${result.failedStep}`)
      // Not `user.delete`: the account still exists.
      await writeUserAudit(request, session, {
        action: 'user.delete_failed',
        targetId: id,
        before: auditBefore,
        after: { projectsDeleted, failedProjectId: project.id, failedStep: result.failedStep, code: result.code },
      })
      if (result.failedStep === 'archive_authorizations') {
        return NextResponse.json(
          {
            error:
              'Could not archive the engagement authorization records of one of this user\'s ' +
              'projects, so the user was not deleted. The record of what authorized an ' +
              'engagement must outlive the engagement. Retry, or contact an administrator.',
            code: 'authorization_archive_failed',
            projectId: project.id,
          },
          { status: 500 }
        )
      }
      throw result.error
    }

    // The account's own Nuclei templates go to the admin deleting it (DV-33, OQ-50): no
    // member gains them and no file is lost. In the delete's transaction, so a deletion
    // that fails leaves them with their owner.
    const deleteAccount = async (tx: Prisma.TransactionClient) => {
      const { count } = await tx.nucleiTemplate.updateMany({
        where: { ownerUserId: id }, data: { ownerUserId: session.userId },
      })
      await tx.user.delete({ where: { id } })
      return count
    }
    let templatesReassigned: number
    if (targetIsAdmin) {
      // The deleter is an admin, but a concurrent demotion of the deleter could
      // leave nobody: the same locked check as a demotion.
      const result = await withLastAdminGuard(id, deleteAccount, rootRecheck(session, rootPower))
      if (!result.ok) {
        if (result.refused) return rootGuardAnswer(request, session, id, result.refused, 'delete')
        return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
      }
      templatesReassigned = result.value
    } else {
      templatesReassigned = await prisma.$transaction(deleteAccount)
    }
    invalidatePrincipal(id)

    await writeUserAudit(request, session, {
      action: 'user.delete',
      targetId: id,
      before: auditBefore,
      after: { projectsDeleted, templatesReassigned },
    })

    return NextResponse.json({ success: true })
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    return internalError(error, 'Failed to delete user')
  }
}
