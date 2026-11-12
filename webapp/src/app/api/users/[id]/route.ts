import { NextRequest, NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import { projectTargetLabel } from '@/lib/projectSummary'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { teardownProject } from '@/lib/projectTeardown'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { normalizeEmail, emailTakenByAnother } from '@/lib/authz/accountEmail'
import { requireStepUp } from '@/lib/authz/stepUp'
import { LAST_ADMIN_REFUSAL, withLastAdminGuard } from '@/lib/authz/adminSet'
import { writeUserAudit } from '@/lib/userAudit'
import { invalidatePrincipal } from '@/lib/authz/principal'

interface RouteParams {
  params: Promise<{ id: string }>
}

const EMAIL_TAKEN = { error: 'A user with this email already exists', code: 'email_taken' } as const

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
 * the project form saves often, not account administration: no row.
 */
async function auditUserEdit(
  request: NextRequest,
  session: { userId: string; role: string },
  id: string,
  written: Record<string, string>,
  before: AuditedFields | null,
  after: AuditedFields,
): Promise<void> {
  const changed = (k: keyof AuditedFields) => k in written && (before?.[k] ?? null) !== (after[k] ?? null)
  const fields = (['name', 'email'] as const).filter(changed)
  if (fields.length > 0) {
    await writeUserAudit(request, session, {
      action: 'user.update',
      targetId: id,
      before: Object.fromEntries(fields.map(k => [k, before?.[k] ?? null])),
      after: Object.fromEntries(fields.map(k => [k, after[k] ?? null])),
    })
  }
  if (changed('role')) {
    await writeUserAudit(request, session, {
      action: 'user.role_changed',
      targetId: id,
      before: { role: before?.role ?? null },
      after: { role: after.role ?? null },
    })
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
    const body = await request.json()
    const { name, email, role, defaultAgentModel, defaultAiPipelineModel, stepUpPassword } = body

    // Check permissions. S2/E2: internal-key no longer bypasses -- updating a
    // user (esp. role escalation) requires a real session.
    const session = await getSession({ fresh: true })
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Standard users can only update their own name/email
    if (session.role !== 'admin' && session.userId !== id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Only admin can change roles
    if (role && session.role !== 'admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

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
    }))
    if (!result.ok) return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
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

    // Prevent self-deletion
    if (session.userId === id) {
      return NextResponse.json(
        { error: 'Cannot delete your own account' },
        { status: 400 }
      )
    }

    // Self-deletion is refused above, so an admin target is another admin.
    const target = await prisma.user.findUnique({ where: { id }, select: { email: true, role: true } })
    const targetIsAdmin = target?.role === 'admin'
    if (targetIsAdmin) {
      const body = await request.json().catch(() => null)
      const refusal = await requireStepUp(request, body?.stepUpPassword)
      if (refusal) return refusal
    }

    // The teardown below cannot be undone, so a deletion the last-admin rule
    // refuses is refused before it; the delete itself checks again under the lock.
    if (targetIsAdmin) {
      const allowed = await withLastAdminGuard(id, async () => undefined)
      if (!allowed.ok) return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
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
      const result = await withLastAdminGuard(id, deleteAccount)
      if (!result.ok) return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
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
