import { NextRequest, NextResponse } from 'next/server'
import { projectTargetLabel } from '@/lib/projectSummary'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { purgeProjectWorkspace } from '@/lib/workspacePurge'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { normalizeEmail, emailTakenByAnother } from '@/lib/authz/accountEmail'
import { requireStepUp } from '@/lib/authz/stepUp'
import { LAST_ADMIN_REFUSAL, withLastAdminGuard } from '@/lib/authz/adminSet'

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
    const session = await getSession()
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
      const user = await prisma.user.update({ where: { id }, data, select: USER_SELECT })
      return NextResponse.json(user)
    }

    // A demotion, the actor's own included: never of the last admin with a password.
    if (await isAnotherAdmin(session.userId, id)) {
      const refusal = await requireStepUp(request, stepUpPassword)
      if (refusal) return refusal
    }
    const result = await withLastAdminGuard(id, tx => tx.user.update({ where: { id }, data, select: USER_SELECT }))
    if (!result.ok) return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
    return NextResponse.json(result.value)
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
    const session = await getSession()
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

    const targetIsAdmin = await isAnotherAdmin(session.userId, id)
    if (targetIsAdmin) {
      const body = await request.json().catch(() => null)
      const refusal = await requireStepUp(request, body?.stepUpPassword)
      if (refusal) return refusal
    }

    // Collect this user's captured-traffic body refs BEFORE the cascade removes
    // the rows (user -> projects -> captured rows), so we can GC the now-orphaned
    // blobs afterward (§6.6). Prisma cascade never touches the filesystem.
    let capturedBodyRefs: (string | null)[] = []
    try {
      const doomed = await prisma.capturedHttpTransaction.findMany({
        where: { userId: id }, select: { reqBodyRef: true, respBodyRef: true },
      })
      capturedBodyRefs = doomed.flatMap(r => [r.reqBodyRef, r.respBodyRef])
    } catch (e) {
      console.warn('Could not enumerate captured body refs before user delete:', e)
    }

    // The cascade deletes the user's projects; their workspaces are on disk.
    let projectIds: string[] = []
    try {
      projectIds = (await prisma.project.findMany({ where: { userId: id }, select: { id: true } })).map(p => p.id)
    } catch (e) {
      console.warn('Could not list projects before user delete:', e)
    }

    if (targetIsAdmin) {
      // The deleter is an admin, but a concurrent demotion of the deleter could
      // leave nobody: the same locked check as a demotion.
      const result = await withLastAdminGuard(id, tx => tx.user.delete({ where: { id } }))
      if (!result.ok) return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
    } else {
      await prisma.user.delete({
        where: { id }
      })
    }

    await Promise.allSettled(projectIds.map(pid => purgeProjectWorkspace(pid)))

    if (capturedBodyRefs.length > 0) {
      try {
        const { gcOrphanBodies } = await import('@/lib/captureBodies')
        const gc = await gcOrphanBodies(capturedBodyRefs)
        if (gc.deleted > 0) console.log(`[user-delete] GC'd ${gc.deleted} captured body blobs for user ${id}`)
      } catch (e) {
        console.warn('Captured body-blob GC failed on user delete:', e)
      }
    }

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
