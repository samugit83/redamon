import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditActor } from '@/lib/auditActor'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { jobActorOf, jobStartResponse, startJob } from '@/lib/tradecraft/jobs'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

// POST /api/users/[id]/tradecraft-resources/[resourceId]/summary/regenerate
// Regenerate summary (§6.9): a `regenerate_summary` job rebuilds the summary from the saved map
// and the homepage, without re-crawling, and swaps the summary alone. A locked summary, or one
// the person wrote, is theirs: the job would keep it, so it is not started.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const actor = jobActorOf(await auditActor())
    if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

    const resource = await loadOwnResource(id, resourceId)
    if (!resource) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    if (resource.summaryLocked) {
      return NextResponse.json({ error: 'The summary is locked: unlock it to regenerate it', code: 'summary_locked' }, { status: 409 })
    }
    if (resource.summarySource === 'manual') {
      return NextResponse.json(
        { error: 'The summary is written by you: switch it back to Generated to regenerate it', code: 'summary_manual' }, { status: 409 })
    }
    // The job reads the homepage: with the resource's login, and with the GitHub token on GitHub.
    const loginRefused = await loginUseRefusal({ ownerId: id, resourceId })
    if (loginRefused) return loginRefused
    const account = resource.githubTokenOverride
      ? null
      : await prisma.userSettings.findUnique({ where: { userId: id }, select: { githubAccessToken: true } })
    if (resource.githubTokenOverride || account?.githubAccessToken) {
      const actingAs = await refuseWhileActingAsOn(id, 'use_github_token')
      if (actingAs) return actingAs
    }
    return jobStartResponse(await startJob({ ownerId: id, resourceId, kind: 'regenerate_summary', actor }))
  } catch (error) {
    return internalError(error, 'Failed to start the summary job')
  }
}
