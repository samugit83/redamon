import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'
import { maskResource } from '@/lib/tradecraft/masking'
import { LEGACY_SELECT, loadOwnLegacyResource } from '@/lib/tradecraft/resourceAccess'
import { USERINFO_REFUSED, hasUserinfo } from '@/lib/tradecraft/urls'
import { jobActorOf } from '@/lib/tradecraft/jobs'
import { resourceViewOf } from '@/lib/tradecraft/v2/list'
import { updateResourceV2 } from '@/lib/tradecraft/v2/update'
import { removeResourceV2 } from '@/lib/tradecraft/v2/remove'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

/**
 * The fields a PUT may write; the rest (slug, type, summary, sitemap, crawl data, errors)
 * belong to the server. A spread body would also carry a relation input Prisma applies as
 * a nested write: `user: {connect}` moves the resource to another account.
 */
const UPDATABLE_FIELDS = ['name', 'url', 'enabled', 'cacheTtlSec', 'llmModel', 'githubTokenOverride'] as const

// GET /api/users/[id]/tradecraft-resources/[resourceId]
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const internal = isInternalRequest(request)
    if (!internal && await tradecraftV2Enabled(id)) {
      const view = await resourceViewOf(id, resourceId)
      if (!view) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
      return NextResponse.json(view)
    }

    const resource = await loadOwnLegacyResource(id, resourceId)
    if (!resource) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    // Unmasked only for trusted internal-key callers, never the ?internal=true param.
    if (internal) {
      return NextResponse.json(resource)
    }
    return NextResponse.json(maskResource(resource as unknown as Record<string, unknown>))
  } catch (error) {
    return internalError(error, 'Failed to fetch tradecraft resource')
  }
}

// PUT /api/users/[id]/tradecraft-resources/[resourceId]
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    if (await tradecraftV2Enabled(id)) {
      // A URL change starts a job, which names the person: the internal key alone edits nothing.
      const actor = jobActorOf(await auditActor())
      if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      const parsed = await readJsonBody(request)
      if (parsed instanceof NextResponse) return parsed
      return await updateResourceV2({ ownerId: id, resourceId, body: parsed.body, actor })
    }

    const body = await request.json()
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json({ error: 'The body must be a JSON object' }, { status: 400 })
    }

    const existing = await loadOwnLegacyResource(id, resourceId)
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    const updateData: Record<string, unknown> = {}
    for (const field of UPDATABLE_FIELDS) {
      if (field in body) updateData[field] = body[field]
    }

    if ('url' in updateData && hasUserinfo(updateData.url)) {
      return NextResponse.json({ error: USERINFO_REFUSED, code: 'userinfo_refused' }, { status: 400 })
    }

    // Preserve masked github token
    if ('githubTokenOverride' in updateData) {
      const val = updateData.githubTokenOverride as string
      if (typeof val === 'string' && val.startsWith('••••')) {
        updateData.githubTokenOverride = existing.githubTokenOverride
      }
    }

    // llmModel is required if explicitly being updated. Empty string would
    // make the resource unusable, so reject it. Callers that don't touch
    // llmModel just omit the key - existing value is preserved.
    if ('llmModel' in updateData) {
      const val = updateData.llmModel
      if (typeof val !== 'string' || !val.trim()) {
        return NextResponse.json(
          { error: 'llmModel cannot be empty' },
          { status: 400 }
        )
      }
      if (isLoopModel(val)) {
        return NextResponse.json({ error: 'Agent in the Loop answers only inside a chat run; pick a provider model for this resource', code: 'loop_model_not_allowed' }, { status: 400 })
      }
      updateData.llmModel = val.trim()
    }

    const updated = await prisma.userTradecraftResource.update({
      where: { id: resourceId },
      data: updateData,
      select: LEGACY_SELECT,
    })
    return NextResponse.json(maskResource(updated as unknown as Record<string, unknown>))
  } catch (error) {
    return internalError(error, 'Failed to update tradecraft resource')
  }
}

// DELETE /api/users/[id]/tradecraft-resources/[resourceId]
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    if (await tradecraftV2Enabled(id)) {
      return await removeResourceV2({ ownerId: id, resourceId })
    }

    const existing = await loadOwnLegacyResource(id, resourceId)
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    await prisma.userTradecraftResource.delete({ where: { id: resourceId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    return internalError(error, 'Failed to delete tradecraft resource')
  }
}
