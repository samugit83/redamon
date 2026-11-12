import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { requireSelfPermission } from '@/lib/authz/selfService'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

/**
 * The fields a PUT may write; the rest (slug, type, summary, sitemap, crawl data, errors)
 * belong to the server. A spread body would also carry a relation input Prisma applies as
 * a nested write: `user: {connect}` moves the resource to another account.
 */
const UPDATABLE_FIELDS = ['name', 'url', 'enabled', 'cacheTtlSec', 'llmModel', 'githubTokenOverride'] as const

function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

function maskResource(r: Record<string, unknown>): Record<string, unknown> {
  return {
    ...r,
    githubTokenOverride: maskSecret(r.githubTokenOverride as string),
  }
}

// GET /api/users/[id]/tradecraft-resources/[resourceId]
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const resource = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!resource) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    // Unmasked only for trusted internal-key callers, never the ?internal=true param.
    if (isInternalRequest(request)) {
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

    const body = await request.json()
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json({ error: 'The body must be a JSON object' }, { status: 400 })
    }

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    const updateData: Record<string, unknown> = {}
    for (const field of UPDATABLE_FIELDS) {
      if (field in body) updateData[field] = body[field]
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

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    await prisma.userTradecraftResource.delete({ where: { id: resourceId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    return internalError(error, 'Failed to delete tradecraft resource')
  }
}
