import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { isLoopModel } from '@/lib/agentInTheLoop'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

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

    const denied = await requireUserAccess(request, id)
    if (denied) return denied

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

    const denied = await requireUserAccess(request, id)
    if (denied) return denied

    const body = await request.json()

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    // Strip server-managed fields
    const updateData: Record<string, unknown> = { ...body }
    delete updateData.id
    delete updateData.userId
    delete updateData.slug              // slug is immutable
    delete updateData.createdAt
    delete updateData.updatedAt
    delete updateData.lastVerifiedAt
    delete updateData.lastRefreshedAt
    delete updateData.summary           // summary set by /verify
    delete updateData.sitemap           // sitemap set by /verify
    delete updateData.resourceType      // type set by /verify
    delete updateData.crawlStoppedBecause
    delete updateData.crawlStats

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

    const denied = await requireUserAccess(request, id)
    if (denied) return denied

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
