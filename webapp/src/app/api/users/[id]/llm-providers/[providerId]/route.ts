import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { isJevProvider, jevPinnedConfig } from '@/lib/llmProviderKinds'
import { isReasoningEffort } from '@/lib/llmReasoning'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

function maskProvider(provider: Record<string, unknown>): Record<string, unknown> {
  return {
    ...provider,
    apiKey: maskSecret(provider.apiKey as string),
    awsAccessKeyId: maskSecret(provider.awsAccessKeyId as string),
    awsSecretKey: maskSecret(provider.awsSecretKey as string),
    awsBearerToken: maskSecret(provider.awsBearerToken as string),
  }
}

// GET /api/users/[id]/llm-providers/[providerId]
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params

    // Ownership + secret-unmask gate (STRIDE I1): browser callers must own the
    // account (or be admin: the read rule) and always get masked rows; unmasked
    // rows require a valid X-Internal-Key header, never the ?internal=true param.
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied

    const provider = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })

    if (!provider) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    if (isInternalRequest(request)) {
      return NextResponse.json(provider)
    }

    return NextResponse.json(maskProvider(provider as unknown as Record<string, unknown>))
  } catch (error) {
    return internalError(error, 'Failed to fetch LLM provider')
  }
}

// PUT /api/users/[id]/llm-providers/[providerId]
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied

    const body = await request.json()

    if (body.reasoningEnabled !== undefined && typeof body.reasoningEnabled !== 'boolean') {
      return NextResponse.json(
        { error: 'reasoningEnabled must be a boolean' },
        { status: 400 }
      )
    }
    if (body.reasoningEffort !== undefined && !isReasoningEffort(body.reasoningEffort)) {
      return NextResponse.json(
        { error: 'reasoningEffort must be one of: low, medium, high, max' },
        { status: 400 }
      )
    }

    // Verify the provider belongs to the target user
    const existing = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    // The type of a Jev row is locked both ways: turning it into a chat type
    // would send the stored token to any base URL, and turning a chat key into
    // Jev would send that key to TypeSafe.
    const bodyType = body.providerType as string | undefined
    const touchesJev = isJevProvider(existing) || isJevProvider({ providerType: bodyType ?? '' })
    if (touchesJev && bodyType !== undefined && bodyType !== existing.providerType) {
      return NextResponse.json(
        { error: 'The backend of a Jev provider cannot be changed' },
        { status: 400 },
      )
    }

    // Preserve masked secrets
    const secretFields = ['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'] as const
    const updateData: Record<string, unknown> = { ...body }
    delete updateData.id
    delete updateData.userId
    delete updateData.createdAt
    delete updateData.updatedAt

    for (const field of secretFields) {
      if (field in updateData) {
        const val = updateData[field] as string
        if (typeof val === 'string' && val.startsWith('••••')) {
          updateData[field] = existing[field]
        }
      }
    }

    // Reasoning controls only apply to OpenAI-compatible providers. For any
    // other type, force the columns back to defaults so a stray body field
    // can't persist a reasoning level on e.g. an Anthropic provider (parity
    // with the POST create path).
    const effectiveType = (updateData.providerType as string) ?? existing.providerType
    if (effectiveType !== 'openai_compatible') {
      updateData.reasoningEnabled = false
      updateData.reasoningEffort = 'high'
    }

    // A Jev row keeps its backend and that backend's pinned model, URL and headers:
    // its name and key are the only fields an update can write.
    if (isJevProvider(existing)) {
      if (body.apiKey !== undefined && typeof body.apiKey !== 'string') {
        return NextResponse.json({ error: 'apiKey must be a string' }, { status: 400 })
      }
      const apiKey = typeof updateData.apiKey === 'string' ? updateData.apiKey.trim() : undefined
      if (apiKey === '') {
        return NextResponse.json({ error: 'apiKey is required for TypeSafe AI (Jev)' }, { status: 400 })
      }
      if (body.name !== undefined && (typeof body.name !== 'string' || !body.name.trim())) {
        return NextResponse.json({ error: 'name is required for Jev' }, { status: 400 })
      }
      for (const field of Object.keys(updateData)) delete updateData[field]
      Object.assign(updateData, jevPinnedConfig(existing.providerType))
      if (body.name !== undefined) updateData.name = body.name.trim()
      if (apiKey !== undefined) updateData.apiKey = apiKey
    }

    const provider = await prisma.userLlmProvider.update({
      where: { id: providerId },
      data: updateData,
    })

    return NextResponse.json(maskProvider(provider as unknown as Record<string, unknown>))
  } catch (error) {
    return internalError(error, 'Failed to update LLM provider')
  }
}

// DELETE /api/users/[id]/llm-providers/[providerId]
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params

    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied

    const existing = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    const affectedProjects = await prisma.$transaction(async tx => {
      // updatedAt is moved explicitly (updateMany does not guarantee it), so a project
      // form opened before the delete gets a stale-save refusal instead of writing
      // the deleted selection back.
      const cleared = await tx.project.updateMany({
        where: { jevProviderId: providerId },
        data: { jevProviderId: null, updatedAt: new Date() },
      })
      await tx.userLlmProvider.delete({ where: { id: providerId } })
      return cleared.count
    })

    return NextResponse.json({
      success: true, affectedProjects,
      warning: affectedProjects > 0
        ? `${affectedProjects} project(s) no longer have a Jev provider selected. Their Jev hooks will use deterministic fallbacks.`
        : null,
    })
  } catch (error) {
    return internalError(error, 'Failed to delete LLM provider')
  }
}
