import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { agentAnswerLastError, thrownLastError } from '../../agentLastError'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

/** The agent crawls the site and asks an LLM for a summary: minutes, not seconds. */
const VERIFY_TIMEOUT_MS = 240_000

// POST /api/users/[id]/tradecraft-resources/[resourceId]/verify
//   Body (optional): { force?: boolean }
//   Calls agent /tradecraft/verify and persists summary + type + sitemap.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const body = await request.json().catch(() => ({}))
    const force = body.force === true

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    // Resolve effective github token: per-resource override or user-level
    const userSettings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })
    const tokenForFetch =
      (existing.githubTokenOverride && existing.githubTokenOverride.length > 0)
        ? existing.githubTokenOverride
        : ((userSettings as unknown as Record<string, string> | null)?.githubAccessToken || '')

    const agentResp = await agentFetch('/tradecraft/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: existing.url,
        user_id: id,
        github_token: tokenForFetch,
        force,
        model: (existing as unknown as { llmModel?: string }).llmModel || '',
      }),
    }, { timeoutMs: VERIFY_TIMEOUT_MS })

    if (!agentResp.ok) {
      const failed = await readUpstreamBody(agentResp)
      const code = failed.code ?? 'agent_error'
      await prisma.userTradecraftResource.update({
        where: { id: resourceId },
        data: { lastError: agentAnswerLastError('verify', code, agentResp.status) },
      })
      return NextResponse.json(
        { error: 'The agent could not verify this resource', code, upstreamStatus: agentResp.status },
        { status: 502 },
      )
    }

    const result = await agentResp.json()
    const updated = await prisma.userTradecraftResource.update({
      where: { id: resourceId },
      data: {
        summary: result.summary ?? '',
        resourceType: result.resource_type ?? existing.resourceType,
        sitemap: result.sitemap ?? {},
        crawlStoppedBecause: result.crawl_stopped_because ?? '',
        crawlStats: result.crawl_stats ?? {},
        lastError: result.last_error ?? '',
        lastVerifiedAt: new Date(),
      },
    })
    return NextResponse.json(updated)
  } catch (error: unknown) {
    if (error instanceof AgentUnreachableError) {
      try {
        // Ownership already enforced at the top of the handler.
        const { resourceId } = await params
        await prisma.userTradecraftResource.update({
          where: { id: resourceId },
          data: { lastError: thrownLastError('verify', error) },
        })
      } catch {}
      return upstreamFailureResponse('agent', error.cause_, 'Failed to verify tradecraft resource')
    }
    return internalError(error, 'Failed to verify tradecraft resource')
  }
}
