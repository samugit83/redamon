import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { agentAnswerLastError } from '../../agentLastError'
import { requireSelfPermission } from '@/lib/authz/selfService'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

/** The agent crawls the site and asks an LLM for a summary: minutes, not seconds. */
const REFRESH_TIMEOUT_MS = 240_000

// POST /api/users/[id]/tradecraft-resources/[resourceId]/refresh
//   Same as /verify with force=true and bumps lastRefreshedAt.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

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
        force: true,
        // Without it the agent falls back to its default model, which the
        // user may have no key for, and the refresh fails with 503.
        model: (existing as unknown as { llmModel?: string }).llmModel || '',
      }),
    }, { timeoutMs: REFRESH_TIMEOUT_MS })

    // Neither the row nor the answer carries the agent's text (agentLastError.ts):
    // the status and the agent's code are what the list and the toast show.
    if (!agentResp.ok) {
      const failed = await readUpstreamBody(agentResp)
      const code = failed.code ?? 'agent_error'
      await prisma.userTradecraftResource.update({
        where: { id: resourceId },
        data: { lastError: agentAnswerLastError('refresh', code, agentResp.status) },
      })
      return NextResponse.json(
        { error: 'The agent could not refresh this resource', code, upstreamStatus: agentResp.status },
        { status: 502 },
      )
    }

    const result = await agentResp.json()
    const now = new Date()
    const updated = await prisma.userTradecraftResource.update({
      where: { id: resourceId },
      data: {
        summary: result.summary ?? '',
        resourceType: result.resource_type ?? existing.resourceType,
        sitemap: result.sitemap ?? {},
        crawlStoppedBecause: result.crawl_stopped_because ?? '',
        crawlStats: result.crawl_stats ?? {},
        lastError: result.last_error ?? '',
        lastVerifiedAt: now,
        lastRefreshedAt: now,
      },
    })
    return NextResponse.json(updated)
  } catch (error: unknown) {
    if (error instanceof AgentUnreachableError) {
      return upstreamFailureResponse('agent', error.cause_, 'Failed to refresh tradecraft resource')
    }
    return internalError(error, 'Failed to refresh tradecraft resource')
  }
}
