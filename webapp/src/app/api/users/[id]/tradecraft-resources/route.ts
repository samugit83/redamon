import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { agentFetch } from '@/lib/agentFetch'
import { internalError, readUpstreamBody } from '@/lib/routeErrors'
import { agentAnswerLastError, thrownLastError } from './agentLastError'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { rbacFlags } from '@/lib/authz/flags'
import { auditActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'
import { maskResource } from '@/lib/tradecraft/masking'
import { LEGACY_SELECT } from '@/lib/tradecraft/resourceAccess'
import { slugify, uniqueSlug, validateUrl } from '@/lib/tradecraft/urls'
import { jobActorOf } from '@/lib/tradecraft/jobs'
import { listResourcesV2 } from '@/lib/tradecraft/v2/list'
import { createResourceV2 } from '@/lib/tradecraft/v2/create'
import { legacyRows } from '@/lib/tradecraft/catalog'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/users/[id]/tradecraft-resources
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership + secret-unmask gate (STRIDE I1): unmasked githubTokenOverride
    // requires a valid X-Internal-Key header (the agent), not ?internal=true.
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const internal = isInternalRequest(request) && request.nextUrl.searchParams.get('internal') === 'true'

    // The agent's 1.x run fetch reads the 1.x rows in both switch states, until it reads the
    // run catalog (T1.9); a browser on 2.0 gets the 2.0 view.
    if (!internal && await tradecraftV2Enabled(id)) {
      return NextResponse.json(await listResourcesV2(id))
    }

    if (internal) {
      // The agent's 1.x run fetch names no person: a resource with a login stays out (R-155).
      return NextResponse.json(await legacyRows(id, { ownerRun: false }))
    }

    const resources = await prisma.userTradecraftResource.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'asc' },
      select: LEGACY_SELECT,
    })

    return NextResponse.json(
      resources.map(r => maskResource(r as unknown as Record<string, unknown>))
    )
  } catch (error) {
    return internalError(error, 'Failed to fetch tradecraft resources')
  }
}

// POST /api/users/[id]/tradecraft-resources
//   Body: { name, url, enabled?, resourceType?, githubTokenOverride?, cacheTtlSec? }
//   Query: ?skipVerify=true to skip the agent /tradecraft/verify call (2.0: the add job)
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const skipVerify = request.nextUrl.searchParams.get('skipVerify') === 'true'

    if (await tradecraftV2Enabled(id)) {
      // A job names the person who started it: the internal key alone starts none.
      const actor = jobActorOf(await auditActor())
      if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      const parsed = await readJsonBody(request)
      if (parsed instanceof NextResponse) return parsed
      return await createResourceV2({ ownerId: id, body: parsed.body, actor, skipVerify })
    }

    const body = await request.json()

    if (!body.name || !body.url) {
      return NextResponse.json(
        { error: 'name and url are required' },
        { status: 400 }
      )
    }
    // llmModel is required at the API layer too - protects against direct
    // API callers that bypass the UI. Empty string is rejected; downstream
    // agent code uses the value as the model id.
    if (!body.llmModel || typeof body.llmModel !== 'string' || !body.llmModel.trim()) {
      return NextResponse.json(
        { error: 'llmModel is required - pick a model for this resource' },
        { status: 400 }
      )
    }
    if (isLoopModel(body.llmModel)) {
      return NextResponse.json({ error: 'Agent in the Loop answers only inside a chat run; pick a provider model for this resource', code: 'loop_model_not_allowed' }, { status: 400 })
    }

    const v = validateUrl(body.url)
    if (!v.ok) {
      return NextResponse.json({ error: v.error, ...(v.code ? { code: v.code } : {}) }, { status: 400 })
    }

    // The crawl below would send the account's GitHub token, which stays with the account while
    // someone acts as it (permissions switch on, step 3.14): refused before anything is written.
    if (rbacFlags().permissions && !skipVerify && !body.githubTokenOverride) {
      const settings = await prisma.userSettings.findUnique({ where: { userId: id }, select: { githubAccessToken: true } })
      if (settings?.githubAccessToken) {
        const actingAs = await refuseWhileActingAsOn(id, 'use_github_token')
        if (actingAs) return actingAs
      }
    }

    const slug = await uniqueSlug(id, slugify(body.name))

    const created = await prisma.userTradecraftResource.create({
      data: {
        userId: id,
        name: body.name,
        slug,
        url: body.url,
        enabled: body.enabled ?? true,
        resourceType: body.resourceType ?? 'agentic-crawl',
        summary: '',
        sitemap: {},
        crawlStoppedBecause: '',
        crawlStats: {},
        githubTokenOverride: body.githubTokenOverride ?? '',
        cacheTtlSec: body.cacheTtlSec ?? 0,
        llmModel: body.llmModel.trim(),
      },
      select: LEGACY_SELECT,
    })

    // Optionally trigger verify in the background
    if (!skipVerify) {
      // fire-and-forget: the UI polls the row to see when fields populate
      ;(async () => {
        try {
          const userSettings = await prisma.userSettings.findUnique({
            where: { userId: id },
          })
          const tokenForFetch =
            (created.githubTokenOverride && created.githubTokenOverride.length > 0)
              ? created.githubTokenOverride
              : ((userSettings as unknown as Record<string, string> | null)?.githubAccessToken || '')

          // No request waits on this background crawl and the agent bounds its
          // own run, so no hop timeout of ours cuts a long but healthy one short.
          const agentResp = await agentFetch('/tradecraft/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: created.url,
              user_id: id,
              github_token: tokenForFetch,
              force: false,
              model: created.llmModel,
            }),
          }, { timeoutMs: 0 })
          if (!agentResp.ok) {
            const failed = await readUpstreamBody(agentResp)
            await prisma.userTradecraftResource.update({
              where: { id: created.id },
              data: { lastError: agentAnswerLastError('verify', failed.code ?? 'agent_error', agentResp.status) },
            })
            return
          }
          const result = await agentResp.json()
          await prisma.userTradecraftResource.update({
            where: { id: created.id },
            data: {
              summary: result.summary ?? '',
              resourceType: result.resource_type ?? created.resourceType,
              sitemap: result.sitemap ?? {},
              crawlStoppedBecause: result.crawl_stopped_because ?? '',
              crawlStats: result.crawl_stats ?? {},
              lastError: result.last_error ?? '',
              lastVerifiedAt: new Date(),
            },
          })
        } catch (e) {
          console.error('Background verify failed:', e)
          await prisma.userTradecraftResource.update({
            where: { id: created.id },
            data: { lastError: thrownLastError('verify', e) },
          }).catch(() => {})
        }
      })()
    }

    return NextResponse.json(
      maskResource(created as unknown as Record<string, unknown>),
      { status: 201 }
    )
  } catch (error: unknown) {
    const e = error as { code?: string; message?: string }
    if (e?.code === 'P2002') {
      return NextResponse.json(
        { error: 'A resource with this URL or slug already exists' },
        { status: 409 }
      )
    }
    return internalError(error, 'Failed to create tradecraft resource')
  }
}
