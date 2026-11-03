import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import { agentFetch } from '@/lib/agentFetch'
import { internalError, readUpstreamBody } from '@/lib/routeErrors'
import { agentAnswerLastError, thrownLastError } from './agentLastError'
import { isLoopModel } from '@/lib/agentInTheLoop'

interface RouteParams {
  params: Promise<{ id: string }>
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

function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || 'resource'
}

async function uniqueSlug(userId: string, base: string): Promise<string> {
  let slug = base
  let suffix = 2
  while (true) {
    const existing = await prisma.userTradecraftResource.findUnique({
      where: { userId_slug: { userId, slug } },
    })
    if (!existing) return slug
    slug = `${base}-${suffix}`
    suffix++
  }
}

function isPrivateHost(hostname: string): boolean {
  if (!hostname) return true
  const lc = hostname.toLowerCase()
  if (lc === 'localhost' || lc.endsWith('.local') || lc.endsWith('.internal')) return true
  // IPv4 literal check
  const m = lc.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (m) {
    const o = m.slice(1).map(Number)
    if (o[0] === 10) return true
    if (o[0] === 127) return true
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true
    if (o[0] === 192 && o[1] === 168) return true
    if (o[0] === 169 && o[1] === 254) return true
    if (o[0] === 0) return true
  }
  // IPv6 loopback / link-local
  if (lc === '::1' || lc.startsWith('fe80:') || lc.startsWith('fc') || lc.startsWith('fd')) return true
  return false
}

function validateUrl(raw: string): { ok: boolean; error?: string } {
  try {
    const u = new URL(raw)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { ok: false, error: 'Only http(s) URLs are allowed' }
    }
    if (isPrivateHost(u.hostname)) {
      return { ok: false, error: 'private address blocked' }
    }
    return { ok: true }
  } catch {
    return { ok: false, error: 'Invalid URL' }
  }
}

// GET /api/users/[id]/tradecraft-resources
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership + secret-unmask gate (STRIDE I1): unmasked githubTokenOverride
    // requires a valid X-Internal-Key header (the agent), not ?internal=true.
    const denied = await requireUserAccess(request, id)
    if (denied) return denied
    const internal = isInternalRequest(request) && request.nextUrl.searchParams.get('internal') === 'true'

    const resources = await prisma.userTradecraftResource.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'asc' },
    })

    if (internal) {
      return NextResponse.json(resources)
    }
    return NextResponse.json(
      resources.map(r => maskResource(r as unknown as Record<string, unknown>))
    )
  } catch (error) {
    return internalError(error, 'Failed to fetch tradecraft resources')
  }
}

// POST /api/users/[id]/tradecraft-resources
//   Body: { name, url, enabled?, resourceType?, githubTokenOverride?, cacheTtlSec? }
//   Query: ?skipVerify=true to skip the agent /tradecraft/verify call
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const denied = await requireUserAccess(request, id)
    if (denied) return denied

    const body = await request.json()
    const skipVerify = request.nextUrl.searchParams.get('skipVerify') === 'true'

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
      return NextResponse.json({ error: v.error }, { status: 400 })
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
