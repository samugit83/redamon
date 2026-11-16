/**
 * Editing a 2.0 resource (§6.13). Name, Enabled and the model are saved with no ingestion; the
 * type, the overrides (crawl, map, fetching, content) and Live → Stored only make the resource
 * stale (staleness.ts: its next refresh, or Save & re-ingest, applies them); the Resource ID
 * never changes (R-137); four changes act at once:
 *  - a new URL passes the address check (D-04) and is ingested again (R-195);
 *  - a change of Enabled forgets every project's choice for the resource (R-062);
 *  - Stored → Live deletes the stored text now (§4.5);
 *  - removing the login stops its use now.
 * A running job is building from the old URL, the old storage or the old login, so those three
 * edits wait for it: 409 `job_running` while its claim holds a live lease, nothing written
 * (D-45). The check and the writes run under the resource's row lock, like a job start.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { claimHolder, jobView, startJob, startedJobFields, type JobActor } from '../jobs'
import { hasStoredLogin } from '../masking'
import { clearChoicesForResource } from '../projectChoices'
import { loadOwnResource, lockOwnResource } from '../resourceAccess'
import { fieldErrorResponse, forcedStorageMode, parseResourceFields, typeOptionsOf } from './fields'
import { resourceViewOf } from './list'

class NotFound extends Error {}
class ClaimHeld extends Error {
  constructor(readonly job: Parameters<typeof jobView>[0]) { super('job_running') }
}

export async function updateResourceV2(input: {
  ownerId: string
  resourceId: string
  body: Record<string, unknown>
  actor: JobActor
}): Promise<NextResponse> {
  const { ownerId, resourceId, body, actor } = input
  const parsed = parseResourceFields(body, 'update')
  if (!parsed.ok) return fieldErrorResponse(parsed.error)
  const fields = parsed.value

  const before = await loadOwnResource(ownerId, resourceId)
  if (!before) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
  // The agent names the resource and its page IDs with it: read-only once added (R-137).
  if (fields.slug !== undefined && fields.slug !== before.slug) {
    return fieldErrorResponse({ field: 'slug', code: 'slug_read_only', error: 'The resource ID cannot change once the resource is added' })
  }
  const reingest = fields.url !== undefined && fields.url !== before.url
  if (reingest) {
    // The re-ingest sends the GitHub token, which stays with the account under act-as (step 3.14).
    const token = fields.githubTokenOverride ?? before.githubTokenOverride
    const account = token ? null : await prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } })
    if (token || account?.githubAccessToken) {
      const actingAs = await refuseWhileActingAsOn(ownerId, 'use_github_token')
      if (actingAs) return actingAs
    }
  }

  try {
    await prisma.$transaction(async (tx) => {
      if (!(await lockOwnResource(tx, ownerId, resourceId))) throw new NotFound()
      const existing = await tx.userTradecraftResource.findUnique({ where: { id: resourceId } })
      if (!existing) throw new NotFound()

      const forcedType = fields.forcedType ?? existing.forcedType
      const storageMode = forcedStorageMode(forcedType || existing.resourceType) ?? fields.storageMode ?? existing.storageMode
      const urlChanged = fields.url !== undefined && fields.url !== existing.url
      const storedToLive = existing.storageMode === 'stored' && storageMode === 'live'
      const loginRemoved = fields.credentials === null && hasStoredLogin(existing)
      if (urlChanged || storedToLive || loginRemoved) {
        const holder = await claimHolder(tx, existing)
        if (holder) throw new ClaimHeld(holder)
      }

      const data: Record<string, unknown> = {}
      for (const key of ['name', 'url', 'enabled', 'llmModel', 'githubTokenOverride'] as const) {
        if (fields[key] !== undefined) data[key] = fields[key]
      }
      if (fields.forcedType !== undefined) data.forcedType = forcedType
      if (fields.overrides !== undefined) {
        data.overrides = fields.overrides
        data.typeOptions = typeOptionsOf(fields.overrides)
      }
      if (storageMode !== existing.storageMode) data.storageMode = storageMode
      if (loginRemoved) {
        data.credentials = {}
        data.hasLogin = false
      }
      if (fields.enabled !== undefined && fields.enabled !== existing.enabled) {
        await clearChoicesForResource(tx, resourceId)
      }
      if (storedToLive) {
        // Sections exist only for stored pages (R-335): they hold the same text.
        await tx.tradecraftEntry.updateMany({ where: { resourceId, storedText: { not: null } }, data: { storedText: null, storedBytes: 0 } })
        await tx.tradecraftSection.deleteMany({ where: { resourceId } })
      }
      if (Object.keys(data).length > 0) await tx.userTradecraftResource.update({ where: { id: resourceId }, data })
    })
  } catch (err) {
    if (err instanceof NotFound) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    if (err instanceof ClaimHeld) {
      return NextResponse.json({
        error: 'A job is running for this resource: cancel it before changing its URL, its storage or its login',
        code: 'job_running', job: jobView(err.job),
      }, { status: 409 })
    }
    if ((err as { code?: string })?.code === 'P2002') {
      return NextResponse.json({ error: 'A resource with this URL or slug already exists', code: 'duplicate' }, { status: 409 })
    }
    throw err
  }

  if (!reingest) return NextResponse.json({ resource: await resourceViewOf(ownerId, resourceId), job: null })
  const outcome = await startJob({ ownerId, resourceId, kind: 'reingest', actor })
  return NextResponse.json({ resource: await resourceViewOf(ownerId, resourceId), ...startedJobFields(outcome) })
}
