/**
 * Editing a 2.0 resource (§6.13). Name, Enabled and the model are saved with no ingestion; the
 * type, the overrides (crawl, map, fetching, content) and Live → Stored only make the resource
 * stale (staleness.ts: its next refresh, or Save & re-ingest, applies them); the Resource ID
 * never changes (R-137); four changes act at once:
 *  - a new URL passes the address check (D-04) and is ingested again (R-195);
 *  - a change of Enabled forgets every project's choice for the resource (R-062);
 *  - Stored → Live deletes the stored text now (§4.5);
 *  - a change of the login (added, changed or removed, audited) applies to the next request.
 * A running job is building from the old URL, the old storage or the old login, so those three
 * edits wait for it: 409 `job_running` while its claim holds a live lease, nothing written
 * (D-45). The check and the writes run under the resource's row lock, like a job start.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { auditedTransaction } from '@/lib/auditForward'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditLoginChange, loginChangeRefusal, loginUseRefusal } from '../actAs'
import { claimHolder, jobView, startJob, startedJobFields, type JobActor } from '../jobs'
import { hasStoredLogin } from '../masking'
import { clearChoicesForResource } from '../projectChoices'
import { loadOwnResource, lockOwnResource } from '../resourceAccess'
import {
  applyCredentials, changedLoginFields, fieldErrorResponse, forcedStorageMode, hasCredentials, parseResourceFields,
  typeOptionsOf, type CredentialsPatch, type FieldError, type StoredCredentials,
} from './fields'
import { focusSkillRefusal } from './focusFields'
import { resourceViewOf } from './list'

class NotFound extends Error {}
class ClaimHeld extends Error {
  constructor(readonly job: Parameters<typeof jobView>[0]) { super('job_running') }
}
class BadLogin extends Error {
  constructor(readonly error: FieldError) { super('bad_credentials') }
}
/** The stored login moved between the refusal check and the write: decided again by the person. */
class LoginMoved extends Error {}

/** The login a write leaves, and whether it changes the stored one (or the flag alone records one). */
function nextLogin(row: { credentials: unknown; hasLogin: boolean }, patch: CredentialsPatch | null):
  { ok: true; value: StoredCredentials; changed: boolean } | { ok: false; error: FieldError } {
  const applied = patch === null ? { ok: true as const, value: {} } : applyCredentials(row.credentials, patch)
  if (!applied.ok) return applied
  const changed = changedLoginFields(row.credentials, applied.value).length > 0 || hasStoredLogin(row) !== hasCredentials(applied.value)
  return { ok: true, value: applied.value, changed }
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
  const foreignSkill = await focusSkillRefusal(ownerId, fields.focus)
  if (foreignSkill) return foreignSkill

  const before = await loadOwnResource(ownerId, resourceId)
  if (!before) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
  // The agent names the resource and its page IDs with it: read-only once added (R-137).
  if (fields.slug !== undefined && fields.slug !== before.slug) {
    return fieldErrorResponse({ field: 'slug', code: 'slug_read_only', error: 'The resource ID cannot change once the resource is added' })
  }
  // A login is never written while someone acts as the account (§6.6), even on an account they may write.
  const loginPatch = fields.credentials
  let loginWrite = false
  if (loginPatch !== undefined) {
    const planned = nextLogin(before, loginPatch)
    if (!planned.ok) return fieldErrorResponse(planned.error)
    loginWrite = planned.changed
    if (loginWrite) {
      const refused = await loginChangeRefusal(ownerId)
      if (refused) return refused
    }
  }
  const reingest = fields.url !== undefined && fields.url !== before.url
  if (reingest) {
    const loginRefused = await loginUseRefusal({ ownerId, resource: before })
    if (loginRefused) return loginRefused
    // The re-ingest sends the GitHub token, which stays with the account under act-as (step 3.14).
    const token = fields.githubTokenOverride ?? before.githubTokenOverride
    const account = token ? null : await prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } })
    if (token || account?.githubAccessToken) {
      const actingAs = await refuseWhileActingAsOn(ownerId, 'use_github_token')
      if (actingAs) return actingAs
    }
  }

  try {
    await auditedTransaction(prisma, async (tx) => {
      if (!(await lockOwnResource(tx, ownerId, resourceId))) throw new NotFound()
      const existing = await tx.userTradecraftResource.findUnique({ where: { id: resourceId } })
      if (!existing) throw new NotFound()

      const forcedType = fields.forcedType ?? existing.forcedType
      const storageMode = forcedStorageMode(forcedType || existing.resourceType) ?? fields.storageMode ?? existing.storageMode
      const urlChanged = fields.url !== undefined && fields.url !== existing.url
      const storedToLive = existing.storageMode === 'stored' && storageMode === 'live'
      let login: StoredCredentials | null = null
      if (loginPatch !== undefined) {
        const next = nextLogin(existing, loginPatch)
        if (!next.ok) throw new BadLogin(next.error)
        if (next.changed && !loginWrite) throw new LoginMoved()
        if (next.changed) login = next.value
      }
      if (urlChanged || storedToLive || login !== null) {
        const holder = await claimHolder(tx, existing)
        if (holder) throw new ClaimHeld(holder)
      }

      const data: Record<string, unknown> = {}
      for (const key of ['name', 'url', 'enabled', 'llmModel', 'githubTokenOverride'] as const) {
        if (fields[key] !== undefined) data[key] = fields[key]
      }
      if (fields.forcedType !== undefined) data.forcedType = forcedType
      if (fields.focus !== undefined) data.focus = fields.focus
      if (fields.overrides !== undefined) {
        data.overrides = fields.overrides
        data.typeOptions = typeOptionsOf(fields.overrides)
      }
      if (storageMode !== existing.storageMode) data.storageMode = storageMode
      if (login !== null) {
        data.credentials = login
        data.hasLogin = hasCredentials(login)
        await auditLoginChange(tx, { actor, ownerId, resourceId, before: existing.credentials, after: login, beforeHasLogin: hasStoredLogin(existing) })
      }
      if (fields.enabled !== undefined && fields.enabled !== existing.enabled) {
        await clearChoicesForResource(tx, resourceId)
      }
      if (storedToLive) {
        // Sections exist only for stored pages (R-335): they hold the same text.
        await tx.tradecraftEntry.updateMany({ where: { resourceId, storedText: { not: null } }, data: { storedText: null, storedBytes: 0 } })
        await tx.tradecraftSection.deleteMany({ where: { resourceId } })
        // The report's stored counts described that text: kept, a later Live → Stored would not
        // read as stale (staleness.ts) although nothing is stored.
        const report = existing.ingestionReport
        if (report && typeof report === 'object' && !Array.isArray(report) && 'stored' in report) {
          data.ingestionReport = { ...report, stored: { pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0 } }
        }
      }
      if (Object.keys(data).length > 0) await tx.userTradecraftResource.update({ where: { id: resourceId }, data })
    })
  } catch (err) {
    if (err instanceof NotFound) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    if (err instanceof BadLogin) return fieldErrorResponse(err.error)
    if (err instanceof LoginMoved) {
      return NextResponse.json({ error: 'The site login changed meanwhile: open the resource again', code: 'resource_changed' }, { status: 409 })
    }
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
