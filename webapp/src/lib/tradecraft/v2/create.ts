/**
 * Adding a 2.0 resource: the row with the account's current settings in force (R-028), then an
 * `add` job that ingests it in the background. An account holds at most `maxResourcesPerUser`
 * resources (OQ-20, D-12); the count and the insert run under one per-account lock, so two
 * adds at once cannot pass the cap together.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { auditedTransaction } from '@/lib/auditForward'
import { featureModelErrorResponse, readFeatureModel } from '@/lib/featureModels'
import { modelAllowedForFeature } from '@/lib/llmFeatures'
import { rbacFlags } from '@/lib/authz/flags'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditLoginChange, loginChangeRefusal } from '../actAs'
import { effectiveSettings } from '../effectiveSettings'
import { startJob, startedJobFields, type JobActor } from '../jobs'
import { SETTINGS_CONSTANTS } from '../settingsSpec'
import { slugify, uniqueSlug } from '../urls'
import {
  applyCredentials, defaultStorageMode, fieldErrorResponse, forcedStorageMode, hasCredentials, parseResourceFields,
  typeOptionsOf, type StoredCredentials,
} from './fields'
import { withOwnSkillTopics } from './focusFields'
import { resourceViewOf } from './list'

export const MAX_RESOURCES_PER_USER: number = SETTINGS_CONSTANTS.maxResourcesPerUser

/**
 * The feature-model gate of the librarian (Q10, R-404): while Librarian use is "Agent decides"
 * (the default), adding a resource or turning one on needs the owner's Tradecraft librarian
 * model, so the agent never meets a library its librarian cannot run on. The `model_required`
 * answer opens the client's gate, which saves a model and sends the same request again. With
 * "Search only" nothing is asked. A saved model no feature may run on (Agent in the Loop) counts
 * as none.
 */
export async function librarianModelRefusal(ownerId: string): Promise<NextResponse | null> {
  const user = await prisma.tradecraftUserSettings.findUnique({ where: { userId: ownerId }, select: { search: true } })
  if (effectiveSettings({ user, scope: 'search' }).values['librarian.use'] !== 'agent') return null
  const model = await readFeatureModel(ownerId, 'tradecraft_librarian')
  if (model && modelAllowedForFeature('tradecraft_librarian', model)) return null
  return featureModelErrorResponse('model_required', 'tradecraft_librarian')
}

class CapReached extends Error {}
class SlugTaken extends Error {}

export async function createResourceV2(input: {
  ownerId: string
  body: Record<string, unknown>
  actor: JobActor
  skipVerify: boolean
}): Promise<NextResponse> {
  const { ownerId, body, actor, skipVerify } = input
  const parsed = parseResourceFields(body, 'create')
  if (!parsed.ok) return fieldErrorResponse(parsed.error)
  const fields = parsed.value
  let login: StoredCredentials = {}
  if (fields.credentials) {
    const applied = applyCredentials({}, fields.credentials)
    if (!applied.ok) return fieldErrorResponse(applied.error)
    login = applied.value
    // A login is never written while someone acts as the account (§6.6): before anything is.
    if (hasCredentials(login)) {
      const refused = await loginChangeRefusal(ownerId)
      if (refused) return refused
    }
  }
  const focus = fields.focus ? await withOwnSkillTopics(ownerId, fields.focus) : {}
  const noLibrarian = await librarianModelRefusal(ownerId)
  if (noLibrarian) return noLibrarian

  // The add job would send the account's GitHub token, which stays with the account while
  // someone acts as it (step 3.14): refused before anything is written, as in 1.x.
  if (rbacFlags().permissions && !skipVerify && !fields.githubTokenOverride) {
    const settings = await prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } })
    if (settings?.githubAccessToken) {
      const actingAs = await refuseWhileActingAsOn(ownerId, 'use_github_token')
      if (actingAs) return actingAs
    }
  }

  const user = await prisma.tradecraftUserSettings.findUnique({ where: { userId: ownerId }, select: { ingestion: true } })
  const forcedType = fields.forcedType ?? ''
  const userDefault = defaultStorageMode(effectiveSettings({ user }).values['storage.defaultMode'], forcedType)
  const storageMode = forcedStorageMode(forcedType) ?? fields.storageMode ?? userDefault
  // A chosen Resource ID must be free (R-137); a generated one takes a suffix instead.
  const slug = fields.slug ?? await uniqueSlug(ownerId, slugify(fields.name!))
  const overrides = fields.overrides ?? {}

  let createdId: string
  try {
    createdId = await auditedTransaction(prisma, async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`tradecraft_resources:${ownerId}`}))`
      if ((await tx.userTradecraftResource.count({ where: { userId: ownerId } })) >= MAX_RESOURCES_PER_USER) throw new CapReached()
      if (fields.slug && (await tx.userTradecraftResource.count({ where: { userId: ownerId, slug: fields.slug } })) > 0) throw new SlugTaken()
      const row = await tx.userTradecraftResource.create({
        data: {
          userId: ownerId,
          name: fields.name!,
          slug,
          url: fields.url!,
          enabled: fields.enabled ?? true,
          resourceType: forcedType || 'agentic-crawl',
          forcedType,
          storageMode,
          llmModel: fields.llmModel!,
          githubTokenOverride: fields.githubTokenOverride ?? '',
          overrides: overrides as object,
          typeOptions: typeOptionsOf(overrides) as object,
          focus: focus as object,
          credentials: login as object,
          hasLogin: hasCredentials(login),
          presetKey: fields.presetKey ?? '',
        },
        select: { id: true },
      })
      await auditLoginChange(tx, { actor, ownerId, resourceId: row.id, before: {}, after: login })
      return row.id
    })
  } catch (err) {
    if (err instanceof SlugTaken) {
      return NextResponse.json(
        { field: 'slug', error: 'You already have a resource with this ID', code: 'slug_taken' }, { status: 409 })
    }
    if (err instanceof CapReached) {
      return NextResponse.json(
        { error: `An account holds at most ${MAX_RESOURCES_PER_USER} Tradecraft resources`, code: 'resource_cap' },
        { status: 409 },
      )
    }
    if ((err as { code?: string })?.code === 'P2002') {
      return NextResponse.json({ error: 'A resource with this URL or slug already exists', code: 'duplicate' }, { status: 409 })
    }
    throw err
  }

  if (skipVerify) {
    return NextResponse.json({ resource: await resourceViewOf(ownerId, createdId), job: null }, { status: 201 })
  }
  const outcome = await startJob({ ownerId, resourceId: createdId, kind: 'add', actor })
  return NextResponse.json({ resource: await resourceViewOf(ownerId, createdId), ...startedJobFields(outcome) }, { status: 201 })
}
