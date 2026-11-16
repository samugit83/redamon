/**
 * Adding a 2.0 resource: the row with the account's current settings in force (R-028), then an
 * `add` job that ingests it in the background. An account holds at most `maxResourcesPerUser`
 * resources (OQ-20, D-12); the count and the insert run under one per-account lock, so two
 * adds at once cannot pass the cap together.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { rbacFlags } from '@/lib/authz/flags'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { effectiveSettings } from '../effectiveSettings'
import { startJob, startedJobFields, type JobActor } from '../jobs'
import { SETTINGS_CONSTANTS } from '../settingsSpec'
import { slugify, uniqueSlug } from '../urls'
import { defaultStorageMode, fieldErrorResponse, forcedStorageMode, parseResourceFields } from './fields'
import { resourceViewOf } from './list'

export const MAX_RESOURCES_PER_USER: number = SETTINGS_CONSTANTS.maxResourcesPerUser

class CapReached extends Error {}

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
  const slug = await uniqueSlug(ownerId, slugify(fields.name!))

  let createdId: string
  try {
    createdId = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`tradecraft_resources:${ownerId}`}))`
      if ((await tx.userTradecraftResource.count({ where: { userId: ownerId } })) >= MAX_RESOURCES_PER_USER) throw new CapReached()
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
        },
        select: { id: true },
      })
      return row.id
    })
  } catch (err) {
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
