/**
 * Refresh (and Verify) of a 2.0 resource: a background job, answered at once with its view
 * (R-097). The job reads the resource's current settings when it starts; the previous map
 * stays live until the new one is swapped in, and a cancel or a failure keeps it.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { jobStartResponse, startJob, type JobActor } from '../jobs'
import { loadOwnResource } from '../resourceAccess'

export async function refreshResourceV2(input: { ownerId: string; resourceId: string; actor: JobActor }): Promise<NextResponse> {
  const { ownerId, resourceId, actor } = input
  const existing = await loadOwnResource(ownerId, resourceId)
  if (!existing) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
  const account = existing.githubTokenOverride
    ? null
    : await prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } })
  // The account's GitHub token stays with the account while someone acts as it (step 3.14).
  if (existing.githubTokenOverride || account?.githubAccessToken) {
    const actingAs = await refuseWhileActingAsOn(ownerId, 'use_github_token')
    if (actingAs) return actingAs
  }
  return jobStartResponse(await startJob({ ownerId, resourceId, kind: 'refresh', actor }))
}
