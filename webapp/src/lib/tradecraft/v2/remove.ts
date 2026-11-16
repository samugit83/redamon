/**
 * Deleting a 2.0 resource removes everything it holds (R-196): the cascade of `schema.prisma`
 * takes its entries, sections, tree, page IDs, curations, jobs and project choices with the row.
 * Its running job is cancelled first; a job that ends later finds no resource and writes nothing
 * (the agent's writes are keyed by the resource, T1.4).
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { cancelJob } from '../jobs'

export async function removeResourceV2(input: { ownerId: string; resourceId: string }): Promise<NextResponse> {
  const { ownerId, resourceId } = input
  const cancelled = await cancelJob(ownerId, resourceId)
  if (!cancelled.found) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
  const { count } = await prisma.userTradecraftResource.deleteMany({ where: { id: resourceId, userId: ownerId } })
  if (count === 0) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
  return NextResponse.json({ success: true, cancelledJob: cancelled.job?.id ?? null })
}
