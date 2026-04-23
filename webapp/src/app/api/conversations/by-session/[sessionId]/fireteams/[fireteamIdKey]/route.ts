import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// PATCH /api/conversations/by-session/[sessionId]/fireteams/[fireteamIdKey]
// Update a fireteam's status and final stats. Called by agent on completion.
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string; fireteamIdKey: string }> }
) {
  try {
    const { fireteamIdKey } = await params
    const body = await request.json()
    const updates: Record<string, unknown> = {}
    if (typeof body.status === 'string') updates.status = body.status
    if (body.statusCounts !== undefined) updates.statusCounts = body.statusCounts
    if (typeof body.wallClockSeconds === 'number') updates.wallClockSeconds = body.wallClockSeconds
    if (body.completedAt === undefined && updates.status && updates.status !== 'running' && updates.status !== 'pending') {
      updates.completedAt = new Date()
    }
    const fireteam = await prisma.fireteam.update({
      where: { fireteamIdKey },
      data: updates,
    })
    return NextResponse.json({ id: fireteam.id, status: fireteam.status })
  } catch (error: any) {
    if (error?.code === 'P2025') {
      return NextResponse.json({ error: 'Fireteam not found' }, { status: 404 })
    }
    console.error('Failed to patch fireteam:', error)
    return NextResponse.json({ error: 'Failed to patch fireteam' }, { status: 500 })
  }
}
