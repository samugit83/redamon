import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// PATCH /api/conversations/by-session/[sessionId]/fireteams/[fireteamIdKey]/members/[memberIdKey]
// Update a fireteam member's final state. Called by agent when the member exits.
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string; fireteamIdKey: string; memberIdKey: string }> }
) {
  try {
    const { memberIdKey } = await params
    const body = await request.json()
    const updates: Record<string, unknown> = {}

    if (typeof body.status === 'string') updates.status = body.status
    if (typeof body.completionReason === 'string') updates.completionReason = body.completionReason
    if (typeof body.iterationsUsed === 'number') updates.iterationsUsed = body.iterationsUsed
    if (typeof body.tokensUsed === 'number') updates.tokensUsed = body.tokensUsed
    if (typeof body.findingsCount === 'number') updates.findingsCount = body.findingsCount
    if (typeof body.wallClockSeconds === 'number') updates.wallClockSeconds = body.wallClockSeconds
    if (body.errorMessage !== undefined) updates.errorMessage = body.errorMessage
    if (body.resultBlob !== undefined) updates.resultBlob = body.resultBlob

    if (updates.status && updates.status !== 'running') {
      updates.completedAt = new Date()
    }

    const member = await prisma.fireteamMember.update({
      where: { memberIdKey },
      data: updates,
    })
    return NextResponse.json({ id: member.id, status: member.status })
  } catch (error: any) {
    if (error?.code === 'P2025') {
      return NextResponse.json({ error: 'Member not found' }, { status: 404 })
    }
    console.error('Failed to patch fireteam member:', error)
    return NextResponse.json({ error: 'Failed to patch fireteam member' }, { status: 500 })
  }
}
