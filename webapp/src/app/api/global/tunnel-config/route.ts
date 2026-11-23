import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { validUserId } from '@/lib/sandbox/orchestratorClient'

const EMPTY = { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }

// GET /api/global/tunnel-config?userId=
// The unmasked tunnel credentials of one person, for the internal key only (HD-05): the
// agent's chisel lookup (agentic/utils.py) is the caller. Anyone else, an admin's browser
// included, gets 404 before anything is read.
//
// Every person has their own tunnel in their own Kali sandbox (group 1, OQ-G1-2 A), so the agent
// names the person and gets that person's own row while their tunnel is on, else empty values.
// No person, an id that is not one, and the unused instance row answer nothing: one person's
// chisel host must never become another person's reverse-shell address.
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  try {
    const userId = request.nextUrl.searchParams.get('userId')
    if (!validUserId(userId)) return NextResponse.json(EMPTY)
    const own = await prisma.userSettings.findUnique({
      where: { userId },
      select: { tunnelsEnabled: true, ngrokAuthtoken: true, chiselServerUrl: true, chiselAuth: true },
    })
    if (!own?.tunnelsEnabled) return NextResponse.json(EMPTY)
    const { ngrokAuthtoken, chiselServerUrl, chiselAuth } = own
    return NextResponse.json({ ngrokAuthtoken, chiselServerUrl, chiselAuth })
  } catch (error) {
    console.error('Failed to fetch tunnel config:', error)
    return NextResponse.json(EMPTY)
  }
}
