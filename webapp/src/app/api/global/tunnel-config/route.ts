import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { TUNNEL_CANDIDATE_WHERE, TUNNEL_ROW_ORDER, instanceSettingsInForce } from '@/lib/sharedInstanceSettings'
import { tunnelMode } from '@/lib/sharedSettingsEffects'
import { validUserId } from '@/lib/sandbox/orchestratorClient'

const EMPTY = { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }

// GET /api/global/tunnel-config
// The unmasked tunnel credentials, for the internal key only (HD-05): the agent's
// chisel lookup (agentic/utils.py) is the caller. Anyone else, an admin's browser
// included, gets 404 before anything is read. With the identity switch on they come from
// the instance settings row (step 2.4); until the boot backfill fills it, and with the
// switch off, from the user row TUNNEL_ROW_ORDER picks.
//
// Per-user Kali sandboxes (group 1, OQ-G1-2 A): every person has their own tunnel, so the agent
// names the person (`?userId=`) and gets that person's own row while their tunnel is on, else
// empty values. No person, an id that is not one, and the unused instance row answer nothing:
// one person's chisel host must never become another person's reverse-shell address. Before the
// orchestrator has named a mode it answers nothing either: the row picked for everybody may be a
// person's own tunnel.
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  try {
    const { mode, named } = await tunnelMode()
    if (!named) return NextResponse.json(EMPTY)
    if (mode === 'per_user') {
      const userId = request.nextUrl.searchParams.get('userId')
      if (!validUserId(userId)) return NextResponse.json(EMPTY)
      const own = await prisma.userSettings.findUnique({
        where: { userId },
        select: { tunnelsEnabled: true, ngrokAuthtoken: true, chiselServerUrl: true, chiselAuth: true },
      })
      if (!own?.tunnelsEnabled) return NextResponse.json(EMPTY)
      const { ngrokAuthtoken, chiselServerUrl, chiselAuth } = own
      return NextResponse.json({ ngrokAuthtoken, chiselServerUrl, chiselAuth })
    }
    const instance = await instanceSettingsInForce()
    if (instance) {
      const { ngrokAuthtoken, chiselServerUrl, chiselAuth } = instance
      return NextResponse.json({ ngrokAuthtoken, chiselServerUrl, chiselAuth })
    }
    const settings = await prisma.userSettings.findFirst({
      where: TUNNEL_CANDIDATE_WHERE,
      orderBy: TUNNEL_ROW_ORDER,
      select: {
        ngrokAuthtoken: true,
        chiselServerUrl: true,
        chiselAuth: true,
      },
    })

    if (!settings) {
      return NextResponse.json({
        ngrokAuthtoken: '',
        chiselServerUrl: '',
        chiselAuth: '',
      })
    }

    return NextResponse.json(settings)
  } catch (error) {
    console.error('Failed to fetch tunnel config:', error)
    return NextResponse.json(
      { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }
    )
  }
}
