import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { TUNNEL_CANDIDATE_WHERE, TUNNEL_ROW_ORDER, instanceSettingsInForce } from '@/lib/sharedInstanceSettings'

// GET /api/global/tunnel-config
// The unmasked tunnel credentials, for the internal key only (HD-05): the agent's
// chisel lookup (agentic/utils.py) is the caller. Anyone else, an admin's browser
// included, gets 404 before anything is read. With the identity switch on they come from
// the instance settings row (step 2.4); until the boot backfill fills it, and with the
// switch off, from the user row TUNNEL_ROW_ORDER picks.
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  try {
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
