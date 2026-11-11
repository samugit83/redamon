import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'

/**
 * Tunnels are stored per account but run as one listener for the instance. The row
 * answered is the enabled one first (the last enable pushed it to the sandbox), then the
 * most recent save, then the lowest id, so every call names the same tunnel; step 2.4's
 * move to instance settings reuses this order.
 */
const TUNNEL_ROW_ORDER = [
  { tunnelsEnabled: 'desc' as const },
  { updatedAt: 'desc' as const },
  { id: 'asc' as const },
]

// GET /api/global/tunnel-config
// The unmasked tunnel credentials, for the internal key only (HD-05): the agent's
// chisel lookup (agentic/utils.py) is the caller. Anyone else, an admin's browser
// included, gets 404 before anything is read.
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  try {
    const settings = await prisma.userSettings.findFirst({
      where: {
        OR: [
          { ngrokAuthtoken: { not: '' } },
          { chiselServerUrl: { not: '' } },
        ],
      },
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
