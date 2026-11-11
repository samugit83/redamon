import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireSession } from '@/lib/session'

// GET /api/global/tunnel-config
// Internal-only endpoint for kali-sandbox boot and agent runtime.
// Returns unmasked tunnel credentials from the first user's settings.
export async function GET(request: NextRequest) {
  // The agent's chisel lookup calls this with X-Internal-Key and no cookie
  // (agentic/utils.py), so the key is admitted before the session check.
  if (!isInternalRequest(request)) {
    const session = await requireSession()
    if (session instanceof NextResponse) return session
  }
  try {
    const settings = await prisma.userSettings.findFirst({
      where: {
        OR: [
          { ngrokAuthtoken: { not: '' } },
          { chiselServerUrl: { not: '' } },
        ],
      },
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
