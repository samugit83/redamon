import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// GET /api/global/tunnel-config
// Internal-only endpoint for kali-sandbox boot and agent runtime.
// Returns unmasked tunnel credentials from the first user's settings.
export async function GET() {
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
