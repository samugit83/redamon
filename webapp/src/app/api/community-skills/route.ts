import { NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// GET /api/community-skills — proxy to agentic service community skill catalog
export async function GET() {
  try {
    const res = await fetch(`${AGENT_API_URL}/community-skills`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!res.ok) {
      return NextResponse.json({ skills: [], total: 0 }, { status: 200 })
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch {
    // Agent service unreachable — return empty list so UI degrades gracefully
    return NextResponse.json({ skills: [], total: 0 }, { status: 200 })
  }
}
