import { NextResponse } from 'next/server'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export async function GET() {
  try {
    const response = await fetch(`${RECON_ORCHESTRATOR_URL}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      return NextResponse.json({ available: false })
    }

    const data = await response.json()
    return NextResponse.json({ available: data.gvm_available ?? false })
  } catch {
    return NextResponse.json({ available: false })
  }
}
