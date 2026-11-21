import { NextResponse } from 'next/server'
import { agentFetch } from '@/lib/agentFetch'
import { requireSession } from '@/lib/session'
import { tunnelStatusPath } from '@/lib/sharedSettingsEffects'

const INACTIVE = { ngrok: { active: false }, chisel: { active: false } }

// Read-only indicator: an unreachable agent reads as "no tunnel", never an error. With per-user
// Kali sandboxes it shows the signed-in effective person's own tunnel (tunnelStatusPath), asked
// of the agent with the master key agentFetch sends.
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const path = await tunnelStatusPath()
    if (!path) return NextResponse.json(INACTIVE)
    const resp = await agentFetch(path, { cache: 'no-store' }, { timeoutMs: 5_000 })
    if (!resp.ok) return NextResponse.json(INACTIVE, { status: 200 })
    return NextResponse.json(await resp.json())
  } catch {
    return NextResponse.json(INACTIVE)
  }
}
