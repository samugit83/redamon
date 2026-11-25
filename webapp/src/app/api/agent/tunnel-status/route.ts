import { NextResponse } from 'next/server'
import { agentFetch } from '@/lib/agentFetch'
import { requireSession } from '@/lib/session'
import { tunnelStatusPath } from '@/lib/sharedSettingsEffects'

// `status` as the tunnel manager answers it, so an indicator reads the fallback like any answer.
const INACTIVE = { ngrok: { active: false, status: 'off' }, chisel: { active: false, status: 'off' } }

// Read-only indicator: an unreachable agent reads as "no tunnel", never an error. It shows the
// signed-in person's own tunnel, and none under act-as (tunnelStatusPath), asked of the agent with
// the master key agentFetch sends.
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
