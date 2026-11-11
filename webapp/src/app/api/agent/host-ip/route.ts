import { NextResponse } from 'next/server'
import { agentFetch } from '@/lib/agentFetch'
import { requireSession } from '@/lib/session'

// Proxies the agent's read-only /host-ip so the project settings UI can suggest
// the Docker host's LAN IP as the reverse-shell LHOST (issue #180). JWT-gated by
// middleware (not in PUBLIC_PATHS); the value is host-global infrastructure, not
// tenant data, so there is no per-project check. Returns { detectedHostIp: '' }
// on any failure so the caller degrades to showing no suggestion.
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const resp = await agentFetch('/host-ip', { cache: 'no-store' }, { timeoutMs: 5_000 })
    if (!resp.ok) {
      return NextResponse.json({ detectedHostIp: '' })
    }
    const data = await resp.json()
    const ip = typeof data?.detectedHostIp === 'string' ? data.detectedHostIp : ''
    return NextResponse.json({ detectedHostIp: ip })
  } catch {
    return NextResponse.json({ detectedHostIp: '' })
  }
}
