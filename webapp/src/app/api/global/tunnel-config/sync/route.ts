import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { constantTimeEqual } from '@/lib/constantTimeEqual'
import { instanceTunnelDown } from '@/lib/sharedInstanceSettings'

// POST /api/global/tunnel-config/sync
//
// The trigger the kali-sandbox worker calls on boot (mcp/kali-sandbox/entrypoint.sh).
//
// F-23 (ID-33, whatever the identity switch): only the sandbox may call it. It presents
// `Authorization: Bearer <TUNNEL_AUTH_TOKEN>`, the inbound token it already holds to check
// the webapp's pushes, compared here in constant time. An unset token refuses every call,
// the posture of the tunnel manager this pushes to (mcp/servers/tunnel_manager.py). The
// middleware lets the path through without a session; nginx closes it at the edge.
//
// STRIDE I19: a worker (re)boot must NEVER silently re-activate tunnels - that
// would re-expose internal listeners to the internet and break the LAN-only
// premise. So on boot we FORCE tunnels down: clear the `tunnelsEnabled` flag (the
// instance settings row's too, with the identity switch on) and push an empty (stop)
// config to the tunnel-manager. The operator must deliberately re-enable tunnels from
// Global Settings, which is the only activation path.
export async function POST(request: NextRequest) {
  const expected = process.env.TUNNEL_AUTH_TOKEN || ''
  if (!expected) {
    console.warn('[rbac] tunnel sync refused code=tunnel_token_unset: TUNNEL_AUTH_TOKEN is not set')
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const presented = (request.headers.get('authorization') || '').match(/^Bearer (.+)$/i)?.[1] ?? ''
  if (!presented || !constantTimeEqual(presented, expected)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    // Reflect reality in the UI: tunnels are down after a restart.
    await prisma.userSettings.updateMany({
      where: { tunnelsEnabled: true },
      data: { tunnelsEnabled: false },
    })
    await instanceTunnelDown()

    await fetch('http://kali-sandbox:8015/tunnel/configure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${expected}` },
      body: JSON.stringify({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }),
    })

    return NextResponse.json({ ok: true, configured: false })
  } catch (error) {
    console.error('Tunnel config sync failed:', error)
    // Return 200 so the worker's best-effort boot trigger does not retry-spam.
    return NextResponse.json({ ok: false })
  }
}
