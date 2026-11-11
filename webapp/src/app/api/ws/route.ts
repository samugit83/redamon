/**
 * WebSocket Proxy Route
 *
 * Proxies WebSocket connections from the Next.js frontend to the FastAPI backend.
 * This avoids CORS issues by keeping the connection within the same origin.
 */

import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const backendWsUrl = process.env.AGENT_WS_URL || 'ws://localhost:8090/ws/agent'

  // For Next.js, we can't directly proxy WebSocket in API routes
  // Instead, return instructions for the client
  return new Response(
    JSON.stringify({
      error: 'WebSocket proxy not supported in Next.js API routes',
      suggestion: 'Use direct connection',
      backend_url: backendWsUrl
    }),
    {
      status: 501,
      headers: { 'Content-Type': 'application/json' }
    }
  )
}
