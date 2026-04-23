import { NextRequest } from 'next/server'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params

  // Proxy the SSE stream from the recon orchestrator
  const response = await fetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/logs`, {
    headers: {
      'Accept': 'text/event-stream',
    },
    signal: request.signal,
  })

  if (!response.ok) {
    return new Response(
      JSON.stringify({ error: 'Failed to connect to TruffleHog log stream' }),
      { status: response.status, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // Forward the SSE stream directly to the client
  return new Response(response.body, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
    },
  })
}
