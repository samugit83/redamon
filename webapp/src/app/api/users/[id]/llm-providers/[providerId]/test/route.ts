import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/users/[id]/llm-providers/[providerId]/test
// Also supports testing unsaved configs by passing full config in body
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const body = await request.json()

    let config: Record<string, unknown>

    if (providerId === 'unsaved') {
      // Testing an unsaved config — full config in body
      config = body
    } else {
      // Testing a saved config — fetch from DB with full keys
      const provider = await prisma.userLlmProvider.findFirst({
        where: { id: providerId, userId: id },
      })
      if (!provider) {
        return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
      }
      config = provider as unknown as Record<string, unknown>
    }

    // Proxy to agent test endpoint
    const agentResp = await fetch(`${AGENT_API_URL}/llm-provider/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    })

    const result = await agentResp.json()
    return NextResponse.json(result, { status: agentResp.status })
  } catch (error) {
    console.error('Failed to test LLM provider:', error)
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 }
    )
  }
}
