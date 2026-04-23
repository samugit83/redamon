import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// GET /api/models?userId=xxx - Fetch available AI models from all configured providers
export async function GET(request: NextRequest) {
  try {
    const userId = request.nextUrl.searchParams.get('userId')

    let providersParam = ''

    // If userId provided, fetch their LLM providers from DB and pass to agent
    if (userId) {
      const providers = await prisma.userLlmProvider.findMany({
        where: { userId },
      })
      if (providers.length > 0) {
        providersParam = `?providers=${encodeURIComponent(JSON.stringify(providers))}`
      }
    }

    const res = await fetch(`${AGENT_API_URL}/models${providersParam}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!res.ok) {
      console.error('Failed to fetch models from agent API:', await res.text())
      return NextResponse.json(
        { error: 'Failed to fetch models from agent API' },
        { status: 503 }
      )
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Failed to connect to agent API for models:', error)
    return NextResponse.json(
      { error: 'Failed to connect to agent API' },
      { status: 503 }
    )
  }
}
