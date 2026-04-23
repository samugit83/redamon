import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/users/[id]/chat-skills/import-community — Import all chat skills from agentic catalog
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Fetch the chat skills catalog from agentic /skills endpoint
    const catalogRes = await fetch(`${AGENT_API_URL}/skills`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!catalogRes.ok) {
      return NextResponse.json(
        { error: 'Failed to fetch skills catalog from agent service' },
        { status: 502 }
      )
    }

    const catalog = await catalogRes.json()
    const skills: Array<{ id: string; name: string; description?: string; category?: string }> = catalog.skills || []

    // Fetch user's existing chat skills to skip duplicates
    const existingSkills = await prisma.userChatSkill.findMany({
      where: { userId: id },
      select: { name: true },
    })
    const existingNames = new Set(existingSkills.map((s) => s.name))

    let imported = 0
    let skipped = 0

    for (const skill of skills) {
      if (existingNames.has(skill.name)) {
        skipped++
        continue
      }

      // Fetch full content for this skill
      try {
        const contentRes = await fetch(`${AGENT_API_URL}/skills/${encodeURIComponent(skill.id)}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
          cache: 'no-store',
        })

        if (!contentRes.ok) {
          skipped++
          continue
        }

        const skillData = await contentRes.json()

        await prisma.userChatSkill.create({
          data: {
            userId: id,
            name: skillData.name || skill.name,
            description: skillData.description || skill.description || null,
            category: skillData.category || skill.category || 'general',
            content: skillData.content,
          },
        })

        imported++
      } catch {
        skipped++
      }
    }

    return NextResponse.json({ imported, skipped, total: skills.length })
  } catch (error) {
    console.error('Failed to import community chat skills:', error)
    return NextResponse.json(
      { error: 'Failed to import community chat skills' },
      { status: 500 }
    )
  }
}
