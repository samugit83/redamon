import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/users/[id]/attack-skills/import-community — Import all community agent skills
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Fetch the community skills catalog from agentic /community-skills endpoint
    const catalogRes = await fetch(`${AGENT_API_URL}/community-skills`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!catalogRes.ok) {
      return NextResponse.json(
        { error: 'Failed to fetch community skills catalog from agent service' },
        { status: 502 }
      )
    }

    const catalog = await catalogRes.json()
    const skills: Array<{ id: string; name: string; description?: string }> = catalog.skills || []

    // Fetch user's existing attack skills to skip duplicates
    const existingSkills = await prisma.userAttackSkill.findMany({
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

      // Fetch full content for this community skill
      try {
        const contentRes = await fetch(`${AGENT_API_URL}/community-skills/${encodeURIComponent(skill.id)}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
          cache: 'no-store',
        })

        if (!contentRes.ok) {
          skipped++
          continue
        }

        const skillData = await contentRes.json()

        await prisma.userAttackSkill.create({
          data: {
            userId: id,
            name: skillData.name || skill.name,
            description: skillData.description || skill.description || null,
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
    console.error('Failed to import community attack skills:', error)
    return NextResponse.json(
      { error: 'Failed to import community attack skills' },
      { status: 500 }
    )
  }
}
