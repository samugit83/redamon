import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'

interface RouteParams {
  params: Promise<{ id: string; skillId: string }>
}

// GET /api/users/[id]/attack-skills/[skillId] — Full skill with content (for download)
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params

    const skill = await prisma.userAttackSkill.findFirst({
      where: { id: skillId, userId: id },
    })

    if (!skill) {
      return NextResponse.json({ error: 'Skill not found' }, { status: 404 })
    }

    return NextResponse.json(skill)
  } catch (error) {
    console.error('Failed to fetch attack skill:', error)
    return NextResponse.json(
      { error: 'Failed to fetch attack skill' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/attack-skills/[skillId] — Update name or content
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params
    const body = await request.json()

    const existing = await prisma.userAttackSkill.findFirst({
      where: { id: skillId, userId: id },
    })

    if (!existing) {
      return NextResponse.json({ error: 'Skill not found' }, { status: 404 })
    }

    const data: { name?: string; description?: string | null; content?: string } = {}
    if (body.name !== undefined) {
      if (typeof body.name !== 'string' || !body.name.trim()) {
        return NextResponse.json({ error: 'name must be a non-empty string' }, { status: 400 })
      }
      data.name = body.name.trim()
    }
    if (body.description !== undefined) {
      if (body.description === null || body.description === '') {
        data.description = null
      } else if (typeof body.description !== 'string') {
        return NextResponse.json({ error: 'description must be a string' }, { status: 400 })
      } else if (body.description.length > 500) {
        return NextResponse.json({ error: 'description must be 500 characters or less' }, { status: 400 })
      } else {
        data.description = body.description.trim()
      }
    }
    if (body.content !== undefined) {
      if (typeof body.content !== 'string') {
        return NextResponse.json({ error: 'content must be a string' }, { status: 400 })
      }
      if (body.content.length > 50 * 1024) {
        return NextResponse.json({ error: 'content exceeds maximum size of 50KB' }, { status: 400 })
      }
      data.content = body.content
    }

    const updated = await prisma.userAttackSkill.update({
      where: { id: skillId },
      data,
      select: { id: true, name: true, description: true, createdAt: true },
    })

    return NextResponse.json(updated)
  } catch (error) {
    console.error('Failed to update attack skill:', error)
    return NextResponse.json(
      { error: 'Failed to update attack skill' },
      { status: 500 }
    )
  }
}

// DELETE /api/users/[id]/attack-skills/[skillId] — Delete + cascade cleanup
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params

    const existing = await prisma.userAttackSkill.findFirst({
      where: { id: skillId, userId: id },
    })

    if (!existing) {
      return NextResponse.json({ error: 'Skill not found' }, { status: 404 })
    }

    // Delete the skill
    await prisma.userAttackSkill.delete({ where: { id: skillId } })

    // Cascade: remove this skillId from attackSkillConfig.user in all user's projects
    const projects = await prisma.project.findMany({
      where: { userId: id },
      select: { id: true, attackSkillConfig: true },
    })

    for (const project of projects) {
      const config = (project.attackSkillConfig as Prisma.JsonObject) || {}
      const userConfig = (config.user as Prisma.JsonObject) || {}
      if (skillId in userConfig) {
        const { [skillId]: _, ...rest } = userConfig
        await prisma.project.update({
          where: { id: project.id },
          data: {
            attackSkillConfig: { ...config, user: rest },
          },
        })
      }
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete attack skill:', error)
    return NextResponse.json(
      { error: 'Failed to delete attack skill' },
      { status: 500 }
    )
  }
}
