import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/users/[id]/chat-skills — List skills (id, name, description, category, createdAt; exclude content)
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const skills = await prisma.userChatSkill.findMany({
      where: { userId: id },
      select: { id: true, name: true, description: true, category: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })

    return NextResponse.json(skills)
  } catch (error) {
    console.error('Failed to fetch chat skills:', error)
    return NextResponse.json(
      { error: 'Failed to fetch chat skills' },
      { status: 500 }
    )
  }
}

const MAX_CONTENT_SIZE = 50 * 1024 // 50KB
const MAX_SKILLS_PER_USER = 50

// POST /api/users/[id]/chat-skills — Create skill { name, content, category?, description? }
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const { name, description, content, category } = body
    if (!name || typeof name !== 'string' || !name.trim()) {
      return NextResponse.json(
        { error: 'name is required' },
        { status: 400 }
      )
    }
    if (description !== undefined && description !== null) {
      if (typeof description !== 'string') {
        return NextResponse.json(
          { error: 'description must be a string' },
          { status: 400 }
        )
      }
      if (description.length > 500) {
        return NextResponse.json(
          { error: 'description must be 500 characters or less' },
          { status: 400 }
        )
      }
    }
    if (!content || typeof content !== 'string') {
      return NextResponse.json(
        { error: 'content is required' },
        { status: 400 }
      )
    }
    if (content.length > MAX_CONTENT_SIZE) {
      return NextResponse.json(
        { error: `content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB` },
        { status: 400 }
      )
    }
    if (category !== undefined && category !== null) {
      if (typeof category !== 'string') {
        return NextResponse.json(
          { error: 'category must be a string' },
          { status: 400 }
        )
      }
    }

    // Check skill count limit
    const count = await prisma.userChatSkill.count({ where: { userId: id } })
    if (count >= MAX_SKILLS_PER_USER) {
      return NextResponse.json(
        { error: `Maximum of ${MAX_SKILLS_PER_USER} skills per user reached` },
        { status: 400 }
      )
    }

    const skill = await prisma.userChatSkill.create({
      data: {
        userId: id,
        name: name.trim(),
        description: description?.trim() || null,
        category: category?.trim() || 'general',
        content,
      },
      select: { id: true, name: true, description: true, category: true, createdAt: true },
    })

    return NextResponse.json(skill, { status: 201 })
  } catch (error) {
    console.error('Failed to create chat skill:', error)
    return NextResponse.json(
      { error: 'Failed to create chat skill' },
      { status: 500 }
    )
  }
}
