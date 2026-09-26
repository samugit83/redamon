import type { Prisma } from '@prisma/client'
import { extractPresetSettings } from '@/lib/project-preset-utils'
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, ownerScope } from '@/lib/access'

// Presets are user-scoped; the client-supplied userId is ignored as an auth input.
export async function GET() {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const presets = await prisma.userProjectPreset.findMany({
      where: ownerScope(eff),
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        description: true,
        createdAt: true,
      },
    })

    return NextResponse.json(presets)
  } catch (error) {
    console.error('Failed to fetch presets:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to fetch presets' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const body = await request.json()
    const { name, description, settings } = body

    if (!name || !name.trim()) {
      return NextResponse.json({ error: 'Preset name is required' }, { status: 400 })
    }
    if (!settings || typeof settings !== 'object') {
      return NextResponse.json({ error: 'Settings object is required' }, { status: 400 })
    }

    // Owner is the effective user, never a client-supplied body value.
    const preset = await prisma.userProjectPreset.create({
      data: {
        userId: eff.userId,
        name: name.trim(),
        description: (description || '').trim(),
        settings: extractPresetSettings(settings) as Prisma.InputJsonObject,
      },
      select: {
        id: true,
        name: true,
        description: true,
        createdAt: true,
      },
    })

    return NextResponse.json(preset, { status: 201 })
  } catch (error) {
    console.error('Failed to create preset:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to create preset' },
      { status: 500 }
    )
  }
}
