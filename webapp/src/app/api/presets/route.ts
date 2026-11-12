import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { ownerScope } from '@/lib/access'
import {
  PRESET_DESCRIPTION_MAX,
  PRESET_NAME_MAX,
  presetSettingsForStorage,
  sanitizePresetText,
} from '@/lib/reconPresets/server'

// Presets are user-scoped; the client-supplied userId is ignored as an auth input.
export async function GET(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'self:presets')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    // Most recently written first, with which door wrote it: an agent-written
    // preset is badged in the drawer before a person applies it.
    const presets = await prisma.userProjectPreset.findMany({
      where: ownerScope(eff),
      orderBy: { updatedAt: 'desc' },
      select: {
        id: true,
        name: true,
        description: true,
        createdAt: true,
        updatedAt: true,
        createdVia: true,
        updatedVia: true,
        lastWriterTokenPrefix: true,
      },
    })

    return NextResponse.json(presets)
  } catch (error) {
    return internalError(error, 'Failed to fetch presets')
  }
}

export async function POST(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'preset:write')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const body = await request.json()
    const { name, description, settings } = body

    const cleanName = sanitizePresetText(name, PRESET_NAME_MAX)
    if (!cleanName) {
      return NextResponse.json({ error: 'Preset name is required' }, { status: 400 })
    }
    // Only preset fields are stored. This route used to store whatever object
    // arrived, which is how an old preset can carry a target or a credential.
    const stored = presetSettingsForStorage(settings)
    if (!stored.ok) {
      return NextResponse.json({ error: stored.error }, { status: 400 })
    }

    // Owner is the effective user, never a client-supplied body value.
    const preset = await prisma.userProjectPreset.create({
      data: {
        userId: eff.userId,
        name: cleanName,
        description: sanitizePresetText(description, PRESET_DESCRIPTION_MAX, { multiline: true }),
        settings: stored.settings as never,
        createdVia: 'ui',
        updatedVia: 'ui',
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
    return internalError(error, 'Failed to create preset')
  }
}
