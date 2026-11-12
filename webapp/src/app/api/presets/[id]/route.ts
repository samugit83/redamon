import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { assertOwner } from '@/lib/access'
import { projectPresetForRead } from '@/lib/reconPresets/server'
import { clearPresetBadges } from '@/lib/reconPresets/badges'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const auth = await requirePermission(request, 'self:presets')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const preset = await prisma.userProjectPreset.findUnique({
      where: { id },
    })

    if (!preset) {
      return NextResponse.json({ error: 'Preset not found' }, { status: 404 })
    }
    const denied = assertOwner(eff, preset.userId)
    if (denied) return denied

    // The preset fields only: a preset stored before storage was filtered can
    // carry a target or a credential, and applying ignores those anyway.
    return NextResponse.json({ ...preset, settings: projectPresetForRead(preset.settings).settings })
  } catch (error) {
    return internalError(error, 'Failed to fetch preset')
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const auth = await requirePermission(request, 'preset:write')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const preset = await prisma.userProjectPreset.findUnique({
      where: { id },
    })

    if (!preset) {
      return NextResponse.json({ error: 'Preset not found' }, { status: 404 })
    }
    // Owner check against the effective user (was a client-supplied ?userId).
    const denied = assertOwner(eff, preset.userId)
    if (denied) return denied

    // The projects that loaded it keep their settings and lose only the badge
    // that names it.
    const badgesCleared = await prisma.$transaction(async tx => {
      await tx.userProjectPreset.delete({ where: { id } })
      return clearPresetBadges(tx, preset.userId, id)
    })

    return NextResponse.json({ success: true, badgesCleared })
  } catch (error) {
    return internalError(error, 'Failed to delete preset')
  }
}
