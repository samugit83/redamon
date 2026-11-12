/**
 * GET / PATCH / DELETE /api/mute-rule-presets/[id] — one of the caller's presets.
 *
 * Another user's preset answers 404, exactly like a missing one, so the route
 * never confirms that an id exists. PATCH renames (name and description); the
 * rules are replaced by saving a new preset, which keeps a loaded preset's
 * badge honest: a project badges the name only while its rules match.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { ownsRow } from '@/lib/authz/rowOwner'
import { readJsonBody } from '@/lib/jsonBody'
import { coerceDoc } from '@/lib/nodeFilters/model'
import { parsePresetText, presetSummary } from '@/lib/nodeFilters/presets'
import { withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string }>
}

const NOT_FOUND = { error: 'Preset not found' }

async function ownPreset(id: string, userId: string) {
  const row = await prisma.userMuteRulesPreset.findUnique({ where: { id } })
  return row && ownsRow({ userId }, row.userId) ? row : null
}

export const GET = withRouteErrors('Failed to read the preset', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'self:presets')
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const row = await ownPreset(id, eff.userId)
  if (!row) return NextResponse.json(NOT_FOUND, { status: 404 })
  return NextResponse.json({ ...presetSummary(row), rules: coerceDoc(row.rules) })
})

export const PATCH = withRouteErrors('Failed to rename the preset', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'self:presets')
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const row = await ownPreset(id, eff.userId)
  if (!row) return NextResponse.json(NOT_FOUND, { status: 404 })

  const { name, description } = parsed.body
  const text = parsePresetText(name, description === undefined ? row.description : description)
  if (!text.ok) return NextResponse.json({ error: text.error }, { status: 400 })

  const updated = await prisma.userMuteRulesPreset.update({
    where: { id },
    data: { name: text.name, description: text.description },
  })
  return NextResponse.json(presetSummary(updated))
})

export const DELETE = withRouteErrors('Failed to delete the preset', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'self:presets')
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const row = await ownPreset(id, eff.userId)
  if (!row) return NextResponse.json(NOT_FOUND, { status: 404 })
  await prisma.userMuteRulesPreset.delete({ where: { id } })
  return NextResponse.json({ ok: true })
})
