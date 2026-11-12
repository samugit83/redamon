/**
 * GET / POST /api/mute-rule-presets — the caller's saved Mute Rules presets.
 *
 * A preset belongs to a user, not a project, so it can be loaded into any
 * project that user owns. The list carries each preset's rule counts but not
 * its rules; GET /api/mute-rule-presets/[id] returns those for a load.
 *
 * POST refuses rules the engine would not run as written, the same check a
 * save makes, so a preset loads cleanly into any project while the catalog
 * still has its fields.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { ownerScope } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'
import { readJsonBody } from '@/lib/jsonBody'
import { coerceDoc } from '@/lib/nodeFilters/model'
import { parsePresetText, presetSummary } from '@/lib/nodeFilters/presets'
import { allErrors, validateNodeFilters } from '@/lib/nodeFilters/validate'
import { withRouteErrors } from '@/lib/routeErrors'

const ROW_SELECT = {
  id: true, name: true, description: true, mode: true, rules: true, createdAt: true, updatedAt: true,
} as const

export const GET = withRouteErrors('Failed to load the presets', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'self:presets')
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const rows = await prisma.userMuteRulesPreset.findMany({
    where: ownerScope(eff),
    orderBy: { updatedAt: 'desc' },
    select: ROW_SELECT,
  })
  return NextResponse.json(rows.map(presetSummary))
})

export const POST = withRouteErrors('Failed to save the preset', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'self:presets')
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed

  const { name, description, mode, rules } = parsed.body
  const text = parsePresetText(name, description)
  if (!text.ok) return NextResponse.json({ error: text.error }, { status: 400 })

  const verdict = validateNodeFilters(mode, rules)
  const errors = allErrors(verdict)
  if (!verdict.ok || errors.length > 0) {
    return NextResponse.json({ error: 'The rules are not valid.', errors }, { status: 400 })
  }

  // Owner is the effective user, never a value from the body.
  const row = await prisma.userMuteRulesPreset.create({
    data: {
      userId: eff.userId,
      name: text.name,
      description: text.description,
      mode: mode as string,
      rules: coerceDoc(rules) as never,
    },
    select: ROW_SELECT,
  })
  return NextResponse.json(presetSummary(row), { status: 201 })
})
