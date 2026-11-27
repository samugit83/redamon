import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { gatherReportData } from '@/lib/report/reportData'
import {
  ALL_FRAMEWORK_IDS,
  evaluateCompliance,
  evidenceFromReportData,
  normalizeFrameworkIds,
} from '@/lib/compliance'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** GET /api/projects/{id}/compliance - Evaluate technical compliance posture from report evidence */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'reports:read', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const rawParam = request.nextUrl.searchParams.get('frameworks')
    const data = await gatherReportData(id)

    const frameworkIds = rawParam
      ? rawParam.trim().toLowerCase() === 'all'
        ? ALL_FRAMEWORK_IDS
        : normalizeFrameworkIds(rawParam.split(','))
      : normalizeFrameworkIds(data.project.roeComplianceFrameworks)

    const selected = frameworkIds.length > 0 ? frameworkIds : ALL_FRAMEWORK_IDS
    const evaluation = evaluateCompliance(evidenceFromReportData(data), selected)

    return NextResponse.json({
      projectId: id,
      configuredFrameworks: data.project.roeComplianceFrameworks ?? [],
      ...evaluation,
    })
  } catch (error) {
    return internalError(error, 'Failed to evaluate compliance mapping', {
      log: 'Compliance evaluation failed',
    })
  }
}
