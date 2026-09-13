import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info'])
const MAX_REMEDIATIONS = 200

// The rows come from an LLM, so every scalar is validated rather than cast.
// A cast of the wrong runtime type reaches Prisma and 500s the whole batch;
// worse, an unbounded string or array is stored and later rendered and fed
// back into the CodeFix prompt.
function str(value: unknown, max: number, fallback = ''): string {
  return typeof value === 'string' ? value.slice(0, max) : fallback
}

function strArray(value: unknown, max = 50, itemMax = 120): string[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((v): v is string => typeof v === 'string')
    .slice(0, max)
    .map((v) => v.slice(0, itemMax))
}

function int(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(min, Math.round(value)))
}

// POST /api/remediations/batch - Batch create remediations (triage agent via
// X-Internal-Key carve-out; browser callers must own the project).
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, remediations } = body

    if (!projectId || typeof projectId !== 'string' ||
        !Array.isArray(remediations) || remediations.length === 0) {
      return NextResponse.json(
        { error: 'projectId and non-empty remediations array are required' },
        { status: 400 }
      )
    }

    if (remediations.length > MAX_REMEDIATIONS) {
      return NextResponse.json(
        { error: `At most ${MAX_REMEDIATIONS} remediations per batch` },
        { status: 400 }
      )
    }

    const invalid = remediations.findIndex(
      (rem) => !rem || typeof rem !== 'object' || Array.isArray(rem) ||
        typeof (rem as Record<string, unknown>).title !== 'string' ||
        !(rem as Record<string, unknown>).title
    )
    if (invalid >= 0) {
      return NextResponse.json(
        { error: `Remediation at index ${invalid} has no title` },
        { status: 400 }
      )
    }

    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const access = await requireProjectAccess(eff, projectId)
      if (access instanceof NextResponse) return access
    }

    // Delete existing pending remediations for this project (re-triage replaces them)
    await prisma.remediation.deleteMany({
      where: { projectId, status: 'pending' },
    })

    // Batch create all new remediations
    const created = await prisma.$transaction(
      remediations.map((rem: Record<string, unknown>) =>
        prisma.remediation.create({
          data: {
            projectId,
            title: str(rem.title, 200),
            description: str(rem.description, 5000),
            severity: SEVERITIES.has(String(rem.severity)) ? String(rem.severity) : 'medium',
            priority: int(rem.priority, 0, 100000, 0),
            category: str(rem.category, 60, 'vulnerability') || 'vulnerability',
            remediationType: str(rem.remediationType, 60, 'code_fix') || 'code_fix',
            affectedAssets: strArray(rem.affectedAssets, 200, 300),
            cvssScore: typeof rem.cvssScore === 'number' && Number.isFinite(rem.cvssScore)
              ? Math.min(10, Math.max(0, rem.cvssScore))
              : undefined,
            cveIds: strArray(rem.cveIds),
            cweIds: strArray(rem.cweIds),
            capecIds: strArray(rem.capecIds),
            evidence: str(rem.evidence, 5000),
            attackChainPath: str(rem.attackChainPath, 2000),
            exploitAvailable: rem.exploitAvailable === true,
            cisaKev: rem.cisaKev === true,
            solution: str(rem.solution, 5000),
            fixComplexity: str(rem.fixComplexity, 40, 'medium') || 'medium',
            estimatedFiles: int(rem.estimatedFiles, 0, 1000, 0),
            // Never LLM output: the CodeFix agent takes its repository from
            // project settings, so this column is display-only.
            targetRepo: str(rem.targetRepo, 200),
            targetBranch: str(rem.targetBranch, 200, 'main') || 'main',
          },
        })
      )
    )

    return NextResponse.json(created, { status: 201 })
  } catch (error) {
    console.error('Failed to batch create remediations:', error)
    return NextResponse.json(
      { error: 'Failed to batch create remediations' },
      { status: 500 }
    )
  }
}
