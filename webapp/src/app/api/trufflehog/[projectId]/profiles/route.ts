import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import {
  getTrufflehogSource,
  rejectTrufflehogSecretFields,
  resolveMissingCredentials,
  validateTrufflehogConfig,
  TRUFFLEHOG_CREDENTIAL_FIELDS,
} from '@/lib/trufflehogSources'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const CREDENTIAL_SELECT = Object.fromEntries(
  TRUFFLEHOG_CREDENTIAL_FIELDS.map(f => [f, true]),
) as Record<string, true>

/**
 * List the project's configured sources.
 *
 * Each row carries `missingCredentials` so the card can disable Start and say
 * which key to set, without the client ever seeing a credential VALUE — only
 * the names of the ones that are empty.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  // Without the catch a DB error is Next's empty 500, which the card reads as
  // "no sources configured".
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true },
    })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    const [profiles, settings] = await Promise.all([
      prisma.trufflehogScanProfile.findMany({
        where: { projectId },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.userSettings.findUnique({
        where: { userId: project.userId },
        select: CREDENTIAL_SELECT,
      }),
    ])

    return NextResponse.json({
      profiles: profiles.map(p => {
        const config = (p.config ?? {}) as Record<string, unknown>
        return {
          ...p,
          validationErrors: validateTrufflehogConfig(p.source, config),
          missingCredentials: resolveMissingCredentials(
            p.source, config, settings as Record<string, unknown> | null,
          ).map(c => ({ settingsKey: c.settingsKey, label: c.label })),
        }
      }),
    })
  } catch (error) {
    return internalError(error, 'Failed to list sources', { log: 'Error listing TruffleHog profiles' })
  }
}

/**
 * Create a profile for a source.
 *
 * The unique (projectId, source) constraint is what makes "one run per source"
 * a database invariant rather than a convention — the same rule the runtime run
 * key enforces.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:secrets', { projectId })
    if (auth instanceof NextResponse) return auth

    const body = await request.json().catch(() => ({}))
    const src = getTrufflehogSource(String(body.source ?? ''))
    if (!src) {
      return NextResponse.json(
        { error: `Unknown Secret Multiscanner source: ${body.source}` },
        { status: 400 },
      )
    }

    const config = (body.config ?? {}) as Record<string, unknown>
    const rejected = rejectTrufflehogSecretFields(src.id, config)
    if (rejected) return NextResponse.json({ error: rejected }, { status: 400 })

    const existing = await prisma.trufflehogScanProfile.findUnique({
      where: { projectId_source: { projectId, source: src.id } },
      select: { id: true },
    })
    if (existing) {
      return NextResponse.json(
        { error: `A ${src.label} profile already exists for this project` },
        { status: 409 },
      )
    }

    try {
      const profile = await prisma.trufflehogScanProfile.create({
        data: {
          projectId,
          source: src.id,
          label: String(body.label ?? '').slice(0, 200),
          config: config as Prisma.InputJsonValue,
        },
      })
      return NextResponse.json({ profile }, { status: 201 })
    } catch (e) {
      // The check above is not atomic with the insert. A double-submitted form
      // loses that race and hits the unique (projectId, source) index; report
      // the same 409 the check would have, not a 500.
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        return NextResponse.json(
          { error: `A ${src.label} profile already exists for this project` },
          { status: 409 },
        )
      }
      throw e
    }
  } catch (error) {
    return internalError(error, 'Failed to add the source', { log: 'Error creating TruffleHog profile' })
  }
}
