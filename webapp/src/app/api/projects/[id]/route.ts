import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'
import { unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { clearProjectGraph } from '@/lib/graphRestore'
import { orchestratorFetch } from '@/lib/orchestrator'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { normalizeOpenApiSourceIds, validateOpenApiSettings } from '@/lib/validation/openapiSettings'

// Path to output directories (fallback for local deletion)
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/gvm_scan/output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/github_secret_hunt/output'

// Recon orchestrator URL for file deletion
const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/projects/[id] - Get project with all params
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership: the agent/orchestrator (INTERNAL_API_KEY) and scanners
    // (SCANNER_API_KEY, S3/E6) read projects with X-Internal-Key (carve-out);
    // every browser caller may only read a project owned by their effective user
    // (admin only while simulating that user). Closes the BOLA where any
    // logged-in user could read another user's project by id (S15/E15).
    if (!isInternalRequest(request) && !isScannerRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const access = await requireProjectAccess(eff, id)
      if (access instanceof NextResponse) return access
    }

    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        }
      }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    // Exclude binary document data from regular responses (use /roe/download instead)
    const { roeDocumentData: _binary, ...projectWithoutBinary } = project

    // If ?includeSkillContent=true, fetch enabled user skill contents for agent consumption
    // Skills default to ON when not present in config.user (matching frontend behaviour).
    const includeSkillContent = request.nextUrl.searchParams.get('includeSkillContent') === 'true'
    if (includeSkillContent && project.userId) {
      const config = (project.attackSkillConfig as Prisma.JsonObject) || {}
      const userToggles = (config.user as Prisma.JsonObject) || {}

      // IDs explicitly disabled (set to false)
      const disabledIds = Object.entries(userToggles)
        .filter(([, v]) => v === false)
        .map(([id]) => id)

      // Fetch all user skills EXCEPT explicitly disabled ones
      const skills = await prisma.userAttackSkill.findMany({
        where: {
          userId: project.userId,
          ...(disabledIds.length > 0 ? { id: { notIn: disabledIds } } : {}),
        },
        select: { id: true, name: true, description: true, content: true },
      })

      // User-managed MCP servers (UI-driven via /settings/mcp). Read raw
      // from UserSettings.mcpServers; the agent validates and merges them
      // with system MCP servers via mcp_registry.parse_user_servers().
      const userSettings = await prisma.userSettings.findUnique({
        where: { userId: project.userId },
        select: { mcpServers: true },
      })
      const userMcpServers = (userSettings?.mcpServers as Prisma.JsonValue) ?? []

      return NextResponse.json({
        ...projectWithoutBinary,
        userAttackSkills: skills,
        userMcpServers,
      })
    }

    return NextResponse.json(projectWithoutBinary)
  } catch (error) {
    console.error('Failed to fetch project:', error)
    return NextResponse.json(
      { error: 'Failed to fetch project' },
      { status: 500 }
    )
  }
}

// PUT /api/projects/[id] - Update project params
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Only the project's effective owner may mutate it (admin while simulating).
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const body = await request.json()

    // Remove fields that shouldn't be updated directly
    const { userId, createdAt, updatedAt, user, ...updateData } = body

    const openapiError = validateOpenApiSettings(updateData)
    if (openapiError) {
      return NextResponse.json({ error: openapiError }, { status: 400 })
    }
    if ('openapiSources' in updateData) {
      updateData.openapiSources = normalizeOpenApiSourceIds(updateData.openapiSources)
    }

    // Sanitize string inputs that are used as hostnames/IPs (trailing spaces break DNS)
    if (typeof updateData.targetDomain === 'string') {
      updateData.targetDomain = updateData.targetDomain.trim()
    }
    if (Array.isArray(updateData.subdomainList)) {
      updateData.subdomainList = updateData.subdomainList.map((s: string) => s.trim()).filter(Boolean)
    }
    if (Array.isArray(updateData.targetIps)) {
      updateData.targetIps = updateData.targetIps.map((s: string) => s.trim()).filter(Boolean)
    }

    // Domain batch: the derived groups are the project's SCOPE (the hard guardrail,
    // the agent and the pipeline all read them), so they are recomputed here from
    // the raw host list and a client-supplied domainBatchGroups is NEVER trusted.
    //
    // Keyed on the project actually BEING a batch, not on the key being present in
    // the body: the project form PUTs the whole row, so `domainBatchHosts: []` is
    // present on every single-domain and IP project too. Validating on presence
    // rejected all of those with "Domain batch mode needs at least one hostname"
    // and made every project edit fail.
    const willBeBatch = 'domainBatchMode' in updateData
      ? updateData.domainBatchMode === true
      : (await prisma.project.findUnique({
          where: { id }, select: { domainBatchMode: true },
        }))?.domainBatchMode === true

    // A client-supplied grouping is never trusted; it is always re-derived below.
    if ('domainBatchGroups' in updateData) delete updateData.domainBatchGroups

    // Re-derive the scope ONLY when this update actually changes the host list or
    // flips the mode. A partial save - a single module toggle auto-saving
    // `{ katanaEnabled: false }` - carries neither, so the stored groups are left
    // untouched. Without this guard the absent domainBatchHosts read as empty and
    // every field toggle on a batch project 400'd with "needs at least one hostname".
    const touchesBatchScope = 'domainBatchHosts' in updateData || 'domainBatchMode' in updateData
    if (willBeBatch && touchesBatchScope) {
      const { validateDomainBatch } = await import('@/lib/domainBatch')
      const raw = updateData.domainBatchHosts
      const hosts: string[] = Array.isArray(raw)
        ? raw.filter((h: unknown): h is string => typeof h === 'string')
        : typeof raw === 'string' ? raw.split(',') : []
      const batch = validateDomainBatch(hosts)
      if (!batch.ok) {
        return NextResponse.json({ error: batch.errors.join(' ') }, { status: 400 })
      }
      updateData.domainBatchHosts = batch.groups.flatMap(g => g.hosts)
      updateData.domainBatchGroups = batch.groups
    }

    // Mutually exclusive modes, enforced on update as well as create: recon checks
    // IP_MODE first, so a project flagged both ways silently never runs its batch.
    const nextIpMode = 'ipMode' in updateData ? updateData.ipMode === true : undefined
    const nextBatchMode = 'domainBatchMode' in updateData ? updateData.domainBatchMode === true : undefined
    if (nextIpMode && nextBatchMode) {
      return NextResponse.json(
        { error: 'A project cannot be in both IP mode and Domain batch mode.' },
        { status: 400 },
      )
    }

    // Supply-chain input: supplyChainRepoUrl becomes a `git clone` argument in
    // the scan container, so it is validated server-side. The Other Scans UI
    // validates too, but a direct PUT bypasses it.
    // A GitHub Enterprise host is allowed only when the operator registered it in
    // their global settings, so the allowlist is read from there (never from the
    // request). Only looked up when a supply-chain field is actually being written.
    if ('supplyChainRepoUrl' in updateData || 'supplyChainInputMode' in updateData
        || 'supplyChainRepoRef' in updateData || 'supplyChainOrgName' in updateData) {
      const [{ validateSupplyChainInput }, { allowedGithubHosts }] = await Promise.all([
        import('@/lib/validation/supplyChainInput'),
        import('@/lib/github/ownerTarget'),
      ])
      const userSettings = await prisma.userSettings.findUnique({
        where: { userId: eff.userId }, select: { githubEnterpriseHost: true },
      }).catch(() => null)
      const err = validateSupplyChainInput(
        updateData, allowedGithubHosts(userSettings?.githubEnterpriseHost))
      if (err) {
        return NextResponse.json({ error: err }, { status: 400 })
      }
    }

    // Fireteam settings: server-side Zod validation so a direct API call
    // with out-of-range values (bypassing the UI form) still gets rejected.
    // Only validate when at least one fireteam field is being touched.
    const FIRETEAM_FIELDS = ['fireteamEnabled', 'fireteamMaxConcurrent',
      'fireteamMaxMembers', 'fireteamMemberMaxIterations',
      'fireteamTimeoutSec', 'fireteamAllowedPhases',
      'fireteamPropensity'] as const
    const touchesFireteam = FIRETEAM_FIELDS.some(k => k in updateData)
    let fireteamOldValues: Record<string, unknown> | null = null
    if (touchesFireteam) {
      const { validateFireteamSettings } = await import('@/lib/validation/fireteamSettings')
      const err = validateFireteamSettings(updateData)
      if (err) {
        return NextResponse.json({ error: err }, { status: 400 })
      }
      // Capture old values for audit log BEFORE the update.
      const existing = await prisma.project.findUnique({
        where: { id },
        select: Object.fromEntries(FIRETEAM_FIELDS.map(k => [k, true])) as any,
      })
      fireteamOldValues = existing as Record<string, unknown> | null
    }

    const project = await prisma.project.update({
      where: { id },
      data: updateData
    })

    // Audit trail for fireteam settings changes. Best-effort: audit failure
    // must not roll back the update.
    if (touchesFireteam && fireteamOldValues) {
      try {
        const auditRows = []
        for (const field of FIRETEAM_FIELDS) {
          if (!(field in updateData)) continue
          const oldV = fireteamOldValues[field]
          const newV = (updateData as Record<string, unknown>)[field]
          if (JSON.stringify(oldV) === JSON.stringify(newV)) continue
          auditRows.push({
            projectId: id,
            userId: (project as { userId?: string | null }).userId ?? null,
            field,
            oldValue: oldV === undefined ? null : (oldV as any),
            newValue: newV === undefined ? null : (newV as any),
            source: 'api',
          })
        }
        if (auditRows.length > 0) {
          await prisma.fireteamSettingsAudit.createMany({ data: auditRows })
        }
      } catch (e) {
        console.warn('Fireteam settings audit write failed:', e)
      }
    }

    // Ensure Domain node exists in Neo4j (create if missing, update if domain changed)
    if (!project.ipMode && project.targetDomain) {
      try {
        const session = getGraphSession()
        try {
          await session.run(
            `MERGE (d:Domain {name: $name, user_id: $userId, project_id: $projectId})
             ON CREATE SET d.source = 'project_creation', d.updated_at = datetime()`,
            { name: project.targetDomain, userId: project.userId, projectId: project.id }
          )
        } finally {
          await session.close()
        }
      } catch (e) {
        console.warn('Failed to ensure Domain node in Neo4j on project update:', e)
      }
    }

    // Exclude binary document data from response (same as GET)
    const { roeDocumentData: _binary, ...projectWithoutBinary } = project
    return NextResponse.json(projectWithoutBinary)
  } catch (error: unknown) {
    console.error('Failed to update project:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update project' },
      { status: 500 }
    )
  }
}

// DELETE /api/projects/[id] - Delete project and all associated data
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Only the project's effective owner may delete it (admin while simulating).
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    // Collect captured-traffic body refs BEFORE the cascade removes the rows, so
    // we can ref-counted-GC the now-unreferenced blobs afterward (§6.6). Prisma
    // cascade removes the rows but never touches the filesystem.
    let capturedBodyRefs: (string | null)[] = []
    try {
      const doomed = await prisma.capturedHttpTransaction.findMany({
        where: { projectId: id }, select: { reqBodyRef: true, respBodyRef: true },
      })
      capturedBodyRefs = doomed.flatMap(r => [r.reqBodyRef, r.respBodyRef])
    } catch (e) {
      console.warn('Could not enumerate captured body refs before project delete:', e)
    }

    // C-7: stop in-flight work BEFORE deleting. A container that is mid-write keeps
    // writing project_id-stamped nodes after the row is gone, resurrecting the
    // deleted project's graph as unreachable orphans; and a scanner falls back to
    // DEFAULT_*_SETTINGS on a 404, so a job dispatched against a deleted project
    // would scan with defaults. Cancel queued work and stop running scans first.
    try {
      await prisma.jobQueue.updateMany({
        where: { projectId: id, status: { in: ['queued', 'dispatching', 'running', 'needs_review'] } },
        data: { status: 'canceled', finishedAt: new Date() },
      })
    } catch (e) {
      console.warn('Could not cancel queued jobs before project delete:', e)
    }
    // Best-effort stop of each PROJECT-LEVEL scan container. Run-based scans
    // (partial_recon, ai_attack) are keyed by run-id, not project, so they are not
    // stopped here; they finish on their own and their orphaned nodes are swept by
    // the graph read-path reconcile. Still strictly better than the prior behavior
    // (which stopped nothing).
    await Promise.allSettled([
      ...['recon', 'gvm', 'github-hunt', 'supply-chain'].map(kind =>
        orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/${kind}/${id}/stop`, { method: 'POST' }),
      ),
      // TruffleHog is run-keyed (one run per source, several in parallel), so a
      // single project-level stop would leave every source but one running with
      // its project row already gone. stop-all loops the nested state dict.
      orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${id}/stop-all`, { method: 'POST' }),
    ])

    // 1. Delete project from PostgreSQL (cascades captured_http_transactions +
    //    job_queue rows)
    await prisma.project.delete({
      where: { id }
    })

    // 1b. GC captured body blobs this project exclusively owned (ref-counted).
    if (capturedBodyRefs.length > 0) {
      try {
        const { gcOrphanBodies } = await import('@/lib/captureBodies')
        const gc = await gcOrphanBodies(capturedBodyRefs)
        if (gc.deleted > 0) console.log(`[project-delete] GC'd ${gc.deleted} captured body blobs for project ${id}`)
      } catch (e) {
        console.warn('Captured body-blob GC failed on project delete:', e)
      }
    }

    // 2. Delete all output JSON files via orchestrator (it has write permissions)
    //    This covers: recon, GVM, and GitHub Secret Hunt JSON files
    try {
      const orchestratorResponse = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/project/${id}/files`, {
        method: 'DELETE',
      })
      if (orchestratorResponse.ok) {
        const result = await orchestratorResponse.json()
        console.log(`Orchestrator deleted files:`, result.deleted)
      } else {
        console.warn(`Orchestrator failed to delete files: ${orchestratorResponse.status}`)
      }
    } catch (orchestratorError) {
      console.warn(`Failed to call orchestrator for file deletion: ${orchestratorError}`)

      // Fallback: try to delete locally (may fail in Docker due to read-only mounts)
      const filesToDelete = [
        { path: path.join(RECON_OUTPUT_PATH, `recon_${id}.json`), name: 'recon' },
        { path: path.join(GVM_OUTPUT_PATH, `gvm_${id}.json`), name: 'GVM' },
        { path: path.join(GITHUB_HUNT_OUTPUT_PATH, `github_hunt_${id}.json`), name: 'GitHub hunt' },
      ]
      for (const file of filesToDelete) {
        if (existsSync(file.path)) {
          try {
            await unlink(file.path)
            console.log(`Deleted ${file.name} file locally: ${file.path}`)
          } catch (err) {
            console.warn(`Failed to delete ${file.name} file locally: ${err}`)
          }
        }
      }
    }

    // 3. Delete all Neo4j nodes for this project
    try {
      const session = getGraphSession()
      try {
        // Via the shared helper: a raw `MATCH (n {project_id})` here also swept
        // the global CVE/CWE/CAPEC nodes, which are shared with every other
        // project that found them, taking those projects' links down too.
        await clearProjectGraph(session, id)
        console.log(`Deleted Neo4j nodes for project: ${id}`)
      } finally {
        await session.close()
      }
    } catch (neo4jError) {
      // Log but don't fail the request if Neo4j cleanup fails
      console.warn(`Failed to delete Neo4j data: ${neo4jError}`)
    }

    return NextResponse.json({ success: true })
  } catch (error: unknown) {
    console.error('Failed to delete project:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to delete project' },
      { status: 500 }
    )
  }
}
