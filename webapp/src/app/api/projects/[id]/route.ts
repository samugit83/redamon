import { NextRequest, NextResponse } from 'next/server'
import { archiveProjectAuthorizations } from '@/lib/engagementArchive'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import { unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { clearProjectGraph } from '@/lib/graphRestore'
import { orchestratorFetch } from '@/lib/orchestrator'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { toAuthProfileMetadata } from '@/lib/authProfile'
import { callGraphTriage } from '@/lib/triageClient'
import { pickProjectColumns } from '@/lib/projectColumns'
import { normalizeOpenApiSourceIds, validateOpenApiSettings } from '@/lib/validation/openapiSettings'

// Path to output directories (fallback for local deletion)
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/gvm_scan/output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/github_secret_hunt/output'

// Agent API, for the soft (LLM) guardrail on a scope edit. Mirrors the POST route.
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'

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
    const isServiceCaller = isInternalRequest(request) || isScannerRequest(request)
    if (!isServiceCaller) {
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
        },
        authProfile: true,
        // Node filters travel to recon here, for service callers only: a scan's
        // end-of-run sweep re-reads them (and the operator's exemptions) at
        // sweep time. A browser reads them through /node-filters instead.
        ...(isServiceCaller
          ? { nodeFilter: true, nodeFilterExemptions: { select: { label: true, nodeKey: true } } }
          : {}),
      }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    // Exclude binary document data from regular responses (use /roe/download instead).
    // The auth profile carries the recorded/entered session: recon and the agent
    // get it whole, a browser only ever gets metadata + hasValue (write-only UI).
    const {
      roeDocumentData: _binary, authProfile, nodeFilter, nodeFilterExemptions, ...rest
    } = project as typeof project & {
      nodeFilter?: { mode: string; applyToScans: boolean; rules: unknown; revision: number } | null
      nodeFilterExemptions?: { label: string; nodeKey: string }[]
    }
    const projectWithoutBinary = {
      ...rest,
      authProfile: isServiceCaller ? authProfile : toAuthProfileMetadata(authProfile),
      ...(isServiceCaller
        ? {
            nodeFilter: nodeFilter
              ? {
                  mode: nodeFilter.mode,
                  applyToScans: nodeFilter.applyToScans,
                  rules: nodeFilter.rules,
                  revision: nodeFilter.revision,
                  exemptions: (nodeFilterExemptions ?? []).map(e => [e.label, e.nodeKey]),
                }
              : null,
          }
        : {}),
    }

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

    // Remove fields that shouldn't be updated directly. authProfile comes back in
    // the whole-row PUT the form sends; it is a relation written only by its own
    // route, and passing it here would make Prisma reject the update.
    //
    // roeEnabled is DERIVED from whether any engagement limit is set, and
    // nothing writes it. The form no longer sends it, but this route takes the
    // whole row, so without this line an older client - or a saved bundle
    // replayed through it - would persist a value that disagrees with the
    // derivation. A column nothing reads but something writes is the residue
    // the derivation exists to remove, so it is dropped here rather than
    // trusted not to arrive.
    const {
      userId, createdAt, updatedAt, user,
      authProfile: _authProfile,
      roeEnabled: _roeEnabledDerived,
      ...rawUpdate
    } = body

    // Only Project COLUMNS may be written here: a relation key in this whole-row
    // body would skip the relation's own route, its validation, its revision
    // check and its audit row.
    const updateData: Record<string, any> = pickProjectColumns(rawUpdate)
    const openapiError = validateOpenApiSettings(updateData)
    if (openapiError) {
      return NextResponse.json({ error: openapiError }, { status: 400 })
    }
    if ('openapiSources' in updateData) {
      updateData.openapiSources = normalizeOpenApiSourceIds(updateData.openapiSources)
    }

    // Sanitize string inputs that are used as hostnames/IPs (trailing spaces break DNS)
    if (typeof updateData.targetDomain === 'string') {
      // Strip a leading wildcard for the same reason POST does: in single-domain
      // mode `*.example.com` already means what an empty prefix list means, and
      // left intact the star reaches tool arguments, filenames and the graph.
      const { splitWildcard } = await import('@/lib/domainBatch')
      updateData.targetDomain = splitWildcard(updateData.targetDomain.trim()).rest
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
    // Read the row ONCE: the mode decides whether to re-derive, and the stored
    // groups + owner are what the guardrails below compare against.
    const existing = await prisma.project.findUnique({
      where: { id },
      select: {
        domainBatchMode: true, domainBatchGroups: true,
        userId: true, targetGuardrailEnabled: true,
      },
    })
    const willBeBatch = 'domainBatchMode' in updateData
      ? updateData.domainBatchMode === true
      : existing?.domainBatchMode === true

    // A client-supplied grouping is never trusted; it is always re-derived below.
    if ('domainBatchGroups' in updateData) delete updateData.domainBatchGroups

    // Re-derive the scope ONLY when this update actually changes the host list or
    // flips the mode. A partial save - a single module toggle auto-saving
    // `{ katanaEnabled: false }` - carries neither, so the stored groups are left
    // untouched. Without this guard the absent domainBatchHosts read as empty and
    // every field toggle on a batch project 400'd with "needs at least one hostname".
    const touchesBatchScope = 'domainBatchHosts' in updateData || 'domainBatchMode' in updateData
    let batchRootsAdded: string[] = []
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
      const nextRoots = batch.groups.map(g => g.rootDomain)
      // Compare the whole derived shape, not just the roots. Turning
      // `api.example.com` into `*.example.com` leaves the root set identical
      // while changing that group from "one host" to "every host under this
      // domain" - the largest widening this feature permits, and the one a
      // root-only comparison waves straight through.
      const signature = (gs: Array<{ rootDomain?: string; prefixes?: string[] }>) =>
        gs.map(g => `${String(g?.rootDomain || '')}|${[...(g?.prefixes || [])].sort().join(',')}`)
          .sort().join(';')
      const scopeChanged = signature(batch.groups) !== signature(
        Array.isArray(existing?.domainBatchGroups)
          ? existing.domainBatchGroups as Array<{ rootDomain?: string; prefixes?: string[] }>
          : []
      )

      if (scopeChanged) {
        // The container reads its settings ONCE at spawn, so this edit cannot
        // re-point a running scan - but it DOES re-point everything that reads
        // scope live from the row (the agent, the next guardrail, the report)
        // while the graph still holds the running scan's results. Refuse rather
        // than leave the two describing different engagements.
        const { describeScanWriters } = await import('@/lib/graphWriters')
        const busy = await describeScanWriters(id)
        if (busy) {
          return NextResponse.json(
            { error: `Cannot change the hostname list while ${busy}. Stop the scan, or wait for it to finish, and try again.` },
            { status: 409 },
          )
        }

        // Every root this project would scan gets the non-disableable check.
        // POST does this at creation; without it here, the one path that can add
        // a root after creation is the one path that never guardrails it.
        const { isHardBlockedDomain } = await import('@/lib/hard-guardrail')
        for (const domain of nextRoots) {
          const hardCheck = isHardBlockedDomain(domain)
          if (hardCheck.blocked) {
            return NextResponse.json(
              { error: `Target permanently blocked: ${domain}: ${hardCheck.reason}` },
              { status: 403 },
            )
          }
        }

        // Soft (LLM) guardrail, mirroring POST. Fails OPEN like POST does: an
        // unreachable agent must not block an edit, because the hard guardrail
        // above is the control that may not be bypassed.
        if (existing?.targetGuardrailEnabled !== false) {
          try {
            const guardrailResponse = await fetch(`${AGENT_API_URL}/guardrail/check-target`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                target_domain: '', target_domains: nextRoots,
                target_ips: [], user_id: existing?.userId ?? eff.userId,
              }),
            })
            if (guardrailResponse.ok) {
              const verdict = await guardrailResponse.json()
              if (verdict?.blocked) {
                return NextResponse.json(
                  { error: verdict.reason || 'Target blocked by the guardrail.' },
                  { status: 403 },
                )
              }
            }
          } catch (e) {
            console.warn('[projects PUT] soft guardrail unreachable, allowing:', e)
          }
        }
      }

      updateData.domainBatchHosts = batch.groups.flatMap(g => g.hosts)
      updateData.domainBatchGroups = batch.groups
      batchRootsAdded = nextRoots
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

    // Ensure Domain node(s) exist in Neo4j (create if missing, update if changed).
    // A batch project has an empty targetDomain and one root per group, so the
    // single-domain condition skipped it entirely: a root added on edit had no
    // Domain node, and the partial-recon picker (which lists Domain nodes) could
    // never offer it.
    const seedDomains = project.ipMode
      ? []
      : project.domainBatchMode
        ? batchRootsAdded
        : (project.targetDomain ? [project.targetDomain] : [])
    if (seedDomains.length > 0) {
      try {
        const session = getGraphSession()
        try {
          for (const name of seedDomains) {
            await session.run(
              `MERGE (d:Domain {name: $name, user_id: $userId, project_id: $projectId})
               ON CREATE SET d.source = 'project_creation', d.updated_at = datetime()`,
              { name, userId: project.userId, projectId: project.id }
            )
          }
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

/**
 * Stop every running partial recon of a project. They are run-keyed, so each
 * one is listed and stopped by id. A partial run over a Domain batch walks up to
 * fifty roots, long enough to keep writing into a project that no longer exists.
 */
async function stopPartialRecons(projectId: string): Promise<void> {
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/all`)
    if (!res.ok) return
    const data = await res.json().catch(() => ({}))
    const runs: Array<{ run_id?: unknown; status?: unknown }> = Array.isArray(data?.runs) ? data.runs : []
    await Promise.allSettled(
      runs
        .filter(run => typeof run?.run_id === 'string' && (run.status === 'running' || run.status === 'starting'))
        .map(run => orchestratorFetch(
          `${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${encodeURIComponent(run.run_id as string)}/stop`,
          { method: 'POST' },
        )),
    )
  } catch (e) {
    console.warn('Could not stop partial recons before project delete:', e)
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

    // A triage run lives in the agent's memory. Deleting the project without
    // telling it leaves the run working against a project that no longer
    // exists, for as long as it takes the next heartbeat to fail (X12).
    // Best-effort: an unreachable agent must not block the delete, because the
    // run's publish and heartbeat both fail closed on the missing project.
    try {
      await callGraphTriage('stop_run', { userId: eff.userId, projectId: id })
    } catch (e) {
      console.warn('Could not stop a triage run before project delete:', e)
    }
    // Best-effort stop of each PROJECT-LEVEL scan container. ai_attack runs are
    // keyed by run-id, not project, so they are not stopped here; they finish on
    // their own and their orphaned nodes are swept by the graph read-path
    // reconcile.
    await Promise.allSettled([
      ...['recon', 'gvm', 'github-hunt', 'supply-chain'].map(kind =>
        orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/${kind}/${id}/stop`, { method: 'POST' }),
      ),
      // TruffleHog is run-keyed (one run per source, several in parallel), so a
      // single project-level stop would leave every source but one running with
      // its project row already gone. stop-all loops the nested state dict.
      orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${id}/stop-all`, { method: 'POST' }),
      stopPartialRecons(id),
    ])

    // Archive the authorization records BEFORE the delete. Every other Project
    // child cascades; these do not, because the record of what authorized a
    // project is the thing an incident review needs most and deleting the
    // project is exactly when it stops being recoverable. The foreign key is
    // `Restrict`, so a failed archive fails the delete rather than quietly
    // taking the records with it.
    const archived = await archiveProjectAuthorizations(id)
    if (archived.error) {
      return NextResponse.json(
        {
          error:
            'Could not archive this project\'s engagement authorization records, so it was ' +
            'not deleted. The record of what authorized an engagement must outlive the ' +
            'engagement. Retry, or contact an administrator.',
        },
        { status: 500 }
      )
    }
    if (archived.archived > 0) {
      console.log(`[project-delete] archived ${archived.archived} authorization record(s) for ${id}`)
    }

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
