import { NextRequest, NextResponse } from 'next/server'
import { archiveProjectAuthorizations } from '@/lib/engagementArchive'
import prisma from '@/lib/prisma'
import { agentFetch } from '@/lib/agentFetch'
import { Prisma } from '@prisma/client'
import { unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { batchGroupFiles } from '@/lib/reconOutputFiles'
import { clearProjectGraph } from '@/lib/graphRestore'
import { orchestratorFetch } from '@/lib/orchestrator'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { purgeProjectWorkspace } from '@/lib/workspacePurge'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { toAuthProfileMetadata } from '@/lib/authProfile'
import { callGraphTriage } from '@/lib/triageClient'
import { pickProjectColumns } from '@/lib/projectColumns'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { writeAudit } from '@/lib/audit'
import { canonicalJson } from '@/lib/fingerprint'
import { field, fieldsWhere } from '@/lib/reconSettings/registry'
import { STALE_SAVE_MESSAGE } from '@/lib/projectVersion'
import { JEV_ENGINE_SELECT, guardProjectWrite, recordProjectWrite } from '@/lib/projectWriteGuards'
import { seedDomainNames, seedProjectDomains } from '@/lib/graphSeedDomains'
import { refreshActiveRecordingScope } from '@/lib/recordingSession'
import { resolveScopeGroups } from '@/lib/scopeGroups'
import { computeSkillTextOverrides } from '@/lib/plugins/overrideDelivery'
import { userSkillsForAgent } from '@/lib/userSkillAgentPayload'
import type { ResolvedPart } from '@/lib/plugins/overrides'
import { cleanOpenApiSources, normalizeOpenApiSourceIds, validateOpenApiSettings } from '@/lib/validation/openapiSettings'
import { internalError } from '@/lib/routeErrors'
import { projectModelProblem } from '@/lib/agentInTheLoop'

// Path to output directories (fallback for local deletion)
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

// Agent API, for the soft (LLM) guardrail on a scope edit. Mirrors the POST route.
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'
const SOFT_GUARDRAIL_TIMEOUT_MS = 10_000

// Recon orchestrator URL for file deletion
const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * Columns the settings form loads with the row and PUTs back whole, but that no
 * save may write.
 *
 * `activation*` is the version-activation lock: a form opened before an
 * activation and saved during it released the lock mid-swap. The upload-managed
 * columns belong to the endpoints that place the file on disk, and the form's
 * copy is whatever it loaded, so writing it back reverted an upload made from
 * inside the same form.
 */
const NOT_WRITABLE_BY_SAVE: ReadonlySet<string> = new Set([
  'id', 'createdById', 'updatedById',
  'activationState', 'activationStartedAt', 'activationVersionId',
  ...fieldsWhere(f => f.deny_reason === 'upload-managed').map(f => f.key),
])

/** Audited by name only: the value is a credential or a whole document. */
function auditsValue(key: string): boolean {
  const reason = field(key)?.read_deny_reason
  return reason !== 'credential' && reason !== 'document_blob'
}

/** canonicalJson renders every Date as `{}`, which would hide a changed timestamp. */
function comparable(value: unknown): string {
  return value instanceof Date ? value.toISOString() : canonicalJson(value)
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
      // Every reader's one derivation of the scope (recon, orchestrator, agent,
      // replay, the form): never stored, recomputed from the target fields.
      scopeGroups: resolveScopeGroups(project).groups,
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

    // Approved plugin overrides of built-in skill text go to the agent's own settings
    // fetch only: its separate flag on the MASTER key. includeSkillContent alone is also
    // sent by text-to-cypher and accepted from the scanner key, which must not get them.
    // Kept out of projectWithoutBinary, and a failure leaves the payload as it was.
    let skillOverridesField: { skillTextOverrides?: Record<string, ResolvedPart> } = {}
    if (request.nextUrl.searchParams.get('includeSkillOverrides') === 'true' && isInternalRequest(request)) {
      try {
        const overrides = await computeSkillTextOverrides(id)
        if (Object.keys(overrides).length) skillOverridesField = { skillTextOverrides: overrides }
      } catch (err) {
        console.warn('[plugins] skill overrides omitted:', err)
      }
    }

    // If ?includeSkillContent=true, the enabled user skills' texts for agent consumption:
    // only those set to true (a missing toggle is OFF, as the form shows it), at most 20,
    // never a quarantined one (lib/userSkillAgentPayload.ts).
    const includeSkillContent = request.nextUrl.searchParams.get('includeSkillContent') === 'true'
    if (includeSkillContent && project.userId) {
      const skills = await userSkillsForAgent(prisma, project.userId, project.attackSkillConfig)

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
        ...skillOverridesField,
      })
    }

    return NextResponse.json({ ...projectWithoutBinary, ...skillOverridesField })
  } catch (error) {
    return internalError(error, 'Failed to fetch project')
  }
}

// PUT /api/projects/[id] - Update project params
export async function PUT(request: NextRequest, { params }: RouteParams) {
  // Whether the row was written when something threw: the steps after the write
  // (audit, Domain seeding, recording scope) can fail with the save already in.
  let stage: 'before_write' | 'after_write' = 'before_write'
  try {
    const { id } = await params

    // Only the project's effective owner may mutate it (admin while simulating).
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    let body
    try {
      body = await request.json()
    } catch {
      return NextResponse.json({ error: 'The request body is not valid JSON.', code: 'invalid_json' }, { status: 400 })
    }

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

    // The form sends back the updatedAt of the row it is editing. Writing only
    // while it still matches is what stops a form left open from reverting,
    // field by field, whatever an MCP agent or another tab wrote meanwhile. The
    // single-field auto-saves carry none and keep writing unconditionally.
    let expectedVersion: Date | null = null
    if (updatedAt !== undefined && updatedAt !== null) {
      expectedVersion = new Date(updatedAt)
      if (Number.isNaN(expectedVersion.getTime())) {
        return NextResponse.json({ error: 'updatedAt is not a valid timestamp' }, { status: 400 })
      }
    }

    // Only Project COLUMNS may be written here: a relation key in this whole-row
    // body would skip the relation's own route, its validation, its revision
    // check and its audit row.
    const updateData: Record<string, any> = pickProjectColumns(rawUpdate)
    for (const key of NOT_WRITABLE_BY_SAVE) delete updateData[key]
    if ('openapiSources' in updateData) updateData.openapiSources = cleanOpenApiSources(updateData.openapiSources)
    const openapiError = validateOpenApiSettings(updateData)
    if (openapiError) {
      return NextResponse.json({ error: openapiError }, { status: 400 })
    }
    const loopProblem = projectModelProblem(updateData)
    if (loopProblem) {
      return NextResponse.json({ error: loopProblem, code: 'loop_model_not_allowed' }, { status: 400 })
    }
    if ('openapiSources' in updateData) {
      updateData.openapiSources = normalizeOpenApiSourceIds(updateData.openapiSources)
    }

    // Sanitize string inputs that are used as hostnames/IPs (trailing spaces break DNS)
    if (typeof updateData.targetDomain === 'string') {
      // Strip a leading wildcard for the same reason POST does: in single-domain
      // mode `*.example.com` already means what an empty prefix list means, and
      // left intact the star reaches tool arguments, filenames and the graph.
      const { normalizeHost, splitWildcard } = await import('@/lib/domainBatch')
      updateData.targetDomain = splitWildcard(normalizeHost(updateData.targetDomain)).rest
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
        domainBatchMode: true, domainBatchGroups: true, domainBatchHosts: true,
        targetDomain: true, subdomainList: true, ipMode: true, targetIps: true,
        userId: true, targetGuardrailEnabled: true, attackSkillConfig: true,
        ...JEV_ENGINE_SELECT,
      },
    })
    // The form sends the toggles with every whole-row save. Unchanged, they are neither
    // validated nor written: a stored value the rules now refuse (a config saved without
    // builtIn, a quarantined skill left on by a race) must not block an unrelated edit.
    if ('attackSkillConfig' in updateData && existing &&
        comparable(updateData.attackSkillConfig) === comparable(existing.attackSkillConfig)) {
      delete updateData.attackSkillConfig
    }
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
    let batchSeedDomains: string[] = []
    let batchScopeChanged = false
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
      // Compare the scope derived from the STORED host list with the new one, never
      // the stored group records: a regroup of the same hosts (a public-suffix
      // change, or a row saved by an older writer) is no change, while
      // `api.example.com` -> `*.example.com` (same root, one host -> every host)
      // is the largest widening this feature permits.
      const { resolveScopeGroups, sameScope } = await import('@/lib/scopeGroups')
      batchScopeChanged = !sameScope(
        resolveScopeGroups({ domainBatchMode: true, domainBatchHosts: existing?.domainBatchHosts ?? [] }).groups,
        batch.groups,
      )
      updateData.domainBatchHosts = batch.entries
      updateData.domainBatchGroups = batch.legacy
      batchSeedDomains = seedDomainNames(batch.groups)
    }

    // A project that is not a batch keeps no batch scope. Recon's auth scope and
    // the agent's replay read these columns whatever the mode, so a list left
    // over from a batch -> single flip would keep authorizing its hosts.
    if (!willBeBatch && (existing?.domainBatchGroups != null
        || (existing?.domainBatchHosts?.length ?? 0) > 0 || 'domainBatchHosts' in updateData)) {
      updateData.domainBatchGroups = Prisma.DbNull
      updateData.domainBatchHosts = []
    }

    // The scope gates apply to EVERY mode and to a mode flip, not only to a batch
    // host-list edit: a single-domain target change, a batch -> single flip and
    // entering or leaving IP mode re-point the engagement just as much.
    const nextScope = {
      ipMode: 'ipMode' in updateData ? updateData.ipMode === true : existing?.ipMode === true,
      domainBatchMode: willBeBatch,
      domainBatchHosts: Array.isArray(updateData.domainBatchHosts)
        ? updateData.domainBatchHosts as string[] : existing?.domainBatchHosts ?? [],
      targetDomain: typeof updateData.targetDomain === 'string'
        ? updateData.targetDomain : existing?.targetDomain ?? '',
      subdomainList: Array.isArray(updateData.subdomainList)
        ? updateData.subdomainList as string[] : existing?.subdomainList ?? [],
      targetIps: Array.isArray(updateData.targetIps)
        ? updateData.targetIps as string[] : existing?.targetIps ?? [],
    }
    // Mutually exclusive modes, enforced on update as well as create, and on the
    // EFFECTIVE next state: recon checks IP_MODE first, so a project flagged both
    // ways silently never runs its batch, and a body carrying only one of the two
    // flags would otherwise leave the stored other one standing. Only a request
    // that sets a mode flag is judged, so a row already in that state can still
    // take an unrelated partial save.
    const setsMode = 'ipMode' in updateData || 'domainBatchMode' in updateData
    if (setsMode && nextScope.ipMode && nextScope.domainBatchMode) {
      return NextResponse.json(
        { error: 'A project cannot be in both IP mode and Domain batch mode.' },
        { status: 400 },
      )
    }
    const { sameScope, softGuardrailNames } = await import('@/lib/scopeGroups')
    const nextGroups = resolveScopeGroups(nextScope)
    // A single-domain target or prefix change gets the batch entry rules: no
    // public suffix, no IP, no malformed prefix. Judged only when the request
    // touches them, so a stored value the rules now refuse cannot block an
    // unrelated partial save.
    const touchesSingleScope = 'targetDomain' in updateData || 'subdomainList' in updateData || setsMode
    if (!nextScope.ipMode && !nextScope.domainBatchMode && touchesSingleScope && nextGroups.invalid.length > 0) {
      const { describeInvalid } = await import('@/lib/domainBatch')
      return NextResponse.json({ error: describeInvalid(nextGroups.invalid) }, { status: 400 })
    }
    const sameSet = (a: readonly string[], b: readonly string[]) =>
      JSON.stringify([...a].sort()) === JSON.stringify([...b].sort())
    // Both sides derived from stored fields, so a legacy spelling (a mixed-case
    // target, an un-normalised prefix) re-saved unchanged is no scope change.
    const singleScopeChanged = () => !sameScope(resolveScopeGroups({
      targetDomain: existing?.targetDomain ?? '', subdomainList: existing?.subdomainList ?? [],
    }).groups, nextGroups.groups)
    const scopeChanged = existing != null && (
      nextScope.ipMode !== (existing.ipMode === true)
      || nextScope.domainBatchMode !== (existing.domainBatchMode === true)
      || (nextScope.ipMode
        ? !sameSet(nextScope.targetIps, existing.targetIps ?? [])
        : nextScope.domainBatchMode
          ? batchScopeChanged
          : singleScopeChanged())
    )
    // An unchanged single target keeps its stored spelling: re-casing it would
    // seed a second graph Domain beside the one a legacy scan named after it.
    if (!scopeChanged && !nextScope.domainBatchMode && !nextScope.ipMode
        && typeof updateData.targetDomain === 'string' && existing?.targetDomain) {
      delete updateData.targetDomain
    }

    if (scopeChanged) {
      // A version activation clears and restores the graph; a scope written
      // between the two would describe neither.
      const { assertGraphNotActivating } = await import('@/lib/activationLock')
      const activating = await assertGraphNotActivating(id)
      if (activating) return activating

      // The container reads its settings ONCE at spawn, so this edit cannot
      // re-point a running scan - but it DOES re-point everything that reads
      // scope live from the row (the agent, the next guardrail, the report)
      // while the graph still holds the running scan's results. Refuse rather
      // than leave the two describing different engagements.
      const { describeScanWriters } = await import('@/lib/graphWriters')
      const busy = await describeScanWriters(id)
      if (busy) {
        return NextResponse.json(
          { error: `Cannot change the project's target while ${busy}. Stop the scan, or wait for it to finish, and try again.` },
          { status: 409 },
        )
      }

      // Every host and root this project would scan gets the non-disableable
      // check. POST does this at creation; without it here, the paths that can
      // re-point a project after creation are the paths that never guardrail it.
      const { scopeGuardrailNames } = await import('@/lib/scopeGroups')
      const { firstHardBlocked } = await import('@/lib/hard-guardrail')
      const blocked = firstHardBlocked(scopeGuardrailNames(nextScope))
      if (blocked) {
        return NextResponse.json(
          { error: `Target permanently blocked: ${blocked.name}: ${blocked.reason}` },
          { status: 403 },
        )
      }

      // Soft (LLM) guardrail, mirroring POST. Fails OPEN like POST does: an
      // unreachable agent must not block an edit, because the hard guardrail
      // above is the control that may not be bypassed.
      if (existing?.targetGuardrailEnabled !== false) {
        try {
          // The agent answers only a caller holding the internal key, and its
          // verdict is `allowed`; without both this check could never block.
          const guardrailResponse = await fetch(`${AGENT_API_URL}/guardrail/check-target`, {
            method: 'POST',
            headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
            signal: AbortSignal.timeout(SOFT_GUARDRAIL_TIMEOUT_MS),
            body: JSON.stringify({
              target_domain: !nextScope.ipMode && !nextScope.domainBatchMode
                ? (nextGroups.groups[0]?.scanRoot ?? '') : '',
              target_domains: nextScope.ipMode ? [] : softGuardrailNames(nextGroups.groups)
                .filter(n => nextScope.domainBatchMode || n !== nextGroups.groups[0]?.scanRoot),
              target_ips: nextScope.ipMode ? nextScope.targetIps : [],
              user_id: existing?.userId ?? eff.userId,
            }),
          })
          if (guardrailResponse.ok) {
            const verdict = await guardrailResponse.json()
            if (verdict?.allowed === false) {
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

    // Supply-chain input becomes a `git clone` argument in the scan container,
    // fireteam carries a rule over two fields, and a switch onto the Jev engine
    // needs a selected Jev provider of the owner: all validated server-side, because a direct
    // PUT bypasses the form's own checks. The same guards as the RoE routes.
    const guardError = await guardProjectWrite({
      existing: existing as ({ userId: string } & Record<string, unknown>) | null,
      updateData,
      actorUserId: eff.userId,
    })
    if (guardError) {
      return NextResponse.json({ error: guardError }, { status: 400 })
    }

    // The values being replaced, for the fireteam audit and the save's own.
    const before = (await prisma.project.findUnique({
      where: { id },
      select: Object.fromEntries(Object.keys(updateData).map(k => [k, true])) as any,
    }) ?? {}) as Record<string, unknown>

    updateData.updatedById = eff.userId
    let project
    if (expectedVersion) {
      const { count } = await prisma.project.updateMany({
        where: { id, updatedAt: expectedVersion },
        data: updateData,
      })
      if (count === 0) {
        return NextResponse.json({ error: STALE_SAVE_MESSAGE }, { status: 409 })
      }
      stage = 'after_write'
      project = await prisma.project.findUnique({ where: { id } })
      if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    } else {
      project = await prisma.project.update({
        where: { id },
        data: updateData
      })
    }
    stage = 'after_write'

    // The UI's own audit row. Without it a person reverting an MCP agent's
    // change left no trace, while the agent's change did.
    // A batch whose derived scope did not change only had its legacy group
    // record rewritten (a row saved by an older writer, or a public-suffix
    // regroup): that must not read as a scope change in the activity feed.
    const regroupOnly = willBeBatch && !scopeChanged
    const changed = Object.keys(updateData).filter(k =>
      k !== 'updatedById' && !(regroupOnly && k === 'domainBatchGroups')
      && comparable(before[k]) !== comparable((project as Record<string, unknown>)[k]))
    if (changed.length > 0) {
      const valued = changed.filter(auditsValue)
      void writeAudit({
        actorId: eff.userId,
        action: 'project.update',
        targetType: 'project',
        targetId: id,
        before: Object.fromEntries(valued.map(k => [k, before[k] ?? null])),
        after: {
          changed,
          values: Object.fromEntries(valued.map(k => [k, (project as Record<string, unknown>)[k] ?? null])),
        },
        source: 'ui',
      })
    }

    await recordProjectWrite(id, before, updateData, {
      userId: (project as { userId?: string | null }).userId ?? null,
      source: 'api',
    })

    // Ensure the Domain nodes (one per org) exist in Neo4j. A batch seeds only
    // when its host list was part of this save; a single domain seeds its org.
    const seedDomains = project.ipMode
      ? []
      : project.domainBatchMode
        ? batchSeedDomains
        : seedDomainNames(resolveScopeGroups(project).groups)
    await seedProjectDomains(seedDomains, project.userId, project.id)

    // An active traffic recording keeps the scope it started with unless moved,
    // as an RoE change moves it; a regroup of the same hosts does not (WEB-15b).
    if (scopeChanged) await refreshActiveRecordingScope(prisma, id, project)

    // Exclude binary document data from response (same as GET)
    const { roeDocumentData: _binary, ...projectWithoutBinary } = project
    return NextResponse.json({ ...projectWithoutBinary, scopeGroups: resolveScopeGroups(project).groups })
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      console.error('Failed to update project:', error)
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    return stage === 'after_write'
      ? internalError(error, 'The project was saved, but a step after the save failed', {
          log: 'Failed to update project', extra: { stage },
        })
      : internalError(error, 'Failed to update project', { extra: { stage } })
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
        .filter(run => typeof run?.run_id === 'string'
          && (run.status === 'running' || run.status === 'starting' || run.status === 'stopping'))
        .map(run => orchestratorFetch(
          `${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${encodeURIComponent(run.run_id as string)}/stop?graceful=false`,
          { method: 'POST' },
        )),
    )
  } catch (e) {
    console.warn('Could not stop partial recons before project delete:', e)
  }
}

// DELETE /api/projects/[id] - Delete project and all associated data
/** Stop every live chat run of a project, best-effort (never throws). */
async function stopProjectChatRuns(projectId: string): Promise<void> {
  let running: { userId: string; sessionId: string }[] = []
  try {
    running = await prisma.conversation.findMany({
      where: { projectId, agentRunning: true },
      select: { userId: true, sessionId: true },
    })
  } catch (e) {
    console.warn('Could not read the running chats before project delete:', e)
    return
  }
  const results = await Promise.allSettled(running.map(c => agentFetch('/agent-session/stop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: c.userId, project_id: projectId, session_id: c.sessionId }),
  })))
  results.forEach((r, i) => {
    if (r.status === 'rejected' || !r.value.ok) {
      console.warn(`Could not stop chat ${running[i].sessionId} before project delete (continuing)`)
    }
  })
}

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
    // A running chat of this project is an orphan once the row is gone, whatever
    // its model, and an Agent in the Loop run would keep offering its steps to
    // the owner's agent. Stopped the way a conversation delete stops its run.
    // The conversations cascade with the project, so they are read first.
    // Best-effort: a stop that fails must not block the delete.
    await stopProjectChatRuns(id)
    // Best-effort stop of each PROJECT-LEVEL scan container. ai_attack runs are
    // keyed by run-id, not project, so they are not stopped here; they finish on
    // their own and their orphaned nodes are swept by the graph read-path
    // reconcile.
    // GVM and the GitHub hunt write a stopped run's saved results to the graph
    // before removing the container, as a backstop for a scan killed mid-write.
    // The graph is cleared below, so here that write could only land after the
    // clear and leave the deleted project's nodes behind: ingest=false skips it.
    // A recon stop drains its queued writes for up to RECON_STOP_GRACE_S unless
    // it is hard: graceful=false kills it and answers once it is gone.
    const stopQuery: Record<string, string> = {
      recon: '?graceful=false', gvm: '?ingest=false', 'github-hunt': '?ingest=false',
    }
    await Promise.allSettled([
      ...['recon', 'gvm', 'github-hunt', 'supply-chain'].map(kind =>
        orchestratorFetch(
          `${RECON_ORCHESTRATOR_URL}/${kind}/${id}/stop${stopQuery[kind] ?? ''}`,
          { method: 'POST' },
        ),
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
          code: 'authorization_archive_failed',
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

    // 1a. The agent workspace (only once the row is gone: the agent acts only on
    //     a project the web app answers 404 for).
    await purgeProjectWorkspace(id)

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
        ...(await batchGroupFiles(RECON_OUTPUT_PATH, id)).map(p => ({ path: p, name: 'recon group' })),
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
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      console.error('Failed to delete project:', error)
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    return internalError(error, 'Failed to delete project')
  }
}
