import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { teardownProject } from '@/lib/projectTeardown'
import { toAuthProfileMetadata } from '@/lib/authProfile'
import { pickProjectColumns } from '@/lib/projectColumns'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { writeAudit } from '@/lib/audit'
import { canonicalJson } from '@/lib/fingerprint'
import { field, fieldsWhere } from '@/lib/reconSettings/registry'
import { numericBoundsRefusal } from '@/lib/reconSettings/numericBounds'
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

// Agent API, for the soft (LLM) guardrail on a scope edit. Mirrors the POST route.
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'
const SOFT_GUARDRAIL_TIMEOUT_MS = 10_000

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
        // The hostname policy is judged on the effective row (guardProjectWrite)
        // and compared for scopeChanged; engagementKind refuses scan_all (D-03).
        engagementKind: true, ipHostnameMode: true, ipHostnameInclude: true, ipHostnameExclude: true,
        ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: true,
        ipHostnamePassiveMaxNames: true,
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

    // A project that is not in IP mode keeps no hostname policy, as a non-batch
    // keeps no batch scope above: it scans nothing there, and a leftover policy
    // would start applying unseen after a flip back into IP mode.
    const {
      IP_HOSTNAME_DEFAULTS, IP_HOSTNAME_FIELDS, ipHostnamePolicyChanged, ipHostnamePolicyNarrowed,
    } = await import('@/lib/scopeGroups')
    const nextIpMode = 'ipMode' in updateData ? updateData.ipMode === true : existing?.ipMode === true
    if (!nextIpMode && existing && (IP_HOSTNAME_FIELDS.some(k => k in updateData)
        || ipHostnamePolicyChanged(existing, IP_HOSTNAME_DEFAULTS))) {
      for (const key of IP_HOSTNAME_FIELDS) {
        const value = IP_HOSTNAME_DEFAULTS[key]
        updateData[key] = Array.isArray(value) ? [] : value
      }
    }

    // The scope gates apply to EVERY mode and to a mode flip, not only to a batch
    // host-list edit: a single-domain target change, a batch -> single flip and
    // entering or leaving IP mode re-point the engagement just as much.
    const nextScope = {
      ipMode: nextIpMode,
      domainBatchMode: willBeBatch,
      domainBatchHosts: Array.isArray(updateData.domainBatchHosts)
        ? updateData.domainBatchHosts as string[] : existing?.domainBatchHosts ?? [],
      targetDomain: typeof updateData.targetDomain === 'string'
        ? updateData.targetDomain : existing?.targetDomain ?? '',
      subdomainList: Array.isArray(updateData.subdomainList)
        ? updateData.subdomainList as string[] : existing?.subdomainList ?? [],
      targetIps: Array.isArray(updateData.targetIps)
        ? updateData.targetIps as string[] : existing?.targetIps ?? [],
      // The hostname policy is part of the scope: its include entries get the hard
      // guardrail below, and any change of it is a scope change.
      ...Object.fromEntries(IP_HOSTNAME_FIELDS.map(k => [k, k in updateData ? updateData[k] : existing?.[k]])),
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
        ? !sameSet(nextScope.targetIps, existing.targetIps ?? []) || ipHostnamePolicyChanged(existing, nextScope)
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

    // Only a value this save CHANGES is judged, as for the skill toggles above:
    // the form PUTs the whole row back, and a number stored before its bound
    // existed must not block an unrelated edit.
    const outOfBounds = numericBoundsRefusal(
      updateData, key => comparable(updateData[key]) === comparable(before[key]))
    if (outOfBounds) {
      return NextResponse.json({ ...outOfBounds, code: 'setting_rejected' }, { status: 400 })
    }

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

    // A narrowed hostname policy marks the names earlier runs scanned that it no
    // longer admits (design §6.3). After the commit and best-effort: the save
    // stands either way, and every reader re-applies the current policy, so the
    // answer only tells the caller whether the graph agrees yet.
    let hostnamePolicyMarked: boolean | undefined
    if (existing && ipHostnamePolicyNarrowed(existing, project)) {
      try {
        const { markOutOfPolicy } = await import('@/lib/ipHostnamePolicy')
        hostnamePolicyMarked = await markOutOfPolicy(id, project.userId, project)
      } catch (e) {
        console.warn('[projects PUT] hostname policy marker failed:', e)
        hostnamePolicyMarked = false
      }
    }

    // Exclude binary document data from response (same as GET)
    const { roeDocumentData: _binary, ...projectWithoutBinary } = project
    return NextResponse.json({
      ...projectWithoutBinary,
      scopeGroups: resolveScopeGroups(project).groups,
      ...(hostnamePolicyMarked === undefined ? {} : { hostnamePolicyMarked }),
    })
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

// DELETE /api/projects/[id] - Delete project and all associated data
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Only the project's effective owner may delete it (admin while simulating).
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    // The teardown's tenant is the owner the access check read, not the caller:
    // in log-only BOLA mode a non-owner gets this far.
    const result = await teardownProject(
      { id, userId: access?.project.userId ?? eff.userId },
      { actorUserId: eff.userId },
    )
    if (!result.ok) {
      if (result.failedStep === 'archive_authorizations') {
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
      throw result.error
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
