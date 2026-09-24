import { stripLegacyOpenApiHeaders } from '@/lib/validation/openapiSettings'
import { NextRequest, NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { clearProjectGraph, restoreGraph } from '@/lib/graphRestore'
import { requireEffectiveUser } from '@/lib/access'
import JSZip from 'jszip'
import { randomUUID } from 'crypto'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import path from 'path'
import { safeBasename } from '@/lib/safePath'
import { orchestratorFetch } from '@/lib/orchestrator'
import { envelopeForKind } from '@/lib/jobQueue'
import { allErrors, validateNodeFilters } from '@/lib/nodeFilters/validate'
import { coerceDoc } from '@/lib/nodeFilters/model'
import { muteRulesFingerprint, parseLoadedPresetInput, parsePresetText } from '@/lib/nodeFilters/presets'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'
import { pickProjectColumns } from '@/lib/projectColumns'

const MUTEABLE_LABELS = new Set<string>(MUTEABLE_FINDING_LABELS)

export const maxDuration = 300

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const REPORT_OUTPUT_PATH = process.env.REPORT_OUTPUT_PATH || '/data/reports'



interface Manifest {
  version: string
  exportDate: string
  projectName: string
  targetDomain: string
  stats: {
    conversations: number
    chatMessages: number
    remediations?: number
    reports?: number
    neo4jNodes: number
    neo4jRelationships: number
    artifacts: number
  }
}

interface ExportedConversation {
  id: string
  projectId: string
  userId: string
  sessionId: string
  title: string
  status: string
  agentRunning: boolean
  currentPhase: string
  iterationCount: number
  createdAt: string
  updatedAt: string
}

interface ExportedMessage {
  id: string
  conversationId: string
  sequenceNum: number
  type: string
  data: unknown
  createdAt: string
}

interface ExportedRemediation {
  id: string
  projectId: string
  title: string
  description: string
  severity: string
  priority: number
  category: string
  remediationType: string
  affectedAssets: unknown
  cvssScore: number | null
  cveIds: string[]
  cweIds: string[]
  capecIds: string[]
  evidence: string
  attackChainPath: string
  exploitAvailable: boolean
  cisaKev: boolean
  solution: string
  fixComplexity: string
  estimatedFiles: number
  targetRepo: string
  targetBranch: string
  fixBranch: string
  prUrl: string
  prStatus: string
  status: string
  agentSessionId: string
  agentNotes: string
  fileChanges: unknown
  createdAt: string
  updatedAt: string
}

interface ExportedNode {
  labels: string[]
  properties: Record<string, unknown>
  _exportId: string
}

interface ExportedRelationship {
  startExportId: string
  endExportId: string
  type: string
  properties: Record<string, unknown>
}

export async function POST(request: NextRequest) {
  try {
    // The imported project is created under the caller's EFFECTIVE user; the
    // client-supplied ?userId is ignored so a caller cannot import a project into
    // another user's account.
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const userId = eff.userId

    // Parse uploaded ZIP
    const formData = await request.formData()
    const file = formData.get('file') as File | null
    if (!file) {
      return NextResponse.json({ error: 'No file uploaded' }, { status: 400 })
    }

    // D10: zip-bomb defense. Cap the upload size, the total DECLARED uncompressed
    // size, and the entry count BEFORE decompressing any entry, so a small crafted
    // archive cannot inflate to tens of GB and OOM-kill the webapp (mem_limit 1g).
    // Caps are sized generously off the real export shape (tens of MB uncompressed)
    // and env-overridable.
    const MAX_UPLOAD_BYTES = parseInt(process.env.PROJECT_IMPORT_MAX_UPLOAD_BYTES || '', 10) || 100 * 1024 * 1024
    const MAX_UNCOMPRESSED_BYTES = parseInt(process.env.PROJECT_IMPORT_MAX_UNCOMPRESSED_BYTES || '', 10) || 500 * 1024 * 1024
    const MAX_ENTRIES = parseInt(process.env.PROJECT_IMPORT_MAX_ENTRIES || '', 10) || 5000

    if (file.size > MAX_UPLOAD_BYTES) {
      return NextResponse.json(
        { error: `Upload too large (${file.size} bytes; max ${MAX_UPLOAD_BYTES})` },
        { status: 413 }
      )
    }

    const arrayBuffer = await file.arrayBuffer()
    const zip = await JSZip.loadAsync(arrayBuffer)

    // Enforce entry-count + total declared uncompressed size from the central
    // directory (available without decompressing).
    let entryCount = 0
    let declaredUncompressed = 0
    zip.forEach((_path, entry) => {
      entryCount += 1
      const sz = (entry as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize
      if (typeof sz === 'number' && sz > 0) declaredUncompressed += sz
    })
    if (entryCount > MAX_ENTRIES) {
      return NextResponse.json(
        { error: `Archive has too many entries (${entryCount}; max ${MAX_ENTRIES})` },
        { status: 400 }
      )
    }
    if (declaredUncompressed > MAX_UNCOMPRESSED_BYTES) {
      return NextResponse.json(
        { error: `Archive decompresses too large (${declaredUncompressed} bytes; max ${MAX_UNCOMPRESSED_BYTES})` },
        { status: 400 }
      )
    }

    // Read and validate manifest
    const manifestFile = zip.file('manifest.json')
    if (!manifestFile) {
      return NextResponse.json({ error: 'Invalid export: missing manifest.json' }, { status: 400 })
    }
    const manifest: Manifest = JSON.parse(await manifestFile.async('text'))
    if (!manifest.version || !manifest.projectName) {
      return NextResponse.json({ error: 'Invalid manifest format' }, { status: 400 })
    }

    // Read project data
    const projectFile = zip.file('project.json')
    if (!projectFile) {
      return NextResponse.json({ error: 'Invalid export: missing project.json' }, { status: 400 })
    }
    const projectData = stripLegacyOpenApiHeaders(JSON.parse(await projectFile.async('text')))

    // Strip fields that will be regenerated.
    //
    // `roeEnabled` is among them: it is DERIVED from whether any engagement
    // limit is set, and an older bundle still carries the column. Replaying it
    // would write a value nothing else believes, so it is dropped here and
    // recomputed from the limits, which round-trip normally.
    const {
      id: _oldProjectId, userId: _oldUserId, createdAt: _pc, updatedAt: _pu, user: _u,
      roeDocumentDataBase64,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      roeEnabled: _roeEnabledLegacy,
      ...bundleFields
    } = projectData
    // Columns only: the bundle is untrusted, and a relation key in it would be
    // a nested write past that relation's own import checks (node filters
    // arriving armed, a run that never goes stale). Export writes columns only.
    const projectFields = pickProjectColumns(bundleFields)

    // Restore binary RoE document from base64 encoding
    if (roeDocumentDataBase64 && typeof roeDocumentDataBase64 === 'string') {
      projectFields.roeDocumentData = Buffer.from(roeDocumentDataBase64, 'base64')
    }

    // Import is a SECOND creation path, and it has to apply the same rule
    // create_project does or it is the way around it. A bundle that claims a
    // third-party engagement without a rate ceiling and an authorization record
    // is refused rather than silently downgraded to internal: downgrading would
    // strip the ceiling the exporting side declared and say nothing.
    const authorizationsFile = zip.file('engagement/authorizations.json')
    const importedAuthorizations: Record<string, unknown>[] = authorizationsFile
      ? JSON.parse(await authorizationsFile.async('text'))
      : []

    if (projectFields.engagementKind === 'third_party') {
      // The ceiling is the number alone now. There is no second switch that
      // could leave it written and inert.
      const ceilingOk = Number(projectFields.roeGlobalMaxRps ?? 0) > 0
      if (!ceilingOk || importedAuthorizations.length === 0) {
        return NextResponse.json(
          {
            error:
              'This bundle declares a third-party engagement but is missing ' +
              (!ceilingOk ? 'a non-zero request-rate ceiling' : '') +
              (!ceilingOk && importedAuthorizations.length === 0 ? ' and ' : '') +
              (importedAuthorizations.length === 0 ? 'its authorization record' : '') +
              '. It was not imported. A third-party engagement must arrive with both, ' +
              'because importing it without them would produce a project that can scan ' +
              'somebody else\'s estate with no ceiling and nothing saying who permitted it.',
          },
          { status: 400 }
        )
      }
    }

    // Create new project under the specified user
    // The bundle's column values are not type-checked here (they never were);
    // pickProjectColumns has already removed everything that is not a column.
    const newProject = await prisma.project.create({
      data: { ...projectFields, userId } as Prisma.ProjectUncheckedCreateInput,
    })

    // The authorization records travel with the project. `recordedVia: import`
    // says plainly that this row is a copy of a claim made elsewhere rather than
    // one made here, and the original id is not reused: two installs holding the
    // same row id would make the audit trail ambiguous.
    for (const auth of importedAuthorizations) {
      try {
        await prisma.engagementAuthorization.create({
          data: {
            projectId: newProject.id,
            documentSha256: String(auth.documentSha256 ?? ''),
            documentKind: String(auth.documentKind ?? 'other'),
            sourceUrl: String(auth.sourceUrl ?? ''),
            programHandle: (auth.programHandle as string | null) ?? null,
            issuedAt: new Date(String(auth.issuedAt)),
            recordedVia: 'import',
            recordedByUserId: userId,
            summary: String(auth.summary ?? ''),
          },
        })
      } catch (e) {
        console.warn('Could not import an engagement authorization record:', e)
      }
    }

    const stats = {
      conversations: 0,
      messages: 0,
      remediations: 0,
      reports: 0,
      neo4jNodes: 0,
      neo4jRelationships: 0,
      artifacts: 0,
    }

    // Import conversations
    const conversationIdMap = new Map<string, string>()
    const conversationsFile = zip.file('conversations/conversations.json')
    if (conversationsFile) {
      const conversations: ExportedConversation[] = JSON.parse(await conversationsFile.async('text'))

      for (const conv of conversations) {
        const newConv = await prisma.conversation.create({
          data: {
            projectId: newProject.id,
            userId,
            sessionId: `${conv.sessionId}_imported_${randomUUID().substring(0, 8)}`,
            title: conv.title,
            status: 'completed',
            agentRunning: false,
            currentPhase: conv.currentPhase,
            iterationCount: conv.iterationCount,
          },
        })
        conversationIdMap.set(conv.id, newConv.id)
        stats.conversations++
      }
    }

    // Import chat messages
    const messagesFile = zip.file('conversations/messages.json')
    if (messagesFile) {
      const messages: ExportedMessage[] = JSON.parse(await messagesFile.async('text'))

      // Batch insert for performance
      const messageBatch = messages
        .filter(msg => conversationIdMap.has(msg.conversationId))
        .map(msg => ({
          conversationId: conversationIdMap.get(msg.conversationId)!,
          sequenceNum: msg.sequenceNum,
          type: msg.type,
          data: (msg.data ?? {}) as object,
        }))

      if (messageBatch.length > 0) {
        // Create in chunks to avoid oversized queries
        const CHUNK_SIZE = 500
        for (let i = 0; i < messageBatch.length; i += CHUNK_SIZE) {
          const chunk = messageBatch.slice(i, i + CHUNK_SIZE)
          await prisma.chatMessage.createMany({ data: chunk })
        }
        stats.messages = messageBatch.length
      }
    }

    // Import remediations
    const remediationsFile = zip.file('remediations/remediations.json')
    if (remediationsFile) {
      const remediations: ExportedRemediation[] = JSON.parse(await remediationsFile.async('text'))

      if (remediations.length > 0) {
        const CHUNK_SIZE = 500
        const remediationBatch = remediations.map(rem => {
          const { id: _id, projectId: _pid, createdAt: _ca, updatedAt: _ua, ...fields } = rem
          return { ...fields, projectId: newProject.id } as any
        })

        for (let i = 0; i < remediationBatch.length; i += CHUNK_SIZE) {
          const chunk = remediationBatch.slice(i, i + CHUNK_SIZE)
          await prisma.remediation.createMany({ data: chunk })
        }
        stats.remediations = remediationBatch.length
      }
    }

    // Import reports (metadata + HTML files)
    const reportsFile = zip.file('reports/reports.json')
    if (reportsFile) {
      const reportMeta: Array<{
        title: string; filename: string; fileSize: number; format: string
        metrics: object; hasNarratives: boolean; createdAt: string
      }> = JSON.parse(await reportsFile.async('text'))

      if (reportMeta.length > 0) {
        if (!existsSync(REPORT_OUTPUT_PATH)) {
          mkdirSync(REPORT_OUTPUT_PATH, { recursive: true })
        }

        for (const rm of reportMeta) {
          // The filename comes from the attacker-controllable import archive.
          // Reject anything that is not a plain basename so a crafted
          // `../../../app/evil.html` cannot escape REPORT_OUTPUT_PATH.
          const safeName = safeBasename(rm.filename)
          if (!safeName) {
            console.warn('Skipping report with unsafe filename during import:', rm.filename)
            continue
          }
          const htmlFile = zip.file(`reports/${rm.filename}`)
          if (!htmlFile) continue

          const htmlContent = await htmlFile.async('nodebuffer')
          const filePath = path.join(REPORT_OUTPUT_PATH, safeName)
          writeFileSync(filePath, htmlContent)

          await prisma.report.create({
            data: {
              projectId: newProject.id,
              title: rm.title,
              filename: safeName,
              filePath,
              fileSize: htmlContent.length,
              format: rm.format || 'html',
              metrics: (rm.metrics ?? {}) as object,
              hasNarratives: rm.hasNarratives ?? false,
            },
          })
          stats.reports++
        }
      }
    }

    // Node filters. They arrive DISARMED: an imported project must never start
    // muting what its next scan finds before its new owner has looked at the
    // rules. A document this install's catalog cannot read is left out rather
    // than stored half-valid.
    const nodeFilterFile = zip.file('node-filters/node-filters.json')
    if (nodeFilterFile) {
      try {
        const nf = JSON.parse(await nodeFilterFile.async('text'))
        const verdict = validateNodeFilters(nf?.mode, nf?.rules)
        if (verdict.ok && allErrors(verdict).length === 0) {
          // The archive's fingerprint is kept, not recomputed: it is what the
          // preset loaded, so the badge still hides if the rules were edited since.
          const loaded = nf.loadedPreset ? parseLoadedPresetInput(nf.loadedPreset) : null
          await prisma.projectNodeFilter.create({
            data: {
              projectId: newProject.id, mode: nf.mode, rules: nf.rules ?? { version: 1, kinds: {} },
              applyToScans: false, updatedBy: userId,
              ...(loaded?.ok && loaded.value
                ? { loadedPreset: { name: loaded.value.name, fingerprint: loaded.value.fingerprint } }
                : {}),
            },
          })
          ;(stats as Record<string, unknown>).nodeFilters = 'imported (not applied to new scans)'
        } else {
          ;(stats as Record<string, unknown>).nodeFilters = `skipped: ${allErrors(verdict)[0] ?? 'invalid rules'}`
        }
      } catch (e) {
        console.warn('Could not import the node filters:', e)
        ;(stats as Record<string, unknown>).nodeFilters = 'skipped: unreadable'
      }
    }
    const exemptionsFile = zip.file('node-filters/node-filter-exemptions.json')
    if (exemptionsFile) {
      try {
        const rows = JSON.parse(await exemptionsFile.async('text'))
        const data = (Array.isArray(rows) ? rows : [])
          .filter((r: { label?: unknown; nodeKey?: unknown }) =>
            typeof r?.label === 'string' && MUTEABLE_LABELS.has(r.label) &&
            typeof r?.nodeKey === 'string' && r.nodeKey.length > 0 && r.nodeKey.length <= 300)
          .map((r: { label: string; nodeKey: string }) => ({
            projectId: newProject.id, label: r.label, nodeKey: r.nodeKey, createdBy: userId,
          }))
        if (data.length > 0) {
          const created = await prisma.nodeFilterExemption.createMany({ data, skipDuplicates: true })
          ;(stats as Record<string, number>).nodeFilterExemptions = created.count
        }
      } catch (e) {
        console.warn('Could not import the node-filter exemptions:', e)
      }
    }

    // Import user project presets (if present)
    const presetsFile = zip.file('presets/user_project_presets.json')
    if (presetsFile) {
      const presets = JSON.parse(await presetsFile.async('text'))
      for (const preset of presets) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { id: _id, userId: _uid, createdAt: _ca, updatedAt: _ua, ...fields } = preset
        await prisma.userProjectPreset.create({
          data: { ...fields, settings: stripLegacyOpenApiHeaders(fields.settings ?? {}), userId },
        })
      }
      (stats as Record<string, number>).userPresets = presets.length
    }

    // Mute Rules presets: each is checked like a save, and one this user already
    // has (same name, same mode and rules) is skipped, so importing the same
    // export twice does not pile up copies.
    const muteRulesPresetsFile = zip.file('presets/user_mute_rules_presets.json')
    if (muteRulesPresetsFile) {
      try {
        const rows = JSON.parse(await muteRulesPresetsFile.async('text'))
        const existing = await prisma.userMuteRulesPreset.findMany({
          where: { userId }, select: { name: true, mode: true, rules: true },
        })
        const key = (name: string, mode: string, rules: unknown) =>
          `${name}\u0000${muteRulesFingerprint(mode === 'allowlist' ? 'allowlist' : 'denylist', rules)}`
        const have = new Set(existing.map(p => key(p.name, p.mode, p.rules)))
        let imported = 0
        let skipped = 0
        for (const row of Array.isArray(rows) ? rows : []) {
          const text = parsePresetText(row?.name, row?.description)
          const verdict = validateNodeFilters(row?.mode, row?.rules)
          if (!text.ok || !verdict.ok || allErrors(verdict).length > 0) {
            skipped += 1
            continue
          }
          const k = key(text.name, row.mode, row.rules)
          if (have.has(k)) continue
          have.add(k)
          await prisma.userMuteRulesPreset.create({
            data: {
              userId, name: text.name, description: text.description, mode: row.mode,
              rules: coerceDoc(row.rules) as never,
            },
          })
          imported += 1
        }
        ;(stats as Record<string, number>).muteRulesPresets = imported
        if (skipped > 0) (stats as Record<string, number>).muteRulesPresetsSkipped = skipped
      } catch (e) {
        console.warn('Could not import the Mute Rules presets:', e)
      }
    }

    // Import Scan Timeline history (plan Section 9). Ids are regenerated and
    // everything is re-owned under the effective user + the new project, so an
    // import can never resurrect another project's rows or ids.
    const versionIdMap = new Map<string, string>()
    const scheduleIdMap = new Map<string, string>()
    const versionsFile = zip.file('timeline/versions.json')
    if (versionsFile) {
      const versions: Array<Record<string, unknown>> = JSON.parse(await versionsFile.async('text'))
      // "exactly one current version per project" is the model's core invariant and
      // the archive is untrusted input, so it is enforced here rather than trusted:
      // the highest-seq flagged row wins and every other flag is dropped.
      const currentSeq = versions
        .filter(v => v.isCurrent)
        .reduce<number | null>((top, v) => Math.max(top ?? -Infinity, Number(v.seq ?? 0)), null)
      let currentTaken = false
      for (const v of versions) {
        const isCurrent = !currentTaken && Boolean(v.isCurrent) && Number(v.seq ?? 0) === currentSeq
        if (isCurrent) currentTaken = true
        const created = await prisma.scanVersion.create({
          data: {
            projectId: newProject.id,
            seq: Number(v.seq ?? 1),
            label: String(v.label ?? ''),
            isCurrent,
            pinned: Boolean(v.pinned),
            nodeCount: v.nodeCount === null || v.nodeCount === undefined ? null : Number(v.nodeCount),
            linkCount: v.linkCount === null || v.linkCount === undefined ? null : Number(v.linkCount),
            summary: (v.summary ?? undefined) as never,
            snapshot: typeof v.snapshotBase64 === 'string' && v.snapshotBase64
              ? new Uint8Array(Buffer.from(v.snapshotBase64, 'base64'))
              : null,
          },
          select: { id: true },
        })
        versionIdMap.set(String(v.id), created.id)
        ;(stats as Record<string, number>).scanVersions =
          ((stats as Record<string, number>).scanVersions ?? 0) + 1
      }
    }

    const schedulesFile = zip.file('timeline/schedules.json')
    if (schedulesFile) {
      const schedules: Array<Record<string, unknown>> = JSON.parse(await schedulesFile.async('text'))
      for (const sc of schedules) {
        const created = await prisma.scanSchedule.create({
          data: {
            projectId: newProject.id,
            userId,
            label: String(sc.label ?? ''),
            mode: String(sc.mode ?? 'once'),
            runAt: sc.runAt ? new Date(sc.runAt as string) : null,
            intervalMinutes: sc.intervalMinutes === null || sc.intervalMinutes === undefined
              ? null : Number(sc.intervalMinutes),
            cronExpr: sc.cronExpr ? String(sc.cronExpr) : null,
            scanMode: String(sc.scanMode ?? 'new'),
            // An imported schedule arrives DISABLED: importing a project must never
            // silently start scanning someone's target on the old cadence.
            enabled: false,
            nextRunAt: null,
            lastRunAt: sc.lastRunAt ? new Date(sc.lastRunAt as string) : null,
            estimatedEnvelopeBytes: sc.estimatedEnvelopeBytes
              ? BigInt(String(sc.estimatedEnvelopeBytes))
              : null,
          },
          select: { id: true },
        })
        scheduleIdMap.set(String(sc.id), created.id)
        ;(stats as Record<string, number>).scanSchedules =
          ((stats as Record<string, number>).scanSchedules ?? 0) + 1
      }
    }

    const jobsFile = zip.file('timeline/jobs.json')
    if (jobsFile) {
      const jobs: Array<Record<string, unknown>> = JSON.parse(await jobsFile.async('text'))
      for (const j of jobs) {
        await prisma.scanJob.create({
          data: {
            projectId: newProject.id,
            versionId: j.versionId ? versionIdMap.get(String(j.versionId)) ?? null : null,
            scheduleId: j.scheduleId ? scheduleIdMap.get(String(j.scheduleId)) ?? null : null,
            trigger: String(j.trigger ?? 'manual'),
            mode: j.mode ? String(j.mode) : null,
            // A run that was in flight in the source project is not running here.
            status: j.status === 'running' || j.status === 'queued' ? 'canceled' : String(j.status ?? 'completed'),
            initiatedByUserId: userId,
            startedAt: j.startedAt ? new Date(j.startedAt as string) : null,
            finishedAt: j.finishedAt ? new Date(j.finishedAt as string) : null,
            ramReason: j.ramReason ? String(j.ramReason) : null,
            nodeCount: j.nodeCount === null || j.nodeCount === undefined ? null : Number(j.nodeCount),
          },
        })
        ;(stats as Record<string, number>).scanJobs =
          ((stats as Record<string, number>).scanJobs ?? 0) + 1
      }
    }

    // C-8: JobQueue rows are excluded from export, so a normal archive has none.
    // But if a future/hand-crafted archive carries them, they MUST import as
    // 'canceled' - an imported archive must never auto-start scans against a
    // freshly created project, and a non-transactional import must not leave any
    // dispatchable row behind.
    const jobQueueFile = zip.file('timeline/job-queue.json')
    if (jobQueueFile) {
      const rows: Array<Record<string, unknown>> = JSON.parse(await jobQueueFile.async('text'))
      for (const r of rows) {
        const kind = String(r.kind ?? 'full_recon')
        await prisma.jobQueue.create({
          data: {
            projectId: newProject.id,
            userId,
            kind,
            payload: (r.payload && typeof r.payload === 'object' ? r.payload : {}) as Prisma.InputJsonValue,
            settingsHash: '',
            envelopeBytes: BigInt(envelopeForKind(kind)),
            status: 'canceled', // NEVER queued/running on import
            finishedAt: new Date(),
          },
        })
        ;(stats as Record<string, number>).jobQueue =
          ((stats as Record<string, number>).jobQueue ?? 0) + 1
      }
    }

    // Import Neo4j data
    const nodesFile = zip.file('neo4j/nodes.json')
    const relsFile = zip.file('neo4j/relationships.json')

    if (nodesFile) {
      const nodes: ExportedNode[] = JSON.parse(await nodesFile.async('text'))
      const relationships: ExportedRelationship[] = relsFile
        ? JSON.parse(await relsFile.async('text'))
        : []

      if (nodes.length > 0) {
        const session = getGraphSession()
        try {
          // Clear any existing data for the new project ID (safety)
          await clearProjectGraph(session, newProject.id)

          // X3: the source project's graph is NOT touched.
          //
          // This used to delete it, because the finding labels were unique on
          // `id` alone: importing an export of a project that still existed
          // would have collided with it, so the source was wiped to make room.
          // That is an operator importing a backup and silently losing the
          // project they took it from.
          //
          // Those constraints are now (id, user_id, project_id), so the same id
          // can exist in both projects and there is nothing to make room for.
          // `_oldProjectId` is kept only for the `_exportId` remapping below.

          // Shared with Scan Timeline version activation (lib/graphRestore.ts):
          // same MERGE-vs-CREATE-by-constraint, batching and _exportId wiring.
          // Nodes are re-owned under the importing user and the new project.
          const restored = await restoreGraph(session, nodes, relationships, {
            projectId: newProject.id,
            userId,
          })
          stats.neo4jNodes = restored.nodes
          stats.neo4jRelationships = restored.relationships
        } finally {
          await session.close()
        }
      }
    }

    // Import artifact files via orchestrator
    const artifactMappings = [
      { zipPath: `artifacts/recon_${_oldProjectId}.json`, type: 'recon' },
      { zipPath: `artifacts/gvm_${_oldProjectId}.json`, type: 'gvm' },
      { zipPath: `artifacts/github_hunt_${_oldProjectId}.json`, type: 'github_hunt' },
    ]

    for (const mapping of artifactMappings) {
      const artifactFile = zip.file(mapping.zipPath)
      if (artifactFile) {
        try {
          const content = await artifactFile.async('text')
          const blob = new Blob([content], { type: 'application/json' })
          const uploadFormData = new FormData()
          uploadFormData.append('file', blob, `${mapping.type}_${newProject.id}.json`)

          const response = await orchestratorFetch(
            `${RECON_ORCHESTRATOR_URL}/project/${newProject.id}/artifacts/${mapping.type}`,
            { method: 'POST', body: uploadFormData }
          )

          if (response.ok) {
            stats.artifacts++
          } else {
            console.warn(`Failed to upload ${mapping.type} artifact: ${response.status}`)
          }
        } catch (err) {
          console.warn(`Failed to upload ${mapping.type} artifact:`, err)
        }
      }
    }

    return NextResponse.json({
      success: true,
      projectId: newProject.id,
      projectName: newProject.name,
      stats,
    })
  } catch (error) {
    console.error('Import failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Import failed' },
      { status: 500 }
    )
  }
}
