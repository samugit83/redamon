import { NextRequest, NextResponse } from 'next/server'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import { stripStepContent } from '@/lib/authz/stepContent'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { existsSync, createReadStream, readdirSync } from 'fs'
import path from 'path'
import archiver from 'archiver'
import { Readable } from 'stream'
import { projectPresetForRead } from '@/lib/reconPresets/server'
import { PROJECT_EXPORT_EXCLUDED, PROJECT_EXPORT_EXCLUDED_REASON } from '@/lib/projectExport/pluginExclusion'
import { exportProjectGraph, type ExportedGraph } from '@/lib/projectExport/graph'
import { REFERENCE_LINKS_BUNDLE_PATH } from '@/lib/graphReferenceLinks'
import { exportRevision, REVISIONS_BUNDLE_PATH } from '@/lib/roe/revisionBundle'
import { internalError } from '@/lib/routeErrors'
import { projectReadView } from '@/lib/authz/projectReadView'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'

const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Export bundles the whole project (row + RoE binary, conversations/messages, reports, the
    // Neo4j subgraph, presets), so it is the most sensitive project route: project:export (M).
    const auth = await requirePermission(request, 'project:export', { projectId: id })
    if (auth instanceof NextResponse) return auth
    // The bundle carries chat messages and the raw scan artifacts as they are, so it is Raw data &
    // files (R*) too, whatever level project:export is given.
    const raw = requireLevel(auth, 'R*')
    if (raw) return raw
    // A co-owner's export (step 5.2, SH-31) is the project as they may read it: the row without the
    // owner's secret columns (projectReadView: credentials, header lists, the RoE document and what
    // was parsed from it), RoE revisions without their bodies, only the conversations they wrote
    // (step 5.8 widens it to the shared ones), none of the owner's presets, and a line in the
    // project's activity feed. The owner's export is unchanged.
    const ownerExport = auth.access?.level === 'owner'
    const exporterId = auth.effective.userId

    // 1. Fetch project from PostgreSQL
    const storedProject = await prisma.project.findUnique({ where: { id } })
    if (!storedProject) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }
    const project = projectReadView(storedProject, auth.access) as typeof storedProject

    // 2. Fetch conversations and messages
    const conversations = await prisma.conversation.findMany({
      where: ownerExport ? { projectId: id } : { projectId: id, userId: exporterId },
      orderBy: { createdAt: 'asc' },
    })

    const conversationIds = conversations.map(c => c.id)
    const messages = await prisma.chatMessage.findMany({
      where: { conversationId: { in: conversationIds } },
      orderBy: [{ conversationId: 'asc' }, { sequenceNum: 'asc' }],
    })

    // 2b. Fetch remediations
    const remediations = await prisma.remediation.findMany({
      where: { projectId: id },
      orderBy: { createdAt: 'asc' },
    })

    // 2c. Fetch reports
    const reports = await prisma.report.findMany({
      where: { projectId: id },
      orderBy: { createdAt: 'asc' },
    })

    // 2c-bis. Scan Timeline (plan Section 9): versions + run history + schedules
    // travel with the project so its history survives a round-trip. Snapshot
    // bytes are base64'd because Bytes cannot survive JSON.stringify.
    const scanVersions = await prisma.scanVersion.findMany({
      where: { projectId: id },
      orderBy: { seq: 'asc' },
    })
    const scanJobs = await prisma.scanJob.findMany({
      where: { projectId: id },
      orderBy: { createdAt: 'asc' },
    })
    const scanSchedules = await prisma.scanSchedule.findMany({
      where: { projectId: id },
      orderBy: { createdAt: 'asc' },
    })

    // 2c-ter. The engagement authorizations. They travel with the project for the
    // same reason its scan history does: an exported project that arrives
    // somewhere else without the record of what authorized it is a project
    // nobody can account for.
    const engagementAuthorizations = await prisma.engagementAuthorization.findMany({
      where: { projectId: id },
      orderBy: { recordedAt: 'asc' },
    })
    // The superseded RoE documents: the terms earlier scans ran under.
    const storedRevisions = await prisma.roeDocumentRevision.findMany({
      where: { projectId: id },
      orderBy: { supersededAt: 'desc' },
    })
    // A superseded document and its parse stay the owner's, as the current one does (OQ-53).
    const roeRevisions = ownerExport
      ? storedRevisions
      : storedRevisions.map(r => ({ ...r, data: null, rawText: '', parsedJson: null }))

    // 2c'. Node filters: the rules and the operator's exemptions. Run history
    // stays behind; it describes this install's graph, not the project.
    const nodeFilter = await prisma.projectNodeFilter.findUnique({
      where: { projectId: id },
      select: { mode: true, rules: true, revision: true, loadedPreset: true },
    })
    const nodeFilterExemptions = await prisma.nodeFilterExemption.findMany({
      where: { projectId: id },
      select: { label: true, nodeKey: true, createdAt: true },
      orderBy: { createdAt: 'asc' },
    })

    // 2d. Fetch user project presets. Their settings leave as the PRESET FIELDS
    // only: a preset stored before storage was filtered can carry a target or a
    // credential, and an export is a file that travels.
    // The presets are the owner's own library, not the project's: a co-owner's export has none.
    const userPresets = !ownerExport ? [] : (await prisma.userProjectPreset.findMany({
      where: { userId: storedProject.userId },
      orderBy: { createdAt: 'asc' },
      select: { name: true, description: true, settings: true, createdAt: true },
    })).map(p => ({ ...p, settings: projectPresetForRead(p.settings).settings }))
    const muteRulesPresets = !ownerExport ? [] : await prisma.userMuteRulesPreset.findMany({
      where: { userId: storedProject.userId },
      orderBy: { createdAt: 'asc' },
      select: { name: true, description: true, mode: true, rules: true },
    })

    // 3. Export Neo4j data: the project's nodes and relationships, and its
    // edges to the global CVE / MitreData / Capec nodes as link records (never
    // the nodes themselves, which every tenant shares).
    const session = getGraphSession()
    let graph: ExportedGraph
    try {
      graph = await exportProjectGraph(session, id)
    } finally {
      await session.close()
    }
    const { relationships: neo4jRelationships, referenceLinks } = graph
    // Every graph output passes through the step-content helper (SH-30); an exporter is at R*
    // (checked above), so it changes nothing unless that check is ever relaxed.
    const neo4jNodes = stripStepContent(graph.nodes, auth.access)

    // 4. Build manifest. 1.1.0 added neo4j/reference_links.json; an older
    // bundle without it imports as before.
    const manifest = {
      version: '1.1.0',
      exportDate: new Date().toISOString(),
      projectName: project.name,
      targetDomain: project.targetDomain,
      // Carried in the manifest as well as the project JSON, so the import rule
      // can be applied before anything is written.
      engagementKind: project.engagementKind,
      // Deliberately left out, not forgotten (OQ-18): plugin rows belong to a plugin install.
      excluded: [...PROJECT_EXPORT_EXCLUDED],
      excludedReason: PROJECT_EXPORT_EXCLUDED_REASON,
      stats: {
        conversations: conversations.length,
        chatMessages: messages.length,
        remediations: remediations.length,
        reports: reports.length,
        neo4jNodes: neo4jNodes.length,
        neo4jRelationships: neo4jRelationships.length,
        neo4jReferenceLinks: referenceLinks.length,
        userPresets: userPresets.length,
        muteRulesPresets: muteRulesPresets.length,
        scanVersions: scanVersions.length,
        scanJobs: scanJobs.length,
        scanSchedules: scanSchedules.length,
        engagementAuthorizations: engagementAuthorizations.length,
        roeRevisions: roeRevisions.length,
        artifacts: 0,
      },
    }

    // 5. Check for artifact files
    const artifacts: Array<{ type: string; filePath: string; archiveName: string }> = []
    // Domain batch writes one file per group beside the canonical one; without
    // them an export silently loses the per-group raw output.
    const batchArtifacts = (() => {
      try {
        return readdirSync(RECON_OUTPUT_PATH)
          .filter(n => n.startsWith(`recon_${id}__`) && n.endsWith('.json'))
          .map(n => ({ type: 'recon', filePath: path.join(RECON_OUTPUT_PATH, n), archiveName: `artifacts/${n}` }))
      } catch {
        return []
      }
    })()

    const artifactFiles = [
      { type: 'recon', filePath: path.join(RECON_OUTPUT_PATH, `recon_${id}.json`), archiveName: `artifacts/recon_${id}.json` },
      ...batchArtifacts,
      { type: 'gvm', filePath: path.join(GVM_OUTPUT_PATH, `gvm_${id}.json`), archiveName: `artifacts/gvm_${id}.json` },
      { type: 'github_hunt', filePath: path.join(GITHUB_HUNT_OUTPUT_PATH, `github_hunt_${id}.json`), archiveName: `artifacts/github_hunt_${id}.json` },
    ]
    for (const af of artifactFiles) {
      if (existsSync(af.filePath)) {
        artifacts.push(af)
        manifest.stats.artifacts++
      }
    }

    // 6. Create ZIP archive
    const archive = archiver('zip', { zlib: { level: 6 } })

    // Separate binary RoE document from project JSON - Bytes can't survive JSON.stringify
    let roeDocumentBase64: string | null = null
    if (project.roeDocumentData) {
      roeDocumentBase64 = Buffer.from(project.roeDocumentData).toString('base64')
    }
    // `roeEnabled` leaves the bundle. It is DERIVED from whether any engagement
    // limit is set, so an exported copy would be a value nothing writes and
    // nothing believes: the far side recomputes it from the limits, which do
    // round-trip normally. Carrying it would let a bundle assert a flag that
    // disagrees with the limits beside it.
    const {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      roeDocumentData: _roeDocBinary,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      roeEnabled: _roeEnabledDerived,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      jevProviderId: _accountScopedJevProvider,
      ...projectWithoutBinary
    } = project
    const projectExport = {
      ...projectWithoutBinary,
      ...(roeDocumentBase64 ? { roeDocumentDataBase64: roeDocumentBase64 } : {}),
    }

    // Append JSON data
    archive.append(Buffer.from(JSON.stringify(manifest, null, 2)), { name: 'manifest.json' })
    archive.append(Buffer.from(JSON.stringify(projectExport, null, 2)), { name: 'project.json' })
    archive.append(Buffer.from(JSON.stringify(conversations, null, 2)), { name: 'conversations/conversations.json' })
    archive.append(Buffer.from(JSON.stringify(messages, null, 2)), { name: 'conversations/messages.json' })
    archive.append(Buffer.from(JSON.stringify(remediations, null, 2)), { name: 'remediations/remediations.json' })

    // Append report metadata and HTML files
    const reportMeta = reports.map(r => ({
      id: r.id,
      title: r.title,
      filename: r.filename,
      fileSize: r.fileSize,
      format: r.format,
      metrics: r.metrics,
      hasNarratives: r.hasNarratives,
      createdAt: r.createdAt,
    }))
    archive.append(Buffer.from(JSON.stringify(reportMeta, null, 2)), { name: 'reports/reports.json' })
    for (const r of reports) {
      if (existsSync(r.filePath)) {
        archive.append(createReadStream(r.filePath), { name: `reports/${r.filename}` })
      }
    }

    // Scan Timeline history (Section 9).
    archive.append(
      Buffer.from(JSON.stringify(
        scanVersions.map(v => {
          const { snapshot, ...rest } = v
          return {
            ...rest,
            snapshotBase64: snapshot ? Buffer.from(snapshot).toString('base64') : null,
          }
        }),
        null, 2
      )),
      { name: 'timeline/versions.json' }
    )
    archive.append(Buffer.from(JSON.stringify(scanJobs, null, 2)), { name: 'timeline/jobs.json' })
    archive.append(
      Buffer.from(JSON.stringify(engagementAuthorizations, null, 2)),
      { name: 'engagement/authorizations.json' }
    )
    if (roeRevisions.length > 0) {
      archive.append(
        Buffer.from(JSON.stringify(roeRevisions.map(exportRevision), null, 2)),
        { name: REVISIONS_BUNDLE_PATH },
      )
    }
    archive.append(
      Buffer.from(JSON.stringify(
        scanSchedules.map(s => ({
          ...s,
          // BigInt is not JSON-serializable.
          estimatedEnvelopeBytes: s.estimatedEnvelopeBytes === null ? null : String(s.estimatedEnvelopeBytes),
        })),
        null, 2
      )),
      { name: 'timeline/schedules.json' }
    )

    archive.append(Buffer.from(JSON.stringify(neo4jNodes, null, 2)), { name: 'neo4j/nodes.json' })
    archive.append(Buffer.from(JSON.stringify(neo4jRelationships, null, 2)), { name: 'neo4j/relationships.json' })
    archive.append(Buffer.from(JSON.stringify(referenceLinks, null, 2)), { name: REFERENCE_LINKS_BUNDLE_PATH })

    if (nodeFilter) {
      archive.append(Buffer.from(JSON.stringify(nodeFilter, null, 2)), { name: 'node-filters/node-filters.json' })
    }
    if (nodeFilterExemptions.length > 0) {
      archive.append(
        Buffer.from(JSON.stringify(nodeFilterExemptions, null, 2)),
        { name: 'node-filters/node-filter-exemptions.json' },
      )
    }

    // Append user project presets
    if (userPresets.length > 0) {
      archive.append(Buffer.from(JSON.stringify(userPresets, null, 2)), { name: 'presets/user_project_presets.json' })
    }
    if (muteRulesPresets.length > 0) {
      archive.append(
        Buffer.from(JSON.stringify(muteRulesPresets, null, 2)),
        { name: 'presets/user_mute_rules_presets.json' },
      )
    }

    // Append artifact files from disk
    for (const af of artifacts) {
      archive.append(createReadStream(af.filePath), { name: af.archiveName })
    }

    archive.finalize()

    if (!ownerExport) {
      // The owner sees in the project's activity feed that a collaborator took a copy away.
      await writeAudit({
        ...actorFields(auditActorOf(auth.principal, exporterId)),
        action: 'project.exported',
        targetType: 'project',
        targetId: id,
        projectId: id,
        after: { projectId: id, conversations: conversations.length, roeRevisions: roeRevisions.length },
        source: 'ui',
      })
    }

    // Convert Node.js readable stream to Web ReadableStream
    const webStream = Readable.toWeb(archive as unknown as Readable) as ReadableStream

    const safeName = project.name.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50)
    const dateStr = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19)
    const filename = `redamon-project-${safeName}-${dateStr}.zip`

    return new Response(webStream, {
      headers: {
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Cache-Control': 'no-cache',
      },
    })
  } catch (error) {
    return internalError(error, 'Export failed')
  }
}
