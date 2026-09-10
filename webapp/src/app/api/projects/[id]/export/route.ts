import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { existsSync, createReadStream, readdirSync } from 'fs'
import path from 'path'
import archiver from 'archiver'
import { Readable } from 'stream'
import { randomUUID } from 'crypto'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { serializeGraphProperties } from '@/lib/graphSerialize'

const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

interface RouteParams {
  params: Promise<{ id: string }>
}

// Shared with lib/scanSnapshot.ts so exports and Scan Timeline snapshots are the
// same restore-fidelity format (a snapshot must be re-importable into Neo4j).
const serializeProperties = serializeGraphProperties

export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership: export bundles the ENTIRE project (row + RoE binary, all
    // conversations/messages, reports, the Neo4j subgraph, presets), so it is the
    // most sensitive project route. Only the effective owner may export it.
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    // 1. Fetch project from PostgreSQL
    const project = await prisma.project.findUnique({ where: { id } })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // 2. Fetch conversations and messages
    const conversations = await prisma.conversation.findMany({
      where: { projectId: id },
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

    // 2d. Fetch user project presets
    const userPresets = await prisma.userProjectPreset.findMany({
      where: { userId: project.userId },
      orderBy: { createdAt: 'asc' },
    })

    // 3. Export Neo4j data
    let neo4jNodes: Array<{ labels: string[]; properties: Record<string, unknown>; _exportId: string }> = []
    let neo4jRelationships: Array<{ startExportId: string; endExportId: string; type: string; properties: Record<string, unknown> }> = []

    const session = getGraphSession()
    try {
      // Export all nodes for this project
      const nodesResult = await session.run(
        `MATCH (n) WHERE n.project_id = $pid
         RETURN labels(n) as labels, properties(n) as props, elementId(n) as eid`,
        { pid: id }
      )

      const elementIdToExportId = new Map<string, string>()

      neo4jNodes = nodesResult.records.map(record => {
        const eid = record.get('eid') as string
        const exportId = randomUUID()
        elementIdToExportId.set(eid, exportId)
        return {
          labels: record.get('labels') as string[],
          properties: serializeProperties(record.get('props') as Record<string, unknown>),
          _exportId: exportId,
        }
      })

      // Export all relationships where at least one end has this project_id
      const relsResult = await session.run(
        `MATCH (a)-[r]->(b)
         WHERE a.project_id = $pid OR b.project_id = $pid
         RETURN elementId(a) as startId, elementId(b) as endId,
                type(r) as relType, properties(r) as relProps`,
        { pid: id }
      )

      neo4jRelationships = relsResult.records
        .filter(record => {
          const startId = record.get('startId') as string
          const endId = record.get('endId') as string
          return elementIdToExportId.has(startId) && elementIdToExportId.has(endId)
        })
        .map(record => ({
          startExportId: elementIdToExportId.get(record.get('startId') as string)!,
          endExportId: elementIdToExportId.get(record.get('endId') as string)!,
          type: record.get('relType') as string,
          properties: serializeProperties((record.get('relProps') as Record<string, unknown>) || {}),
        }))
    } finally {
      await session.close()
    }

    // 4. Build manifest
    const manifest = {
      version: '1.0.0',
      exportDate: new Date().toISOString(),
      projectName: project.name,
      targetDomain: project.targetDomain,
      stats: {
        conversations: conversations.length,
        chatMessages: messages.length,
        remediations: remediations.length,
        reports: reports.length,
        neo4jNodes: neo4jNodes.length,
        neo4jRelationships: neo4jRelationships.length,
        userPresets: userPresets.length,
        scanVersions: scanVersions.length,
        scanJobs: scanJobs.length,
        scanSchedules: scanSchedules.length,
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
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { roeDocumentData: _roeDocBinary, ...projectWithoutBinary } = project
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

    // Append user project presets
    if (userPresets.length > 0) {
      archive.append(Buffer.from(JSON.stringify(userPresets, null, 2)), { name: 'presets/user_project_presets.json' })
    }

    // Append artifact files from disk
    for (const af of artifacts) {
      archive.append(createReadStream(af.filePath), { name: af.archiveName })
    }

    archive.finalize()

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
    console.error('Export failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Export failed' },
      { status: 500 }
    )
  }
}
