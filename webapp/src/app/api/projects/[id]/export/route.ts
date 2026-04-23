import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'
import { existsSync, createReadStream } from 'fs'
import path from 'path'
import archiver from 'archiver'
import { Readable } from 'stream'
import { randomUUID } from 'crypto'

const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

interface RouteParams {
  params: Promise<{ id: string }>
}

function serializeValue(value: unknown): unknown {
  if (value === null || value === undefined) return value

  // Neo4j DateTime: has year/month/day fields (check before integer check)
  if (typeof value === 'object' && 'year' in value && 'month' in value && 'day' in value) {
    const v = value as Record<string, unknown>
    const get = (k: string): number => {
      const f = v[k]
      if (f && typeof f === 'object' && 'low' in f) return (f as { low: number }).low
      return typeof f === 'number' ? f : 0
    }
    const year = get('year')
    const month = String(get('month')).padStart(2, '0')
    const day = String(get('day')).padStart(2, '0')
    const hour = String(get('hour')).padStart(2, '0')
    const minute = String(get('minute')).padStart(2, '0')
    const second = String(get('second')).padStart(2, '0')
    return `${year}-${month}-${day}T${hour}:${minute}:${second}Z`
  }

  // Neo4j Integer: has low/high fields (driver Integer objects)
  if (typeof value === 'object' && 'low' in value && 'high' in value) {
    return (value as { low: number }).low
  }

  // Arrays: recurse into elements
  if (Array.isArray(value)) {
    return value.map(v => serializeValue(v))
  }

  return value
}

function serializeProperties(props: Record<string, unknown>): Record<string, unknown> {
  const serialized: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(props)) {
    serialized[key] = serializeValue(value)
  }
  return serialized
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

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

    // 2d. Fetch user project presets
    const userPresets = await prisma.userProjectPreset.findMany({
      where: { userId: project.userId },
      orderBy: { createdAt: 'asc' },
    })

    // 3. Export Neo4j data
    let neo4jNodes: Array<{ labels: string[]; properties: Record<string, unknown>; _exportId: string }> = []
    let neo4jRelationships: Array<{ startExportId: string; endExportId: string; type: string; properties: Record<string, unknown> }> = []

    const session = getSession()
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
        artifacts: 0,
      },
    }

    // 5. Check for artifact files
    const artifacts: Array<{ type: string; filePath: string; archiveName: string }> = []
    const artifactFiles = [
      { type: 'recon', filePath: path.join(RECON_OUTPUT_PATH, `recon_${id}.json`), archiveName: `artifacts/recon_${id}.json` },
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

    // Separate binary RoE document from project JSON — Bytes can't survive JSON.stringify
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
