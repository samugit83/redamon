import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'
import JSZip from 'jszip'
import { randomUUID } from 'crypto'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import path from 'path'

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
    const userId = request.nextUrl.searchParams.get('userId')
    if (!userId) {
      return NextResponse.json({ error: 'userId query parameter is required' }, { status: 400 })
    }

    // Verify user exists
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // Parse uploaded ZIP
    const formData = await request.formData()
    const file = formData.get('file') as File | null
    if (!file) {
      return NextResponse.json({ error: 'No file uploaded' }, { status: 400 })
    }

    const arrayBuffer = await file.arrayBuffer()
    const zip = await JSZip.loadAsync(arrayBuffer)

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
    const projectData = JSON.parse(await projectFile.async('text'))

    // Strip fields that will be regenerated
    const { id: _oldProjectId, userId: _oldUserId, createdAt: _pc, updatedAt: _pu, user: _u, roeDocumentDataBase64, ...projectFields } = projectData

    // Restore binary RoE document from base64 encoding
    if (roeDocumentDataBase64 && typeof roeDocumentDataBase64 === 'string') {
      projectFields.roeDocumentData = Buffer.from(roeDocumentDataBase64, 'base64')
    }

    // Create new project under the specified user
    const newProject = await prisma.project.create({
      data: {
        ...projectFields,
        userId,
      },
    })

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
          const htmlFile = zip.file(`reports/${rm.filename}`)
          if (!htmlFile) continue

          const htmlContent = await htmlFile.async('nodebuffer')
          const filePath = path.join(REPORT_OUTPUT_PATH, rm.filename)
          writeFileSync(filePath, htmlContent)

          await prisma.report.create({
            data: {
              projectId: newProject.id,
              title: rm.title,
              filename: rm.filename,
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

    // Import user project presets (if present)
    const presetsFile = zip.file('presets/user_project_presets.json')
    if (presetsFile) {
      const presets = JSON.parse(await presetsFile.async('text'))
      for (const preset of presets) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { id: _id, userId: _uid, createdAt: _ca, updatedAt: _ua, ...fields } = preset
        await prisma.userProjectPreset.create({
          data: { ...fields, userId },
        })
      }
      (stats as Record<string, number>).userPresets = presets.length
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
        const session = getSession()
        try {
          // Clear any existing data for the new project ID (safety)
          await session.run(
            'MATCH (n {project_id: $pid}) DETACH DELETE n',
            { pid: newProject.id }
          )

          // Also clear the original project's Neo4j data to prevent duplicates.
          // With global unique constraints, nodes from the old project would conflict
          // or create stale relationships pointing to orphaned unconstrained nodes.
          if (_oldProjectId && _oldProjectId !== newProject.id) {
            await session.run(
              'MATCH (n {project_id: $pid}) DETACH DELETE n',
              { pid: _oldProjectId }
            )
          }

          // Query unique constraints so we can MERGE instead of CREATE
          // for labels that have them (avoids IndexEntryConflictException)
          const constraintResult = await session.run(
            `SHOW CONSTRAINTS YIELD labelsOrTypes, properties, type
             WHERE type = 'UNIQUENESS'
             RETURN labelsOrTypes[0] AS label, properties`
          )
          const uniqueKeyMap = new Map<string, string[]>()
          for (const record of constraintResult.records) {
            const label = record.get('label') as string
            const props = record.get('properties') as string[]
            uniqueKeyMap.set(label, props)
          }

          // Remap user_id and project_id in node properties, add _exportId
          const remappedNodes = nodes.map(node => ({
            labels: node.labels,
            properties: {
              ...node.properties,
              user_id: userId,
              project_id: newProject.id,
              _exportId: node._exportId,
            },
          }))

          // Group nodes by primary label to apply correct merge strategy
          const nodesByLabel = new Map<string, typeof remappedNodes>()
          for (const node of remappedNodes) {
            const primaryLabel = node.labels[0] || '__no_label__'
            if (!nodesByLabel.has(primaryLabel)) {
              nodesByLabel.set(primaryLabel, [])
            }
            nodesByLabel.get(primaryLabel)!.push(node)
          }

          // Create/merge nodes per label group
          const NODE_BATCH_SIZE = 500
          for (const [label, labelNodes] of nodesByLabel) {
            // Check if this label (or any label on nodes in this group) has a unique constraint
            const uniqueKeys = uniqueKeyMap.get(label)

            for (let i = 0; i < labelNodes.length; i += NODE_BATCH_SIZE) {
              const batch = labelNodes.slice(i, i + NODE_BATCH_SIZE)

              if (uniqueKeys && uniqueKeys.length > 0) {
                // Has unique constraint — use MERGE to avoid conflict
                // Build identity expression from constraint keys
                const identExpr = uniqueKeys
                  .map(k => `\`${k}\`: node.properties.\`${k}\``)
                  .join(', ')

                await session.run(
                  `UNWIND $nodes AS node
                   CALL apoc.merge.node(node.labels, {${identExpr}}, node.properties, node.properties) YIELD node AS n
                   RETURN count(n)`,
                  { nodes: batch }
                )
              } else {
                // No unique constraint — safe to CREATE
                await session.run(
                  `UNWIND $nodes AS node
                   CALL apoc.create.node(node.labels, node.properties) YIELD node AS n
                   RETURN count(n)`,
                  { nodes: batch }
                )
              }
            }
          }
          stats.neo4jNodes = nodes.length

          // Create relationships using _exportId references
          if (relationships.length > 0) {
            const REL_BATCH_SIZE = 500
            for (let i = 0; i < relationships.length; i += REL_BATCH_SIZE) {
              const batch = relationships.slice(i, i + REL_BATCH_SIZE)
              await session.run(
                `UNWIND $rels AS rel
                 MATCH (a {_exportId: rel.startExportId, project_id: $pid})
                 MATCH (b {_exportId: rel.endExportId, project_id: $pid})
                 CALL apoc.create.relationship(a, rel.type, rel.properties, b) YIELD rel AS r
                 RETURN count(r)`,
                { rels: batch, pid: newProject.id }
              )
            }
            stats.neo4jRelationships = relationships.length
          }

          // Clean up temporary _exportId property
          await session.run(
            'MATCH (n {project_id: $pid}) WHERE n._exportId IS NOT NULL REMOVE n._exportId',
            { pid: newProject.id }
          )
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

          const response = await fetch(
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
