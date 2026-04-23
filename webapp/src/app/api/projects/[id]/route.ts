import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'
import { unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { getSession } from '@/app/api/graph/neo4j'

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
      return NextResponse.json({ ...projectWithoutBinary, userAttackSkills: skills })
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
    const body = await request.json()

    // Remove fields that shouldn't be updated directly
    const { userId, createdAt, updatedAt, user, ...updateData } = body

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
        const session = getSession()
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
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // 1. Delete project from PostgreSQL
    await prisma.project.delete({
      where: { id }
    })

    // 2. Delete all output JSON files via orchestrator (it has write permissions)
    //    This covers: recon, GVM, and GitHub Secret Hunt JSON files
    try {
      const orchestratorResponse = await fetch(`${RECON_ORCHESTRATOR_URL}/project/${id}/files`, {
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
      const session = getSession()
      try {
        // Delete all nodes that belong to this project (DETACH DELETE removes relationships too)
        await session.run(
          `MATCH (n {project_id: $projectId}) DETACH DELETE n`,
          { projectId: id }
        )
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
