import { NextRequest, NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'

// GET /api/projects - List projects (optional user_id filter)
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get('userId')

    const projects = await prisma.project.findMany({
      where: userId ? { userId } : undefined,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        userId: true,
        name: true,
        description: true,
        targetDomain: true,
        createdAt: true,
        updatedAt: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        }
      }
    })

    return NextResponse.json(projects)
  } catch (error) {
    console.error('Failed to fetch projects:', error)
    return NextResponse.json(
      { error: 'Failed to fetch projects' },
      { status: 500 }
    )
  }
}

// POST /api/projects - Create a new project
// Accepts either JSON or multipart/form-data (when RoE document is attached)
export async function POST(request: NextRequest) {
  try {
    let body: Record<string, unknown>
    let roeFileBuffer: Buffer | null = null
    let roeFileName = ''
    let roeFileMimeType = ''

    const contentType = request.headers.get('content-type') || ''

    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData()
      const jsonStr = formData.get('data') as string
      body = JSON.parse(jsonStr)

      const file = formData.get('roeDocument') as File | null
      if (file) {
        const arrayBuffer = await file.arrayBuffer()
        roeFileBuffer = Buffer.from(arrayBuffer)
        roeFileName = file.name
        roeFileMimeType = file.type || 'application/octet-stream'
      }
    } else {
      body = await request.json()
    }

    const { userId, name, targetDomain, ipMode, id: clientId, ...optionalParams } = body as {
      userId: string
      name: string
      targetDomain?: string
      ipMode?: boolean
      id?: string
      [key: string]: unknown
    }

    if (!userId || !name) {
      return NextResponse.json(
        { error: 'userId and name are required' },
        { status: 400 }
      )
    }

    // targetDomain is required only when not in IP mode
    if (!ipMode && !targetDomain) {
      return NextResponse.json(
        { error: 'targetDomain is required when not in IP mode' },
        { status: 400 }
      )
    }

    // Verify user exists
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // Hard guardrail: deterministic, non-disableable — always blocks government/public domains
    if (!ipMode && targetDomain) {
      const { isHardBlockedDomain } = await import('@/lib/hard-guardrail')
      const hardCheck = isHardBlockedDomain(targetDomain)
      if (hardCheck.blocked) {
        return NextResponse.json(
          { error: `Target permanently blocked: ${hardCheck.reason}` },
          { status: 403 }
        )
      }
    }

    // Soft guardrail (LLM-based): check if domain/IPs are allowed before creating
    if (optionalParams.targetGuardrailEnabled !== false) {
      try {
        const guardrailResponse = await fetch(`${AGENT_API_URL}/guardrail/check-target`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_domain: ipMode ? '' : (targetDomain || ''),
            target_ips: ipMode ? (optionalParams.targetIps || []) : [],
            user_id: userId,
          }),
        })

        if (guardrailResponse.ok) {
          const guardrailResult = await guardrailResponse.json()
          if (guardrailResult.allowed === false) {
            return NextResponse.json(
              { error: `Target blocked by guardrail: ${guardrailResult.reason}` },
              { status: 403 }
            )
          }
        }
        // If guardrail is unreachable or returns non-OK, fail open (allow)
      } catch (guardrailError) {
        console.warn('Guardrail check failed, proceeding with project creation:', guardrailError)
      }
    }

    // Attach RoE document binary if uploaded
    if (roeFileBuffer) {
      optionalParams.roeDocumentData = roeFileBuffer
      optionalParams.roeDocumentName = roeFileName
      optionalParams.roeDocumentMimeType = roeFileMimeType
    }

    // Sanitize array fields — LLM parsing may return strings instead of arrays
    // String[] fields: split comma-separated strings into arrays
    const STRING_ARRAY_FIELDS = [
      'subdomainList', 'targetIps', 'scanModules', 'nucleiSeverity',
      'nucleiTemplates', 'nucleiExcludeTemplates', 'nucleiCustomTemplates',
      'nucleiTags', 'nucleiExcludeTags',
      'httpxPaths', 'httpxCustomHeaders', 'httpxMatchCodes', 'httpxFilterCodes',
      'katanaExcludePatterns', 'katanaCustomHeaders',
      'gauProviders', 'gauBlacklistExtensions', 'gauYearRange',
      'kiterunnerWordlists', 'kiterunnerHeaders', 'kiterunnerBruteforceMethods',
      'roeExcludedHosts', 'roeExcludedHostReasons', 'roeTimeWindowDays',
      'roeForbiddenTools', 'roeForbiddenCategories',
      'roeThirdPartyProviders', 'roeComplianceFrameworks',
    ]
    for (const key of STRING_ARRAY_FIELDS) {
      if (key in optionalParams && typeof optionalParams[key] === 'string') {
        optionalParams[key] = (optionalParams[key] as string).split(',').map((s: string) => s.trim()).filter(Boolean)
      }
    }
    // Int[] fields: ensure elements are numbers, not strings
    const INT_ARRAY_FIELDS = [
      'gauVerifyAcceptStatus', 'kiterunnerIgnoreStatus', 'kiterunnerMatchStatus',
    ]
    for (const key of INT_ARRAY_FIELDS) {
      if (key in optionalParams) {
        const val = optionalParams[key]
        if (typeof val === 'string') {
          optionalParams[key] = val.split(',').map((s: string) => parseInt(s.trim(), 10)).filter((n: number) => !isNaN(n))
        } else if (Array.isArray(val)) {
          optionalParams[key] = val.map((v: unknown) => typeof v === 'string' ? parseInt(v, 10) : v).filter((n: unknown) => typeof n === 'number' && !isNaN(n))
        }
      }
    }

    // Strip unknown keys + coerce types (LLM may return strings for Int/Boolean fields)
    const VALID_FIELDS = new Set(Object.values(Prisma.ProjectScalarFieldEnum))
    const NON_SETTABLE = new Set(['id', 'userId', 'name', 'targetDomain', 'ipMode', 'createdAt', 'updatedAt'])

    // Build type map from Prisma DMMF for type coercion
    const projectModel = Prisma.dmmf.datamodel.models.find((m: { name: string }) => m.name === 'Project')
    const fieldTypeMap = new Map<string, string>()
    if (projectModel) {
      for (const f of projectModel.fields as readonly { name: string; type: string }[]) {
        fieldTypeMap.set(f.name, f.type)
      }
    }

    const sanitizedParams: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(optionalParams)) {
      if (!VALID_FIELDS.has(key as Prisma.ProjectScalarFieldEnum) || NON_SETTABLE.has(key) || value === null || value === undefined) {
        continue
      }
      const fieldType = fieldTypeMap.get(key)
      // Coerce string → Boolean
      if (fieldType === 'Boolean' && typeof value === 'string') {
        sanitizedParams[key] = value.toLowerCase() === 'true'
      // Coerce string → Int
      } else if (fieldType === 'Int' && typeof value === 'string') {
        const num = parseInt(value, 10)
        if (!isNaN(num)) sanitizedParams[key] = num
      // Coerce string → Float
      } else if (fieldType === 'Float' && typeof value === 'string') {
        const num = parseFloat(value)
        if (!isNaN(num)) sanitizedParams[key] = num
      // Parse string → Json
      } else if (fieldType === 'Json' && typeof value === 'string') {
        try { sanitizedParams[key] = JSON.parse(value) } catch { /* skip invalid JSON */ }
      } else {
        sanitizedParams[key] = value
      }
    }

    // Sanitize string inputs that are used as hostnames/IPs (trailing spaces break DNS)
    if (typeof sanitizedParams.subdomainList === 'object' && Array.isArray(sanitizedParams.subdomainList)) {
      sanitizedParams.subdomainList = (sanitizedParams.subdomainList as string[]).map(s => s.trim()).filter(Boolean)
    }
    if (typeof sanitizedParams.targetIps === 'object' && Array.isArray(sanitizedParams.targetIps)) {
      sanitizedParams.targetIps = (sanitizedParams.targetIps as string[]).map(s => s.trim()).filter(Boolean)
    }

    // Create project with required fields and valid optional params.
    // If the frontend provided a pre-generated ID (for uploads during creation), use it.
    const project = await prisma.project.create({
      data: {
        ...(clientId ? { id: clientId } : {}),
        userId,
        name: name.trim(),
        targetDomain: ipMode ? '' : (targetDomain || '').trim(),
        ipMode: ipMode || false,
        ...sanitizedParams
      }
    })

    // Create Domain node in Neo4j so it's visible in the graph immediately
    if (!ipMode && project.targetDomain) {
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
        console.warn('Failed to create Domain node in Neo4j on project creation:', e)
      }
    }

    // Sync JS Recon files uploaded during creation (before project existed in DB)
    if (clientId) {
      try {
        const { existsSync } = await import('fs')
        const { readdir } = await import('fs/promises')
        const path = await import('path')

        const JS_RECON_UPLOAD_PATH = process.env.JS_RECON_UPLOAD_PATH || '/data/js-recon-uploads'
        const JS_RECON_CUSTOM_PATH = process.env.JS_RECON_CUSTOM_PATH || '/data/js-recon-custom'

        const updateData: Record<string, unknown> = {}

        // Sync uploaded JS files
        const uploadDir = path.join(JS_RECON_UPLOAD_PATH, clientId)
        if (existsSync(uploadDir)) {
          const files = (await readdir(uploadDir)).filter(f => !f.startsWith('.'))
          if (files.length > 0) updateData.jsReconUploadedFiles = files
        }

        // Sync custom extension files
        const customDir = path.join(JS_RECON_CUSTOM_PATH, clientId)
        const FILE_TYPE_MAP: Record<string, string> = {
          patterns: 'jsReconCustomPatterns',
          'sourcemap-paths': 'jsReconCustomSourcemapPaths',
          packages: 'jsReconCustomPackages',
          'endpoint-keywords': 'jsReconCustomEndpointKeywords',
          frameworks: 'jsReconCustomFrameworks',
        }
        for (const [dirName, prismaField] of Object.entries(FILE_TYPE_MAP)) {
          const typeDir = path.join(customDir, dirName)
          if (existsSync(typeDir)) {
            const entries = await readdir(typeDir)
            if (entries.length > 0) {
              updateData[prismaField] = path.join(typeDir, entries[0])
            }
          }
        }

        if (Object.keys(updateData).length > 0) {
          await prisma.project.update({ where: { id: clientId }, data: updateData })
        }
      } catch (e) {
        console.warn('Failed to sync JS Recon uploads on project creation:', e)
      }
    }

    return NextResponse.json(project, { status: 201 })
  } catch (error) {
    console.error('Failed to create project:', error)
    return NextResponse.json(
      { error: 'Failed to create project' },
      { status: 500 }
    )
  }
}
