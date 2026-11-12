import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { mkdir, readdir, stat, unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { declaredBodyTooLarge } from '@/lib/roe/upload'
import { internalError } from '@/lib/routeErrors'

const JS_RECON_CUSTOM_PATH = process.env.JS_RECON_CUSTOM_PATH || '/data/js-recon-custom'
const MAX_FILE_SIZE = 2 * 1024 * 1024 // 2 MB
const ALLOWED_EXTENSIONS = ['.json', '.txt']

// Maps custom file types to their Prisma field names
const FILE_TYPE_MAP: Record<string, string> = {
  patterns: 'jsReconCustomPatterns',
  'sourcemap-paths': 'jsReconCustomSourcemapPaths',
  packages: 'jsReconCustomPackages',
  'endpoint-keywords': 'jsReconCustomEndpointKeywords',
  frameworks: 'jsReconCustomFrameworks',
}

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

function sanitizeFilename(name: string): string {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_')
}

// ---------------------------------------------------------------------------
// GET /api/js-recon/[projectId]/custom-files -- list custom extension files
// ---------------------------------------------------------------------------
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const projectDir = path.join(JS_RECON_CUSTOM_PATH, projectId)
    if (!existsSync(projectDir)) {
      return NextResponse.json({ files: {} })
    }

    const files: Record<string, { name: string; size: number; uploaded_at: string } | null> = {}

    for (const fileType of Object.keys(FILE_TYPE_MAP)) {
      const typeDir = path.join(projectDir, fileType)
      if (!existsSync(typeDir)) {
        files[fileType] = null
        continue
      }

      const entries = await readdir(typeDir)
      if (entries.length === 0) {
        files[fileType] = null
        continue
      }

      // Only one file per type
      const filename = entries[0]
      try {
        const fileStat = await stat(path.join(typeDir, filename))
        files[fileType] = {
          name: filename,
          size: fileStat.size,
          uploaded_at: fileStat.mtime.toISOString(),
        }
      } catch {
        files[fileType] = null
      }
    }

    return NextResponse.json({ files })
  } catch (error) {
    return internalError(error, 'Failed to list files', { log: 'Error listing JS Recon custom files' })
  }
}

// ---------------------------------------------------------------------------
// POST /api/js-recon/[projectId]/custom-files -- upload a custom extension file
// Body: multipart/form-data with 'file' and 'type' (patterns|sourcemap-paths|packages|endpoint-keywords|frameworks)
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const lengthProblem = declaredBodyTooLarge(request, MAX_FILE_SIZE)
    if (lengthProblem) return lengthProblem

    let formData: FormData
    try {
      formData = await request.formData()
    } catch {
      return NextResponse.json(
        { error: 'The upload could not be read as multipart form data.', code: 'invalid_multipart' },
        { status: 400 }
      )
    }
    const file = formData.get('file') as File | null
    const fileType = formData.get('type') as string | null

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (!fileType || !FILE_TYPE_MAP[fileType]) {
      return NextResponse.json(
        { error: `Invalid type. Allowed: ${Object.keys(FILE_TYPE_MAP).join(', ')}` },
        { status: 400 }
      )
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB`, code: 'file_too_large', limitBytes: MAX_FILE_SIZE },
        { status: 400 }
      )
    }

    const ext = path.extname(file.name).toLowerCase()
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return NextResponse.json(
        { error: `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}` },
        { status: 400 }
      )
    }

    // Validate JSON if .json file
    if (ext === '.json') {
      try {
        const content = await file.text()
        JSON.parse(content)
      } catch {
        return NextResponse.json({ error: 'Invalid JSON file' }, { status: 400 })
      }
    }

    const filename = sanitizeFilename(file.name)
    const typeDir = path.join(JS_RECON_CUSTOM_PATH, projectId, fileType)
    await mkdir(typeDir, { recursive: true })

    // Remove existing file for this type (one file per type)
    if (existsSync(typeDir)) {
      const existing = await readdir(typeDir)
      for (const f of existing) {
        await unlink(path.join(typeDir, f))
      }
    }

    const { writeFile: writeFileFs } = await import('fs/promises')
    const buffer = Buffer.from(await file.arrayBuffer())
    const filePath = path.join(typeDir, filename)
    await writeFileFs(filePath, buffer)

    const prismaField = FILE_TYPE_MAP[fileType]
    // Its new updatedAt goes back to the settings form, whose save is a
    // compare-and-swap on it.
    let projectUpdatedAt: Date | null = null
    try {
      const updated = await prisma.project.update({
        where: { id: projectId },
        data: { [prismaField]: filePath },
        select: { updatedAt: true },
      })
      projectUpdatedAt = updated.updatedAt
    } catch {
      // Best-effort: the guard above found the project, so this fails only on a
      // database error or a delete in between, and the file stays on disk unrecorded.
    }

    return NextResponse.json({
      uploaded: { name: filename, size: file.size, type: fileType, path: filePath },
      projectUpdatedAt,
    })
  } catch (error) {
    return internalError(error, 'Failed to upload file', { log: 'Error uploading JS Recon custom file' })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/js-recon/[projectId]/custom-files?type=patterns -- delete custom file
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId })
    if (auth instanceof NextResponse) return auth
    const fileType = request.nextUrl.searchParams.get('type')

    if (!fileType || !FILE_TYPE_MAP[fileType]) {
      return NextResponse.json(
        { error: `Invalid type. Allowed: ${Object.keys(FILE_TYPE_MAP).join(', ')}` },
        { status: 400 }
      )
    }

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const typeDir = path.join(JS_RECON_CUSTOM_PATH, projectId, fileType)
    if (existsSync(typeDir)) {
      const entries = await readdir(typeDir)
      for (const f of entries) {
        await unlink(path.join(typeDir, f))
      }
    }

    // Clear the Prisma field
    const prismaField = FILE_TYPE_MAP[fileType]
    const updated = await prisma.project.update({
      where: { id: projectId },
      data: { [prismaField]: '' },
      select: { updatedAt: true },
    })

    return NextResponse.json({ deleted: fileType, projectUpdatedAt: updated.updatedAt })
  } catch (error) {
    return internalError(error, 'Failed to delete file', { log: 'Error deleting JS Recon custom file' })
  }
}
