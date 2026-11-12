import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { mkdir, readdir, stat, unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { declaredBodyTooLarge } from '@/lib/roe/upload'
import { internalError } from '@/lib/routeErrors'

const JS_RECON_UPLOAD_PATH = process.env.JS_RECON_UPLOAD_PATH || '/data/js-recon-uploads'
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB
const ALLOWED_EXTENSIONS = ['.js', '.mjs', '.map', '.json']

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

function sanitizeFilename(name: string): string {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_')
}

function isAllowedExtension(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase()
  return ALLOWED_EXTENSIONS.includes(ext)
}

// ---------------------------------------------------------------------------
// GET /api/js-recon/[projectId]/upload -- list uploaded JS files
// ---------------------------------------------------------------------------
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const projectDir = path.join(JS_RECON_UPLOAD_PATH, projectId)
    if (!existsSync(projectDir)) {
      return NextResponse.json({ files: [] })
    }

    const entries = await readdir(projectDir)
    const files = []

    for (const entry of entries) {
      const filePath = path.join(projectDir, entry)
      try {
        const fileStat = await stat(filePath)
        if (fileStat.isFile()) {
          files.push({
            name: entry,
            size: fileStat.size,
            uploaded_at: fileStat.mtime.toISOString(),
          })
        }
      } catch {
        // Skip unreadable files
      }
    }

    return NextResponse.json({ files })
  } catch (error) {
    return internalError(error, 'Failed to list files', { log: 'Error listing JS Recon uploads' })
  }
}

// ---------------------------------------------------------------------------
// POST /api/js-recon/[projectId]/upload -- upload JS files for analysis
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    // The id becomes a directory name; the format check above is what makes that safe.

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

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB`, code: 'file_too_large', limitBytes: MAX_FILE_SIZE },
        { status: 400 }
      )
    }

    const filename = sanitizeFilename(file.name)
    if (!isAllowedExtension(filename)) {
      return NextResponse.json(
        { error: `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}` },
        { status: 400 }
      )
    }

    const projectDir = path.join(JS_RECON_UPLOAD_PATH, projectId)
    await mkdir(projectDir, { recursive: true })

    const filePath = path.join(projectDir, filename)

    // Prevent silent overwrite -- require explicit delete first
    if (existsSync(filePath)) {
      return NextResponse.json(
        { error: `File '${filename}' already exists. Delete it first or rename before uploading.` },
        { status: 409 }
      )
    }

    const { writeFile: writeFileFs } = await import('fs/promises')
    const buffer = Buffer.from(await file.arrayBuffer())
    await writeFileFs(filePath, buffer)

    // Record the file in jsReconUploadedFiles. Its new updatedAt goes back to the
    // settings form, whose save is a compare-and-swap on it.
    let projectUpdatedAt: Date | null = null
    try {
      const currentFiles = (await prisma.project.findUnique({
        where: { id: projectId },
        select: { jsReconUploadedFiles: true }
      }))?.jsReconUploadedFiles || []

      if (!currentFiles.includes(filename)) {
        const updated = await prisma.project.update({
          where: { id: projectId },
          data: { jsReconUploadedFiles: [...currentFiles, filename] },
          select: { updatedAt: true },
        })
        projectUpdatedAt = updated.updatedAt
      }
    } catch {
      // Best-effort: the guard above found the project, so this fails only on a
      // database error or a delete in between, and the file stays on disk unrecorded.
    }

    return NextResponse.json({
      uploaded: { name: filename, size: file.size, path: filePath },
      projectUpdatedAt,
    })
  } catch (error) {
    return internalError(error, 'Failed to upload file', { log: 'Error uploading JS file' })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/js-recon/[projectId]/upload?name=filename.js -- delete uploaded file
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId })
    if (auth instanceof NextResponse) return auth
    const filename = request.nextUrl.searchParams.get('name')

    if (!filename) {
      return NextResponse.json({ error: 'Missing name parameter' }, { status: 400 })
    }

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, jsReconUploadedFiles: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const safeName = sanitizeFilename(filename)
    const filePath = path.join(JS_RECON_UPLOAD_PATH, projectId, safeName)

    if (existsSync(filePath)) {
      await unlink(filePath)
    }

    // Remove from jsReconUploadedFiles
    const updatedFiles = (project.jsReconUploadedFiles || []).filter(f => f !== safeName)
    const updated = await prisma.project.update({
      where: { id: projectId },
      data: { jsReconUploadedFiles: updatedFiles },
      select: { updatedAt: true },
    })

    return NextResponse.json({ deleted: safeName, projectUpdatedAt: updated.updatedAt })
  } catch (error) {
    return internalError(error, 'Failed to delete file', { log: 'Error deleting JS file' })
  }
}
