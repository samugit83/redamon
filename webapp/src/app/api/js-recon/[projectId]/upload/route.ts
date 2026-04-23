import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { mkdir, readdir, stat, unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

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
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    // Skip DB lookup -- project may not exist yet (pre-generated ID during creation)
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
    console.error('Error listing JS Recon uploads:', error)
    return NextResponse.json({ error: 'Failed to list files' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// POST /api/js-recon/[projectId]/upload -- upload JS files for analysis
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    // Skip DB lookup -- project may not exist yet (pre-generated ID during creation).
    // The projectId format validation above is sufficient for directory creation.

    const formData = await request.formData()
    const file = formData.get('file') as File | null

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB` },
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

    // Update jsReconUploadedFiles in the project (skip if project doesn't exist yet -- during creation)
    try {
      const currentFiles = (await prisma.project.findUnique({
        where: { id: projectId },
        select: { jsReconUploadedFiles: true }
      }))?.jsReconUploadedFiles || []

      if (!currentFiles.includes(filename)) {
        await prisma.project.update({
          where: { id: projectId },
          data: { jsReconUploadedFiles: [...currentFiles, filename] }
        })
      }
    } catch {
      // Project may not exist yet (pre-generated ID during creation) -- file is on disk, DB update will happen on save
    }

    return NextResponse.json({
      uploaded: { name: filename, size: file.size, path: filePath },
    })
  } catch (error) {
    console.error('Error uploading JS file:', error)
    return NextResponse.json({ error: 'Failed to upload file' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/js-recon/[projectId]/upload?name=filename.js -- delete uploaded file
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
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
    await prisma.project.update({
      where: { id: projectId },
      data: { jsReconUploadedFiles: updatedFiles }
    })

    return NextResponse.json({ deleted: safeName })
  } catch (error) {
    console.error('Error deleting JS file:', error)
    return NextResponse.json({ error: 'Failed to delete file' }, { status: 500 })
  }
}
