import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { mkdir, readdir, stat, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { declaredBodyTooLarge } from '@/lib/roe/upload'
import { internalError } from '@/lib/routeErrors'

const WORDLIST_UPLOAD_PATH = process.env.WORDLIST_UPLOAD_PATH || '/data/recon-wordlists'
const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50 MB

interface RouteParams {
  params: Promise<{ id: string }>
}

function sanitizeFilename(name: string): string | null {
  const basename = path.basename(name)
  if (!basename || basename.includes('..') || basename.startsWith('.')) return null
  const cleaned = basename.replace(/[^a-zA-Z0-9._-]/g, '_')
  if (!cleaned.toLowerCase().endsWith('.txt')) return null
  return cleaned
}

function getProjectWordlistDir(projectId: string): string {
  const safeId = projectId.replace(/[^a-zA-Z0-9_-]/g, '')
  if (!safeId) throw new Error('Invalid project ID')
  return path.join(WORDLIST_UPLOAD_PATH, safeId)
}

function toContainerPath(projectId: string, filename: string): string {
  const safeId = projectId.replace(/[^a-zA-Z0-9_-]/g, '')
  return `/app/recon/wordlists/${safeId}/${filename}`
}

async function listWordlists(projectId: string) {
  const dir = getProjectWordlistDir(projectId)
  if (!existsSync(dir)) return []

  const files = await readdir(dir)
  const wordlists = []

  for (const file of files) {
    if (!file.toLowerCase().endsWith('.txt')) continue
    const filePath = path.join(dir, file)
    const fileStat = await stat(filePath)
    wordlists.push({
      name: file,
      path: toContainerPath(projectId, file),
      size: fileStat.size,
    })
  }

  return wordlists.sort((a, b) => a.name.localeCompare(b.name))
}

// GET /api/projects/[id]/wordlists -- list uploaded wordlists
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId: id })
    if (auth instanceof NextResponse) return auth
    const wordlists = await listWordlists(id)
    return NextResponse.json({ wordlists })
  } catch (error) {
    return internalError(error, 'Failed to list wordlists', { log: 'Error listing wordlists' })
  }
}

// POST /api/projects/[id]/wordlists -- upload a .txt wordlist
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId: id })
    if (auth instanceof NextResponse) return auth
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

    const safeName = sanitizeFilename(file.name)
    if (!safeName) {
      return NextResponse.json(
        { error: 'Invalid filename. Only .txt files with alphanumeric names are allowed.' },
        { status: 400 }
      )
    }

    const dir = getProjectWordlistDir(id)
    await mkdir(dir, { recursive: true })

    const arrayBuffer = await file.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)
    await writeFile(path.join(dir, safeName), buffer)

    const wordlists = await listWordlists(id)
    return NextResponse.json({
      wordlists,
      uploaded: { name: safeName, path: toContainerPath(id, safeName) },
    })
  } catch (error) {
    return internalError(error, 'Failed to upload wordlist', { log: 'Error uploading wordlist' })
  }
}

// DELETE /api/projects/[id]/wordlists?name=filename.txt -- delete a wordlist
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'scan:uploads', { projectId: id })
    if (auth instanceof NextResponse) return auth
    const name = request.nextUrl.searchParams.get('name')

    if (!name) {
      return NextResponse.json({ error: 'Missing name parameter' }, { status: 400 })
    }

    const safeName = sanitizeFilename(name)
    if (!safeName) {
      return NextResponse.json({ error: 'Invalid filename' }, { status: 400 })
    }

    const filePath = path.join(getProjectWordlistDir(id), safeName)

    if (existsSync(filePath)) {
      await unlink(filePath)
    }

    const wordlists = await listWordlists(id)
    return NextResponse.json({ wordlists })
  } catch (error) {
    return internalError(error, 'Failed to delete wordlist', { log: 'Error deleting wordlist' })
  }
}
