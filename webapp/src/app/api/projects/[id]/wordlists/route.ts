import { NextRequest, NextResponse } from 'next/server'
import { mkdir, readdir, stat, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

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
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const wordlists = await listWordlists(id)
    return NextResponse.json({ wordlists })
  } catch (error) {
    console.error('Error listing wordlists:', error)
    return NextResponse.json(
      { error: 'Failed to list wordlists' },
      { status: 500 }
    )
  }
}

// POST /api/projects/[id]/wordlists -- upload a .txt wordlist
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
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
    console.error('Error uploading wordlist:', error)
    return NextResponse.json(
      { error: 'Failed to upload wordlist' },
      { status: 500 }
    )
  }
}

// DELETE /api/projects/[id]/wordlists?name=filename.txt -- delete a wordlist
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
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
    console.error('Error deleting wordlist:', error)
    return NextResponse.json(
      { error: 'Failed to delete wordlist' },
      { status: 500 }
    )
  }
}
