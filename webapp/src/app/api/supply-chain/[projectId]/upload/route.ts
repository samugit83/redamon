import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { mkdir, writeFile, readdir, stat, unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { internalError } from '@/lib/routeErrors'

// Shared with the supply-chain scan container (named volume supply_chain_uploads).
const SUPPLY_CHAIN_UPLOAD_PATH = process.env.SUPPLY_CHAIN_UPLOAD_PATH || '/data/supply-chain-uploads'
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB
// SBOMs + committed lockfiles only. NEVER an archive/script (S1/S7).
const ALLOWED_EXTENSIONS = ['.json', '.xml', '.txt', '.lock', '.toml', '.mod', '.sum', '.yaml', '.yml']

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

function sanitizeFilename(name: string): string {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_')
}

function isAllowedExtension(filename: string): boolean {
  return ALLOWED_EXTENSIONS.includes(path.extname(filename).toLowerCase())
}

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// GET -- list uploaded SBOM/lockfiles for this project.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }
    const projectDir = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId)
    if (!existsSync(projectDir)) return NextResponse.json({ files: [] })

    const files = []
    for (const entry of await readdir(projectDir)) {
      try {
        const s = await stat(path.join(projectDir, entry))
        if (s.isFile()) files.push({ name: entry, size: s.size, uploaded_at: s.mtime.toISOString() })
      } catch { /* skip */ }
    }
    return NextResponse.json({ files })
  } catch (error) {
    return internalError(error, 'Failed to list files', { log: 'Error listing Supply-Chain uploads' })
  }
}

// POST -- upload one SBOM/lockfile. It REPLACES any previous upload and becomes
// the scan input (supplyChainSbomFile).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:supply_chain', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    // Reject on the declared length BEFORE touching the body. `formData()`
    // buffers the entire request into memory, so checking `file.size` after it
    // resolves is too late to prevent the exhaustion it is meant to prevent: a
    // 2 GB upload is fully resident before the 10 MB limit is ever consulted.
    // Content-Length is attacker-supplied and so cannot be trusted as an
    // upper bound, which is why the real size is still re-checked below - this
    // is the cheap rejection, not the authoritative one.
    const declared = Number(request.headers.get('content-length') || 0)
    if (declared > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB` }, { status: 413 })
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null
    if (!file) return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB` }, { status: 400 })
    }

    const filename = sanitizeFilename(file.name)
    if (!isAllowedExtension(filename)) {
      return NextResponse.json({ error: `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}` }, { status: 400 })
    }

    const projectDir = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId)
    await mkdir(projectDir, { recursive: true })

    // ONE input file per project: the newest upload replaces everything before
    // it. Without this the directory only grows - every upload left its
    // predecessors behind on a volume shared by all projects, while only the
    // single file named by supplyChainSbomFile was ever scanned. The rest were
    // invisible, unscanned, and unbounded.
    const buffer = Buffer.from(await file.arrayBuffer())
    let replaced = 0
    try {
      for (const stale of await readdir(projectDir)) {
        if (stale === filename) continue
        try {
          if ((await stat(path.join(projectDir, stale))).isFile()) {
            await unlink(path.join(projectDir, stale))
            replaced += 1
          }
        } catch { /* another request may have removed it already */ }
      }
    } catch { /* directory was just created */ }

    await writeFile(path.join(projectDir, filename), buffer)

    // The latest upload becomes the active scan input. A failure here is NOT
    // cosmetic: the file is on disk but the project still points at the old
    // one, so reporting success would send the operator to Start and silently
    // scan the previous SBOM. The one benign case is a project row that does
    // not exist yet (the form saves it later), which Prisma reports as P2025.
    // The row's new updatedAt goes back to the settings form, whose next save is a
    // compare-and-swap on it: without it the form reads this upload as a
    // concurrent change and refuses its own save.
    let projectUpdatedAt: Date | null = null
    try {
      const updated = await prisma.project.update({
        where: { id: projectId }, data: { supplyChainSbomFile: filename }, select: { updatedAt: true },
      })
      projectUpdatedAt = updated.updatedAt
    } catch (err) {
      const code = (err as { code?: string })?.code
      if (code !== 'P2025') {
        return internalError(err, 'File saved but could not be set as the scan input. Try again.', {
          log: 'Uploaded SBOM but failed to record it as the scan input',
        })
      }
    }

    return NextResponse.json({ success: true, filename, replaced, projectUpdatedAt })
  } catch (error) {
    return internalError(error, 'Failed to upload file', { log: 'Error uploading SBOM' })
  }
}

// DELETE -- remove an uploaded file (and clear it as the active input).
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:supply_chain', { projectId })
    if (auth instanceof NextResponse) return auth
    if (!PROJECT_ID_RE.test(projectId)) {  // W3: same guard as GET/POST
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }
    const { searchParams } = new URL(request.url)
    const filename = sanitizeFilename(searchParams.get('filename') || '')
    if (!filename) return NextResponse.json({ error: 'No filename' }, { status: 400 })

    const projectDir = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId)
    const filePath = path.join(projectDir, filename)
    if (existsSync(filePath)) {
      // Gone between the check and the unlink is the state the caller asked for.
      await unlink(filePath).catch((err: NodeJS.ErrnoException) => { if (err?.code !== 'ENOENT') throw err })
    }
    let projectUpdatedAt: Date | null = null
    try {
      const current = await prisma.project.findUnique({ where: { id: projectId }, select: { supplyChainSbomFile: true } })
      if (current?.supplyChainSbomFile === filename) {
        // Uploads replace each other, so deleting the active file leaves the
        // project with no upload at all - there is no older file to promote.
        // (This used to hunt for the most-recent survivor, which only made
        // sense while uploads accumulated.)
        const updated = await prisma.project.update({
          where: { id: projectId }, data: { supplyChainSbomFile: '' }, select: { updatedAt: true },
        })
        projectUpdatedAt = updated.updatedAt
      }
    } catch (err) {
      // The file is gone but the project may still name it as the scan input,
      // so a Start would fail on a missing file: that is not a success. A row
      // deleted meanwhile (P2025) has no input left to clear.
      if ((err as { code?: string })?.code !== 'P2025') {
        return internalError(err, 'File removed but could not be cleared as the scan input. Try again.', {
          log: 'Deleted SBOM but failed to clear it as the scan input',
        })
      }
    }
    return NextResponse.json({ success: true, projectUpdatedAt })
  } catch (error) {
    return internalError(error, 'Failed to delete file', { log: 'Error deleting Supply-Chain upload' })
  }
}
