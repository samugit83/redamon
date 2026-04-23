import { NextRequest, NextResponse } from 'next/server'
import { mkdir, readdir, readFile, stat, unlink, rmdir } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

const TEMPLATES_PATH = process.env.NUCLEI_TEMPLATES_PATH || '/data/nuclei-templates'
const MAX_FILE_SIZE = 1 * 1024 * 1024 // 1 MB

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sanitizePath(rawPath: string): string | null {
  const normalized = path.normalize(rawPath)
  if (normalized.includes('..') || path.isAbsolute(normalized)) return null
  if (!normalized.match(/\.(ya?ml)$/i)) return null
  return normalized
}

function sanitizeSubdir(rawDir: string): string | null {
  if (!rawDir) return null
  const normalized = path.normalize(rawDir).replace(/^\/+|\/+$/g, '')
  if (normalized.includes('..') || path.isAbsolute(normalized)) return null
  // Only allow alphanumeric, hyphens, underscores, slashes
  if (!/^[a-zA-Z0-9/_-]+$/.test(normalized)) return null
  return normalized
}

/** Extract id, info.name, info.severity from a nuclei YAML template using regex (no js-yaml dep). */
function parseTemplateMeta(content: string): { id: string; name: string; severity: string } | null {
  // Only parse the first YAML document (stop at ---)
  const firstDoc = content.split(/^---$/m)[0] || content

  const idMatch = firstDoc.match(/^id:\s*(.+)$/m)
  if (!idMatch) return null

  const nameMatch = firstDoc.match(/^\s+name:\s*(.+)$/m)
  const severityMatch = firstDoc.match(/^\s+severity:\s*(.+)$/m)

  return {
    id: idMatch[1].trim(),
    name: nameMatch?.[1]?.trim() || '',
    severity: severityMatch?.[1]?.trim().toLowerCase() || 'unknown',
  }
}

async function listTemplates() {
  if (!existsSync(TEMPLATES_PATH)) return []

  const templates: { id: string; name: string; severity: string; file: string; path: string; size: number }[] = []

  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        await walk(fullPath)
      } else if (entry.isFile() && /\.(ya?ml)$/i.test(entry.name)) {
        const relPath = path.relative(TEMPLATES_PATH, fullPath)
        try {
          const content = await readFile(fullPath, 'utf-8')
          const meta = parseTemplateMeta(content)
          const fileStat = await stat(fullPath)
          templates.push({
            id: meta?.id || entry.name,
            name: meta?.name || '',
            severity: meta?.severity || 'unknown',
            file: entry.name,
            path: relPath,
            size: fileStat.size,
          })
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  await walk(TEMPLATES_PATH)
  return templates.sort((a, b) => a.id.localeCompare(b.id))
}

// ---------------------------------------------------------------------------
// GET /api/nuclei-templates — list all custom templates
// ---------------------------------------------------------------------------
export async function GET() {
  try {
    const templates = await listTemplates()
    return NextResponse.json({ templates })
  } catch (error) {
    console.error('Error listing nuclei templates:', error)
    return NextResponse.json({ error: 'Failed to list templates' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// POST /api/nuclei-templates — upload a .yaml/.yml template
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File | null
    const subdir = (formData.get('subdir') as string) || ''

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB` },
        { status: 400 }
      )
    }

    const filename = path.basename(file.name)
    if (!filename.match(/\.(ya?ml)$/i)) {
      return NextResponse.json(
        { error: 'Invalid file type. Only .yaml and .yml files are allowed.' },
        { status: 400 }
      )
    }

    // Sanitize filename
    const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, '_')

    // Validate YAML content
    const content = await file.text()
    const meta = parseTemplateMeta(content)
    if (!meta) {
      return NextResponse.json(
        { error: 'Invalid nuclei template. File must contain an "id:" field and an "info:" section with "name:" and "severity:".' },
        { status: 400 }
      )
    }

    // Determine target directory
    let targetDir = TEMPLATES_PATH
    if (subdir) {
      const safeSubdir = sanitizeSubdir(subdir)
      if (!safeSubdir) {
        return NextResponse.json({ error: 'Invalid subdirectory path' }, { status: 400 })
      }
      targetDir = path.join(TEMPLATES_PATH, safeSubdir)
    }

    await mkdir(targetDir, { recursive: true })

    const { writeFile: writeFileFs } = await import('fs/promises')
    const buffer = Buffer.from(await file.arrayBuffer())
    await writeFileFs(path.join(targetDir, safeName), buffer)

    const templates = await listTemplates()
    const relPath = subdir ? `${subdir}/${safeName}` : safeName
    return NextResponse.json({
      templates,
      uploaded: { name: safeName, path: relPath, id: meta.id },
    })
  } catch (error) {
    console.error('Error uploading nuclei template:', error)
    return NextResponse.json({ error: 'Failed to upload template' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/nuclei-templates?path=relative/path/to/template.yaml
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest) {
  try {
    const rawPath = request.nextUrl.searchParams.get('path')

    if (!rawPath) {
      return NextResponse.json({ error: 'Missing path parameter' }, { status: 400 })
    }

    const safePath = sanitizePath(rawPath)
    if (!safePath) {
      return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
    }

    const fullPath = path.join(TEMPLATES_PATH, safePath)

    if (existsSync(fullPath)) {
      await unlink(fullPath)

      // Clean up empty parent directories (but not the root templates dir)
      let parentDir = path.dirname(fullPath)
      while (parentDir !== TEMPLATES_PATH && parentDir.startsWith(TEMPLATES_PATH)) {
        try {
          const entries = await readdir(parentDir)
          if (entries.length === 0) {
            await rmdir(parentDir)
            parentDir = path.dirname(parentDir)
          } else {
            break
          }
        } catch {
          break
        }
      }
    }

    const templates = await listTemplates()
    return NextResponse.json({ templates })
  } catch (error) {
    console.error('Error deleting nuclei template:', error)
    return NextResponse.json({ error: 'Failed to delete template' }, { status: 500 })
  }
}
