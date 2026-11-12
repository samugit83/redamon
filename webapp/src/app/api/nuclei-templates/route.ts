import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'
import { mkdir, readdir, readFile, stat, unlink, rmdir, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { declaredBodyTooLarge } from '@/lib/roe/upload'
import { internalError } from '@/lib/routeErrors'
import { getEffectiveUser, requireSession, type Session } from '@/lib/session'
import { loadPrincipal } from '@/lib/authz/principal'
import { SHARED_TOOL_PERMISSIONS, sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { requirePermission } from '@/lib/authz/guards'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, sessionActor } from '@/lib/auditActor'
import { ownershipOf, templatesRoot, type TemplateOwnership } from '@/lib/nucleiTemplateOwnership'

const TEMPLATES_PATH = templatesRoot()
const MAX_FILE_SIZE = 1 * 1024 * 1024 // 1 MB

const MANAGE_ALL = SHARED_TOOL_PERMISSIONS.nuclei_templates_all
const DENIED: SharedToolAccess = { allowed: false, via: null }

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

interface TemplateFile { id: string; name: string; severity: string; file: string; path: string; size: number }

async function listTemplateFiles(): Promise<TemplateFile[]> {
  if (!existsSync(TEMPLATES_PATH)) return []

  const templates: TemplateFile[] = []

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

interface Caller {
  session: Session
  /** The effective user: whose templates these are (an admin acting as X uploads as X). */
  userId: string
}

async function readCaller(): Promise<Caller | NextResponse> {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return { session, userId: eff.userId }
}

/**
 * Whether the signed-in account (never the acted-as one) may change every template:
 * platform:nuclei_templates (every admin with RBAC_PERMISSIONS_ENABLED off), or a
 * pre-upgrade account under the escape hatch (sharedTools.ts). `record: false` asks
 * without counting a use of that hatch.
 */
async function managesAll(session: Session, record: boolean): Promise<SharedToolAccess> {
  const principal = await loadPrincipal(session.userId)
  if (!principal) return DENIED
  return sharedToolAccess(principal, 'nuclei_templates_all', { record })
}

/** The audit actor: the signed-in account, and the account it acts as when acting. */
function callerActor(caller: Caller) {
  return actorFields(auditActorOf(sessionActor(caller.session), caller.userId))
}

function forbidden(error: string): NextResponse {
  return NextResponse.json({ error, code: 'forbidden', permission: MANAGE_ALL }, { status: 403 })
}

interface ListedTemplate extends TemplateFile {
  ownership: TemplateOwnership
  /** Only for an account that manages every template, on another account's file: its email, or null once deleted. */
  owner?: string | null
}

/**
 * The templates the caller may see: their own and the instance ones, and for an
 * account that manages every template also everyone else's, labelled with the owner.
 */
async function visibleTemplates(caller: Caller, access: SharedToolAccess) {
  const files = await listTemplateFiles()
  const rows = await prisma.nucleiTemplate.findMany({ select: { path: true, ownerUserId: true } })
  const ownerOf = new Map(rows.map(r => [r.path, r.ownerUserId]))
  const listed: (ListedTemplate & { ownerUserId: string | null })[] = files.map(f => {
    const ownerUserId = ownerOf.get(f.path) ?? null
    return { ...f, ownerUserId, ownership: ownershipOf(ownerUserId, caller.userId) }
  })
  let shown = listed.filter(t => access.allowed || t.ownership !== 'other')
  if (access.allowed && shown.some(t => t.ownership === 'other')) {
    if (access.via === 'compat') await managesAll(caller.session, true)
    const ids = [...new Set(shown.filter(t => t.ownership === 'other').map(t => t.ownerUserId as string))]
    const emails = new Map((await prisma.user.findMany({
      where: { id: { in: ids } }, select: { id: true, email: true },
    })).map(u => [u.id, u.email]))
    shown = shown.map(t => (t.ownership === 'other' ? { ...t, owner: emails.get(t.ownerUserId as string) ?? null } : t))
  }
  return shown.map(({ ownerUserId: _owner, ...t }) => t)
}

async function templatesBody(caller: Caller) {
  const access = await managesAll(caller.session, false)
  return { templates: await visibleTemplates(caller, access), canManageAll: access.allowed }
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002'
}

// ---------------------------------------------------------------------------
// GET /api/nuclei-templates - the custom templates the caller may see
// ---------------------------------------------------------------------------
export async function GET() {
  try {
    const caller = await readCaller()
    if (caller instanceof NextResponse) return caller
    return NextResponse.json(await templatesBody(caller))
  } catch (error) {
    return internalError(error, 'Failed to list templates', { log: 'Error listing nuclei templates' })
  }
}

// ---------------------------------------------------------------------------
// POST /api/nuclei-templates - upload a .yaml/.yml template
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest) {
  try {
    const caller = await readCaller()
    if (caller instanceof NextResponse) return caller
    const auth = await requirePermission(request, 'scan:custom_templates')
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
    const subdir = (formData.get('subdir') as string) || ''
    const overwrite = formData.get('overwrite') === 'true'

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB`, code: 'file_too_large', limitBytes: MAX_FILE_SIZE },
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

    // Sanitize filename. Nuclei v3+ ONLY recognizes the `.yaml` extension as a
    // template file -- a `-t foo.yml` is treated as a path-list file (one
    // template path per line) and the actual template is never loaded, with
    // a confusing "no templates provided for scan" fatal. Normalize to .yaml
    // on upload so this footgun can't reach the scanner.
    const normalized = filename.replace(/\.yml$/i, '.yaml')
    const safeName = normalized.replace(/[^a-zA-Z0-9._-]/g, '_')

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
    let safeSubdir = ''
    if (subdir) {
      safeSubdir = sanitizeSubdir(subdir) ?? ''
      if (!safeSubdir) {
        return NextResponse.json({ error: 'Invalid subdirectory path' }, { status: 400 })
      }
      targetDir = path.join(TEMPLATES_PATH, safeSubdir)
    }
    const relPath = safeSubdir ? `${safeSubdir}/${safeName}` : safeName
    const fullPath = path.join(targetDir, safeName)
    const buffer = Buffer.from(await file.arrayBuffer())
    const facts = { sha256: createHash('sha256').update(buffer).digest('hex'), sizeBytes: buffer.length }

    // The path is the owner record's key: a new path is claimed (row first, so two
    // uploads of the same new name cannot both win), an existing one is replaced only
    // by its owner, or by an account that manages every template when it asks to.
    let row = await prisma.nucleiTemplate.findUnique({ where: { path: relPath }, select: { ownerUserId: true } })
    let claimed = false
    if (!row && !existsSync(fullPath)) {
      try {
        await prisma.nucleiTemplate.create({ data: { path: relPath, ownerUserId: caller.userId, ...facts } })
        claimed = true
      } catch (err) {
        if (!isUniqueViolation(err)) throw err
        row = await prisma.nucleiTemplate.findUnique({ where: { path: relPath }, select: { ownerUserId: true } })
      }
    }
    // No row for a file already on disk: an instance template (added on the host).
    const previousOwner = claimed ? undefined : (row ? row.ownerUserId : null)
    let via: SharedToolAccess['via'] = null
    if (previousOwner !== undefined && previousOwner !== caller.userId) {
      const access = overwrite ? await managesAll(caller.session, true) : DENIED
      if (!access.allowed) {
        const instance = previousOwner === null
        return NextResponse.json(
          {
            error: instance
              ? `A template named ${relPath} already exists as an instance template: only an administrator can replace it. Rename your file or upload it to another folder.`
              : `A template named ${relPath} already exists and belongs to another account. Rename your file or upload it to another folder.`,
            code: 'template_owned_by_other',
            path: relPath,
            ownership: instance ? 'instance' : 'other',
          },
          { status: 409 }
        )
      }
      via = access.via
    }

    try {
      await mkdir(targetDir, { recursive: true })
      await writeFile(fullPath, buffer)
    } catch (err) {
      if (claimed) await prisma.nucleiTemplate.deleteMany({ where: { path: relPath, ownerUserId: caller.userId } }).catch(() => undefined)
      throw err
    }
    if (!claimed) {
      // An instance file added on the host gets its row now, still owned by the instance.
      await prisma.nucleiTemplate.upsert({
        where: { path: relPath },
        create: { path: relPath, ownerUserId: previousOwner ?? null, ...facts },
        update: facts,
      })
    }

    await writeAudit({
      ...callerActor(caller),
      action: 'nuclei_template.upload',
      targetType: 'nuclei_template',
      targetId: relPath,
      before: claimed ? null : { ownerUserId: previousOwner ?? null },
      after: {
        ownerUserId: claimed ? caller.userId : previousOwner ?? null,
        ...facts,
        ...(via ? { replacedAs: via } : {}),
      },
    })

    return NextResponse.json({
      ...(await templatesBody(caller)),
      uploaded: { name: safeName, path: relPath, id: meta.id },
    })
  } catch (error) {
    return internalError(error, 'Failed to upload template', { log: 'Error uploading nuclei template' })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/nuclei-templates?path=relative/path/to/template.yaml
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest) {
  try {
    const caller = await readCaller()
    if (caller instanceof NextResponse) return caller
    const auth = await requirePermission(request, 'scan:custom_templates')
    if (auth instanceof NextResponse) return auth
    const rawPath = request.nextUrl.searchParams.get('path')

    if (!rawPath) {
      return NextResponse.json({ error: 'Missing path parameter' }, { status: 400 })
    }

    const safePath = sanitizePath(rawPath)
    if (!safePath) {
      return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
    }

    const fullPath = path.join(TEMPLATES_PATH, safePath)
    const row = await prisma.nucleiTemplate.findUnique({ where: { path: safePath }, select: { ownerUserId: true } })
    const onDisk = existsSync(fullPath)

    if (row || onDisk) {
      const owner = row ? row.ownerUserId : null
      if (owner !== caller.userId && !(await managesAll(caller.session, true)).allowed) {
        return forbidden(owner === null
          ? 'Only an administrator can delete an instance template.'
          : 'Only its owner or an administrator can delete this template.')
      }

      if (onDisk) {
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
      await prisma.nucleiTemplate.deleteMany({ where: { path: safePath } })

      await writeAudit({
        ...callerActor(caller),
        action: 'nuclei_template.delete',
        targetType: 'nuclei_template',
        targetId: safePath,
        before: { ownerUserId: owner },
      })
    }

    return NextResponse.json(await templatesBody(caller))
  } catch (error) {
    return internalError(error, 'Failed to delete template', { log: 'Error deleting nuclei template' })
  }
}

// ---------------------------------------------------------------------------
// PATCH /api/nuclei-templates {path, promote: true} - an account's template becomes
// an instance template every member may select
// ---------------------------------------------------------------------------
export async function PATCH(request: NextRequest) {
  try {
    const caller = await readCaller()
    if (caller instanceof NextResponse) return caller
    if (!(await managesAll(caller.session, true)).allowed) {
      return forbidden('Only an administrator can make a template an instance template.')
    }

    const body = await request.json().catch(() => null) as { path?: unknown; promote?: unknown } | null
    if (!body || body.promote !== true) {
      return NextResponse.json(
        { error: 'Send {"path": "<template path>", "promote": true}.', code: 'invalid_request' },
        { status: 400 }
      )
    }
    const safePath = typeof body.path === 'string' ? sanitizePath(body.path) : null
    if (!safePath) {
      return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
    }

    const row = await prisma.nucleiTemplate.findUnique({ where: { path: safePath }, select: { ownerUserId: true } })
    if (!row && !existsSync(path.join(TEMPLATES_PATH, safePath))) {
      return NextResponse.json({ error: 'Template not found', code: 'template_not_found' }, { status: 404 })
    }
    if (!row || row.ownerUserId === null) {
      return NextResponse.json({ ...(await templatesBody(caller)), promoted: false })
    }

    await prisma.nucleiTemplate.update({
      where: { path: safePath },
      data: { ownerUserId: null, promotedById: caller.session.userId },
    })
    await writeAudit({
      ...callerActor(caller),
      action: 'nuclei_template.promote',
      targetType: 'nuclei_template',
      targetId: safePath,
      before: { ownerUserId: row.ownerUserId },
      after: { ownerUserId: null, promotedById: caller.session.userId },
    })
    return NextResponse.json({ ...(await templatesBody(caller)), promoted: true })
  } catch (error) {
    return internalError(error, 'Failed to promote template', { log: 'Error promoting nuclei template' })
  }
}
