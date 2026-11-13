import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { internalError } from '@/lib/routeErrors'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { applyRoe } from '@/lib/roe/applyRoe'
import { extractRoeText, ExtractError } from '@/lib/roe/extractText'
import { readRoeUpload } from '@/lib/roe/upload'
import { roeReadView } from '@/lib/roe/readView'

interface RouteParams {
  params: Promise<{ id: string }>
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

function jsonField(form: FormData, name: string): unknown {
  const raw = form.get(name)
  if (typeof raw !== 'string') return undefined
  try {
    return JSON.parse(raw)
  } catch {
    return undefined
  }
}

// GET /api/projects/[id]/roe - The Rules of Engagement as any reader may see them
// (OQ-53): the document's metadata and the scope and time window it enforces,
// never the contacts, the text, the parse or the document (lib/roe/readView.ts).
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'roe:read', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const roe = await roeReadView(id)
    if (!roe) return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    return NextResponse.json({ roe }, { headers: { 'Cache-Control': 'private, no-cache' } })
  } catch (error) {
    return internalError(error, 'Failed to read the Rules of Engagement.', { log: 'RoE read error' })
  }
}

// POST /api/projects/[id]/roe - Replace the project's Rules of Engagement with a
// reviewed document. multipart: file, changes (JSON, the confirmed set),
// parsedFields (JSON, the model output the review was built on), rowVersion,
// bytesSha256, and optionally modelUsed and unknownKeys.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    if (!sameOrigin(request)) return crossOriginResponse()
    const auth = await requirePermission(request, 'roe:manage', { projectId: id })
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const upload = await readRoeUpload(request)
    if (upload instanceof NextResponse) return upload
    const { formData, file, kind, bytes } = upload

    const changes = jsonField(formData, 'changes')
    const parsedFields = jsonField(formData, 'parsedFields')
    const rowVersion = formData.get('rowVersion')
    const bytesSha256 = formData.get('bytesSha256')
    if (!isObject(changes) || !isObject(parsedFields) || typeof rowVersion !== 'string' || typeof bytesSha256 !== 'string') {
      return NextResponse.json(
        { error: 'changes, parsedFields, rowVersion and bytesSha256 are required.', code: 'bad_request' },
        { status: 400 },
      )
    }

    let doc
    try {
      doc = await extractRoeText(bytes, kind)
    } catch (e) {
      if (e instanceof ExtractError) return NextResponse.json({ error: e.message, code: e.code }, { status: e.status })
      throw e
    }
    // The file must be the one the review was built on.
    if (doc.bytesSha256 !== bytesSha256) {
      return NextResponse.json(
        { error: 'The file is not the document that was reviewed. Upload it again.', code: 'roe_document_mismatch' },
        { status: 400 },
      )
    }

    const modelUsed = formData.get('modelUsed')
    const unknownKeys = jsonField(formData, 'unknownKeys')
    return await applyRoe({
      mode: 'replace',
      projectId: id,
      eff,
      access: auth.access,
      rowVersion,
      changes,
      parsedFields,
      doc,
      file: { name: file.name, kind, bytes },
      modelUsed: typeof modelUsed === 'string' ? modelUsed : null,
      unknownKeys: Array.isArray(unknownKeys) ? unknownKeys.filter((k): k is string => typeof k === 'string') : [],
    })
  } catch (error) {
    return internalError(error, 'Failed to apply the Rules of Engagement.', { log: 'RoE replace error' })
  }
}

// DELETE /api/projects/[id]/roe - Remove the project's Rules of Engagement: a
// replace with an empty document. JSON: rowVersion, changes (the confirmed set).
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    if (!sameOrigin(request)) return crossOriginResponse()
    const auth = await requirePermission(request, 'roe:manage', { projectId: id })
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const body = await request.json().catch(() => null)
    if (!isObject(body) || typeof body.rowVersion !== 'string' || !isObject(body.changes)) {
      return NextResponse.json({ error: 'rowVersion and changes are required.', code: 'bad_request' }, { status: 400 })
    }
    return await applyRoe({ mode: 'remove', projectId: id, eff, access: auth.access, rowVersion: body.rowVersion, changes: body.changes })
  } catch (error) {
    return internalError(error, 'Failed to remove the Rules of Engagement.', { log: 'RoE remove error' })
  }
}
