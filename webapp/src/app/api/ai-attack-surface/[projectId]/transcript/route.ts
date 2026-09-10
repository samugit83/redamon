import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { promises as fs } from 'fs'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { resolveTranscriptPath, transcriptContentType, transcriptDisposition } from '@/lib/aiAttackTranscript'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// Cap: native reports are small (KB–low MB); refuse to stream anything huge.
const MAX_BYTES = 8 * 1024 * 1024

// GET /api/ai-attack-surface/{projectId}/transcript?ref=<ai_transcript_ref>
// Serves a tool's native report for drill-down (§9c). Defence in depth:
//   1. the ref must resolve to a path UNDER the read-only output mount (no
//      traversal - resolveTranscriptPath), and
//   2. some Vulnerability IN THIS PROJECT must actually carry that ref (so a
//      caller can't read another project's transcripts or arbitrary files).
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  const ref = request.nextUrl.searchParams.get('ref') || ''

  const filePath = resolveTranscriptPath(ref)
  if (!filePath) {
    return NextResponse.json({ error: 'Invalid transcript reference' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    const owned = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE v.ai_transcript_ref = $ref AND ${notMuted('v')}
       RETURN count(v) AS n LIMIT 1`,
      { pid: projectId, ref },
    )
    const n = owned.records[0]?.get('n')
    const count = typeof n === 'number' ? n : (n?.toNumber?.() ?? n?.low ?? 0)
    if (!count) {
      return NextResponse.json({ error: 'Transcript not found for this project' }, { status: 404 })
    }

    const stat = await fs.stat(filePath).catch(() => null)
    if (!stat || !stat.isFile()) {
      return NextResponse.json({ error: 'Transcript file missing on disk' }, { status: 404 })
    }
    if (stat.size > MAX_BYTES) {
      return NextResponse.json({ error: 'Transcript too large to preview' }, { status: 413 })
    }

    const body = await fs.readFile(filePath)
    const filename = (filePath.split('/').pop() || 'transcript').replace(/[^\w.\-]/g, '_')
    return new NextResponse(body, {
      status: 200,
      headers: {
        'Content-Type': transcriptContentType(filePath),
        // HTML reports are forced to download; inert types preview inline. Plus
        // nosniff so the browser can't re-interpret a .txt as HTML (XSS guard).
        'Content-Disposition': `${transcriptDisposition(filePath)}; filename="${filename}"`,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'private, max-age=300',
      },
    })
  } catch (error) {
    console.error('AI Attack Surface transcript error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to read transcript' },
      { status: 500 },
    )
  } finally {
    await session.close()
  }
}
