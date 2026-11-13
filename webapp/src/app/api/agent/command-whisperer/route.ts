import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { requirePermission } from '@/lib/authz/guards'
import { readFeatureModel, featureModelErrorResponse } from '@/lib/featureModels'
import { callFeatureAgent } from '@/lib/featureAgentCall'
import { recordFeatureSpend } from '@/lib/authz/ownerSpend'

const WHISPERER_TIMEOUT_MS = 60_000
const MAX_PROMPT_CHARS = 4_000
// Formatted into the agent's system prompt, so only a short plain token passes.
const SESSION_TYPE_RE = /^[a-z0-9_-]{1,32}$/i

/**
 * POST /api/agent/command-whisperer - turn a plain-English request into one
 * shell command, on the project owner's "Command whisperer" model and keys. A
 * collaborator reaches it through Use AI agent (agent:assistants is W+A), which
 * counts only with the owner's consent, and the spend is recorded as theirs
 * (step 5.6, C1).
 *
 * The agent body is built field by field, never forwarded: the client could
 * otherwise name another user, another project or a model the caller never
 * chose. The answer only fills the terminal's input box; nothing runs it.
 */
export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { prompt, session_type: sessionType, project_id: projectId } = parsed.body as {
    prompt?: unknown; session_type?: unknown; project_id?: unknown
  }

  const auth = await requirePermission(request, 'agent:assistants', { projectId: typeof projectId === 'string' ? projectId : null })
  if (auth instanceof NextResponse) return auth
  const caller = { userId: auth.access!.project.userId, projectId: auth.access!.project.id }

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return NextResponse.json({ error: 'prompt is required' }, { status: 400 })
  }
  const type = typeof sessionType === 'string' && SESSION_TYPE_RE.test(sessionType) ? sessionType : 'shell'

  const model = await readFeatureModel(caller.userId, 'command_whisperer')
  if (!model) return featureModelErrorResponse('model_required', 'command_whisperer')

  const unrecorded = await recordFeatureSpend(auth, 'command_whisperer')
  if (unrecorded) return unrecorded
  const agent = await callFeatureAgent({
    featureId: 'command_whisperer',
    path: '/command-whisperer',
    model,
    body: {
      prompt: prompt.slice(0, MAX_PROMPT_CHARS),
      session_type: type,
      project_id: caller.projectId,
      user_id: caller.userId,
      model,
    },
    timeoutMs: WHISPERER_TIMEOUT_MS,
  })
  if (!agent.ok) return agent.response
  return NextResponse.json({
    command: typeof agent.body.command === 'string' ? agent.body.command : '',
    modelUsed: model,
  })
}
