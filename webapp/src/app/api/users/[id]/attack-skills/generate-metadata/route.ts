import { NextRequest, NextResponse } from 'next/server'
import { signedInActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { writeAudit } from '@/lib/audit'
import { readFeatureModel, featureModelErrorResponse } from '@/lib/featureModels'
import { callFeatureAgent } from '@/lib/featureAgentCall'
import { hasSecretKeyShape } from '@/lib/plugins/redact'
import { cleanSkillText, tidySkillDescription } from '@/lib/skillMetadata'
import {
  MAX_CONTENT_SIZE, MAX_SKILLS_PER_BATCH, NAME_MAX_CHARS, SKILL_METADATA_ITEMS_PER_REQUEST,
} from '@/lib/userSkills'
import { nameProblem, normalizeName } from '@/lib/userSkillNames'
import { requireOwnBrowserRequest } from '@/lib/userSkillRouteGuard'
import { USER_SKILL_AUDIT_TARGET, auditActorFor, contentSha256 } from '@/lib/userSkillWrites'
import { withRouteErrors } from '@/lib/routeErrors'

// Above the agent's own 150 s cap (agentic/skill_metadata.py REQUEST_TIMEOUT_S), below undici's 300 s.
const AGENT_TIMEOUT_MS = 180_000

const FIELDS = ['name', 'description'] as const
type Field = (typeof FIELDS)[number]
const FILE_NAME_MAX_CHARS = 255
// The agent's own codes (timeout, model_call_failed, ...) are shown per row; anything else is dropped.
const AGENT_ITEM_ERROR = /^[a-z_]{1,40}$/

interface RequestedItem { key: string; fileName: string; content: string; name: string; fields: Field[] }
interface AnsweredItem { key: string; name?: string; description?: string; error?: string }

interface RouteParams {
  params: Promise<{ id: string }>
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

function readItems(body: Record<string, unknown>): { items: RequestedItem[]; otherNames: string[] } | null {
  const { items, otherNames = [] } = body
  if (!Array.isArray(items) || items.length < 1 || items.length > SKILL_METADATA_ITEMS_PER_REQUEST) return null
  if (!Array.isArray(otherNames) || otherNames.length > MAX_SKILLS_PER_BATCH
    || !otherNames.every((n) => typeof n === 'string' && n.length <= NAME_MAX_CHARS)) return null
  const out: RequestedItem[] = []
  const keys = new Set<string>()
  for (const raw of items) {
    if (!isObject(raw)) return null
    const { key, content, fields, name = '', fileName = '' } = raw
    if (typeof key !== 'string' || !key || key.length > 64 || keys.has(key)) return null
    if (typeof content !== 'string' || !content.trim() || content.length > MAX_CONTENT_SIZE) return null
    if (!Array.isArray(fields) || !fields.length || !fields.every((f) => (FIELDS as readonly unknown[]).includes(f))) return null
    if (typeof name !== 'string' || name.length > NAME_MAX_CHARS) return null
    if (typeof fileName !== 'string' || fileName.length > FILE_NAME_MAX_CHARS) return null
    keys.add(key)
    out.push({ key, content, name, fileName, fields: FIELDS.filter((f) => fields.includes(f)) })
  }
  return { items: out, otherNames: otherNames as string[] }
}

/** The model's proposal for one item, re-validated as untrusted text. */
function revalidate(asked: RequestedItem, raw: unknown): AnsweredItem {
  if (!isObject(raw)) return { key: asked.key, error: 'no_answer' }
  const out: AnsweredItem = { key: asked.key }
  if (asked.fields.includes('name') && typeof raw.name === 'string') {
    // Invisible characters go, as in a name read from a file; a name still breaking the
    // rules (too long, empty) is refused rather than cut into something the model did not write.
    const name = normalizeName(cleanSkillText(raw.name))
    if (nameProblem(name)) out.error = 'invalid_name'
    else out.name = name
  }
  if (asked.fields.includes('description') && typeof raw.description === 'string') {
    const description = tidySkillDescription(raw.description).value
    if (description) out.description = description
    else out.error ??= 'empty_answer'
  }
  if (typeof raw.error === 'string' && AGENT_ITEM_ERROR.test(raw.error)) out.error ??= raw.error
  if (!out.name && !out.description) out.error ??= 'empty_answer'
  return out
}

/**
 * POST .../generate-metadata {items: [{key, fileName, content, name, fields}], otherNames} →
 * {items: [{key, name?, description?, error?}], modelUsed}. Runs the owner's own "Skill names &
 * descriptions" model on their own keys; never saves anything, and never sends a file that holds
 * a key or token.
 */
async function generateMetadata(request: NextRequest, { params }: RouteParams): Promise<Response> {
  const { id } = await params
  const eff = await requireOwnBrowserRequest(request, id)
  if (eff instanceof NextResponse) return eff
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const read = readItems(parsed.body)
  if (!read) {
    return NextResponse.json({
      error: `Send 1 to ${SKILL_METADATA_ITEMS_PER_REQUEST} skills, each with a unique key, its text and the fields to write.`,
      code: 'items_invalid',
    }, { status: 400 })
  }
  const requested = read.items

  // The text would reach a provider the person picked for another job; the plugin Gateway
  // refuses the same text for the same reason.
  const answered = new Map<string, AnsweredItem>()
  const toSend = requested.filter((i) => {
    if (!hasSecretKeyShape([i.name, i.fileName, i.content].join('\n'))) return true
    answered.set(i.key, { key: i.key, error: 'skill_contains_credentials' })
    return false
  })
  if (!toSend.length) {
    return NextResponse.json({ items: requested.map((i) => answered.get(i.key)), modelUsed: null })
  }

  const model = await readFeatureModel(eff.userId, 'skill_metadata')
  if (!model) return featureModelErrorResponse('model_required', 'skill_metadata')
  // Read now: the agent call can outlast the session, and the audit row must still name the caller.
  const actor = auditActorFor((await signedInActor())?.id, id)

  const agent = await callFeatureAgent({
    featureId: 'skill_metadata',
    path: '/skill-metadata/generate',
    model,
    body: {
      items: toSend.map((i) => ({
        key: i.key,
        content: i.content,
        file_name: i.fileName,
        name: i.name,
        want_name: i.fields.includes('name'),
        want_description: i.fields.includes('description'),
      })),
      // Another row's name came from a file too, so it gets the same rule as the items.
      other_names: read.otherNames.filter((n) => !hasSecretKeyShape(n)),
      model,
      user_id: eff.userId,
    },
    timeoutMs: AGENT_TIMEOUT_MS,
    notFoundIsOutdated: true,
  })
  if (!agent.ok) return agent.response

  const agentItems = Array.isArray(agent.body.items) ? agent.body.items : []
  for (const asked of toSend) {
    const raw = agentItems.find((a) => isObject(a) && a.key === asked.key)
    answered.set(asked.key, raw === undefined ? { key: asked.key, error: 'no_answer' } : revalidate(asked, raw))
  }
  const items = requested.map((i) => answered.get(i.key)!)

  // The server's record of what the model wrote for: the model and each file's hash, which
  // matches the create row of the same file. No text: the proposals may never be saved.
  if (items.some((i) => i.name || i.description)) {
    await writeAudit({
      actorId: actor.actorId,
      source: actor.source,
      action: 'user_attack_skill.ai_metadata',
      targetType: USER_SKILL_AUDIT_TARGET,
      targetId: null,
      after: {
        userId: eff.userId,
        model,
        ...(actor.onBehalfOf ? { onBehalfOf: actor.onBehalfOf } : {}),
        items: requested.map((i) => ({
          contentSha256: contentSha256(i.content), fields: i.fields, outcome: answered.get(i.key)?.error ?? 'ok',
        })),
      },
    })
  }
  return NextResponse.json({ items, modelUsed: model })
}

export const POST = withRouteErrors('Failed to generate the names and descriptions', generateMetadata)
