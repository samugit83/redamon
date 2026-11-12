import type { ChatMessage, Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { redactKeyedValue, redactSecretShapes } from './redact'
import { transcriptMaxBytes } from './settings'

/**
 * A session as plugin code receives it (`sdk.session.read`, README.PLUGINS.md §7.3,
 * TD-25): read on demand, never stored, masked, capped, marked untrusted.
 *
 * Memory stays bounded by the cap and one page, whatever the session's length (R-47: a
 * long run has tens of thousands of rows, `raw_output` values of 20,000 characters, and a
 * `todo_update`/`phase_update` per step, while the webapp has 1 GB):
 * - rows are read 500 at a time in the compound order (sequenceNum, createdAt, id), with
 *   a keyset cursor on all three, because sequenceNum has duplicates (RV-13);
 * - each event is masked, then its long strings are cut to head and tail (masking first,
 *   so a cut never splits a secret into a half that no longer looks like one); a value is
 *   masked together with its key, as Python would see it in JSON text, and a key that is
 *   itself secret-shaped is masked too;
 * - only the latest `todo_update` and `lats_tree_update` are kept, and a `phase_update`
 *   is dropped when only its iteration count differs from the previous one (the agent
 *   sends one per iteration), so the first row of each phase is what remains;
 * - the event loop is given back every 50 rows;
 * - three tiers, each held as a head plus a sliding tail, so the middle of a long session
 *   is what gets dropped: what people wrote (the operator's messages, guidance, answers to
 *   the agent's requests), then the agent's own priority events (errors, requests, deep
 *   thinking, phase changes) with the snapshots, then the rest. Each tier is chosen in
 *   that order, the first and the last of it filling what the tiers before it left.
 */
export const TRANSCRIPT_PAGE_ROWS = 500
const STRING_MAX_CHARS = 4_000
const STRING_HEAD_CHARS = 2_500
const STRING_TAIL_CHARS = 1_000
const EVENT_MAX_BYTES = 64 * 1024
const EVENT_PREVIEW_CHARS = 16_000
const MAX_DEPTH = 64
// Masking is CPU work on the webapp's one thread (~1 ms per 20,000 characters): give the
// event loop back this often, so a long session never stalls other requests.
const YIELD_EVERY_ROWS = 50
// The JSON around meta and events: keys, brackets and two counts.
const WRAPPER_BYTES = 128

const PEOPLE_TYPES = new Set([
  'user_message',
  'guidance',
  'tool_confirmation_response',
  'approval_response',
  'answer_response',
])
const PRIORITY_TYPES = new Set([
  'deep_think',
  'error',
  'assistant_message',
  'task_complete',
  'tool_confirmation_request',
  'approval_request',
  'question_request',
  'phase_update',
])
const SNAPSHOT_TYPES = new Set(['todo_update', 'lats_tree_update'])

export interface TranscriptEvent {
  seq: number
  type: string
  at: string
  data: unknown
}

export interface TranscriptMeta {
  id: string
  title: string
  status: string
  currentPhase: string
  iterationCount: number
  createdAt: string
  updatedAt: string
  running: boolean | 'unverified'
  highWaterSeq: number | null
}

export interface Transcript {
  meta: TranscriptMeta
  events: TranscriptEvent[]
  truncated: { keptEvents: number; droppedEvents: number }
  untrusted: true
}

export interface TranscriptConversation {
  id: string
  title: string
  status: string
  currentPhase: string
  iterationCount: number
  createdAt: Date
  updatedAt: Date
}

interface Held {
  order: number
  event: TranscriptEvent
  bytes: number
}

const jsonBytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v), 'utf8')

function cutString(s: string): string {
  if (s.length <= STRING_MAX_CHARS) return s
  const cps = Array.from(s)
  if (cps.length <= STRING_MAX_CHARS) return s
  const cut = cps.length - STRING_HEAD_CHARS - STRING_TAIL_CHARS
  return (
    cps.slice(0, STRING_HEAD_CHARS).join('') +
    `\n…[${cut} characters cut]…\n` +
    cps.slice(cps.length - STRING_TAIL_CHARS).join('')
  )
}

function maskAndCut(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return cutString(redactSecretShapes(value))
  if (value === null || typeof value !== 'object') return value
  if (depth >= MAX_DEPTH) return '[nested too deep]'
  if (Array.isArray(value)) return value.map((v) => maskAndCut(v, depth + 1))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[redactSecretShapes(k)] = typeof v === 'string' ? cutString(redactKeyedValue(k, v)) : maskAndCut(v, depth + 1)
  }
  return out
}

/** A phase row as compared with the previous one: everything but the iteration count. */
function phaseKey(data: unknown): string {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return JSON.stringify(data)
  return JSON.stringify(Object.entries(data).filter(([k]) => k !== 'iteration_count'))
}

/**
 * A row's data without its top-level `actor`: the account that answered one of the agent's
 * requests and, under act-as, the admin acting as it. Plugin code needs what was decided, not by
 * whom; its call already names the user it runs for, and an act-as admin is a person it would
 * otherwise never see.
 */
function withoutActor(data: unknown): unknown {
  if (!data || typeof data !== 'object' || Array.isArray(data) || !('actor' in data)) return data
  return Object.fromEntries(Object.entries(data).filter(([k]) => k !== 'actor'))
}

function toEvent(row: Pick<ChatMessage, 'sequenceNum' | 'type' | 'data' | 'createdAt'>): TranscriptEvent {
  const event: TranscriptEvent = {
    seq: row.sequenceNum,
    type: row.type,
    at: row.createdAt.toISOString(),
    data: maskAndCut(withoutActor(row.data)),
  }
  if (jsonBytes(event) > EVENT_MAX_BYTES) {
    // Already masked; the preview is the start of its JSON text.
    const preview = Array.from(JSON.stringify(event.data)).slice(0, EVENT_PREVIEW_CHARS).join('')
    event.data = { truncated: true, preview: `${preview}…` }
  }
  return event
}

/** The first events in full, then a tail that slides: what falls out of it is the middle. */
class HeadAndTail {
  readonly head: Held[] = []
  readonly tail: Held[] = []
  private headBytes = 0
  private tailBytes = 0
  private sliding = false

  constructor(private readonly half: number) {}

  push(h: Held) {
    if (!this.sliding && this.headBytes + h.bytes <= this.half) {
      this.head.push(h)
      this.headBytes += h.bytes
      return
    }
    this.sliding = true
    this.tail.push(h)
    this.tailBytes += h.bytes
    while (this.tailBytes > this.half && this.tail.length) this.tailBytes -= this.tail.shift()!.bytes
  }

  items(): Held[] {
    return [...this.head, ...this.tail]
  }
}

/** The first and the last of `items` (in order) that fit `budget`, each side up to half. */
function firstAndLast(items: Held[], budget: number): Held[] {
  const total = items.reduce((s, h) => s + h.bytes, 0)
  if (total <= budget) return items
  const keep = new Set<number>()
  let used = 0
  let i = 0
  for (; i < items.length && used + items[i].bytes <= budget / 2; i++) {
    keep.add(i)
    used += items[i].bytes
  }
  for (let j = items.length - 1; j >= i && used + items[j].bytes <= budget; j--) {
    keep.add(j)
    used += items[j].bytes
  }
  return items.filter((_, k) => keep.has(k))
}

const pageWhere = (conversationId: string, last: Pick<ChatMessage, 'sequenceNum' | 'createdAt' | 'id'> | null) => {
  const where: Prisma.ChatMessageWhereInput = { conversationId }
  if (last) {
    // Redundant with the OR, but it gives the (conversationId, sequenceNum) index a lower
    // bound: without it each page rescans the session from its first row.
    where.sequenceNum = { gte: last.sequenceNum }
    where.OR = [
      { sequenceNum: { gt: last.sequenceNum } },
      { sequenceNum: last.sequenceNum, createdAt: { gt: last.createdAt } },
      { sequenceNum: last.sequenceNum, createdAt: last.createdAt, id: { gt: last.id } },
    ]
  }
  return where
}

export async function readTranscript(
  conversation: TranscriptConversation,
  opts: { running: boolean | 'unverified'; maxBytes?: number; pageRows?: number },
): Promise<Transcript> {
  const maxBytes = opts.maxBytes ?? transcriptMaxBytes()
  const pageRows = Math.max(1, Math.min(TRANSCRIPT_PAGE_ROWS, Math.floor(opts.pageRows ?? TRANSCRIPT_PAGE_ROWS)))
  const people = new HeadAndTail(maxBytes)
  const priority = new HeadAndTail(maxBytes / 2)
  const others = new HeadAndTail(maxBytes / 2)
  const snapshots = new Map<string, Held>()
  let lastPhase: string | null = null
  let rowsRead = 0
  let highWaterSeq: number | null = null
  let order = 0

  let last: ChatMessage | null = null
  for (;;) {
    const rows: ChatMessage[] = await prisma.chatMessage.findMany({
      where: pageWhere(conversation.id, last),
      orderBy: [{ sequenceNum: 'asc' }, { createdAt: 'asc' }, { id: 'asc' }],
      take: pageRows,
    })
    for (const row of rows) {
      rowsRead++
      if (rowsRead % YIELD_EVERY_ROWS === 0) await new Promise((resolve) => setImmediate(resolve))
      highWaterSeq = highWaterSeq === null ? row.sequenceNum : Math.max(highWaterSeq, row.sequenceNum)
      const event = toEvent(row)
      const held: Held = { order: order++, event, bytes: jsonBytes(event) + 1 }
      if (SNAPSHOT_TYPES.has(row.type)) {
        snapshots.set(row.type, held)
      } else if (row.type === 'phase_update') {
        const key = phaseKey(event.data)
        if (key === lastPhase) continue
        lastPhase = key
        priority.push(held)
      } else if (PEOPLE_TYPES.has(row.type)) {
        people.push(held)
      } else if (PRIORITY_TYPES.has(row.type)) {
        priority.push(held)
      } else {
        others.push(held)
      }
    }
    if (rows.length < pageRows) break
    last = rows[rows.length - 1]
  }

  const meta: TranscriptMeta = {
    id: conversation.id,
    title: cutString(redactSecretShapes(conversation.title)),
    status: conversation.status,
    currentPhase: conversation.currentPhase,
    iterationCount: conversation.iterationCount,
    createdAt: conversation.createdAt.toISOString(),
    updatedAt: conversation.updatedAt.toISOString(),
    running: opts.running,
    highWaterSeq,
  }

  let budget = maxBytes - jsonBytes(meta) - WRAPPER_BYTES
  const tiers = [
    people.items(),
    [...priority.items(), ...snapshots.values()].sort((a, b) => a.order - b.order),
    others.items(),
  ]
  const kept: Held[] = []
  for (const tier of tiers) {
    const chosen = firstAndLast(tier, Math.max(0, budget))
    budget -= chosen.reduce((s, h) => s + h.bytes, 0)
    kept.push(...chosen)
  }
  kept.sort((a, b) => a.order - b.order)

  return {
    meta,
    events: kept.map((h) => h.event),
    truncated: { keptEvents: kept.length, droppedEvents: rowsRead - kept.length },
    untrusted: true,
  }
}
