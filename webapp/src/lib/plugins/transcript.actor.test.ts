/**
 * Plugin code never learns who answered the agent (step 3.9b review, finding 5).
 *
 * Since 3.9b the agent saves each answer to its requests with `actor: {sub, act?}`: the account
 * that answered and, under act-as, the admin acting as it. A plugin needs what was decided, not
 * by whom; its call already carries the acting user it runs for (`ctx.user_id`), and the admin
 * behind an act-as is a person it would otherwise never see. So `sdk.session.read` drops a row's
 * top-level `actor` and keeps the rest of the row.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { readTranscript } from './transcript'

let db: FakePrisma
const T = (ms: number) => new Date(Date.parse('2026-10-09T10:00:00.000Z') + ms)

const conversation = {
  id: 'conv-1',
  title: '',
  status: 'active',
  currentPhase: 'exploitation',
  iterationCount: 3,
  createdAt: T(0),
  updatedAt: T(0),
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
})

function seed(rows: [type: string, data: unknown][]) {
  db.seed('chatMessage', rows.map(([type, data], i) => ({
    id: `m-${i}`, conversationId: 'conv-1', sequenceNum: i, createdAt: T(i), type, data,
  })))
}

describe('who answered the agent stays out of plugin transcripts', () => {
  test('the three answer rows keep their decision and lose the actor', async () => {
    seed([
      ['approval_response', { decision: 'approve', modification: null, actor: { sub: 'member-1', act: 'admin-7' } }],
      ['tool_confirmation_response', { decision: 'reject', modifications: null, actor: { sub: 'member-1' } }],
      ['fireteam_member_confirmation_response', {
        wave_id: 'w1', member_id: 'm1', decision: 'approve', resolved: true, actor: { sub: 'member-1', act: 'admin-7' },
      }],
    ])
    const t = await readTranscript(conversation, { running: false })
    expect(t.events.map((e) => e.data)).toEqual([
      { decision: 'approve', modification: null },
      { decision: 'reject', modifications: null },
      { wave_id: 'w1', member_id: 'm1', decision: 'approve', resolved: true },
    ])
    expect(JSON.stringify(t)).not.toMatch(/member-1|admin-7|"actor"/)
  })

  test('any row: only the top-level actor goes, text and nested values that mention one stay', async () => {
    seed([
      ['user_message', { content: 'the actor field of the form is vulnerable', actor: { sub: 'member-1' } }],
      ['tool_complete', { tool_name: 'execute_curl', output: { actor: 'value from the target' } }],
    ])
    const t = await readTranscript(conversation, { running: false })
    expect(t.events.map((e) => e.data)).toEqual([
      { content: 'the actor field of the form is vulnerable' },
      { tool_name: 'execute_curl', output: { actor: 'value from the target' } },
    ])
  })

  test('a row without an actor, or whose data is not an object, is unchanged', async () => {
    seed([
      ['approval_response', { decision: 'abort' }],
      ['thinking', 'plain text'],
      ['todo_update', [{ description: 'x', status: 'pending' }]],
    ])
    const t = await readTranscript(conversation, { running: false })
    expect(t.events.map((e) => e.data)).toEqual([
      { decision: 'abort' },
      'plain text',
      [{ description: 'x', status: 'pending' }],
    ])
  })
})
