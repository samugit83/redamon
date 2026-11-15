/**
 * The NDJSON → SSE relay (plan §7.4, §10.2 rows 24, 25, 34): the webapp's `thread` event first,
 * unknown events dropped, an oversized line fails the run, a bad citation never reaches the browser,
 * exactly one answer saved with the right status, a deleted thread is not recreated, and nothing of
 * the text is logged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { relayStream } from './stream'
import type { AnswerToSave } from './threads'

const enc = new TextEncoder()
const CANARY = 'CANARY-7c3f-answer-text'

function agentBody(lines: string[], { hang = false }: { hang?: boolean } = {}): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      for (const l of lines) c.enqueue(enc.encode(l + '\n'))
      if (!hang) c.close()
    },
  })
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Array<{ type: string; data: Record<string, unknown> }>> {
  const text = await new Response(stream).text()
  return text.split('\n\n').filter(Boolean).map((block) => {
    const type = /event: (\S+)/.exec(block)![1]
    const data = JSON.parse(/data: (.*)/.exec(block)![1])
    return { type, data }
  })
}

let saved: AnswerToSave[]
let ended: number
let logs: string[]

function relay(lines: string[], opts: { save?: (a: AnswerToSave) => Promise<'saved' | 'thread_gone'>; abort?: AbortController; hang?: boolean } = {}) {
  const abort = opts.abort ?? new AbortController()
  return relayStream({
    agentBody: agentBody(lines, { hang: opts.hang }),
    runId: 'run-1', threadId: 'thread-1', userMessageId: 'msg-1', actorId: null, abort,
    save: opts.save ?? (async (a) => { saved.push(a); return 'saved' }),
    end: () => { ended += 1 },
    clientGone: () => false,
  })
}

const j = (o: unknown) => JSON.stringify(o)

beforeEach(() => {
  saved = []
  ended = 0
  logs = []
  for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, level).mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')) })
  }
})
afterEach(() => vi.restoreAllMocks())

describe('relay', () => {
  test('thread first, validated events forwarded, one complete answer saved', async () => {
    const events = await readAll(relay([
      j({ type: 'meta', run_id: 'run-1', model_used: 'openai/x' }),
      j({ type: 'route', routes: ['docs'] }),
      j({ type: 'tool', route: 'docs', name: 'wiki_read', status: 'start', summary: 'Reading' }),
      j({ type: 'tool', route: 'docs', name: 'wiki_read', status: 'end', summary: "Read 'A'" }),
      j({ type: 'mystery', payload: 'dropped' }),
      j({ type: 'delta', text: `Hello ${CANARY} [S1] [S9]` }),
      j({ type: 'citations', items: [{ id: 'S1', title: 'T', heading: 'H', url: 'https://www.redamon.org/docs/t#h', mirror_url: 'https://github.com/samugit83/redamon/wiki/T#h' }] }),
      j({ type: 'done', status: 'complete' }),
    ]))
    expect(events[0]).toEqual({ type: 'thread', data: { type: 'thread', thread_id: 'thread-1', user_message_id: 'msg-1' } })
    expect(events.map((e) => e.type)).toEqual(['thread', 'meta', 'route', 'tool', 'tool', 'delta', 'citations', 'done'])
    expect(saved).toHaveLength(1)
    expect(saved[0]).toMatchObject({ status: 'complete', routes: ['docs'], modelUsed: 'openai/x', errorCode: null })
    expect(saved[0].content).toBe(`Hello ${CANARY} [S1] `)
    expect(saved[0].trace).toEqual([{ route: 'docs', tool: 'wiki_read', status: 'end', summary: "Read 'A'" }])
    expect(ended).toBe(1)
    expect(logs.join('\n')).not.toContain(CANARY)
  })

  test('a bad citation URL never reaches the browser or the saved row', async () => {
    const events = await readAll(relay([
      j({ type: 'citations', items: [{ id: 'S1', title: 'T', heading: 'H', url: 'https://evil.example/', mirror_url: 'https://github.com/samugit83/redamon/wiki/T' }] }),
      j({ type: 'done', status: 'complete' }),
    ]))
    expect(events.find((e) => e.type === 'citations')!.data.items).toEqual([])
    expect(saved[0].citations).toEqual([])
  })

  test('an oversized line fails the run with agent_protocol', async () => {
    const events = await readAll(relay([j({ type: 'delta', text: 'x'.repeat(70_000) })]))
    expect(events.at(-1)!.data).toMatchObject({ type: 'error', code: 'agent_protocol' })
    expect(saved[0]).toMatchObject({ status: 'failed', errorCode: 'agent_protocol' })
  })

  test('an agent error is saved as failed with its code', async () => {
    await readAll(relay([j({ type: 'delta', text: 'part' }), j({ type: 'error', code: 'model_error', message: 'The model call failed.' })]))
    expect(saved[0]).toMatchObject({ status: 'failed', errorCode: 'model_error', content: 'part' })
  })

  test('a stream that ends without a terminal event is a protocol failure', async () => {
    await readAll(relay([j({ type: 'delta', text: 'half' })]))
    expect(saved[0]).toMatchObject({ status: 'failed', errorCode: 'agent_protocol' })
  })

  test('an abort mid-answer saves the partial text as stopped', async () => {
    const abort = new AbortController()
    const stream = relay([j({ type: 'delta', text: 'partial answer' })], { abort, hang: true })
    setTimeout(() => abort.abort(), 20)
    const events = await readAll(stream)
    expect(events.at(-1)!.data).toMatchObject({ type: 'error', code: 'stopped' })
    expect(saved).toHaveLength(1)
    expect(saved[0]).toMatchObject({ status: 'stopped', content: 'partial answer' })
  })

  test('the hand-off and a refused route are kept in the trace', async () => {
    await readAll(relay([
      j({ type: 'refused_route', route: 'workspace', reason_code: 'needs_raw_data' }),
      j({ type: 'handoff', target: 'ai_agent' }),
      j({ type: 'done', status: 'complete' }),
    ]))
    expect(saved[0].trace).toEqual([
      { route: 'workspace', tool: 'refused_route', status: 'error', summary: 'needs_raw_data' },
      { route: 'direct', tool: 'handoff', status: 'end', summary: 'Offered the AI Agent' },
    ])
  })

  test('a thread deleted mid-run: logged as thread_gone, never recreated, the stream ends cleanly', async () => {
    const events = await readAll(relay([j({ type: 'done', status: 'complete' })], { save: async () => 'thread_gone' }))
    expect(events.at(-1)!.type).toBe('done')
    expect(logs.some((l) => l.includes('[navigator] answer not saved code=thread_gone run=run-1'))).toBe(true)
    expect(ended).toBe(1)
  })
})
