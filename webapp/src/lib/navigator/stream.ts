/**
 * The relay between the agent's NDJSON and the browser's SSE (plan §7.4).
 *
 * The webapp's own `thread` event goes first, so a new conversation shows in History at once. Every
 * agent line is capped at NDJSON_LINE_MAX_BYTES, parsed and validated (events.ts); unknown events
 * are dropped. The answer, the routes, the citations and the trace (tool names, summaries and the
 * generated Cypher, never a result) are kept in memory, and exactly one assistant message is saved
 * at the end: `complete` on `done`, `stopped` on an abort or the answer cap, `failed` on an error or
 * a protocol fault. A thread deleted meanwhile is never recreated. Nothing here logs message text,
 * deltas or tool details: ids, codes and timings only.
 */
import { ANSWER_MAX_CHARS, NDJSON_LINE_MAX_BYTES, type NavigatorRoute } from './constants'
import { sse, stripUnknownMarkers, validateAgentEvent, type Citation, type NavigatorEvent } from './events'
import type { AnswerToSave } from './threads'

/**
 * One line of "How I got this". Two pseudo-tools keep what a reopened conversation must still show:
 * `handoff` (the answer offered the AI Agent) and `refused_route` (a source the person may not read
 * here, its reason code in `summary`).
 */
export interface TraceEntry {
  route: NavigatorRoute
  tool: string
  status: 'end' | 'error'
  summary: string
  detail?: string
}

export interface RelayInput {
  agentBody: ReadableStream<Uint8Array>
  runId: string
  threadId: string
  userMessageId: string
  actorId: string | null
  /** The run's controller: aborting it ends the agent fetch. */
  abort: AbortController
  save: (answer: AnswerToSave) => Promise<'saved' | 'thread_gone'>
  /** Ends the run in the registry; called once, after the save. */
  end: () => void
  /** True when the browser itself went away (the abort is then not news to it). */
  clientGone: () => boolean
}

const encoder = new TextEncoder()

export function relayStream(input: RelayInput): ReadableStream<Uint8Array> {
  const started = Date.now()
  let answer = ''
  let routes: NavigatorRoute[] = []
  let citations: Citation[] = []
  const trace: TraceEntry[] = []
  let modelUsed: string | null = null
  let terminal: { status: AnswerToSave['status']; code: string | null } | null = null
  let finished = false

  // start() returns at once and the pump runs on its own, so a browser that goes away reaches
  // cancel() (and the abort) while a read is still pending.
  const pump = async (controller: ReadableStreamDefaultController<Uint8Array>) => {
      const send = (ev: NavigatorEvent) => {
        try {
          controller.enqueue(encoder.encode(sse(ev)))
        } catch {
          // the browser is gone; the answer is still saved below
        }
      }
      send({ type: 'thread', thread_id: input.threadId, user_message_id: input.userMessageId })

      const reader = input.agentBody.getReader()
      // Any abort (Stop, a revocation, the switch) ends the read at once, whatever the transport does.
      const onAbort = () => { reader.cancel().catch(() => {}) }
      if (input.abort.signal.aborted) onAbort()
      else input.abort.signal.addEventListener('abort', onAbort, { once: true })
      const decoder = new TextDecoder()
      let buffered = ''

      const handle = (line: string): boolean => {
        if (!line.trim()) return true
        let raw: unknown
        try {
          raw = JSON.parse(line)
        } catch {
          return true
        }
        const ev = validateAgentEvent(raw)
        if (!ev) return true
        switch (ev.type) {
          case 'meta':
            modelUsed = ev.model_used
            break
          case 'route':
            routes = ev.routes
            break
          case 'tool':
            if (ev.status !== 'start') {
              trace.push({ route: ev.route, tool: ev.name, status: ev.status, summary: ev.summary,
                ...(ev.detail ? { detail: ev.detail } : {}) })
            }
            break
          case 'delta': {
            const room = ANSWER_MAX_CHARS - answer.length
            if (ev.text.length > room) {
              answer += ev.text.slice(0, Math.max(0, room))
              send({ type: 'delta', text: ev.text.slice(0, Math.max(0, room)) })
              terminal = { status: 'stopped', code: 'answer_too_long' }
              send({ type: 'error', code: 'answer_too_long', message: 'The answer was cut because it grew too long.' })
              return false
            }
            answer += ev.text
            break
          }
          case 'citations':
            citations = ev.items
            break
          case 'handoff':
            trace.push({ route: 'direct', tool: 'handoff', status: 'end', summary: 'Offered the AI Agent' })
            break
          case 'refused_route':
            trace.push({ route: ev.route, tool: 'refused_route', status: 'error', summary: ev.reason_code })
            break
          case 'done':
            terminal = { status: 'complete', code: null }
            break
          case 'error':
            terminal = { status: 'failed', code: ev.code }
            break
        }
        send(ev)
        return !(ev.type === 'done' || ev.type === 'error')
      }

      try {
        let going = true
        while (going) {
          const { value, done } = await reader.read()
          if (done) break
          buffered += decoder.decode(value, { stream: true })
          let nl: number
          while (going && (nl = buffered.indexOf('\n')) >= 0) {
            const line = buffered.slice(0, nl)
            buffered = buffered.slice(nl + 1)
            if (Buffer.byteLength(line, 'utf8') > NDJSON_LINE_MAX_BYTES) {
              terminal = { status: 'failed', code: 'agent_protocol' }
              send({ type: 'error', code: 'agent_protocol', message: 'The answer could not be read.' })
              going = false
              break
            }
            going = handle(line)
          }
          if (going && Buffer.byteLength(buffered, 'utf8') > NDJSON_LINE_MAX_BYTES) {
            terminal = { status: 'failed', code: 'agent_protocol' }
            send({ type: 'error', code: 'agent_protocol', message: 'The answer could not be read.' })
            going = false
          }
        }
        if (going && buffered.trim()) handle(buffered)
      } catch {
        // an abort (Stop, a revocation, the browser closing) or the agent dropping the connection
      }
      if (!terminal) {
        if (input.abort.signal.aborted) {
          terminal = { status: 'stopped', code: null }
          if (!input.clientGone()) send({ type: 'error', code: 'stopped', message: 'The answer was stopped.' })
        } else {
          terminal = { status: 'failed', code: 'agent_protocol' }
          send({ type: 'error', code: 'agent_protocol', message: 'The answer could not be read.' })
        }
      }
      if (!input.abort.signal.aborted) input.abort.abort()
      reader.cancel().catch(() => {})

      if (!finished) {
        finished = true
        const t = terminal as { status: AnswerToSave['status']; code: string | null }
        try {
          const outcome = await input.save({
            content: stripUnknownMarkers(answer, citations),
            status: t.status,
            routes,
            citations,
            trace,
            modelUsed,
            actorId: input.actorId,
            errorCode: t.code,
          })
          if (outcome === 'thread_gone') console.warn(`[navigator] answer not saved code=thread_gone run=${input.runId}`)
        } catch (err) {
          const code = (err as { code?: string })?.code ?? (err as Error)?.name ?? 'unknown'
          console.error(`[navigator] answer not saved code=${String(code).slice(0, 40)} run=${input.runId}`)
        }
        input.end()
        console.info(`[navigator] run ended run=${input.runId} status=${t.status} code=${t.code ?? 'none'} ` +
          `tools=${trace.length} ms=${Date.now() - started}`)
      }
      try {
        controller.close()
      } catch {
        // already closed by the browser
      }
  }

  return new ReadableStream<Uint8Array>({
    start(controller) {
      void pump(controller)
    },
    cancel() {
      if (!input.abort.signal.aborted) input.abort.abort()
    },
  })
}
