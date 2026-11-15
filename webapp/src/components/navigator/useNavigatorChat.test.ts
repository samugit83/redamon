/** The browser's SSE reader and the saved-message mapping of AI Navigator. */
import { describe, test, expect } from 'vitest'
import { fromSaved, parseSse } from './useNavigatorChat'

describe('parseSse', () => {
  test('complete events out, the partial one kept', () => {
    const { events, rest } = parseSse('event: thread\ndata: {"thread_id":"t"}\n\nevent: delta\ndata: {"text":"he"}\n\nevent: delta\ndata: {"te')
    expect(events).toEqual([{ type: 'thread', data: { thread_id: 't' } }, { type: 'delta', data: { text: 'he' } }])
    expect(rest).toBe('event: delta\ndata: {"te')
  })

  test('a malformed block is skipped', () => {
    expect(parseSse('event: x\ndata: {nope\n\n').events).toEqual([])
  })
})

describe('fromSaved', () => {
  test('unknown fields and statuses fall back safely', () => {
    expect(fromSaved({ id: 'm', role: 'assistant', content: 'c', status: 'weird', citations: 'x', trace: null })).toMatchObject({
      status: 'complete', citations: [], trace: [], routes: [], errorCode: null, actedByAdmin: false,
    })
  })
})
