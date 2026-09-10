/**
 * Strategy row 8: Domain batch group progress over the recon SSE stream.
 *
 * A batch runs the six pipeline phases once PER GROUP, so the phase counter
 * restarts at 1 every time a new domain begins. Without the outer group counter
 * the drawer cannot tell "group 2 starting" from "group 1 looping", and the
 * progress display reads as though the scan went backwards.
 *
 * The hook must also RESET the group state when the project changes, or a batch
 * project's "Group 3/3" would linger over an unrelated project's scan.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useReconSSE } from './useReconSSE'

afterEach(cleanup)

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onerror: (() => void) | null = null
  onopen: (() => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  listeners: Record<string, (ev: MessageEvent) => void> = {}
  closed = false
  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }
  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    this.listeners[type] = cb
  }
  emit(type: string, data: unknown) {
    this.listeners[type]?.({ data: JSON.stringify(data) } as MessageEvent)
  }
  close() { this.closed = true }
}

const logEvent = (over: Record<string, unknown> = {}) => ({
  log: 'line', timestamp: new Date().toISOString(), level: 'info',
  phase: null, phaseNumber: null, isPhaseStart: false,
  groupNumber: null, totalGroups: null, currentGroup: null, isGroupStart: false,
  ...over,
})

const groupMarker = (n: number, total: number, domain: string) => logEvent({
  log: `[Batch] Group ${n}/${total}: ${domain}`,
  isGroupStart: true, groupNumber: n, totalGroups: total, currentGroup: domain,
})

function mount(projectId = 'p1') {
  return renderHook(
    ({ id }: { id: string }) => useReconSSE({ projectId: id, enabled: true }),
    { initialProps: { id: projectId } },
  )
}

const stream = () => MockEventSource.instances[MockEventSource.instances.length - 1]

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
})

describe('group progress', () => {
  test('a group marker sets the outer progress', () => {
    const { result } = mount()
    act(() => stream().emit('log', groupMarker(2, 3, 'domain3.com')))

    expect(result.current.groupNumber).toBe(2)
    expect(result.current.totalGroups).toBe(3)
    expect(result.current.currentGroup).toBe('domain3.com')
  })

  test('a later group replaces the earlier one', () => {
    const { result } = mount()
    act(() => stream().emit('log', groupMarker(1, 3, 'a.com')))
    act(() => stream().emit('log', groupMarker(3, 3, 'c.com')))

    expect(result.current.groupNumber).toBe(3)
    expect(result.current.currentGroup).toBe('c.com')
  })

  test('a phase restart inside a group does not clear the group', () => {
    // The exact confusion this exists to prevent: phase 1 arriving again.
    const { result } = mount()
    act(() => stream().emit('log', groupMarker(2, 3, 'b.com')))
    act(() => stream().emit('log', logEvent({
      isPhaseStart: true, phase: 'Domain Discovery', phaseNumber: 1,
    })))

    expect(result.current.currentPhaseNumber).toBe(1)
    expect(result.current.groupNumber).toBe(2)
    expect(result.current.currentGroup).toBe('b.com')
  })

  test('an ordinary log line leaves the group progress untouched', () => {
    const { result } = mount()
    act(() => stream().emit('log', groupMarker(1, 2, 'a.com')))
    act(() => stream().emit('log', logEvent({ log: '[*][httpx] probing' })))

    expect(result.current.groupNumber).toBe(1)
  })

  test('a single-domain scan reports no group progress', () => {
    const { result } = mount()
    act(() => stream().emit('log', logEvent({
      isPhaseStart: true, phase: 'Port Scanning', phaseNumber: 2,
    })))

    expect(result.current.groupNumber).toBeNull()
    expect(result.current.totalGroups).toBeNull()
    expect(result.current.currentGroup).toBeNull()
  })
})

describe('reset', () => {
  test('switching project clears the previous project group progress', () => {
    const { result, rerender } = mount('p1')
    act(() => stream().emit('log', groupMarker(3, 3, 'c.com')))
    expect(result.current.groupNumber).toBe(3)

    rerender({ id: 'p2' })

    expect(result.current.groupNumber).toBeNull()
    expect(result.current.currentGroup).toBeNull()
  })

  test('clearLogs clears the group progress too', () => {
    const { result } = mount()
    act(() => stream().emit('log', groupMarker(2, 2, 'b.com')))
    act(() => result.current.clearLogs())

    expect(result.current.groupNumber).toBeNull()
    expect(result.current.totalGroups).toBeNull()
    expect(result.current.currentGroup).toBeNull()
  })
})
