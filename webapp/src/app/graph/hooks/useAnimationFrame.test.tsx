import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useAnimationFrame } from './useAnimationFrame'

function hidden(value: boolean) {
  Object.defineProperty(document, 'hidden', { configurable: true, value })
  document.dispatchEvent(new Event('visibilitychange'))
}
beforeEach(() => { vi.useFakeTimers(); hidden(false) })
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

it('runs at the existing cadence, stops hidden, resumes once, and cleans up', () => {
  const callback = vi.fn()
  const h = renderHook(() => useAnimationFrame(callback, true))
  act(() => vi.advanceTimersByTime(160))
  expect(callback).toHaveBeenCalledTimes(4)
  act(() => { hidden(true); vi.advanceTimersByTime(1000) })
  expect(callback).toHaveBeenCalledTimes(4)
  act(() => { hidden(false); hidden(false); vi.advanceTimersByTime(160) })
  expect(callback).toHaveBeenCalledTimes(7)
  h.unmount()
  act(() => { hidden(true); hidden(false); vi.advanceTimersByTime(1000) })
  expect(callback).toHaveBeenCalledTimes(7)
  expect(vi.getTimerCount()).toBe(0)
})

it('does not schedule frames while disabled or mounted hidden, and uses the latest callback', () => {
  const first = vi.fn()
  const latest = vi.fn()
  hidden(true)
  const h = renderHook(({ enabled, callback }) => useAnimationFrame(callback, enabled), {
    initialProps: { enabled: true, callback: first },
  })
  act(() => vi.advanceTimersByTime(1000))
  expect(first).not.toHaveBeenCalled()
  h.rerender({ enabled: true, callback: latest })
  act(() => { hidden(false); vi.advanceTimersByTime(16) })
  expect(latest).toHaveBeenCalledOnce()
  h.rerender({ enabled: false, callback: latest })
  act(() => vi.advanceTimersByTime(1000))
  expect(latest).toHaveBeenCalledOnce()
  expect(vi.getTimerCount()).toBe(0)
  h.unmount()
})
