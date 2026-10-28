import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useGraphRendering } from './useGraphRendering'

function fixture() {
  const canvas = document.createElement('canvas')
  const controls = new EventTarget()
  const graph = {
    pauseAnimation: vi.fn(),
    resumeAnimation: vi.fn(),
    d3ReheatSimulation: vi.fn(),
    renderer: () => ({ domElement: canvas }),
    controls: () => controls,
  }
  return { graph, canvas, controls }
}
function hidden(value: boolean) {
  Object.defineProperty(document, 'hidden', { configurable: true, value })
  document.dispatchEvent(new Event('visibilitychange'))
}

beforeEach(() => { vi.useFakeTimers(); hidden(false) })
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

function mount(continuous = false, pauseWhenIdle = true) {
  const f = fixture()
  const labels = vi.fn()
  const hook = renderHook(({ animated }) => useGraphRendering(animated, pauseWhenIdle, labels), {
    initialProps: { animated: continuous },
  })
  act(() => { hook.result.current.bindGraphRef.current = f.graph })
  act(() => { vi.advanceTimersByTime(101) })
  f.graph.pauseAnimation.mockClear()
  f.graph.resumeAnimation.mockClear()
  return { ...f, ...hook, labels }
}

describe('graph rendering lifecycle', () => {
  it('observes delayed dynamic attachment and sleeps after the last layout frame', () => {
    const h = mount()
    expect(h.result.current.graphRef.current).toBe(h.graph)
    act(() => { h.result.current.onEngineTick(); vi.advanceTimersByTime(500) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => { h.result.current.onEngineStop() })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => { vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
    h.unmount()
  })

  it.each([true, false])('suspends even animated graphs in hidden tabs (animated=%s)', animated => {
    const h = mount(animated)
    act(() => { hidden(true) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    act(() => { h.result.current.invalidate(true); vi.advanceTimersByTime(1000) })
    expect(h.graph.resumeAnimation).not.toHaveBeenCalled()
    act(() => { hidden(false); vi.advanceTimersByTime(1) })
    expect(h.graph.resumeAnimation).toHaveBeenCalledOnce()
    expect(h.graph.d3ReheatSimulation).not.toHaveBeenCalled()
    h.unmount()
  })

  it('does not reheat layout on initial attachment, tab visibility, or ordinary invalidation', () => {
    const h = mount()
    act(() => { h.result.current.invalidate(); hidden(true); hidden(false); vi.advanceTimersByTime(101) })
    expect(h.graph.d3ReheatSimulation).not.toHaveBeenCalled()
    h.unmount()
  })

  it('does not start a hidden-mounted graph until visible', () => {
    act(() => hidden(true))
    const f = fixture()
    const h = renderHook(() => useGraphRendering(false, true))
    act(() => { h.result.current.bindGraphRef.current = f.graph; vi.advanceTimersByTime(1000) })
    expect(f.graph.resumeAnimation).not.toHaveBeenCalled()
    expect(f.graph.pauseAnimation).toHaveBeenCalledOnce()
    act(() => { hidden(false); vi.advanceTimersByTime(1) })
    expect(f.graph.resumeAnimation).toHaveBeenCalledOnce()
    h.unmount()
  })

  it('preserves continuous particles/glow, then sleeps when animation ends', () => {
    const h = mount(true)
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    h.rerender({ animated: false })
    act(() => vi.advanceTimersByTime(101))
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    h.unmount()
  })

  it('wakes for pointer hover, pan/zoom inertia, and programmatic camera changes', () => {
    const h = mount()
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(101) })
    act(() => { h.canvas.dispatchEvent(new Event('pointermove')); vi.advanceTimersByTime(1) })
    expect(h.graph.resumeAnimation).toHaveBeenCalledOnce()
    h.graph.pauseAnimation.mockClear()
    act(() => { h.controls.dispatchEvent(new Event('start')); vi.advanceTimersByTime(1000) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => { h.controls.dispatchEvent(new Event('end')); vi.advanceTimersByTime(50) })
    act(() => { h.controls.dispatchEvent(new Event('change')); vi.advanceTimersByTime(50) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => vi.advanceTimersByTime(52))
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    expect(h.labels).toHaveBeenCalled()
    h.unmount()
  })

  it('wakes a sleeping graph for live data and waits for the new layout to settle', () => {
    const h = mount()
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(101) })
    h.graph.pauseAnimation.mockClear()
    act(() => { h.result.current.invalidate(true); vi.advanceTimersByTime(500) })
    expect(h.graph.resumeAnimation).toHaveBeenCalledOnce()
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    h.unmount()
  })

  it('leaves visible 2D idle redraw decisions to force-graph', () => {
    const h = mount(false, false)
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(1000) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => hidden(true))
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    h.unmount()
  })

  it('does not keep rendering after a drag loses focus or the tab is hidden', () => {
    const h = mount()
    act(() => { h.result.current.onEngineStop(); vi.advanceTimersByTime(101) })
    act(() => { h.controls.dispatchEvent(new Event('start')); vi.advanceTimersByTime(1) })
    act(() => { window.dispatchEvent(new Event('blur')); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledTimes(2)
    act(() => { h.controls.dispatchEvent(new Event('start')); hidden(true); hidden(false); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledTimes(4)
    h.unmount()
  })

  it('cleans listeners and pending callbacks across repeated mount/unmount', () => {
    for (let i = 0; i < 5; i++) {
      const h = mount()
      act(() => h.result.current.invalidate())
      h.unmount()
      h.graph.resumeAnimation.mockClear()
      act(() => {
        h.controls.dispatchEvent(new Event('change'))
        h.canvas.dispatchEvent(new Event('pointermove'))
        hidden(true); hidden(false)
        vi.advanceTimersByTime(1000)
      })
      expect(h.graph.resumeAnimation).not.toHaveBeenCalled()
      expect(vi.getTimerCount()).toBe(0)
    }
  })
})
