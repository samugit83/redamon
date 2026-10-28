import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { GraphNavControls } from './GraphNavControls'

afterEach(() => { vi.useRealTimers() })

it('notifies a sleeping 3D renderer after imperative pan and fit, and cancels timers on unmount', () => {
  vi.useFakeTimers()
  const controls = { target: { x: 0, y: 0 }, dispatchEvent: vi.fn() }
  const position = { x: 0, y: 0, lerp: vi.fn() }
  const graph = {
    controls: () => controls,
    camera: () => ({ position }),
    zoomToFit: vi.fn(),
  }
  const { unmount } = render(<GraphNavControls graphRef={{ current: graph }} is3D />)
  fireEvent.mouseDown(screen.getByTitle('Pan right'))
  expect(position.x).toBe(15)
  expect(controls.target.x).toBe(15)
  expect(controls.dispatchEvent).toHaveBeenCalledWith({ type: 'change' })
  fireEvent.mouseUp(screen.getByTitle('Pan right'))
  fireEvent.click(screen.getByTitle('Fit all nodes'))
  expect(graph.zoomToFit).toHaveBeenCalledWith(400, 0)
  unmount()
  vi.advanceTimersByTime(1000)
  expect(position.lerp).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

it('preserves every delayed camera adjustment from repeated fit clicks', () => {
  vi.useFakeTimers()
  const position = { lerp: vi.fn() }
  const controls = { target: {}, dispatchEvent: vi.fn() }
  const graph = { controls: () => controls, camera: () => ({ position }), zoomToFit: vi.fn() }
  const { unmount } = render(<GraphNavControls graphRef={{ current: graph }} is3D />)
  fireEvent.click(screen.getByTitle('Fit all nodes'))
  fireEvent.click(screen.getByTitle('Fit all nodes'))
  vi.advanceTimersByTime(500)
  expect(graph.zoomToFit).toHaveBeenCalledTimes(2)
  expect(position.lerp).toHaveBeenCalledTimes(2)
  expect(vi.getTimerCount()).toBe(0)
  unmount()
})
