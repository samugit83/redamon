/**
 * The Render switch has to actually save the work, not just hide the canvas.
 * The two failure modes these lock down: fetching the graph before the saved
 * preference has arrived (so "off" costs a full read on every page load), and
 * suppressing the fetch for the table views, which would break the very screen
 * the off-state message tells the user to go to.
 */
import { describe, test, expect } from 'vitest'
import { isGraphRenderOff, shouldFetchGraph } from './renderGate'

const gate = (over: Partial<Parameters<typeof shouldFetchGraph>[0]> = {}) => ({
  prefsLoading: false,
  renderEnabled: true,
  activeView: 'graph',
  ...over,
})

describe('isGraphRenderOff', () => {
  test('off only once the saved preference says so', () => {
    expect(isGraphRenderOff(gate({ renderEnabled: false }))).toBe(true)
    expect(isGraphRenderOff(gate({ renderEnabled: true }))).toBe(false)
  })

  test('never claims "off" while the preference is still loading', () => {
    expect(isGraphRenderOff(gate({ prefsLoading: true, renderEnabled: false }))).toBe(false)
  })
})

describe('shouldFetchGraph', () => {
  test('rendering off on the graph map fetches nothing', () => {
    expect(shouldFetchGraph(gate({ renderEnabled: false }))).toBe(false)
  })

  test('rendering off still fetches for every other view', () => {
    for (const activeView of ['table', 'graphViews', 'sessions', 'terminal', 'roe']) {
      expect(shouldFetchGraph(gate({ renderEnabled: false, activeView }))).toBe(true)
    }
  })

  test('nothing is fetched until the preference has loaded', () => {
    expect(shouldFetchGraph(gate({ prefsLoading: true }))).toBe(false)
    expect(shouldFetchGraph(gate({ prefsLoading: true, activeView: 'table' }))).toBe(false)
  })

  test('rendering on behaves exactly as before the switch existed', () => {
    expect(shouldFetchGraph(gate())).toBe(true)
    expect(shouldFetchGraph(gate({ activeView: 'table' }))).toBe(true)
  })
})
