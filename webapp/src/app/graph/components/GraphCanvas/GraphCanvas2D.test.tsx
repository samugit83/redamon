import { forwardRef, useImperativeHandle, useEffect } from 'react'
import { act, render } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { GraphCanvas2D } from './GraphCanvas2D'

const h = vi.hoisted(() => ({
  props: {} as Record<string, unknown>,
  graph: { pauseAnimation: vi.fn(), resumeAnimation: vi.fn(), d3ReheatSimulation: vi.fn(), zoom: () => 1 },
}))
vi.mock('next/dynamic', () => ({
  default: () => forwardRef(function Graph(props, ref) {
    useEffect(() => { h.props = props }, [props])
    useImperativeHandle(ref, () => h.graph, [])
    return null
  }),
}))
beforeEach(() => {
  vi.useFakeTimers()
  vi.clearAllMocks()
  Object.defineProperty(document, 'hidden', { configurable: true, value: false })
})
afterEach(() => { vi.useRealTimers() })

it('keeps the existing 2D redraw policy even with severity glow or an active chain', () => {
  const data = {
    projectId: 'synthetic',
    nodes: [
      { id: 'cve', name: 'Synthetic CVE', type: 'CVE', properties: { severity: 'critical' } },
      { id: 'chain', name: 'Synthetic chain', type: 'AttackChain', properties: { chain_id: 'synthetic-chain' } },
    ],
    links: [{ source: 'cve', target: 'chain', type: 'RELATES_TO' }],
  }
  const view = render(<GraphCanvas2D data={data} width={800} height={600} showLabels selectedNode={data.nodes[0]} onNodeClick={vi.fn()} activeChainId="synthetic-chain" />)
  expect(h.props.autoPauseRedraw).toBeUndefined()
  expect(h.graph.d3ReheatSimulation).not.toHaveBeenCalled()
  expect((h.props.linkDirectionalParticles as (link: object) => number)(data.links[0])).toBeGreaterThan(0)
  act(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true })
    document.dispatchEvent(new Event('visibilitychange'))
  })
  expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
  view.unmount()
  expect(vi.getTimerCount()).toBe(0)
})
