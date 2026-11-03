import { forwardRef, useEffect, useImperativeHandle } from 'react'
import { act, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as THREE from 'three'
import { GraphCanvas3D } from './GraphCanvas3D'
import type { GraphData, GraphNode } from '../../types'

const h = vi.hoisted(() => ({
  props: {} as Record<string, unknown>,
  graph: null as unknown as ReturnType<typeof fakeGraph>,
}))
vi.mock('next/dynamic', () => ({
  default: () => forwardRef(function Graph(props, ref) {
    useEffect(() => { h.props = props }, [props])
    useImperativeHandle(ref, () => h.graph, [])
    return null
  }),
}))
// jsdom has no 2D canvas for SpriteText to draw on; these tests only read label visibility.
vi.mock('three-spritetext', async () => {
  const { Object3D } = await import('three')
  return { default: class extends Object3D { dispose() {} } }
})

function fakeGraph() {
  const camera = new THREE.PerspectiveCamera()
  const controls = new EventTarget()
  const canvas = document.createElement('canvas')
  return {
    camera: () => camera,
    controls: () => controls,
    renderer: () => ({ domElement: canvas }),
    pauseAnimation: vi.fn(),
    resumeAnimation: vi.fn(),
    d3ReheatSimulation: vi.fn(),
    refresh: vi.fn(),
  }
}

const node = (id: string, type: string, properties: Record<string, unknown> = {}): GraphNode =>
  ({ id, name: `synthetic-${id}`, type, properties })

function graphOf(nodes: GraphNode[]): GraphData {
  return {
    projectId: 'synthetic',
    nodes,
    links: nodes.slice(1).map(n => ({ source: nodes[0].id, target: n.id, type: 'SYNTHETIC_LINK' })),
  }
}

function mount(data: GraphData, opts: { selected?: GraphNode; activeChainId?: string; showLabels?: boolean } = {}) {
  const view = render(
    <GraphCanvas3D data={data} width={800} height={600} showLabels={opts.showLabels ?? true}
      selectedNode={opts.selected ?? null} onNodeClick={vi.fn()} activeChainId={opts.activeChainId} />,
  )
  act(() => { vi.advanceTimersByTime(1000) })
  return view
}

// `three` is an untyped module here (src/types/three.d.ts), so name only what these tests touch.
interface NodeObject {
  position: { set: (x: number, y: number, z: number) => void }
  getObjectByName: (name: string) => { visible: boolean } | undefined
}

const engineStop = () => (h.props.onEngineStop as () => void)()
const buildNode = (n: GraphNode) => (h.props.nodeThreeObject as (node: object) => NodeObject)(n)
const label = (group: NodeObject) => group.getObjectByName('label')!

beforeEach(() => {
  vi.useFakeTimers()
  h.graph = fakeGraph()
  Object.defineProperty(document, 'hidden', { configurable: true, value: false })
})
afterEach(() => { vi.useRealTimers() })

describe('3D render sleep', () => {
  it('sleeps a settled scene once the layout stops, when nothing animates', () => {
    const view = mount(graphOf([node('a', 'Domain'), node('b', 'IP')]))
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    act(() => { engineStop(); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    view.unmount()
  })

  const domain = node('a', 'Domain')
  it.each([
    ['a critical CVE glows', graphOf([domain, node('cve', 'CVE', { severity: 'critical' })]), {}],
    ['an exploit always glows', graphOf([domain, node('x', 'ExploitGvm')]), {}],
    ['the active chain pulses', graphOf([domain, node('s', 'ChainStep', { chain_id: 'c1' })]), { activeChainId: 'c1' }],
    ['a selected node has particles', graphOf([domain, node('b', 'IP')]), { selected: domain }],
  ])('keeps rendering while %s', (_, data, opts) => {
    const view = mount(data, opts)
    act(() => { engineStop(); vi.advanceTimersByTime(1000) })
    expect(h.graph.pauseAnimation).not.toHaveBeenCalled()
    view.unmount()
  })

  it.each([
    ['a medium CVE has no glow', graphOf([domain, node('cve', 'CVE', { severity: 'medium' })]), {}],
    ['a chain node outside the active chain', graphOf([domain, node('s', 'ChainStep', { chain_id: 'c2' })]), { activeChainId: 'c1' }],
  ])('still sleeps when %s', (_, data, opts) => {
    const view = mount(data, opts)
    act(() => { engineStop(); vi.advanceTimersByTime(101) })
    expect(h.graph.pauseAnimation).toHaveBeenCalledOnce()
    view.unmount()
  })
})

describe('3D labels without a per-frame loop', () => {
  it('follows camera distance on camera changes, and hides every label when labels are off', () => {
    const data = graphOf([node('near', 'Domain'), node('far', 'IP')])
    const view = mount(data)
    const near = buildNode(data.nodes[0])
    const far = buildNode(data.nodes[1])
    near.position.set(0, 0, 100)
    far.position.set(0, 0, 1000)

    act(() => { engineStop() })
    expect(label(near).visible).toBe(true)
    expect(label(far).visible).toBe(false)

    h.graph.camera().position.set(0, 0, 900)
    act(() => { h.graph.controls().dispatchEvent(new Event('change')) })
    expect(label(near).visible).toBe(false)
    expect(label(far).visible).toBe(true)

    view.rerender(
      <GraphCanvas3D data={data} width={800} height={600} showLabels={false}
        selectedNode={null} onNodeClick={vi.fn()} />,
    )
    expect(label(near).visible).toBe(false)
    expect(label(far).visible).toBe(false)
    view.unmount()
  })
})
