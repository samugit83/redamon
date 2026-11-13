/**
 * graphReadView (step 4.6; SH-07, NF-10): the one place that decides what a reader of a project's
 * graph sees of it. Step 4.9 (SH-30) decided what a reader without Raw data & files loses, by design
 * changes to 4.6's "every access reads the graph unchanged" cases:
 *   - the owner, a share with Raw data & files and break-glass read the graph whole, etag kept;
 *   - a Read share without Raw data and an overseer read the chain nodes without their step
 *     content, and no tabular row of a saved view (a column can be any expression over it); the
 *     recon-found secret values stay (OQ-R7, open: option b as written, RAW_DATA_GRAPH_PROPS empty);
 *   - such a view gets its own etag when it changed something, so a browser holding the full
 *     graph's etag is not answered 304; when nothing changed the body and the etag are the same.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { READ_VIEW_ETAG_SUFFIX, TABULAR_ROW_TYPE, graphReadView } from './graphReadView'
import { STEP_CONTENT_PROPS } from './stepContent'
import type { ProjectAccess } from './projectAccess'

const PROJECT = { id: 'P-alice', userId: 'alice' }
const access = (level: ProjectAccess['level'], rawData: boolean, via: ProjectAccess['via']): ProjectAccess =>
  ({ project: PROJECT, level, toggles: { rawData }, via })

const WHOLE: Array<[string, ProjectAccess]> = [
  ['the owner', access('owner', true, 'owner')],
  ['a read collaborator with Raw data', access('read', true, 'share')],
  ['a break-glass reader', access('read', true, 'break_glass')],
]
const BELOW_RAW: Array<[string, ProjectAccess | null]> = [
  ['a read collaborator', access('read', false, 'share')],
  ['an overseer', access('read', false, 'oversight')],
  ['no decided access', null],
]

function graph() {
  return {
    nodes: [
      { id: '1', name: 'rbac.test', type: 'Domain', properties: { user_id: 'alice', project_id: 'P-alice' } },
      { id: '2', name: 'step', type: 'ChainStep', properties: { iteration: 1, tool_name: 'nmap', thought: 'next I try the login', output_summary: 'ok' } },
      { id: '3', name: 'key', type: 'Secret', properties: { secret_value: 'rbac-fake-secret-value', sample: 'rbac...' } },
    ],
    links: [{ source: '1', target: '3', type: 'HAS_SECRET' }, { source: '2', target: '1', type: 'STEP_TARGETED' }],
    etag: 'abc123',
  }
}

const tabular = () => ({ id: 'row-0', name: 'next I try the login', type: TABULAR_ROW_TYPE, properties: { 's.thought': 'next I try the login' } })

describe('graphReadView: the whole graph at R*', () => {
  test.each(WHOLE)('%s gets the same graph object, its etag kept', (_who, a) => {
    const g = graph()
    expect(graphReadView(g, a)).toBe(g)
  })

  test.each(WHOLE)('%s gets a saved view\'s tabular rows', (_who, a) => {
    const preview = { nodes: [tabular()], links: [] }
    expect(graphReadView(preview, a)).toBe(preview)
  })
})

describe('graphReadView: below R* (step 4.9)', () => {
  test.each(BELOW_RAW)('%s: the chain step keeps its structure, loses its content; the other nodes and the links are the same', (_who, a) => {
    const g = graph()
    const view = graphReadView(g, a)
    expect(view.nodes[1]).toEqual({ id: '2', name: 'step', type: 'ChainStep', properties: { iteration: 1, tool_name: 'nmap' } })
    for (const key of STEP_CONTENT_PROPS) expect((view.nodes[1] as { properties: object }).properties).not.toHaveProperty(key)
    expect(view.nodes[0]).toBe(g.nodes[0])
    expect(view.links).toBe(g.links)
  })

  test.each(BELOW_RAW)('%s still reads the recon-found secret value (OQ-R7 open: option b as written)', (_who, a) => {
    const view = graphReadView(graph(), a)
    expect(view.nodes[2]).toEqual(graph().nodes[2])
  })

  test.each(BELOW_RAW)('%s: a changed view gets its own etag, so the full graph\'s etag never answers 304', (_who, a) => {
    const view = graphReadView(graph(), a)
    expect(view.etag).toBe(`abc123${READ_VIEW_ETAG_SUFFIX}`)
    expect(view.etag).not.toBe('abc123')
  })

  test('a graph with nothing to strip is answered as it is: the same body, the same etag', () => {
    const g = { nodes: [graph().nodes[0], graph().nodes[2]], links: [], etag: 'abc123' }
    expect(graphReadView(g, access('read', false, 'share'))).toBe(g)
  })

  test('a saved view\'s tabular rows are withheld, its graph rows kept and stripped', () => {
    const preview = { nodes: [tabular(), graph().nodes[0], graph().nodes[1]], links: [] }
    const view = graphReadView(preview, access('read', false, 'share'))
    expect(view.nodes.map(n => (n as { id: string }).id)).toEqual(['1', '2'])
    expect(JSON.stringify(view)).not.toContain('next I try the login')
    expect(view).not.toHaveProperty('etag')
  })

  test('a tabular-only answer reads as empty, never as the rows', () => {
    const view = graphReadView({ nodes: [tabular(), { ...tabular(), id: 'row-1' }], links: [] }, access('read', false, 'oversight'))
    expect(view.nodes).toEqual([])
  })

  test('the suffix names what the view leaves out: a short stable tag', () => {
    expect(READ_VIEW_ETAG_SUFFIX).toMatch(/^-r[0-9a-f]{8}$/)
  })

  test('the view never writes into the graph it was given (the cached copy is shared by every reader)', () => {
    const frozen = () => Object.freeze({
      ...graph(),
      nodes: Object.freeze([...graph().nodes, tabular()].map(n => Object.freeze({ ...n, properties: Object.freeze({ ...n.properties }) }))),
    })
    const g = frozen()
    expect(() => graphReadView(g, access('read', false, 'share'))).not.toThrow()
    expect(() => graphReadView(g, access('owner', true, 'owner'))).not.toThrow()
    expect(g).toEqual(frozen())
  })
})
