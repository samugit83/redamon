/**
 * graphReadView (step 4.6; SH-07, NF-10): the one place that decides what a reader of a project's
 * graph sees of it. In this step every access reads the owner's graph as it is: the read areas give
 * a Read collaborator the graph (feature document §6.2), and what a reader without Raw data loses
 * (chain step content, step 4.9; recon-found secret values, OQ-R7) is decided there, by design
 * changes to these cases.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { graphReadView } from './graphReadView'
import type { ProjectAccess } from './projectAccess'

const PROJECT = { id: 'P-alice', userId: 'alice' }
const access = (level: ProjectAccess['level'], rawData: boolean, via: ProjectAccess['via']): ProjectAccess =>
  ({ project: PROJECT, level, toggles: { rawData }, via })

const ACCESSES: Array<[string, ProjectAccess]> = [
  ['the owner', access('owner', true, 'owner')],
  ['a read collaborator', access('read', false, 'share')],
  ['a read collaborator with Raw data', access('read', true, 'share')],
  ['an overseer', access('read', false, 'oversight')],
  ['a break-glass reader', access('read', true, 'break_glass')],
]

function graph() {
  return {
    nodes: [
      { id: '1', name: 'rbac.test', type: 'Domain', properties: { user_id: 'alice', project_id: 'P-alice' } },
      { id: '2', name: 'step', type: 'ChainStep', properties: { thought: 'next I try the login', output_summary: 'ok' } },
      { id: '3', name: 'key', type: 'Secret', properties: { secret_value: 'rbac-fake-secret-value', sample: 'rbac...' } },
    ],
    links: [{ source: '1', target: '3', type: 'HAS_SECRET' }],
    etag: 'abc123',
  }
}

describe('graphReadView: every access reads the owner graph in step 4.6', () => {
  test.each(ACCESSES)('%s gets the graph unchanged, its etag kept', (_who, a) => {
    const g = graph()
    const view = graphReadView(g, a)
    expect(view).toEqual(graph())
    expect(view.etag).toBe('abc123')
  })

  test('a payload without an etag (a saved view preview) keeps its shape', () => {
    const { etag: _etag, ...preview } = graph()
    expect(graphReadView(preview, access('read', false, 'share'))).toEqual(preview)
  })

  test('the view never writes into the graph it was given (the cached copy is shared by every reader)', () => {
    const g = Object.freeze({ ...graph(), nodes: Object.freeze(graph().nodes.map(n => Object.freeze({ ...n, properties: Object.freeze({ ...n.properties }) }))) })
    expect(() => graphReadView(g, access('read', false, 'share'))).not.toThrow()
    expect(() => graphReadView(g, access('owner', true, 'owner'))).not.toThrow()
  })
})
