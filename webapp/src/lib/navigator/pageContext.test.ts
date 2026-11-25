/**
 * The page a question was asked from (plan §7.3): a hint for the docs route, never trusted for
 * access. Only a known screen's path is kept, without its query string, and a project or plugin id
 * in the path never reaches the agent.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { PAGE_WIKI } from '@/components/ui/WikiInfoButton/wiki-links'
import { pageContextOf } from './pageContext'

describe('pageContextOf', () => {
  test('a known screen gets its wiki page as the hint', () => {
    expect(pageContextOf({ path: '/graph' })).toEqual({ path: '/graph', wiki_hint: PAGE_WIKI.graph.page })
    expect(pageContextOf({ path: '/settings' })).toEqual({ path: '/settings', wiki_hint: PAGE_WIKI.settings.page })
    expect(pageContextOf({ path: '/' })).toEqual({ path: '/', wiki_hint: null })
    // The IAM Console's screens are documented on the Identity & Access Management page.
    expect(pageContextOf({ path: '/admin/instance' })).toEqual({ path: '/admin/instance', wiki_hint: 'Identity-and-Access-Management' })
  })

  test('the query string and the fragment are dropped', () => {
    expect(pageContextOf({ path: '/graph?project=cabc&agent=open#x' })).toEqual({ path: '/graph', wiki_hint: PAGE_WIKI.graph.page })
  })

  test('a project or plugin id in the path is replaced, so it never reaches the agent', () => {
    expect(pageContextOf({ path: '/projects/cmabc123secret/settings' }))
      .toEqual({ path: '/projects/<id>/settings', wiki_hint: PAGE_WIKI.projectSettings.page })
    expect(pageContextOf({ path: '/plugins/acme-skiller' })).toEqual({ path: '/plugins/<id>', wiki_hint: PAGE_WIKI.plugins.page })
  })

  test.each([
    ['an unknown screen', { path: '/api/navigator/status' }],
    ['a traversal', { path: '/projects/../settings' }],
    ['a full URL', { path: 'https://evil.example/graph' }],
    ['a path over 120 characters', { path: `/graph${'x'.repeat(120)}` }],
    ['a non-string path', { path: 42 }],
    ['no object', 'graph'],
    ['nothing', null],
  ])('%s is dropped', (_name, raw) => {
    expect(pageContextOf(raw)).toBeNull()
  })
})
