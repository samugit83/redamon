/**
 * AI Navigator's "Open the AI Agent" deep link (plan §9.6): /graph?project=<id>&agent=open opens the
 * AI Agent drawer once the provider holds that project, then drops the parameter. Source-level, like
 * the page's other deep-link wiring tests: mounting /graph needs providers and live data.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const page = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')
const root = readFileSync(join(process.cwd(), 'src/components/navigator/NavigatorRoot.tsx'), 'utf8')

describe('?agent=open', () => {
  test('is read inside the deep-link effect, after the wrong-project early return', () => {
    const effect = page.slice(page.indexOf("const urlProjectId = searchParams.get('project')"))
    const guard = effect.indexOf('if (urlProjectId && urlProjectId !== projectId) return')
    const agent = effect.indexOf("searchParams.get('agent') === 'open' && projectId")
    expect(guard).toBeGreaterThanOrEqual(0)
    expect(agent).toBeGreaterThan(guard)
    const branch = effect.slice(agent, agent + 200)
    expect(branch).toContain('setIsAIOpen(true)')
    expect(branch).toContain('router.replace(`/graph?project=${projectId}`)')
  })

  test('the Navigator closes its panel before it navigates there', () => {
    const fn = root.slice(root.indexOf('const openAgent'))
    expect(fn.indexOf('setOpen(false)')).toBeLessThan(fn.indexOf('router.push('))
    expect(fn).toContain('&agent=open')
  })
})
