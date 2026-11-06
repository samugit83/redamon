/** @vitest-environment node */
/**
 * Every webapp reader that means CURRENT DNS reads RESOLVES_TO through
 * currentDns(): a passive source (Shodan's reverse DNS, Censys, FOFA, OTX,
 * ZoomEye) stamps the edge with a source, and its old address may belong to
 * someone else now. The raw graph view (clusterNodes.ts) keeps every edge.
 *
 * Run: npx vitest run src/lib/graph/forwardDns.test.ts
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test, expect } from 'vitest'
import { currentDns } from './forwardDns'

const SRC = resolve(__dirname, '../..')
const READERS = [
  'app/api/analytics/graph-overview/route.ts',
  'app/api/analytics/attack-surface/route.ts',
  'app/api/analytics/redzone/killChain/route.ts',
  'app/api/analytics/redzone/sharedInfra/route.ts',
  'app/api/analytics/redzone/netInitAccess/route.ts',
  'app/api/analytics/redzone/threatIntel/route.ts',
  'app/api/analytics/redzone/dnsDrift/route.ts',
  'lib/report/reportData.ts',
]

describe('current DNS readers', () => {
  test('the fragment mirrors the Python builders', () => {
    const builders = readFileSync(resolve(SRC, '../../recon/partial_recon_modules/graph_builders.py'), 'utf8')
    expect(builders).toContain('FORWARD_DNS = "r.source IS NULL"')
    expect(currentDns('r')).toBe('r.source IS NULL')
  })

  test.each(READERS)('%s reads RESOLVES_TO through currentDns', (file) => {
    const text = readFileSync(resolve(SRC, file), 'utf8')
    // Every edge read binds a variable; an unbound one cannot be filtered.
    // The one exception is an existence check of "has any data".
    const unbound = [...text.matchAll(/\[:RESOLVES_TO\]/g)].filter(m => {
      const line = text.slice(text.lastIndexOf('\n', m.index) + 1, text.indexOf('\n', m.index))
      return !line.includes('AS hasData')
    })
    expect(unbound, file).toEqual([])
    for (const m of text.matchAll(/\[(\w+):RESOLVES_TO\]/g)) {
      const after = text.slice(m.index, m.index + 400)
      expect(after, `${file}: ${m[1]}`).toContain(`currentDns('${m[1]}')`)
    }
  })
})
