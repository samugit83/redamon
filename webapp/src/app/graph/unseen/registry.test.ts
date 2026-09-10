/**
 * The badge feature's coverage contract: every table tab either carries a badge
 * backed by a real source, or is listed as deliberately unbadged. Nothing else
 * enforces that, and both failures are silent - a tab added next month renders
 * fine and simply never says it has new rows, or worse, gets a badge with no
 * source behind it and reads a permanent zero.
 *
 * Reads the SOURCE of ViewTabs rather than importing it: that module is a client
 * component pulling in lucide-react and CSS modules, and this needs nothing from
 * it but the list of tab ids.
 *
 * Run: npx vitest run src/app/graph/unseen/registry.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ALL_GRAPH_LABELS, BADGED_TABS, UNBADGED_TABS } from './registry'
import { isSafeLabel } from './counts'
import { LABEL_TABS, ROUTE_TABS, labelsForTab } from '@/app/api/analytics/unseen/sources'

const VIEW_TABS = join(__dirname, '../components/ViewTabs/ViewTabs.tsx')
const SCHEMA_PY = join(__dirname, '../../../../../graph_db/schema.py')

/** Every member of the `TableViewMode` union, read out of its declaration. */
function tableViewModes(): string[] {
  const src = readFileSync(VIEW_TABS, 'utf8')
  const union = src.match(/export type TableViewMode =([\s\S]*?)\n\n/)
  if (!union) throw new Error('TableViewMode union not found in ViewTabs.tsx')
  return [...union[1].matchAll(/'([a-zA-Z]+)'/g)].map(m => m[1])
}

describe('the tab list was actually found', () => {
  // A rename would otherwise make every assertion below pass over an empty set.
  test('parses a plausible number of tabs', () => {
    expect(tableViewModes().length).toBeGreaterThanOrEqual(20)
  })
})

describe('every table tab is accounted for', () => {
  test.each(tableViewModes())('%s is badged or explicitly unbadged', mode => {
    const badged = (BADGED_TABS as readonly string[]).includes(mode)
    const unbadged = (UNBADGED_TABS as readonly string[]).includes(mode)
    expect(badged || unbadged).toBe(true)
  })

  test('no entry names a tab that no longer exists', () => {
    const modes = new Set(tableViewModes())
    for (const tab of [...BADGED_TABS, ...UNBADGED_TABS]) expect(modes.has(tab)).toBe(true)
  })
})

describe('every badged tab has something to count', () => {
  const sourced = new Set([...LABEL_TABS, ...ROUTE_TABS])

  test.each(BADGED_TABS)('%s has a source', tab => {
    // A badged tab with no source is not a crash, it is a badge that is always
    // zero - indistinguishable from a quiet tab, and never noticed.
    expect(sourced.has(tab)).toBe(true)
  })

  test('no source names a tab that is not badged', () => {
    const badged = new Set<string>(BADGED_TABS)
    for (const tab of sourced) expect(badged.has(tab)).toBe(true)
  })

  test('a tab is counted one way or the other, never both', () => {
    for (const tab of LABEL_TABS) expect(ROUTE_TABS).not.toContain(tab)
  })

  test('only whole-graph tabs are counted by label', () => {
    // The bug this file exists to stop coming back: counting a FILTERED sheet by
    // label badges it for nodes it would never show. Web Cache Poisoning lists
    // only cache-poisoning vulns, so four ordinary Vulnerability nodes must not
    // put a 4 over it.
    expect([...LABEL_TABS].sort()).toEqual(['all', 'jsRecon', 'nodeDetails'])
  })
})

describe('the labels used for the whole-graph tabs', () => {
  test('are bare identifiers', () => {
    // They are interpolated into Cypher, so anything else is an injection.
    for (const tab of LABEL_TABS) {
      for (const label of labelsForTab(tab)) expect(isSafeLabel(label)).toBe(true)
    }
  })

  test('are labels the graph actually writes', () => {
    const known = new Set<string>(ALL_GRAPH_LABELS)
    for (const tab of LABEL_TABS) {
      for (const label of labelsForTab(tab)) expect(known.has(label)).toBe(true)
    }
  })
})

describe('ALL_GRAPH_LABELS tracks the graph schema', () => {
  // Skipped in the webapp image, which copies only webapp/.
  const available = existsSync(SCHEMA_PY)

  test.skipIf(!available)('matches the tenant-indexed labels, minus the KB corpus', () => {
    const src = readFileSync(SCHEMA_PY, 'utf8')
    const indexed = new Set(
      [...src.matchAll(/FOR \([a-zA-Z_]+:([A-Za-z][A-Za-z0-9_]*)\)/g)].map(m => m[1]),
    )
    indexed.delete('KBChunk')
    // `Muted` is a marker ADDED to a finding that an operator suppressed, not a
    // node type. It must never appear here: these labels drive the whole-graph
    // tabs, and every read path strips muted nodes before rendering, so a tab
    // for them would always be empty -- and listing it would make a
    // dual-labelled node look like a first-class type.
    indexed.delete('Muted')
    expect([...new Set(ALL_GRAPH_LABELS)].sort()).toEqual([...indexed].sort())
  })
})

describe('regression: triage is guarded against past-version viewing', () => {
  // Triage reads the LIVE graph -- verdicts and mute state are current, never
  // version-scoped. It was originally branched ABOVE the past-version guard, so
  // opening a saved snapshot rendered current triage data under an old version
  // label with no notice. It must sit below the guard, like the RedZone panels.
  const PAGE = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')

  test('the triage branch comes after the past-version guard', () => {
    const guard = PAGE.indexOf('isViewingPastVersion && tableViewMode !== ')
    const triage = PAGE.indexOf("tableViewMode === 'triage' ?")
    expect(guard, 'past-version guard not found').toBeGreaterThan(-1)
    expect(triage, 'triage branch not found').toBeGreaterThan(-1)
    expect(triage).toBeGreaterThan(guard)
  })

  test('triage is not exempted from the guard the way nodeDetails and all are', () => {
    // Those two render the SELECTED version's payload and are legitimately
    // exempt. Triage is not: it has no version-scoped form.
    const guardLine = PAGE.split('\n').find(l => l.includes('isViewingPastVersion && tableViewMode !=='))!
    expect(guardLine).not.toContain("'triage'")
  })
})
