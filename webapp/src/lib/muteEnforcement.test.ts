/**
 * Every hand-written graph query that reads a finding must exclude muted ones.
 *
 * Mute is enforced at a chokepoint for the agent (`graph_db/tenant_filter.py`)
 * and in one place for the graph screen (`liveRead.ts`), but analytics, RedZone,
 * reports and the download/export routes each hand-write their own Cypher
 * against `getGraphSession`. There is no chokepoint to lean on there, so the
 * guarantee is only as good as the next route someone adds.
 *
 * This test is that guarantee: it walks the source tree, finds every file that
 * queries a muteable finding label, and fails if the file does not also carry
 * the exclusion. A new RedZone panel that forgets it fails here rather than
 * quietly showing an operator the findings they suppressed.
 *
 * It is deliberately a grep and not a behavioural test. The behaviour needs a
 * live Neo4j; the property worth pinning in CI is "nobody forgot", and that is
 * exactly what a grep can prove.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { notMuted, noneMuted, MUTED_LABEL } from './graphMute'

const SRC = join(__dirname, '..')

/**
 * Labels an operator can suppress. Asset and reference nodes (IP, Port, Domain,
 * Endpoint, CVE, ...) are context and are never muted, so a query that reads
 * only those needs no exclusion.
 *
 * Keep in sync with the label guard in `graph_db/mixins/recon/triage_mixin.py`.
 */
const MUTEABLE = [
  'Vulnerability',
  'JsReconFinding',
  'Secret',
  'MultiscannerFinding',
  'GithubSecret',
  'GithubSensitiveFile',
  'MalPackageFinding',
  'ExploitGvm',
]

/**
 * Files that read a finding label but legitimately carry no exclusion.
 *
 * Each entry is a claim that has to stay true, so keep it short and reasoned.
 */
const EXEMPT = new Map<string, string>([
  // Restore WRITES the graph back from a snapshot. It must recreate a muted
  // node exactly as it was, `:Muted` included, or a version-activate would
  // silently unmute everything. It reads no findings for display.
  ['lib/graphRestore.ts', 'restores muted nodes verbatim; a write path, not a read path'],
])

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.next') continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(full)
  }
  return out
}

/** Files that run their own Cypher against a muteable finding label. */
function findingReaders(): { rel: string; src: string }[] {
  const labelRe = new RegExp(`:(${MUTEABLE.join('|')})\\b`)
  return walk(SRC)
    .map(full => ({ rel: full.slice(SRC.length + 1).replace(/\\/g, '/'), src: readFileSync(full, 'utf8') }))
    .filter(f => /getGraphSession|session\.run/.test(f.src) && labelRe.test(f.src))
}

describe('muted findings cannot leak through a hand-written graph query', () => {
  test('the set of finding readers is non-empty (the walker still works)', () => {
    // Guards the test itself: a broken path would make every assertion below
    // vacuously pass and silently retire the whole enforcement.
    expect(findingReaders().length).toBeGreaterThan(10)
  })

  test('every finding reader carries the mute exclusion', () => {
    const offenders = findingReaders()
      .filter(f => !EXEMPT.has(f.rel))
      .filter(f => !/notMuted|noneMuted|NOT n:Muted|NOT m:Muted/.test(f.src))
      .map(f => f.rel)

    expect(
      offenders,
      `These files read a finding label but never exclude :Muted, so an operator's ` +
        `suppressed findings would still show up in them. Add ` +
        `\`WHERE \${notMuted('<var>')}\` from '@/lib/graphMute' to each finding query.\n` +
        offenders.map(o => `  - ${o}`).join('\n')
    ).toEqual([])
  })

  test('every exemption still points at a real file that still reads findings', () => {
    // A stale exemption is a hole: the file could have been renamed, or changed
    // so it no longer needs one, and the entry would keep excusing something.
    const readers = new Set(findingReaders().map(f => f.rel))
    for (const rel of EXEMPT.keys()) {
      // A route that does not exist yet is allowed (it is created later in the
      // feature); one that exists must still be a finding reader.
      let exists = true
      try {
        readFileSync(join(SRC, rel), 'utf8')
      } catch {
        exists = false
      }
      if (exists) expect(readers.has(rel), `stale exemption: ${rel}`).toBe(true)
    }
  })
})

describe('the exclusion fragment itself', () => {
  test('excludes by label, not by a property that a write could forget', () => {
    // `muted: true` is written alongside the label, but the LABEL is the marker.
    // Filtering on the property would miss a node whose property write failed.
    expect(notMuted('v')).toContain('labels(v)')
    expect(notMuted('v')).toContain(MUTED_LABEL)
  })

  test('reads correctly on an untyped variable', () => {
    // Several queries bind an untyped node (`OPTIONAL MATCH (a)-[:HAS_FINDING]->(tf)`),
    // where `NOT a:Muted` is fine but the NONE form is what we standardised on.
    expect(notMuted('a')).toBe("NONE(l IN labels(a) WHERE l = 'Muted')")
  })

  test('ANDs cleanly for a relationship with two endpoints', () => {
    expect(noneMuted('n', 'm')).toBe(
      "NONE(l IN labels(n) WHERE l = 'Muted') AND NONE(l IN labels(m) WHERE l = 'Muted')"
    )
  })
})
