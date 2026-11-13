/**
 * Only the files below may name the stored `domainBatchGroups` record (§4.3).
 *
 * The scope every service reads is the scope groups derived from
 * domainBatchHosts on each read. The stored record is the legacy shape kept for
 * readers that have not moved and for a rollback; a new reader of it would read
 * a grouping that can disagree with the derived one (a row written before the
 * Public Suffix List regroup still says `co.uk`). So a new file naming it fails
 * here, and has to argue its way onto the list.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync, readdirSync, statSync } from 'fs'
import { join, relative } from 'path'

const REPO = join(process.cwd(), '..')

const ALLOWED: Record<string, string> = {
  // writers: each stores the record computed from the derived groups
  'webapp/src/app/api/projects/route.ts': 'writer (create)',
  'webapp/src/app/api/projects/[id]/route.ts': 'writer (update); never trusts a body value',
  'webapp/src/lib/importScope.ts': 'writer (import); re-derives from the hosts',
  'webapp/src/lib/mcp/engagementTools.ts': 'writer (MCP create_project)',
  'webapp/src/lib/mcp/scopeTools.ts': 'writer (MCP update_project_scope)',
  'webapp/src/lib/domainBatch.ts': 'defines the record (toLegacyRecord)',
  // legacy fallbacks: used only when a read carries no host list
  'webapp/src/lib/partialReconScope.ts': 'legacy fallback',
  'webapp/src/lib/openapiSourceStatus.ts': 'legacy fallback',
  'webapp/src/lib/report/reportTemplate.ts': 'legacy fallback (a row read without its host list)',
  // documentation of the model, in comments
  'webapp/src/lib/scopeGroups.ts': 'comment',
  'webapp/src/lib/projectSummary.ts': 'comment',
  // the Python normalisers' legacy branch, for a webapp that sends no scopeGroups
  'recon/project_settings.py': 'legacy fallback (REC-01)',
  'recon_orchestrator/batch_scope.py': 'legacy fallback (ORC-01)',
  'agentic/project_settings.py': 'legacy fallback (AGT-01)',
  'agentic/scope_groups.py': 'legacy fallback (AGT-01)',
  // the settings registry tooling names every Project column
  'tooling/scripts/extract_recon_registry.py': 'registry tooling',
}

/**
 * Files that may name the record only on lines of one shape, so a read added elsewhere in them
 * still fails. settingsRisk.ts (step 5.1a) classes the column's change risk by name, in its
 * OWN_DIRECTIONS map; it never reads the stored value.
 */
const NAMED_ONLY_AS: Record<string, RegExp> = {
  'webapp/src/lib/authz/settingsRisk.ts': /^\s*domainBatchGroups: '[a-z]+',$/,
}

const ROOTS: [string, RegExp][] = [
  ['webapp/src', /\.(ts|tsx)$/],
  ['recon', /\.py$/],
  ['recon_orchestrator', /\.py$/],
  ['agentic', /\.py$/],
  ['graph_db', /\.py$/],
  ['scanners', /\.py$/],
  ['mcp', /\.py$/],
  ['tooling', /\.py$/],
]

const SKIP_DIR = new Set(['node_modules', '__pycache__', 'tests', '.next', 'output', 'data'])
const isTest = (name: string) => /\.test\.tsx?$/.test(name) || /^test_.*\.py$/.test(name) || name === 'conftest.py'

function* walk(dir: string, ext: RegExp): Generator<string> {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) {
      if (!SKIP_DIR.has(name)) yield* walk(full, ext)
    } else if (ext.test(name) && !isTest(name)) {
      yield full
    }
  }
}

// Run from webapp/ in the repo; a copy of webapp/ alone has nothing to sweep.
describe.skipIf(!existsSync(join(REPO, 'webapp', 'src')))('domainBatchGroups readers (§4.3)', () => {
  test('no file outside the allowlist names the stored record', () => {
    const offenders: string[] = []
    for (const [root, ext] of ROOTS) {
      const dir = join(REPO, root)
      if (!existsSync(dir)) continue
      for (const file of walk(dir, ext)) {
        const rel = relative(REPO, file)
        if (rel in ALLOWED) continue
        const text = readFileSync(file, 'utf8')
        if (!text.includes('domainBatchGroups')) continue
        const shape = NAMED_ONLY_AS[rel]
        if (!shape) {
          offenders.push(rel)
          continue
        }
        for (const [i, line] of text.split('\n').entries()) {
          if (line.includes('domainBatchGroups') && !shape.test(line)) offenders.push(`${rel}:${i + 1}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  test('the sweep reaches the files it guards', () => {
    // A walk that found nothing would pass the test above vacuously.
    expect(existsSync(join(REPO, 'webapp/src/app/api/projects/route.ts'))).toBe(true)
    expect(readFileSync(join(REPO, 'webapp/src/app/api/projects/route.ts'), 'utf8')).toContain('domainBatchGroups')
  })
})
