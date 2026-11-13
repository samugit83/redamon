/**
 * P7: the two derivations of `roeEnabled` agree, and nobody reads the column.
 *
 * The rule lives in `recon_settings/engagement.py` for recon, the agent and the
 * orchestrator, and in `deriveRoeEnabled` here for the webapp. The webapp cannot
 * import Python, so the copy is unavoidable; what is avoidable is the two
 * copies disagreeing, which is the exact two-sources-of-truth failure the
 * derivation exists to end.
 *
 * So both read one fixture table. `recon_settings/tests/test_engagement_derivation.py`
 * asserts the same rows against the Python implementation. Adding a row here
 * tests both languages; changing one implementation without the other fails on
 * one side.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync, statSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { deriveRoeEnabled } from './engagement'

import fixtures from './engagement.derivation.fixtures.json'

interface Case {
  name: string
  row: Record<string, unknown>
  enabled: boolean
}

const CASES = fixtures.cases as Case[]

describe('the TypeScript derivation matches the shared fixture table', () => {
  test('the table is a real set, not an empty one', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(12)
  })

  for (const c of CASES) {
    test(c.name, () => {
      expect(deriveRoeEnabled(c.row as never)).toBe(c.enabled)
    })
  }
})

// --- P7's other half: no service reads the column ----------------------------------

const SRC = fileURLToPath(new URL('..', import.meta.url))

/**
 * Files that may legitimately name the column.
 *
 * The derivation itself, and the three paths that name the column in order to
 * NOT use it: import ignores it, export omits it, and preflight reports the
 * disagreement between it and the derived answer. Everything else reading it is
 * the defect.
 */
const ALLOWED = new Set([
  'lib/engagement.ts',
  // Everything below names the column in order to NOT use it, and each one is
  // asserted positively by the write-path describe above - so removing the drop
  // fails there rather than silently passing here.
  //
  //   import   ignores a `roeEnabled` carried by an older bundle
  //   export   omits it from a new one
  //   PUT      strips it from a whole-row body
  //   POST     lists it as non-settable at creation
  //   the form keeps it out of formData, which is what the form submits
  //
  // preflight is the one exception that genuinely READS it: it compares stored
  // against derived precisely so it can report that a project's limits changed
  // without anyone touching them.
  'app/api/projects/import/route.ts',
  'app/api/projects/[id]/export/route.ts',
  'app/api/projects/[id]/route.ts',
  'app/api/projects/route.ts',
  'components/projects/ProjectForm/ProjectForm.tsx',
  'lib/mcp/engagementTools.ts',
])

/**
 * Files that may name the column only on lines of one shape, so a read added elsewhere in them
 * still fails. settingsRisk.ts (step 5.1a) classes the column's change risk by name, in its
 * OWN_DIRECTIONS map; it never reads the stored value.
 */
const NAMED_ONLY_AS: Record<string, RegExp> = {
  'lib/authz/settingsRisk.ts': /^\s*roeEnabled: '[a-z]+',$/,
}

/**
 * Tests are out of scope, deliberately.
 *
 * A test that names the column is usually ASSERTING it is refused, absent from
 * a preset or ignored on import - which is the property this guard exists to
 * protect, not a violation of it. What matters is that no shipped code path
 * reads it.
 */
function isTest(rel: string): boolean {
  return /\.test\.(ts|tsx)$/.test(rel) || rel.includes('/__tests__/')
}

/** Comments may name the column: explaining the derivation is the point. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
}

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next') continue
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) {
      sourceFiles(full, out)
      continue
    }
    if (/\.(ts|tsx)$/.test(name)) out.push(full)
  }
  return out
}

/**
 * The half the read-sweep above does NOT cover.
 *
 * A file can name the column in order to DROP it and still be correct, which is
 * why three of them are on the allow list. But "nothing writes it" is a separate
 * claim, and it was false in three places after the read sweep was already
 * green: the form loaded the column from the project row and submitted it back,
 * the project PUT route spread the whole body into `prisma.project.update`, and
 * the create route's NON_SETTABLE list did not name it.
 *
 * None of those READ the value. They persisted it, which leaves a stored number
 * that disagrees with the derivation - the exact two-sources-of-truth state the
 * derivation removes. So the write paths are asserted by name.
 */
describe('nothing in the webapp writes the roeEnabled column', () => {
  const read = (rel: string) => readFileSync(path.join(SRC, rel), 'utf8')

  test('the project form never lets it into formData', () => {
    const form = read('components/projects/ProjectForm/ProjectForm.tsx')
    // The form SUBMITS formData wholesale, so keeping it out of formData is
    // what keeps it out of the write.
    expect(form).toMatch(/function withoutDerived/)
    expect(form).toMatch(/withoutDerived\(initialData/)
    expect(form).toMatch(/loaded = withoutDerived\(/)
  })

  test('the project PUT route drops it from the body', () => {
    const route = read('app/api/projects/[id]/route.ts')
    expect(route).toMatch(/roeEnabled: _roeEnabledDerived/)
  })

  test('the project CREATE route refuses it as non-settable', () => {
    const route = read('app/api/projects/route.ts')
    const block = route.slice(route.indexOf('const NON_SETTABLE'), route.indexOf('const NON_SETTABLE') + 400)
    expect(block).toMatch(/'roeEnabled'/)
  })

  test('the export bundle omits it and the import bundle ignores it', () => {
    expect(read('app/api/projects/[id]/export/route.ts')).toMatch(/roeEnabled: _roeEnabledDerived/)
    expect(read('app/api/projects/import/route.ts')).toMatch(/roeEnabled: _roeEnabledLegacy/)
  })
})

describe('nothing in the webapp reads the roeEnabled column', () => {
  test('every reader is the derivation or a deliberate exception', () => {
    const offenders: string[] = []
    for (const file of sourceFiles(SRC)) {
      const rel = path.relative(SRC, file).split(path.sep).join('/')
      if (ALLOWED.has(rel) || isTest(rel)) continue
      for (const [i, line] of stripComments(readFileSync(file, 'utf8')).split('\n').entries()) {
        if (!/\broeEnabled\b/.test(line)) continue
        if (NAMED_ONLY_AS[rel]?.test(line)) continue
        offenders.push(`${rel}:${i + 1}: ${line.trim()}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
