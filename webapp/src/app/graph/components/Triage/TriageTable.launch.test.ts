/**
 * Regression: the Triage tab shipped with no way to start a triage run.
 *
 * The "Run triage" button was gated behind an optional `onRunTriage` prop, and
 * page.tsx mounted `<TriageTable projectId=... />` without passing it, so the
 * button never rendered. The tab could show verdicts but not produce them.
 *
 * The fix made the launch self-contained: TriageTable drives the CypherFix
 * triage WebSocket itself. These guard the two ways it could regress -- the
 * button becoming conditional again, or the launch wiring being removed -- by
 * reading the source, because a full render pulls in a live WebSocket hook and
 * the project context, which a source check does not need to prove the wiring
 * exists.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

const SRC = readFileSync(join(__dirname, 'TriageTable.tsx'), 'utf8')
const PAGE = readFileSync(join(__dirname, '..', '..', 'page.tsx'), 'utf8')

describe('the Triage tab can actually launch a run', () => {
  test('the Run triage button is not gated behind a caller-supplied prop', () => {
    // The exact defect: `{onRunTriage && (<button>Run …</button>)}` with no
    // caller passing onRunTriage.
    expect(SRC).toContain('Rank Findings')
    expect(SRC).not.toMatch(/onRunTriage\s*&&/)
    expect(SRC).not.toMatch(/onRunTriage\?:/)
  })

  test('the button is wired to a launch handler, not left inert', () => {
    expect(SRC).toMatch(/onClick=\{\(\)\s*=>\s*void runTriage\(\)\}/)
  })

  test('launch goes through the CypherFix triage WebSocket', () => {
    // Triage IS a run of the CypherFix pipeline; the tab must drive that hook
    // rather than being a dead view of results produced elsewhere.
    expect(SRC).toContain('useCypherFixTriageWS')
    expect(SRC).toContain('triage.startTriage()')
  })

  test('progress is shown while a run is in flight', () => {
    expect(SRC).toContain('TriageProgress')
    expect(SRC).toMatch(/isVisible=\{showProgress\}/)
  })

  test('the table reloads when a run completes', () => {
    // Without this the operator launches triage, it finishes, and the verdicts
    // never appear until a manual refresh.
    expect(SRC).toMatch(/onComplete:\s*\(\)\s*=>\s*\{\s*void load\(\)/)
  })

  test('page.tsx mounts the tab (so the wiring above is reachable)', () => {
    expect(PAGE).toContain('<TriageTable projectId={projectId} />')
  })
})
