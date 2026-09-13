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
const BUTTON = readFileSync(
  join(__dirname, '..', '..', '..', '..', 'components', 'triage', 'TriageRunButton.tsx'),
  'utf8'
)
const CYPHERFIX_EMPTY = readFileSync(
  join(__dirname, '..', 'CypherFixTab', 'EmptyState', 'EmptyState.tsx'), 'utf8'
)
const CYPHERFIX_DASH = readFileSync(
  join(__dirname, '..', 'CypherFixTab', 'RemediationDashboard',
       'RemediationDashboard.tsx'), 'utf8'
)

describe('the Triage tab can actually launch a run', () => {
  test('the button is not gated behind a caller-supplied prop', () => {
    // The original defect: `{onRunTriage && (<button>Run …</button>)}` with no
    // caller passing onRunTriage.
    expect(SRC).toContain('TriageRunButton')
    expect(SRC).not.toMatch(/onRunTriage\s*&&/)
    expect(SRC).not.toMatch(/onRunTriage\?:/)
  })

  test('the button is wired to a launch handler, not left inert', () => {
    expect(SRC).toMatch(/onConfirm=\{runTriage\}/)
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

describe('one button, in all three places', () => {
  // There used to be three buttons sending the same message under two different
  // names, and only one of them asked for confirmation. An operator could press
  // one, see the other page change, and have no idea the two were connected.
  test('every entry point renders the same component', () => {
    for (const [name, src] of Object.entries({
      'Priority Board': SRC,
      'CypherFix empty state': CYPHERFIX_EMPTY,
      'CypherFix dashboard': CYPHERFIX_DASH,
    })) {
      expect(src, name).toContain('TriageRunButton')
    }
  })

  test('the old labels are gone from every entry point', () => {
    for (const src of [SRC, CYPHERFIX_EMPTY, CYPHERFIX_DASH]) {
      expect(src).not.toContain('Rank Findings')
      expect(src).not.toContain('Start Vulnerability Triage')
    }
  })

  test('no entry point starts a run without going through the dialog', () => {
    for (const src of [CYPHERFIX_EMPTY, CYPHERFIX_DASH]) {
      expect(src).not.toMatch(/onClick=\{onStartTriage\}/)
    }
  })

  test('the dialog is fetched from preflight, so it carries real numbers', () => {
    expect(BUTTON).toContain('/api/triage/preflight')
    expect(BUTTON).toMatch(/if \(ok\) onConfirm\(\)/)
  })

  test('Cancel sends nothing', () => {
    // `onConfirm` is called only inside the `if (ok)`, so a dismissed dialog
    // cannot start a run.
    const confirmCalls = BUTTON.match(/onConfirm\(\)/g) ?? []
    expect(confirmCalls).toHaveLength(1)
  })

  test('a blocked project is refused before the dialog is even shown', () => {
    expect(BUTTON).toMatch(/if \(pre\.blockedReason\)/)
  })

  test('the no-key case still offers the run, math-only', () => {
    // The button stays enabled: the ranking does not need a model, and
    // disabling it here would hide the whole feature from a project with no key.
    expect(BUTTON).toContain('hasModelKey')
    expect(BUTTON).toContain('ranked by the score alone')
  })
})

describe('the board reloads on every terminal state', () => {
  test('completion, error and stop all reload', () => {
    // R8: the error path used to leave the previous order on screen with no
    // hint that it was stale, and a stopped run may have published part of its
    // result before it stopped.
    expect(SRC).toMatch(/\['error', 'stopped', 'completed'\]/)
  })

  test('a mute that matched nothing reloads instead of silently failing', () => {
    // X13: a rescan or an activation replaces the node an open tab is holding
    // an id for.
    expect(SRC).toContain('res.status === 409')
  })
})
