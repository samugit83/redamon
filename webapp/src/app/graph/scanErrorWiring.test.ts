/**
 * The graph page is where scan, filter and node actions fail in front of the
 * person, and every one of these used to end in nothing, or in a false success:
 * - GVM pause/resume/stop toasted "paused"/"resumed"/"stopped" whatever happened;
 * - recon, GitHub Hunt, Supply-Chain and Secret Multiscanner pause/stop failed
 *   silently (the hooks resolve to null);
 * - Emergency "Pause all" ignored every allSettled result;
 * - the stealth toggle and the agent model picker dropped the server's refusal;
 * - deleting a node read a non-JSON error body as an unhandled SyntaxError;
 * - a saved filter that failed drew the unfiltered graph with no word;
 * - the log drawers never showed a lost stream or a failed status read;
 * - the GVM confirm modal showed whatever the status poll last failed with.
 *
 * Source-level, like otherScansStartWiring.test.ts: rendering /graph needs
 * providers, a router and live scan data, none of which is what is checked.
 * The hooks' own behaviour is covered in hooks/scanStatusHooks.errors.test.tsx.
 *
 * Run: npx vitest run src/app/graph/scanErrorWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const pageSrc = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')

/** The body of one `const <name> = useCallback(...)` handler. */
function handler(name: string): string {
  const start = pageSrc.indexOf(`const ${name} = useCallback(`)
  expect(start, `${name} not found in page.tsx`).toBeGreaterThan(-1)
  const next = pageSrc.indexOf('\n  const ', start + 1)
  return pageSrc.slice(start, next === -1 ? undefined : next)
}

/** Every `<Component ... />` element of one kind, as source text. */
function elements(component: string): string[] {
  const out: string[] = []
  let at = pageSrc.indexOf(`<${component}\n`)
  while (at !== -1) {
    out.push(pageSrc.slice(at, pageSrc.indexOf('/>', at)))
    at = pageSrc.indexOf(`<${component}\n`, at + 1)
  }
  return out
}

describe('GVM pause/resume/stop: no false success (S-4)', () => {
  test.each([
    ['handlePauseGvm', 'pauseGvm', 'GVM scan paused'],
    ['handleResumeGvm', 'resumeGvm', 'GVM scan resumed'],
    ['handleStopGvm', 'stopGvm', 'GVM scan stopped'],
  ])('%s toasts success only when the call succeeded', (name, call, success) => {
    const body = handler(name)
    expect(body).toContain(`reportAction(await ${call}(), getGvmActionError`)
    expect(body).toMatch(new RegExp(`if \\(reportAction\\([^)]*\\)[^)]*\\)\\) toast\\.info\\('${success}'\\)`))
  })

  test('reportAction shows the hook\'s reason (code and status) on failure', () => {
    const body = handler('reportAction')
    expect(body).toContain('toast.error(lastError() ?? fallback)')
  })
})

describe('silent pause/stop failures now reach the person (S-5, P-11, P-12)', () => {
  test.each([
    ['handlePauseGithubHunt', 'getGithubActionError'],
    ['handleResumeGithubHunt', 'getGithubActionError'],
    ['handleStopGithubHunt', 'getGithubActionError'],
    ['handleStopTrufflehog', 'getTrufflehogActionError'],
    ['handlePauseSupplyChain', 'getSupplyActionError'],
    ['handleResumeSupplyChain', 'getSupplyActionError'],
    ['handleStopSupplyChain', 'getSupplyActionError'],
  ])('%s reports a failure with %s', (name, getter) => {
    expect(handler(name)).toContain(`reportAction(await `)
    expect(handler(name)).toContain(getter)
  })

  test('the Supply-Chain card and drawer go through the reporting handlers', () => {
    expect(pageSrc).not.toContain('void pauseSupplyChain()')
    expect(pageSrc).not.toContain('void resumeSupplyChain()')
    expect(pageSrc).not.toContain('void stopSupplyChain()')
  })

  test.each([
    ['handlePauseRecon', "reportReconFailure('Recon did not pause', 'recon')"],
    ['handleStopRecon', "reportReconFailure('Recon did not stop', 'recon')"],
    ['handleStopPartialRecon', "reportReconFailure('Partial recon did not stop', 'partial')"],
  ])('%s reports a null result', (name, call) => {
    expect(handler(name)).toContain(call)
  })

  test('a recon failure is toasted with the hook\'s own error once it lands', () => {
    const effect = pageSrc.slice(pageSrc.indexOf('const [failedReconActions'), pageSrc.indexOf('// The other scan hooks keep'))
    expect(effect).toContain("failed.source === 'recon' ? reconError : partialReconError")
    expect(effect).toContain('toast.error(reason')
  })

  test('a refused resume no longer calls an outage a refusal (P-13)', () => {
    expect(handler('handleResumeRecon')).toContain('Resume failed: ')
    expect(handler('handleResumeRecon')).not.toContain('Resume refused')
  })
})

describe('Emergency "Pause all" (S-21, G-29, P-12)', () => {
  const body = handler('handleEmergencyPauseAll')

  test('every result is inspected and the failures are toasted together', () => {
    expect(body).toContain('await Promise.allSettled(tasks)')
    expect(body).toContain(".filter((f): f is string => !!f)")
    expect(body).toContain("toast.error(failures.join('; '), 'Emergency pause: not everything stopped')")
  })

  test('the agents\' stop is read for its status and reason', () => {
    expect(body).toContain("readApiError(res, 'Failed to stop agents')")
    expect(body).toContain("toApiError(err, 'Failed to stop agents')")
  })

  test('each scan names itself with the hook\'s reason', () => {
    expect(body).toContain("viaHook('GVM scan', pauseGvm(), getGvmActionError)")
    expect(body).toContain("viaHook('GitHub Secret Hunt', pauseGithubHunt(), getGithubActionError)")
    expect(body).toContain('getTrufflehogActionError')
    expect(body).toContain("reportReconFailure('Emergency pause: recon did not pause', 'recon')")
  })
})

describe('project setting changes from the toolbar and drawer (P-21, G-19)', () => {
  // Step 5.2 moved both saves into useProjectFieldSave (one field, sent with the row's version): the
  // server's refusal is read by saveProjectFields (readApiError) and shown, as is a network failure,
  // with each handler's own fallback (behaviour: src/hooks/useProjectFieldSave.test.tsx).
  const hookSrc = readFileSync(join(process.cwd(), 'src/hooks/useProjectFieldSave.ts'), 'utf8')
  const saveSrc = readFileSync(join(process.cwd(), 'src/lib/projectFieldSave.ts'), 'utf8')
  test.each([
    ['handleToggleStealth', 'stealthMode', 'Could not change Stealth Mode'],
    ['handleModelChange', 'agentOpenaiModel', 'Could not change the agent model'],
  ])('%s shows the server\'s refusal and a network failure', (name, field, fallback) => {
    const body = handler(name)
    expect(body).toContain(`saveProjectField('${field}',`)
    expect(body).toContain(`'${fallback}')`)
    expect(saveSrc).toContain('throw await readApiError(res, failure)')
    expect(hookSrc).toContain('toast.error(toApiError(error, failure).message)')
    expect(hookSrc).not.toContain('if (res.ok && currentProject)')
  })
})

describe('delete node (P-38, G-53)', () => {
  const body = handler('handleDeleteNode')
  test('a non-JSON or network failure is read, not thrown', () => {
    expect(body).toContain("alertError((await readApiError(res, 'Failed to delete node')).message)")
    expect(body).toContain("alertError(toApiError(err, 'Failed to delete node').message)")
    expect(body).not.toContain('await res.json()')
  })
})

describe('saved filter that fails (G-25)', () => {
  test('the execute error is toasted, once per filter and reason', () => {
    const effect = pageSrc.slice(pageSrc.indexOf('executeCypher(selectedFilterCypherQuery)'))
    const branch = effect.slice(0, effect.indexOf('} else {'))
    expect(branch).toContain("toast.error(result.error, 'Data filter failed: showing the unfiltered graph')")
    expect(branch).toContain('filterErrorShownRef.current !== key')
  })
})

describe('log drawers (S-17, P-16) and status reads (S-7)', () => {
  test('every logs drawer gets the stream and status errors', () => {
    const drawers = elements('ReconLogsDrawer')
    expect(drawers.length).toBe(6)
    for (const d of drawers) {
      expect(d).toContain('streamError=')
      expect(d).toContain('statusError=')
    }
  })

  test('the toolbar gets each scan\'s status error and the GVM availability reason', () => {
    const [toolbar] = elements('GraphToolbar')
    expect(toolbar).toContain('scanStatusErrors={[gvmStatusError, githubHuntStatusError, trufflehogStatusError, supplyChainStatusError]}')
    expect(toolbar).toContain('gvmUnavailableReason={gvmAvailability.reason}')
  })

  test('Other Scans gets the source-list error and each run\'s reason (S-13, S-22)', () => {
    const [modal] = elements('OtherScansModal')
    for (const prop of ['trufflehogProfilesError=', 'githubHuntError=', 'supplyChainError=', 'githubHuntStatusError=',
      'trufflehogStatusError=', 'supplyChainStatusError=']) {
      expect(modal).toContain(prop)
    }
  })

  test('a scan seen live that ends in error is toasted (S-13)', () => {
    expect(pageSrc).toContain('const message = scanFailureToast(label, seen[key], status, error)')
  })
})

describe('recon JSON download and the version list', () => {
  test('the download is fetched, so a refusal is shown instead of a raw tab', () => {
    const body = handler('handleDownloadJSON')
    expect(body).toContain("downloadScanFile(`/api/recon/${projectId}/download`, `recon_${projectId}.json`)")
    expect(body).toContain("toast.error(error, 'Recon JSON not downloaded')")
    expect(body).not.toContain('window.open')
  })

  test('a failed version list is toasted once per reason', () => {
    const block = pageSrc.slice(pageSrc.indexOf('const scanVersionsErrorText'), pageSrc.indexOf('const viewedVersion'))
    expect(block).toContain("toast.error(scanVersionsErrorText, 'Scan versions unavailable')")
    expect(block).toContain('scanVersionsErrorShownRef.current !== scanVersionsErrorText')
  })
})

describe('Active Sessions panel (G-15)', () => {
  test('gets the sessions hook error, so an agent outage is not an empty list', () => {
    const [panel] = elements('ActiveSessions')
    expect(panel).toContain('error={activeSessions.error}')
  })
})

describe('GVM confirm modal (S-18)', () => {
  test('shows only this opening\'s start error, never a status poll failure', () => {
    const [modal] = elements('GvmConfirmModal')
    expect(modal).toContain('error={gvmConfirmAttempted ? gvmStartError : null}')
    expect(handler('handleStartGvm')).toContain('setGvmConfirmAttempted(false)')
    expect(handler('handleConfirmGvm')).toContain('setGvmConfirmAttempted(true)')
  })
})

describe('a filter deleted from the toolbar (G-26)', () => {
  test("toasts the graph-view hook's error, which nothing else on this page shows", () => {
    expect(pageSrc).toContain('actionError: graphViewActionError } = useGraphViews(projectId)')
    expect(pageSrc).toContain("useErrorToast(graphViewFailure, 'Filter not changed')")
  })
})
