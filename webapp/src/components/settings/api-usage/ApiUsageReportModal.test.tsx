/**
 * The report modal and the header controls, rendered from a hand-built
 * controller: sections and counts, meter wording, error rows, the stale and
 * not-saved banners, the running view, and the rendering rules for values this
 * build does not know or must not trust (unknown kinds, non-https links, markup
 * in provider strings).
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { ApiUsageReportModal } from './ApiUsageReportModal'
import { ApiUsageControls } from './ApiUsageControls'
import type { ApiUsageController } from './useApiUsageReport'
import type { ApiUsageReportV1, KeyResult, Meter } from '@/lib/apiUsage/types'

afterEach(cleanup)

const meter = (over: Partial<Meter>): Meter => ({
  id: 'm', label: 'Query credits', unit: 'credits', window: 'month', used: 16, limit: 100, remaining: 84,
  resetsAt: '2026-10-01T00:00:00.000Z', resetsAtSource: 'computed', primary: true, ...over,
})

const row = (over: Partial<KeyResult>): KeyResult => ({
  serviceId: 'shodan', serviceLabel: 'Shodan', group: 'keys', field: 'shodanApiKey', keyRole: 'primary', keyIndex: 0,
  keyHint: '••••••••a1b2', outcome: 'usage', health: 'ok', meters: [meter({})], costNote: 'Free: no credits spent',
  dashboardUrl: 'https://account.shodan.io/', docsUrl: 'https://developer.shodan.io/api', endpoint: 'GET api.shodan.io/api-info',
  checkedAt: '2026-09-26T14:32:01.000Z', latencyMs: 120, ...over,
})

function makeReport(results: KeyResult[], over: Partial<ApiUsageReportV1> = {}): ApiUsageReportV1 {
  const count = (o: string) => results.filter(r => r.outcome === o).length
  return {
    schemaVersion: 1, startedAt: '2026-09-26T14:32:00.000Z', finishedAt: '2026-09-26T14:32:05.000Z', durationMs: 4200,
    counts: {
      services: new Set(results.map(r => r.serviceId)).size, keys: results.length, usage: count('usage'),
      validNoUsage: count('valid_no_usage'), notChecked: count('not_checked'), errors: count('error'), low: 0, exhausted: 0,
    },
    skippedEmpty: [{ field: 'tavilyApiKey', label: 'Tavily' }, { field: 'serpApiKey', label: 'SerpAPI' }],
    inventory: {},
    results,
    ...over,
  }
}

function controller(over: Partial<ApiUsageController> = {}): ApiUsageController {
  const report = makeReport([row({})])
  return {
    meta: { enabled: true, report, running: null, runBy: null, activity: null, tracked: [] },
    summary: { keys: 3, services: [{ id: 'shodan', label: 'Shodan' }, { id: 'tavily', label: 'Tavily' }] },
    stale: false,
    view: 'report',
    shown: { report, saved: true },
    running: false,
    runStartedAt: null,
    startCheck: vi.fn(async () => {}),
    openReport: vi.fn(),
    close: vi.fn(),
    refresh: vi.fn(async () => null),
    ...over,
  } as ApiUsageController
}

describe('ApiUsageReportModal: report view', () => {
  test('sections run errors first, each with its count; chips mirror the counts', () => {
    const results = [
      row({}),
      row({ serviceId: 'nvd', serviceLabel: 'NVD', field: 'nvdApiKey', outcome: 'valid_no_usage', health: undefined, meters: [] }),
      row({ serviceId: 'hunterhow', serviceLabel: 'hunter.how', field: 'hunterHowApiKey', outcome: 'not_checked', health: undefined, meters: [], notCheckedReason: 'costs_credits' }),
      row({ serviceId: 'netlas', serviceLabel: 'Netlas', field: 'netlasApiKey', outcome: 'error', health: undefined, meters: [], error: { kind: 'timeout', message: 'timed out after 10 s' } }),
    ]
    const report = makeReport(results)
    render(<ApiUsageReportModal controller={controller({ shown: { report, saved: true } })} />)
    const titles = screen.getAllByRole('heading', { level: 3 }).map(h => h.textContent)
    expect(titles).toEqual(['Errors (1)', 'Usage reported (1)', 'Valid, no usage API (1)', 'Not checked (1)'])
    // Singular for one: "1 error", never "1 errors".
    expect(screen.getByRole('button', { name: /^\s*1 error\s*$/ })).toBeInTheDocument()
    expect(screen.getByText('Checking would spend credits')).toBeInTheDocument()
  })

  test('the header line has the date, the key count and the duration', () => {
    render(<ApiUsageReportModal controller={controller()} />)
    const summary = screen.getByText(/^Checked /)
    expect(summary.textContent).toMatch(/2026/)
    expect(summary.textContent).toMatch(/1 key/)
    expect(summary.textContent).toMatch(/4\.2 s/)
  })

  test('meter wording: left of limit, unlimited, not in plan, not reported; a progressbar with aria values', () => {
    const r = row({ meters: [
      meter({ id: 'a', label: 'Credits A' }),
      meter({ id: 'b', label: 'Credits B', limit: null, remaining: null, used: null, note: 'unlimited' }),
      meter({ id: 'c', label: 'Credits C', limit: 0, remaining: 0, used: 0 }),
      meter({ id: 'd', label: 'Credits D', limit: null, remaining: null, used: null }),
      meter({ id: 'e', label: 'Credits E', limit: 20000000, remaining: null, used: null }),
    ] })
    render(<ApiUsageReportModal controller={controller({ shown: { report: makeReport([r]), saved: true } })} />)
    expect(screen.getByText(/84 \/ 100 credits left/)).toBeInTheDocument()
    expect(screen.getAllByText(/unlimited/).length).toBeGreaterThan(0)
    expect(screen.getByText(/not in plan/)).toBeInTheDocument()
    expect(screen.getByText(/not reported/)).toBeInTheDocument()
    expect(screen.getByText(/cap 20,000,000 credits/)).toBeInTheDocument()
    const bar = screen.getByRole('progressbar', { name: /Credits A/ })
    expect(bar).toHaveAttribute('aria-valuenow', '84')
    expect(bar).toHaveAttribute('aria-valuemax', '100')
  })

  test('secondary meters sit behind "show more"', () => {
    const r = row({ meters: [meter({}), meter({ id: 's', label: 'Search (minute)', window: 'minute', primary: false })] })
    render(<ApiUsageReportModal controller={controller({ shown: { report: makeReport([r]), saved: true } })} />)
    expect(screen.queryByText('Search (minute)')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Show 1 more meter/ }))
    expect(screen.getByText('Search (minute)')).toBeInTheDocument()
  })

  test('an error row shows the kind in words, HTTP status and code, the message and an action', () => {
    const r = row({ outcome: 'error', health: undefined, meters: [], keyRole: 'rotation', keyIndex: 2, keyHint: '••••••••9f3c',
      error: { kind: 'invalid_key', httpStatus: 401, providerCode: '-700', message: 'Account invalid' } })
    render(<ApiUsageReportModal controller={controller({ shown: { report: makeReport([r]), saved: true } })} />)
    const errors = screen.getByRole('region', { name: 'Errors' })
    expect(within(errors).getAllByText('Key rejected').length).toBeGreaterThan(0)
    expect(within(errors).getByText(/HTTP 401 · code -700/)).toBeInTheDocument()
    expect(within(errors).getByText('Account invalid')).toBeInTheDocument()
    expect(within(errors).getByText('Re-enter the key or remove it')).toBeInTheDocument()
    expect(within(errors).getByText('rotation #2')).toBeInTheDocument()
    expect(within(errors).getByText('••••••••9f3c')).toBeInTheDocument()
  })

  test('values this build does not know render as "unknown", not a crash', () => {
    const r = row({ outcome: 'error', health: undefined, meters: [], error: { kind: 'brand_new_kind' as never, message: 'x' } })
    const odd = row({ serviceId: 'odd', field: 'oddKey', outcome: 'mystery' as never, health: undefined, meters: [] })
    render(<ApiUsageReportModal controller={controller({ shown: { report: makeReport([r, odd]), saved: true } })} />)
    expect(screen.getAllByText('Unknown error').length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { name: 'Other (1)' })).toBeInTheDocument()
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  test('provider strings are text; only https dashboard links render', () => {
    const r = row({ account: { plan: '<img src=x onerror=alert(1)>' }, dashboardUrl: 'javascript:alert(1)' })
    const ok = row({ serviceId: 'tavily', field: 'tavilyApiKey', serviceLabel: 'Tavily' })
    const { container } = render(<ApiUsageReportModal controller={controller({ shown: { report: makeReport([r, ok]), saved: true } })} />)
    expect(document.body.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    const links = [...document.body.querySelectorAll('a')].map(a => a.getAttribute('href'))
    expect(links).toEqual(['https://account.shodan.io/'])
    expect(container).toBeTruthy()
  })

  test('the stale banner offers a new check', () => {
    const c = controller({ stale: true })
    render(<ApiUsageReportModal controller={c} />)
    expect(screen.getByText('Your keys changed since this report.')).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('status')).getByRole('button', { name: 'Run new check' }))
    expect(c.startCheck).toHaveBeenCalled()
  })

  test('a run that could not be saved says so, naming the report that stays', () => {
    const report = makeReport([row({})])
    render(<ApiUsageReportModal controller={controller({ shown: { report, saved: false, saveError: 'the database refused the save', previousFinishedAt: '2026-09-25T10:00:00.000Z' } })} />)
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/Not saved: the database refused the save/)
    expect(alert.textContent).toMatch(/2025|2026/)
    expect(alert.textContent).toMatch(/is unchanged/)
  })

  test('"run by" appears for a report an admin ran while acting as the user', () => {
    const report = makeReport([row({})])
    render(<ApiUsageReportModal controller={controller({
      meta: { enabled: true, report, running: null, runBy: { id: 'a1', name: 'Ada Admin' }, activity: null, tracked: [] },
      shown: { report, saved: true },
    })} />)
    expect(screen.getByText('Run by Ada Admin while acting as you')).toBeInTheDocument()
  })

  test('empty fields are listed behind a disclosure', () => {
    render(<ApiUsageReportModal controller={controller()} />)
    expect(screen.getByText(/Empty, skipped: 2 fields/)).toBeInTheDocument()
  })
})

describe('ApiUsageReportModal: running view', () => {
  test('lists the services about to be checked', () => {
    render(<ApiUsageReportModal controller={controller({ view: 'running', running: true, runStartedAt: new Date().toISOString() })} />)
    expect(screen.getByText(/Checking 2 services/)).toBeInTheDocument()
    expect(screen.getByText('Tavily')).toBeInTheDocument()
    expect(screen.getByText(/does not stop the check/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Run new check/ })).toBeDisabled()
  })

  test('closed renders nothing', () => {
    render(<ApiUsageReportModal controller={controller({ view: 'closed' })} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})

describe('ApiUsageControls', () => {
  test('label with the key count, and "Last report" with its date', () => {
    const c = controller()
    render(<ApiUsageControls controller={c} buttonClassName="btn" />)
    fireEvent.click(screen.getByRole('button', { name: /Check API usage \(3 keys\)/ }))
    expect(c.startCheck).toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /Last report · .*2026/ }))
    expect(c.openReport).toHaveBeenCalled()
  })

  test('disabled on this host: the reason is in the tooltip and clicking does nothing', () => {
    const c = controller({ meta: { enabled: false, report: null, running: null, runBy: null, activity: null, tracked: [] } })
    render(<ApiUsageControls controller={c} buttonClassName="btn" />)
    const btn = screen.getByRole('button', { name: /Check API usage/ })
    expect(btn).toHaveAttribute('aria-disabled', 'true')
    expect(btn.getAttribute('title')).toMatch(/API_USAGE_CHECK_ENABLED=false/)
    fireEvent.click(btn)
    expect(c.startCheck).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: /Last report/ })).not.toBeInTheDocument()
  })

  test('no key saved: disabled with its reason', () => {
    const c = controller({ summary: { keys: 0, services: [] } })
    render(<ApiUsageControls controller={c} buttonClassName="btn" />)
    expect(screen.getByRole('button', { name: /Check API usage \(0 keys\)/ }).getAttribute('title')).toBe('No key is saved')
  })

  test('a run in progress: "Checking… since", and a click follows it instead of starting another', () => {
    const c = controller({ running: true, runStartedAt: '2026-09-26T14:32:00.000Z' })
    render(<ApiUsageControls controller={c} buttonClassName="btn" />)
    const btn = screen.getByRole('button', { name: /Checking… since/ })
    fireEvent.click(btn)
    expect(c.openReport).toHaveBeenCalled()
    expect(c.startCheck).not.toHaveBeenCalled()
  })
})

describe('ApiUsageReportModal: spent by collaborators (step 5.6)', () => {
  const base = controller()
  const withSpends = (spends: NonNullable<ApiUsageController['meta']>['collaboratorSpends']) =>
    controller({ meta: { ...base.meta!, collaboratorSpends: spends } })

  test('usage report breakdown: each collaborator with their uses by feature and project', () => {
    render(<ApiUsageReportModal controller={withSpends({
      sinceDays: 30, truncated: false,
      people: [{
        userId: 'c1', name: 'Bob', email: 'bob@example.test', total: 3, byFeature: { agent_session: 2, scan: 1 },
        projects: [{ id: 'P1', name: 'Acme', count: 3 }], lastAt: '2026-09-26T14:32:00.000Z',
      }],
    })} />)
    const section = screen.getByRole('region', { name: 'Spent by collaborators' })
    expect(within(section).getByRole('heading', { level: 3 }).textContent).toBe('Spent by collaborators, last 30 days (1)')
    expect(within(section).getByText('Bob')).toBeInTheDocument()
    expect(within(section).getByText('3 uses')).toBeInTheDocument()
    expect(within(section).getByText('agent sessions 2 · scans 1')).toBeInTheDocument()
    expect(within(section).getByText(/Acme \(3\)/)).toBeInTheDocument()
  })

  test('no breakdown in the answer (write sharing off), or nobody spent: no section', () => {
    render(<ApiUsageReportModal controller={base} />)
    expect(screen.queryByRole('region', { name: 'Spent by collaborators' })).not.toBeInTheDocument()
    cleanup()
    render(<ApiUsageReportModal controller={withSpends({ sinceDays: 30, truncated: false, people: [] })} />)
    expect(screen.queryByRole('region', { name: 'Spent by collaborators' })).not.toBeInTheDocument()
  })

  test('a name is text, never markup; a deleted account and a capped count say so', () => {
    render(<ApiUsageReportModal controller={withSpends({
      sinceDays: 30, truncated: true,
      people: [
        { userId: 'c2', name: '<img src=x onerror=alert(1)>', email: null, total: 1, byFeature: {}, projects: [], lastAt: '2026-09-26T14:32:00.000Z' },
        { userId: 'c3', name: null, email: null, total: 1, byFeature: { later_feature: 1 } as never, projects: [], lastAt: '2026-09-26T14:32:00.000Z' },
      ],
    })} />)
    const section = screen.getByRole('region', { name: 'Spent by collaborators' })
    expect(within(section).getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(section.querySelector('img')).toBeNull()
    expect(within(section).getByText('A deleted account')).toBeInTheDocument()
    expect(within(section).getByText('later_feature 1')).toBeInTheDocument()
    expect(within(section).getByText(/Only the most recent uses were counted/)).toBeInTheDocument()
  })
})
