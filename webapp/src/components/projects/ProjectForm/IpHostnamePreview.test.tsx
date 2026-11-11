/**
 * The preview under the filters of Record + scan matching (04_ui_spec.md §2,
 * §7, §8): every state of §8, the counts equal to the rule's own answer
 * (evaluatePreview) for the unsaved filters, a DNS refusal shown as the last
 * run's, and paging with a reason chip row and a search box.
 *
 * The fetch is answered by the route's own logic (buildIpHostnamePreview) over a
 * fixed graph, so the component is tested against what the server computes.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/IpHostnamePreview.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'
import { IpHostnamePreview } from './IpHostnamePreview'
import { evaluatePreview } from '@/lib/ipHostnameFilter'
import { type PreviewGraph, type PreviewProjectRow, buildIpHostnamePreview } from '@/lib/ipHostnamePreview'

const ROW: PreviewProjectRow = {
  id: 'p1', userId: 'u1', ipMode: true, ipHostnameMode: 'record_filter',
  ipHostnameInclude: ['*.example.com'], ipHostnameExclude: [], ipHostnameMaxScanned: 100, roeExcludedHosts: [],
}

const n = (name: string, reason = 'record_only', ips = ['203.0.113.10'], sources = ['tlsx_san']) => ({
  name, reason, ips, sources, last_seen: null, kind: 'recorded' as const,
  org: name.split('.').slice(-2).join('.'), evaluatedAt: '2026-11-10T10:00:00Z',
})

let graph: PreviewGraph
const urls: string[] = []

function serve(status = 200) {
  vi.stubGlobal('fetch', vi.fn(async (input: string) => {
    urls.push(input)
    if (status !== 200) {
      return new Response(JSON.stringify({ error: status === 404 ? 'Not found' : 'Failed', code: 'ServiceUnavailable' }),
        { status })
    }
    const u = new URL(input, 'http://x')
    const sp = u.searchParams
    const body = buildIpHostnamePreview(graph, ROW, {
      limit: Number(sp.get('limit') ?? 100),
      cursor: sp.get('cursor'),
      reason: sp.get('reason'),
      q: sp.get('q'),
      policy: sp.has('mode') ? {
        mode: sp.get('mode') as never, include: sp.getAll('include'), exclude: sp.getAll('exclude'),
        maxScanned: Number(sp.get('cap')),
      } : undefined,
    })
    return new Response(JSON.stringify(body), { status: 200 })
  }))
}

beforeEach(() => {
  urls.length = 0
  graph = {
    names: [
      n('app.example.com', 'record_only', ['203.0.113.10'], ['tlsx_san', 'ptr']),
      n('old.example.com', 'record_only', ['203.0.113.10'], ['otx_passive_dns']),
      n('blog.other.test', 'record_only', ['203.0.113.10'], ['shodan_hostnames']),
      n('split.example.com', 'resolves_outside_targets'),
    ],
    sharedEdge: [], attributionFailed: [], attributed: 1, ipCount: 1, lastRunMode: 'record_only',
    legacyNames: 0, seenEdges: 4,
  }
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const props = { mode: 'record_filter' as const, include: ['*.example.com'], exclude: ['old.example.com'], maxScanned: 100 }
const count = () => screen.findByTestId('ip-hostname-preview-count')

describe('the states of §8', () => {
  test('create mode: available after the first scan, nothing fetched', () => {
    serve()
    render(<IpHostnamePreview {...props} />)
    expect(screen.getByText('Available after the first scan in a recording mode.')).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  test('loading: three skeleton rows and the loading line, no counts', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(screen.getByText('Loading names found last run…')).toBeInTheDocument()
    expect(screen.getByTestId('ip-hostname-preview-skeleton').children).toHaveLength(3)
    expect(screen.queryByTestId('ip-hostname-preview-count')).toBeNull()
  })

  test('a failed read: the warning, the cause, and a Retry that reads again; the form is untouched', async () => {
    serve(500)
    render(<IpHostnamePreview projectId="p1" {...props} />)
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Couldn't load the names found last run\. The filters still apply at run time\./)
    expect(alert.textContent).toMatch(/ServiceUnavailable/)
    serve()
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }))
    expect(await count()).toBeInTheDocument()
  })

  test('404 (not the owner): reload the page', async () => {
    serve(404)
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(await screen.findByText("Couldn't find this project's names. Reload the page.")).toBeInTheDocument()
  })

  test('never run in a recording mode (or unknown): run once in Record hostnames', async () => {
    graph = { ...graph, names: [], lastRunMode: null }
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(await screen.findByText(/No names recorded yet\. Run once in Record hostnames \(or higher\)/))
      .toBeInTheDocument()
  })

  test('the last run was IP only: same message', async () => {
    graph = { ...graph, names: [], lastRunMode: 'ip_only' }
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(await screen.findByText(/No names recorded yet/)).toBeInTheDocument()
  })

  test('a legacy graph: run a full scan', async () => {
    graph = { ...graph, names: [], legacyNames: 4, seenEdges: 0, lastRunMode: null }
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(await screen.findByText(
      "This project's graph predates hostname recording. Run a full scan to see names here.")).toBeInTheDocument()
  })

  test('a recording run found nothing', async () => {
    graph = { ...graph, names: [], lastRunMode: 'record_only' }
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect(await screen.findByText('No hostname was found on these IPs.')).toBeInTheDocument()
  })
})

describe('the names', () => {
  test('"would scan N of M" equals the rule for the UNSAVED filters, which the request carries', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    const expected = evaluatePreview(graph.names.map(c => ({ name: c.name, ipsSeen: c.ips, orgDomain: c.org, lastReason: c.reason })), {
      mode: 'record_filter', include: props.include, exclude: props.exclude, cap: 100,
      sharedEdge: new Set(), attributionFailed: new Set(), wildcardZone: new Set(),
      hardBlocked: () => false, roeExcluded: () => false,
    })
    expect((await count()).textContent).toBe(`would scan ${expected.selected.length} of ${graph.names.length}`)
    expect(expected.selected).toEqual(['app.example.com'])
    const url = new URL(urls[0], 'http://x')
    expect(url.pathname).toBe('/api/projects/p1/ip-hostnames')
    expect(url.searchParams.get('mode')).toBe('record_filter')
    expect(url.searchParams.getAll('include')).toEqual(['*.example.com'])
    expect(url.searchParams.getAll('exclude')).toEqual(['old.example.com'])
    expect(url.searchParams.get('cap')).toBe('100')
  })

  test('each row: name, seen on, sources in short form, and the result in words', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    const row = (name: string) => screen.getAllByText(name)[0].closest('tr')!
    expect(row('app.example.com').textContent).toMatch(/203\.0\.113\.10.*cert, ptr.*scan \(DNS checked at run time\)/)
    expect(row('old.example.com').textContent).toMatch(/otx.*matches an exclude entry/)
    expect(row('blog.other.test').textContent).toMatch(/shodan.*matches no include entry/)
  })

  test('a name refused for a DNS reason shows the last run\'s reason', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    const row = screen.getAllByText('split.example.com')[0].closest('tr')!
    expect(row.textContent).toMatch(/last run: points outside your IPs/)
  })

  test('changing the filters asks again and the count follows', async () => {
    serve()
    const { rerender } = render(<IpHostnamePreview projectId="p1" {...props} />)
    expect((await count()).textContent).toBe('would scan 1 of 4')
    rerender(<IpHostnamePreview projectId="p1" {...props} include={['*.example.com', '*.other.test']} exclude={[]} />)
    await waitFor(() => expect(screen.getByTestId('ip-hostname-preview-count').textContent).toBe('would scan 3 of 4'))
  })

  test('narrow layout: Seen on and Sources also sit in an expandable row detail', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    const row = screen.getAllByText('app.example.com')[0].closest('tr')!
    const detail = row.querySelector('details')!
    expect(detail.className).toMatch(/rowDetail/)
    expect(detail.textContent).toMatch(/Seen on203\.0\.113\.10Sourcescert, ptr/)
    expect(row.querySelectorAll('td.wideOnly')).toHaveLength(2)
  })
})

describe('more than one page', () => {
  beforeEach(() => {
    graph = {
      ...graph,
      names: Array.from({ length: 250 }, (_, i) => n(`h${String(i).padStart(3, '0')}.example.com`)),
    }
    graph.names.push(n('a.other.test'))
  })

  test('the pager walks the pages; totals stay exact', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    expect((await count()).textContent).toBe('would scan 100 of 251')
    expect(screen.getByText('Showing 1-100 of 251')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('Showing 101-200 of 251')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
    expect(await screen.findByText('Showing 1-100 of 251')).toBeInTheDocument()
    expect((screen.getByRole('button', { name: 'Previous' }) as HTMLButtonElement).disabled).toBe(true)
  })

  test('a reason chip narrows the rows to that result', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    const chips = screen.getByRole('group', { name: 'Show names by result' })
    fireEvent.click(within(chips).getByRole('button', { name: /matches no include entry \(1\)/ }))
    expect(await screen.findByText('Showing 1-1 of 1')).toBeInTheDocument()
    expect(screen.getAllByText('a.other.test').length).toBeGreaterThan(0)
    expect(within(chips).getByRole('button', { name: /matches no include entry/ }).getAttribute('aria-pressed')).toBe('true')
  })

  test('a filter change starts again from the first page', async () => {
    serve()
    const { rerender } = render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('Showing 101-200 of 251')).toBeInTheDocument()
    rerender(<IpHostnamePreview projectId="p1" {...props} exclude={['h000.example.com']} />)
    await waitFor(() => expect(new URL(urls[urls.length - 1], 'http://x').searchParams.getAll('exclude'))
      .toEqual(['h000.example.com']))
    expect(new URL(urls[urls.length - 1], 'http://x').searchParams.get('cursor')).toBeNull()
    expect(await screen.findByText('Showing 1-100 of 251')).toBeInTheDocument()
  })

  test('a result chip the new answer no longer has is dropped', async () => {
    serve()
    const { rerender } = render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    const chips = screen.getByRole('group', { name: 'Show names by result' })
    fireEvent.click(within(chips).getByRole('button', { name: /matches no include entry \(1\)/ }))
    expect(await screen.findByText('Showing 1-1 of 1')).toBeInTheDocument()
    // Now a.other.test matches too: no name is left without a filter match.
    rerender(<IpHostnamePreview projectId="p1" {...props} include={['*.example.com', '*.other.test']} />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'All' }).getAttribute('aria-pressed')).toBe('true'))
    expect(await screen.findByText('Showing 1-100 of 251')).toBeInTheDocument()
    expect(new URL(urls[urls.length - 1], 'http://x').searchParams.get('reason')).toBeNull()
  })

  test('the search box narrows by name', async () => {
    serve()
    render(<IpHostnamePreview projectId="p1" {...props} />)
    await count()
    fireEvent.change(screen.getByLabelText('Search names'), { target: { value: 'h24' } })
    expect(await screen.findByText('Showing 1-10 of 10')).toBeInTheDocument()
  })
})
