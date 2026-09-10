/**
 * Strategy row 1 (L2): the Origin Discovery partial-recon modal must not let a
 * no-op run through, and must not block a valid one.
 *
 * Origin Discovery needs a CDN-fronted host. With zero fronted hosts in the graph
 * and no subdomain typed, "Run Partial Recon" must be DISABLED (originDiscoveryNoFronted);
 * typing an in-scope fronted subdomain must ENABLE it. This owns the G7 guard from
 * the consumer side (the L4 test owns the fronted_count producer side).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.originDiscovery.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

// graph-inputs returns a project with NO fronted hosts; user settings empty.
function mockFetch(frontedCount: number) {
  return vi.fn((url: string) => {
    if (url.includes('/graph-inputs/')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          domain: 'acme.test', existing_subdomains: [], existing_subdomains_count: 0,
          fronted_count: frontedCount, source: 'graph',
        }),
      } as Response)
    }
    // /api/users/:id/settings and anything else
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
  })
}

function renderModal() {
  return render(
    <PartialReconModal
      isOpen
      toolId="OriginDiscovery"
      onClose={vi.fn()}
      onConfirm={vi.fn()}
      projectId="p1"
      targetDomain="acme.test"
      userId="u1"
    />,
  )
}

afterEach(cleanup)
beforeEach(() => { vi.stubGlobal('fetch', mockFetch(0)) })

describe('PartialReconModal — Origin Discovery fronted-host guard', () => {
  test('Run disabled with no fronted hosts and no subdomain; enabled once a subdomain is typed', async () => {
    renderModal()

    const runBtn = await screen.findByRole('button', { name: /Run Partial Recon/i })
    // after graph-inputs resolves (fronted_count 0, no subdomain) -> blocked
    await waitFor(() => expect(runBtn).toBeDisabled())

    // typing an in-scope subdomain lifts the guard
    const textarea = screen.getByPlaceholderText(/^api\.acme\.test/)
    fireEvent.change(textarea, { target: { value: 'origin.acme.test' } })
    await waitFor(() => expect(runBtn).toBeEnabled())
  })
})
