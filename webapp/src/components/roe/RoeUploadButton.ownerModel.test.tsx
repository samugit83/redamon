/**
 * Uploading an RoE on a project the person does not own: since step 5.6 /api/roe/parse reads the
 * project OWNER's "RoE parsing" model (a collaborator needs Use AI agent and the owner's consent),
 * so the button neither asks for nor shows the person's own model there, and a model code is
 * worded as the owner's. The rule is `readsOwnerCatalog` on the project's access, as on the reports
 * page and the project form. The owner's project, a project being created (the caller's own) and
 * RBAC_SHARING_ENABLED off (no `myAccess`) keep the person's own model line and gate; nothing asks
 * for the owner's catalog (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/components/roe/RoeUploadButton.ownerModel.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { GATE_USER, jsonResponse, stubGateFetch, type GateFetchStub } from '@/components/shared/featureModelGate.testUtils'
import type { MyAccess } from '@/lib/authz/projectAccess'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))
vi.mock('@/components/ui', () => ({ useToast: () => ({ addToast: vi.fn() }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import { RoeUploadButton } from './RoeUploadButton'

const PARSE_URL = '/api/roe/parse'
const SETTINGS_URL = `/api/users/${GATE_USER}/settings`
const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const MANAGE: MyAccess = {
  level: 'write', via: 'share', owner: OWNER,
  toggles: { rawData: false, runScans: false, useAgent: true, exploit: false, manage: true },
}
const OWNS: MyAccess = { level: 'owner', via: 'owner', owner: OWNER, toggles: { rawData: true } }

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

let n = 0
function upload(myAccess: MyAccess | null, { projectId = 'p1' as string | null } = {}) {
  const key = `roe-owner-model-${++n}`
  render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess }}>
      <FeatureModelGateProvider>
        <RoeUploadButton storeKey={key} projectId={projectId} hasDocument={false} />
      </FeatureModelGateProvider>
    </ProjectAccessContext.Provider>,
  )
  const file = new File(['Rules of engagement'], 'roe.txt', { type: 'text/plain' })
  fireEvent.change(screen.getByTestId(`roe-file-input-${key}`), { target: { files: [file] } })
}

const ownerCatalogAsked = (stub: GateFetchStub) =>
  stub.fetch.mock.calls.some(([url]) => String(url).includes('/owner-catalog'))

describe('RoE upload on a project the person does not own', () => {
  test("a Manage collaborator: parsed on the owner's model, no gate and no read of the person's own model", async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { changes: [] }))
    upload(MANAGE)
    await waitFor(() => expect(stub.calls(PARSE_URL, 'POST')).toHaveLength(1))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(stub.calls(SETTINGS_URL)).toHaveLength(0)
    expect(stub.calls('/api/models')).toHaveLength(0)
    expect(screen.getByText("Model: the project owner's")).toBeTruthy()
    expect(ownerCatalogAsked(stub)).toBe(false)
  })

  test("the owner has no RoE parsing model: the error says so, the person's gate never opens", async () => {
    const stub = stubGateFetch({}, () =>
      jsonResponse(409, { error: 'x', code: 'model_required', featureId: 'roe_parse' }))
    upload(MANAGE)
    expect(await screen.findByRole('alert')).toHaveTextContent("The project's owner has not chosen an RoE parsing model")
    expect(stub.calls(PARSE_URL, 'POST')).toHaveLength(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe("the person's own model, as before", () => {
  test("the owner's project: the gate asks for the person's own model first, the own model line shows", async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { changes: [] }))
    upload(OWNS)
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(stub.calls(PARSE_URL, 'POST')).toHaveLength(0)
    expect(document.querySelector('[data-feature-model="roe_parse"]')?.textContent).toContain('Model:')
    expect(screen.queryByText("Model: the project owner's")).toBeNull()
    expect(ownerCatalogAsked(stub)).toBe(false)
  })

  test('a project being created is the caller\'s own, even while a shared project is open', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { changes: [] }))
    upload(MANAGE, { projectId: null })
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(stub.calls(PARSE_URL, 'POST')).toHaveLength(0)
  })

  test('switch off (no myAccess): the gate as before', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { changes: [] }))
    upload(null)
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(stub.calls(PARSE_URL, 'POST')).toHaveLength(0)
    expect(ownerCatalogAsked(stub)).toBe(false)
  })
})
