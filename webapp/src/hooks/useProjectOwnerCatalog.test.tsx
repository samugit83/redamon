/**
 * Who reads a project owner's catalog (step 5.7, SH-26): the one rule the project form and the graph
 * page (Other Scans, the AI drawer) share. Any non-owner access (read, write, oversight, break-glass)
 * reads GET /api/projects/[id]/owner-catalog once, and the owner's models (`?models=1`) only at
 * Manage and only while the screen wants them; the owner, and every screen with
 * RBAC_SHARING_ENABLED off (no `myAccess`), read nothing from it (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useProjectOwnerCatalog.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { OWNER_KEY_FIELDS, type OwnerKeyField } from '@/lib/ownerCatalog'
import { catalogPickRefusal } from '@/lib/settingsFieldAccess'
import { useProjectOwnerCatalog } from './useProjectOwnerCatalog'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const writeAccess = (manage: boolean): MyAccess => ({
  level: 'write', via: 'share', owner: OWNER,
  toggles: { rawData: true, runScans: false, useAgent: true, exploit: false, manage },
})
const EDITOR = writeAccess(false)
const CO_OWNER = writeAccess(true)
const READ: MyAccess = { level: 'read', via: 'share', owner: OWNER, toggles: { rawData: false } }
const OWNS: MyAccess = { level: 'owner', via: 'owner', owner: OWNER, toggles: { rawData: true } }

const CATALOG = {
  providers: [], jevProviders: [], attackSkills: [], tradecraftResources: [], mcpServers: [],
  keys: Object.fromEntries(OWNER_KEY_FIELDS.map(f => [f, false])) as Record<OwnerKeyField, boolean>,
}
const MODELS = { 'OpenAI (owner)': [{ id: 'openai/gpt-owner', name: 'GPT Owner', context_length: null, description: '' }] }

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
const asked = () => fetchMock.mock.calls.map(c => String(c[0]))
const settle = () => new Promise(r => setTimeout(r, 30))

beforeEach(() => {
  fetchMock = vi.fn(async (input: string) => {
    const url = String(input)
    if (url === '/api/projects/p1/owner-catalog?models=1') return json({ ...CATALOG, models: MODELS })
    if (url === '/api/projects/p1/owner-catalog') return json(CATALOG)
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useProjectOwnerCatalog', () => {
  test('the owner reads no owner catalog', async () => {
    const { result } = renderHook(() => useProjectOwnerCatalog('p1', OWNS))
    await settle()
    expect(result.current).toBeNull()
    expect(asked()).toEqual([])
  })

  test.each([null, undefined])('switch off (myAccess %s): no owner catalog, nothing asked (DV-30)', async (access) => {
    const { result } = renderHook(() => useProjectOwnerCatalog('p1', access))
    await settle()
    expect(result.current).toBeNull()
    expect(asked()).toEqual([])
  })

  test('no project yet: nothing asked', async () => {
    const { result } = renderHook(() => useProjectOwnerCatalog(null, EDITOR))
    await settle()
    expect(result.current).toBeNull()
    expect(asked()).toEqual([])
  })

  test('an editor reads the catalog once, no models, with the pick refusal', async () => {
    const { result } = renderHook(() => useProjectOwnerCatalog('p1', EDITOR))
    await waitFor(() => expect(result.current?.status).toBe('ready'))
    expect(asked()).toEqual(['/api/projects/p1/owner-catalog'])
    expect(result.current?.catalog).toEqual(CATALOG)
    expect(result.current?.modelsStatus).toBe('off')
    expect(result.current?.pickRefusal).toBe(catalogPickRefusal(EDITOR))
    expect(result.current?.pickRefusal).toMatch(/needs Manage$/)
  })

  test('a read share reads the catalog too (shown read-only)', async () => {
    const { result } = renderHook(() => useProjectOwnerCatalog('p1', READ))
    await waitFor(() => expect(result.current?.status).toBe('ready'))
    expect(asked()).toEqual(['/api/projects/p1/owner-catalog'])
    expect(result.current?.pickRefusal).not.toBeNull()
  })

  test('a co-owner also reads the owner models', async () => {
    const { result } = renderHook(() => useProjectOwnerCatalog('p1', CO_OWNER))
    await waitFor(() => expect(result.current?.modelsStatus).toBe('ready'))
    expect(asked().sort()).toEqual(['/api/projects/p1/owner-catalog', '/api/projects/p1/owner-catalog?models=1'])
    expect(result.current?.models).toEqual(MODELS)
    expect(result.current?.pickRefusal).toBeNull()
  })

  test('a co-owner on a screen that wants no models yet reads the catalog only, then the models when asked', async () => {
    const { result, rerender } = renderHook(({ models }) => useProjectOwnerCatalog('p1', CO_OWNER, { models }), {
      initialProps: { models: false },
    })
    await waitFor(() => expect(result.current?.status).toBe('ready'))
    await settle()
    expect(asked()).toEqual(['/api/projects/p1/owner-catalog'])
    expect(result.current?.modelsStatus).toBe('off')
    rerender({ models: true })
    await waitFor(() => expect(result.current?.modelsStatus).toBe('ready'))
    expect(asked()).toEqual(['/api/projects/p1/owner-catalog', '/api/projects/p1/owner-catalog?models=1'])
  })
})
