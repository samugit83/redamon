/**
 * Vitest global setup.
 *
 * Registers @testing-library/jest-dom matchers (toBeInTheDocument, etc.)
 * so component tests can assert against DOM presence. Without this, vitest's
 * expect throws "Invalid Chai property: toBeInTheDocument".
 */
import '@testing-library/jest-dom/vitest'
import { vi } from 'vitest'

// The Kali sandbox lifecycle hooks (group 1, src/lib/sandbox/lifecycle.ts) call the recon
// orchestrator after every access loss, project deletion, emergency stop and RBAC sweep; a test that
// does not stub fetch would reach whatever answers on its URL (a dev stack takes the default key).
// Every test gets them answering shared mode, the product before per-user sandboxes; a test of a hook
// mocks the module itself, and lifecycle.test.ts asks for the real one with vi.unmock.
vi.mock('@/lib/sandbox/lifecycle', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/sandbox/lifecycle')>()
  const shared = async () => ({ mode: 'shared' as const })
  return {
    ...real,
    sandboxAccessChanged: shared, sandboxAccountEnded: shared, sandboxAccountsEnded: shared, sandboxProjectDeleted: shared,
    sandboxEmergencyStop: shared, reconcileRunningSandboxes: shared,
  }
})

// jsdom ships no ResizeObserver; components that measure their container via the
// useDimensions hook (e.g. the Recon Delta graph overlay) reference it at render.
// A no-op stub keeps them mountable — dimension math is exercised in the browser.
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
}
