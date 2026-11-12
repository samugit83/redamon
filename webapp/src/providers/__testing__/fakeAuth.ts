/**
 * An AuthContext value for component tests of permission-gated controls: render the component under
 * `<AuthContext.Provider value={fakeAuth(FLAGS_ON, ['recon:scan'])}>` instead of the real provider,
 * which reads /api/auth/me.
 */
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { RbacFlags } from '@/lib/authz/flags'
import type { PermissionId } from '@/lib/authz/permissions'

export const FLAGS_OFF: RbacFlags = {
  sharedToolsCompat: false, identity: false, permissions: false, sharing: false, sharingWrite: false, governance: false,
}
export const FLAGS_ON: RbacFlags = { ...FLAGS_OFF, identity: true, permissions: true }

export function fakeAuth(flags: RbacFlags | null, held: PermissionId[], over: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    user: flags ? { id: 'm1', name: 'Member', email: 'member@e2e.local', role: 'standard', flags } : null,
    isLoading: false,
    capabilities: new Set(held),
    flags,
    sessionError: null,
    login: async () => ({}),
    logout: async () => {},
    refresh: async () => {},
    ...over,
  }
}
