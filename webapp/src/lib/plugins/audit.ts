import { writeAudit } from '@/lib/audit'

/**
 * The audit action names of the plugin platform. They are a published, searchable
 * vocabulary (admins filter the audit log by them), so a name is never renamed: add a
 * new one instead. Lifecycle events target the plugin; override decisions target the
 * change set and record the plugin in `after`, because AuditLog has no plugin column.
 */
export const PLUGIN_AUDIT_ACTIONS = [
  'plugin.install',
  'plugin.install_failed',
  'plugin.enable',
  'plugin.disable',
  'plugin.update',
  'plugin.rollback',
  'plugin.uninstall',
  'plugin.purge',
  'plugin.export',
  'plugin.permissions_granted',
  'plugin.revoked',
  'plugin.override.propose',
  'plugin.override.withdraw',
  'plugin.override.approve',
  'plugin.override.reject',
  'plugin.override.reset',
  'plugin.override.delete',
  'plugin.override.stale',
  'plugin.override.adopt',
  'plugin.access_rules_changed',
] as const
export type PluginAuditAction = (typeof PLUGIN_AUDIT_ACTIONS)[number]

export interface PluginAuditEntry {
  actorId?: string | null
  pluginId: string
  /** Defaults to `plugin`; override decisions use `plugin_change_set`. */
  targetType?: string
  targetId?: string | null
  before?: unknown
  after?: unknown
  source?: 'api' | 'ui' | 'admin' | 'system'
}

function withPluginId(after: unknown, pluginId: string): Record<string, unknown> {
  if (after === undefined || after === null) return { pluginId }
  if (typeof after === 'object' && !Array.isArray(after)) return { ...(after as Record<string, unknown>), pluginId }
  return { value: after, pluginId }
}

/** Never throws for a persistence failure (writeAudit logs and swallows it). */
export async function auditPlugin(action: PluginAuditAction, entry: PluginAuditEntry): Promise<void> {
  if (!(PLUGIN_AUDIT_ACTIONS as readonly string[]).includes(action)) {
    throw new Error(`Unknown plugin audit action ${action}`)
  }
  const targetType = entry.targetType ?? 'plugin'
  const isPlugin = targetType === 'plugin'
  await writeAudit({
    actorId: entry.actorId ?? null,
    action,
    targetType,
    targetId: entry.targetId !== undefined ? entry.targetId : isPlugin ? entry.pluginId : null,
    before: entry.before,
    after: isPlugin ? entry.after : withPluginId(entry.after, entry.pluginId),
    source: entry.source ?? 'api',
  })
}
