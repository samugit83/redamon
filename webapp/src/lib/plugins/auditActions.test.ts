/**
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))

import { PLUGIN_AUDIT_ACTIONS, auditPlugin } from './audit'

beforeEach(() => {
  h.writeAudit.mockReset()
  h.writeAudit.mockResolvedValue(undefined)
})

describe('the plugin audit action names (R-11)', () => {
  test('are the published, searchable list: renaming one breaks every saved search', () => {
    expect([...PLUGIN_AUDIT_ACTIONS]).toEqual([
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
    ])
  })

  test('are unique, dotted, lower case and start with plugin.', () => {
    expect(new Set(PLUGIN_AUDIT_ACTIONS).size).toBe(PLUGIN_AUDIT_ACTIONS.length)
    for (const a of PLUGIN_AUDIT_ACTIONS) expect(a).toMatch(/^plugin(\.[a-z][a-z_]*)+$/)
  })
})

describe('auditPlugin', () => {
  test('passes a lifecycle event through to writeAudit with the plugin as target and the source', async () => {
    await auditPlugin('plugin.install', {
      actorId: 'admin-1',
      pluginId: 'skiller',
      after: { version: '1.0.0' },
      source: 'admin',
    })
    expect(h.writeAudit).toHaveBeenCalledWith({
      actorId: 'admin-1',
      action: 'plugin.install',
      targetType: 'plugin',
      targetId: 'skiller',
      before: undefined,
      after: { version: '1.0.0' },
      source: 'admin',
    })
  })

  test('an override decision targets the change set and still records the plugin', async () => {
    await auditPlugin('plugin.override.approve', {
      actorId: 'u1',
      pluginId: 'skiller',
      targetType: 'plugin_change_set',
      targetId: 'cs-1',
      before: { revision: 2 },
      after: { revision: 3, scope: 'user' },
    })
    expect(h.writeAudit).toHaveBeenCalledWith({
      actorId: 'u1',
      action: 'plugin.override.approve',
      targetType: 'plugin_change_set',
      targetId: 'cs-1',
      before: { revision: 2 },
      after: { revision: 3, scope: 'user', pluginId: 'skiller' },
      source: 'api',
    })
  })

  test('a system event without details still names the plugin', async () => {
    await auditPlugin('plugin.override.stale', {
      pluginId: 'skiller',
      targetType: 'plugin_change_set',
      targetId: 'cs-2',
      source: 'system',
    })
    expect(h.writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({ actorId: null, after: { pluginId: 'skiller' }, source: 'system' }),
    )
  })

  test('a non-object detail is kept under value', async () => {
    await auditPlugin('plugin.export', { pluginId: 'skiller', targetType: 'plugin_export', targetId: null, after: 3 })
    expect(h.writeAudit.mock.calls[0][0].after).toEqual({ value: 3, pluginId: 'skiller' })
  })

  test('an unknown action name is refused at compile time and at run time', async () => {
    // @ts-expect-error not a plugin audit action
    await expect(auditPlugin('plugin.hack', { pluginId: 'skiller' })).rejects.toThrow(/Unknown plugin audit action/)
    expect(h.writeAudit).not.toHaveBeenCalled()
  })
})
