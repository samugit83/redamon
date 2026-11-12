/**
 * R1 — the audit helper inserts an append-only AuditLog / ActAsAudit row with the
 * expected fields, and NEVER throws even when the DB insert fails.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/audit.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const auditCreate = vi.fn()
const actAsCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    auditLog: { create: (args: unknown) => auditCreate(args) },
    actAsAudit: { create: (args: unknown) => actAsCreate(args) },
  },
}))

import { writeAudit, writeActAsAudit } from './audit'

beforeEach(() => {
  auditCreate.mockReset().mockResolvedValue({})
  actAsCreate.mockReset().mockResolvedValue({})
})

describe('writeAudit', () => {
  test('inserts an AuditLog row with the expected fields', async () => {
    await writeAudit({
      actorId: 'admin1', action: 'auth.login.success',
      targetType: 'user', targetId: 'user1', source: 'api',
    })
    expect(auditCreate).toHaveBeenCalledTimes(1)
    const data = auditCreate.mock.calls[0][0].data
    expect(data.actorId).toBe('admin1')
    expect(data.action).toBe('auth.login.success')
    expect(data.targetType).toBe('user')
    expect(data.targetId).toBe('user1')
  })

  test('defaults actorId/targetId to null and source to api', async () => {
    await writeAudit({ action: 'auth.login.failure', targetType: 'user' })
    const data = auditCreate.mock.calls[0][0].data
    expect(data.actorId).toBeNull()
    expect(data.targetId).toBeNull()
    expect(data.source).toBe('api')
  })

  test('columns: the person acted for, the project, the permission and the actor email (AU-01)', async () => {
    await writeAudit({
      actorId: 'admin1', onBehalfOfUserId: 'user1', projectId: 'p1', permission: 'project:read',
      actorEmail: 'admin1@e2e.local', action: 'x', targetType: 'project', targetId: 'p1',
    })
    expect(auditCreate.mock.calls[0][0].data).toMatchObject({
      actorId: 'admin1', onBehalfOfUserId: 'user1', projectId: 'p1', permission: 'project:read', actorEmail: 'admin1@e2e.local',
    })
  })

  test('never throws when the DB insert fails', async () => {
    auditCreate.mockRejectedValue(new Error('db down'))
    await expect(
      writeAudit({ action: 'x', targetType: 'y' })
    ).resolves.toBeUndefined()
  })
})

describe('writeActAsAudit', () => {
  test('inserts an ActAsAudit row', async () => {
    await writeActAsAudit({ adminId: 'a', targetUserId: 't', event: 'start' })
    const data = actAsCreate.mock.calls[0][0].data
    expect(data.adminId).toBe('a')
    expect(data.targetUserId).toBe('t')
    expect(data.event).toBe('start')
  })
})
