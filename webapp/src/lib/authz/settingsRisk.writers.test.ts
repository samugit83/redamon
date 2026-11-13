/**
 * Every writer of the project row asks classifyChange, or is shown not to need it (step 5.1b;
 * SH-08). A new writer fails here until it is placed:
 *   - judged: a collaborator's change goes through classifyChange (directly, or through
 *     `refuseSettingsChange`, the MCP tools' wrapper), and the file's own tests prove it;
 *   - ordinary at W: it writes only columns the registry calls ordinary, behind a permission at
 *     Write or above, so classifyChange could only agree with the guard; reclassifying one of its
 *     columns fails the test below, and the writer must then be judged;
 *   - owner or system: no collaborator reaches it (the owner's own projects, a creation, a lock).
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { classifyField } from './settingsRisk'
import { PERMISSIONS, type PermissionId, type ProjectLevel } from './permissions'

const SRC = path.resolve(__dirname, '../..')

function sources(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name !== '__testing__' && name !== '__fixtures__') out.push(...sources(full))
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) {
      out.push(full)
    }
  }
  return out
}

const WRITES_PROJECT = /\bproject\.update(Many)?\(/

const JUDGED = [
  'app/api/projects/[id]/route.ts',
  'lib/roe/applyRoe.ts',
  'lib/mcp/writeTools.ts',
  'lib/mcp/scopeTools.ts',
  'lib/mcp/presetTools.ts',
]

/** Each upload route: the columns it writes and the permissions it asks before writing them. */
const ORDINARY_AT_W: Record<string, { columns: string[]; permissions: PermissionId[] }> = {
  'app/api/js-recon/[projectId]/upload/route.ts': { columns: ['jsReconUploadedFiles'], permissions: ['scan:uploads'] },
  'app/api/js-recon/[projectId]/custom-files/route.ts': {
    columns: ['jsReconCustomPatterns', 'jsReconCustomSourcemapPaths', 'jsReconCustomPackages', 'jsReconCustomEndpointKeywords', 'jsReconCustomFrameworks'],
    permissions: ['scan:uploads'],
  },
  'app/api/supply-chain/[projectId]/upload/route.ts': { columns: ['supplyChainSbomFile'], permissions: ['scan:supply_chain'] },
}

const OWNER_OR_SYSTEM: Record<string, string> = {
  'app/api/projects/route.ts': 'the create: the creator owns the new project',
  'app/api/users/[id]/llm-providers/[providerId]/route.ts': "clears a deleted provider from the account's own projects",
  'lib/activationLock.ts': 'the version-activation lock columns, written by the activation itself',
  'lib/plugins/userSkillAdoption.ts': 'system: a plugin skill adopted into its author\'s own projects',
  'lib/plugins/userSkillRevocation.ts': 'system: a revoked skill switched off where it was on',
  'lib/reconPresets/badges.ts': "the preset owner's own projects' badge",
  'lib/userSkillWrites.ts': "the skill author's own projects (where: {userId})",
}

/** The levels at or above Write: a permission at one of them is never a reader's. */
const WRITE_OR_ABOVE: readonly ProjectLevel[] = ['W', 'W+S', 'W+A', 'W+X', 'M', 'O']

describe('every writer of the project row is placed (step 5.1b)', () => {
  const writers = sources(SRC).filter(f => WRITES_PROJECT.test(readFileSync(f, 'utf8'))).map(f => path.relative(SRC, f)).sort()

  test('the writers found are exactly the placed ones', () => {
    expect(writers).toEqual([...JUDGED, ...Object.keys(ORDINARY_AT_W), ...Object.keys(OWNER_OR_SYSTEM)].sort())
  })

  test.each(JUDGED)('%s judges the change with classifyChange', file => {
    const src = readFileSync(path.join(SRC, file), 'utf8')
    expect(src).toMatch(/\b(classifyChange|refuseSettingsChange)\(/)
  })

  test.each(Object.entries(ORDINARY_AT_W))('%s writes only ordinary columns behind a Write permission', (file, { columns, permissions }) => {
    const src = readFileSync(path.join(SRC, file), 'utf8')
    for (const key of columns) {
      expect(src, key).toContain(key)
      expect(classifyField(key, 'before', 'after').needs, key).toBe('write')
    }
    for (const p of permissions) {
      expect(src, p).toContain(`'${p}'`)
      expect(WRITE_OR_ABOVE, p).toContain(PERMISSIONS[p].level)
    }
  })
})
