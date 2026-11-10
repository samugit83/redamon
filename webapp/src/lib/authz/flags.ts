/**
 * The RBAC feature switches: environment variables, read only here. The webapp
 * has no env_file, so each one is forwarded in the webapp's `environment:` block
 * of docker-compose.yml with a `false` default, and documented in .env.example.
 *
 * Fail safe: unset, empty, `false`, `0` and `no` are off; `true`, `1` and `yes`
 * (any case) are on; anything else is off and logged once per process. A switch
 * whose requirement is off also reads off, logged once, so no partial state of
 * the chain identity -> permissions -> sharing -> sharingWrite (and
 * permissions -> governance) ever reaches the code.
 */

export interface RbacFlags {
  sharedToolsCompat: boolean
  identity: boolean
  permissions: boolean
  sharing: boolean
  sharingWrite: boolean
  governance: boolean
}

type FlagName = keyof RbacFlags

const ENV_NAME: Record<FlagName, string> = {
  sharedToolsCompat: 'REDAMON_SHARED_TOOLS_COMPAT',
  identity: 'RBAC_IDENTITY_ENABLED',
  permissions: 'RBAC_PERMISSIONS_ENABLED',
  sharing: 'RBAC_SHARING_ENABLED',
  sharingWrite: 'RBAC_SHARING_WRITE_ENABLED',
  governance: 'RBAC_GOVERNANCE_ENABLED',
}

// Applied in this order, so a switch reads its requirement after that one was resolved.
const REQUIRES: ReadonlyArray<readonly [FlagName, FlagName]> = [
  ['permissions', 'identity'],
  ['sharing', 'permissions'],
  ['sharingWrite', 'sharing'],
  ['governance', 'permissions'],
]

const ON = new Set(['true', '1', 'yes'])
const OFF = new Set(['', 'false', '0', 'no'])

const warned = new Set<string>()
let override: Partial<RbacFlags> | null = null

function warnOnce(line: string): void {
  if (warned.has(line)) return
  warned.add(line)
  console.warn(line)
}

// The value is never logged: an operator may have pasted anything into .env.
function parseSwitch(name: string, raw: string | undefined): boolean {
  const value = (raw ?? '').trim().toLowerCase()
  if (ON.has(value)) return true
  if (!OFF.has(value)) warnOnce(`[rbac] unrecognised value for ${name}; the switch reads off`)
  return false
}

// Static property reads, not process.env[name]: the bundler can only see these.
function readEnv(): RbacFlags {
  return {
    sharedToolsCompat: parseSwitch(ENV_NAME.sharedToolsCompat, process.env.REDAMON_SHARED_TOOLS_COMPAT),
    identity: parseSwitch(ENV_NAME.identity, process.env.RBAC_IDENTITY_ENABLED),
    permissions: parseSwitch(ENV_NAME.permissions, process.env.RBAC_PERMISSIONS_ENABLED),
    sharing: parseSwitch(ENV_NAME.sharing, process.env.RBAC_SHARING_ENABLED),
    sharingWrite: parseSwitch(ENV_NAME.sharingWrite, process.env.RBAC_SHARING_WRITE_ENABLED),
    governance: parseSwitch(ENV_NAME.governance, process.env.RBAC_GOVERNANCE_ENABLED),
  }
}

export function rbacFlags(): Readonly<RbacFlags> {
  const flags: RbacFlags = override
    ? {
        sharedToolsCompat: override.sharedToolsCompat === true,
        identity: override.identity === true,
        permissions: override.permissions === true,
        sharing: override.sharing === true,
        sharingWrite: override.sharingWrite === true,
        governance: override.governance === true,
      }
    : readEnv()
  for (const [flag, requirement] of REQUIRES) {
    if (flags[flag] && !flags[requirement]) {
      warnOnce(`[rbac] ${ENV_NAME[flag]} requires ${ENV_NAME[requirement]}, which is off; the switch reads off`)
      flags[flag] = false
    }
  }
  return Object.freeze(flags)
}

/**
 * Tests only: replaces the environment with these values (a missing switch is
 * off; the dependency chain still applies). `null` restores the environment.
 * Refused in a production build so a stray call cannot flip a live switch.
 */
export function setFlagsForTests(values: Partial<RbacFlags> | null): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('setFlagsForTests is for tests only')
  }
  override = values ? { ...values } : null
}
