/**
 * The password policy in force (step 2.8, ID-20, ID-29). With the identity switch on: the
 * instance settings row's minimum (never below the floor; Root sets it), the deny list and the
 * two rules, and `askChangeIfShort`, Root's setting that flags an account at sign-in when the
 * password it used is shorter than that minimum. Off: Phase 1's policy, nothing read.
 *
 * Read on every use: a password write or a sign-in is rare next to an ordinary request, and a
 * minimum Root just raised applies to the next password at once. A failed read throws, so no
 * caller mistakes it for a weaker policy.
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { BASE_PASSWORD_POLICY, effectiveMinLength, type PasswordPolicy } from './passwordPolicy'
import { INSTANCE_SETTINGS_ROW } from './root'

export interface InstancePasswordPolicy extends PasswordPolicy {
  askChangeIfShort: boolean
}

export async function passwordPolicyInForce(): Promise<InstancePasswordPolicy> {
  if (!rbacFlags().identity) return { ...BASE_PASSWORD_POLICY, askChangeIfShort: false }
  const row = await prisma.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { passwordMinLength: true, passwordAskChangeIfShort: true },
  })
  return {
    minLength: effectiveMinLength(row?.passwordMinLength),
    rules: true,
    askChangeIfShort: row?.passwordAskChangeIfShort === true,
  }
}
