import prisma from '@/lib/prisma'
import { instanceSettingsInForce } from '@/lib/sharedInstanceSettings'

/**
 * Is the capture proxy enabled globally? Mirrors the capture-config route: the
 * setting lives on the instance settings row with the identity switch on, else on
 * the admin UserSettings row (last admin save wins). Defaults to false (disabled)
 * on absence or error — recording is gated on this.
 */
export async function isCaptureGloballyEnabled(): Promise<boolean> {
  try {
    const instance = await instanceSettingsInForce()
    if (instance) return instance.captureProxyEnabled
    const admins = await prisma.user.findMany({ where: { role: 'admin' }, select: { id: true } })
    const adminIds = admins.map(a => a.id)
    if (!adminIds.length) return false
    const s = await prisma.userSettings.findFirst({
      where: { userId: { in: adminIds } },
      orderBy: { updatedAt: 'desc' },
      select: { captureProxyEnabled: true },
    })
    return s?.captureProxyEnabled ?? true // matches capture-config b() default (block=true=enabled)
  } catch {
    return false
  }
}
