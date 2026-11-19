/**
 * Root's AI Navigator switch (D15, plan §5.5), read once per request.
 *
 * With the identity switch off there is no Root and no IAM console to change it, and
 * `instanceSettingsInForce()` answers null: the Navigator is on, its default (Q4). A missing row
 * (the boot backfill has not run yet) is the default too. A failed read throws, so every route
 * answers a coded 500 and the tool route refuses: it never reads as on.
 */
import { instanceSettingsInForce } from '@/lib/sharedInstanceSettings'

export async function navigatorEnabled(): Promise<boolean> {
  const row = await instanceSettingsInForce()
  if (!row) return true
  return row.navigatorEnabled !== false
}
