import { readApiError } from '@/lib/apiError'
import type { InstanceSettingsView } from './instanceView'

export const INSTANCE_SETTINGS_URL = '/api/admin/instance-settings'

/**
 * A change to the instance settings, as the signed-in person (the route reads them fresh and
 * decides each field). It answers the settings as the GET does; a refusal throws an ApiError
 * whose message the step-up dialog shows (a wrong password, root_only, a value out of bounds).
 */
export async function putInstanceSettings(body: Record<string, unknown>, failure: string): Promise<InstanceSettingsView> {
  const res = await fetch(INSTANCE_SETTINGS_URL, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await readApiError(res, failure)
  return await res.json() as InstanceSettingsView
}
