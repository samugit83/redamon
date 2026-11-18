'use client'

import type { ResourceView } from '@/lib/tradecraft/client'
import { isRunning } from '@/lib/tradecraft/client'
import css from './tradecraft.module.css'

/**
 * What deleting a 2.0 resource removes (R-196), shown in the danger confirmation. Every item
 * the resource holds is named, so nobody deletes stored pages or a login without being told.
 */
export function DeleteConfirm({ resource }: { resource: ResourceView }) {
  const goes: string[] = []
  goes.push(resource.storageMode === 'stored'
    ? `its map and the ${resource.entryCount} stored ${resource.entryCount === 1 ? 'page' : 'pages'}`
    : `its map (${resource.entryCount} ${resource.entryCount === 1 ? 'entry' : 'entries'})`)
  goes.push('its summary and its ingestion report')
  if (isRunning(resource.job)) goes.push('the job running now, which is cancelled first')
  if (resource.hasLogin) goes.push('its site login')
  if (resource.githubTokenOverride) goes.push('its GitHub token')
  goes.push('the choices every project made for it')
  return (
    <div>
      <p>Delete &quot;{resource.name}&quot;? This removes, from every project:</p>
      <ul className={css.goes} aria-label="What is deleted">
        {goes.map(item => <li key={item}>{item}</li>)}
      </ul>
      <p>Conversations that quoted its pages keep their text.</p>
    </div>
  )
}
