'use client'

import { SITE_TYPES } from '@/lib/tradecraft/agentContract'
import { FormSection } from './FormSection'
import { OverrideList, type FormContext } from './OverrideList'
import { SECTION_KEYS, TYPE_LABELS, defsOf, overrideStatus } from './sections'
import css from './form.module.css'

/** "Auto (detected: Website)" or the forced type: the status line of the Site type section. */
export function siteTypeStatus(forcedType: string, detectedType: string): string {
  if (forcedType) return TYPE_LABELS[forcedType] ?? forcedType
  return detectedType ? `Auto (detected: ${TYPE_LABELS[detectedType] ?? detectedType})` : 'Auto'
}

/**
 * Site type (§6.5): Auto, today's detection, or a forced type that skips it. With Auto, the
 * detection thresholds can be overridden for this resource.
 */
export function SiteTypeSection({ ctx, forcedType, detectedType, onForcedType }: {
  ctx: FormContext
  forcedType: string
  detectedType: string
  onForcedType: (type: string) => void
}) {
  const status = siteTypeStatus(forcedType, detectedType)
  const detection = overrideStatus(SECTION_KEYS.detection, ctx.overrides)
  return (
    <FormSection title="Site type" status={detection === 'Inherit' ? status : `${status} · ${detection}`}>
      <div className={css.field}>
        <label className={css.fieldLabel} htmlFor="tc-site-type">Type</label>
        <select id="tc-site-type" className="select" value={forcedType} onChange={e => onForcedType(e.target.value)}>
          <option value="">{detectedType ? `Auto (detected: ${TYPE_LABELS[detectedType] ?? detectedType})` : 'Auto (detect it)'}</option>
          {SITE_TYPES.map(t => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
        </select>
        <span className="formHint">A forced type skips detection. The section of the type shows its own options.</span>
      </div>
      {!forcedType && <OverrideList ctx={ctx} defs={defsOf('detection')} />}
    </FormSection>
  )
}
