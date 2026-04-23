import { Fragment, type ReactNode } from 'react'
import { ExternalLink } from '@/components/ui'
import { isHttpUrl } from '@/lib/url-utils'
import { formatPropertyValue } from './formatters'

export function renderPropertyValue(value: unknown): ReactNode {
  if (Array.isArray(value) && value.length > 0) {
    return value.map((item, i) => (
      <Fragment key={i}>
        {i > 0 && ', '}
        {isHttpUrl(item) ? <ExternalLink href={item} /> : String(item)}
      </Fragment>
    ))
  }

  const formatted = formatPropertyValue(value)
  if (isHttpUrl(formatted)) {
    return <ExternalLink href={formatted} />
  }
  return formatted
}
