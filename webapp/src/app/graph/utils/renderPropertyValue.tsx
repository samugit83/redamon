import { Fragment, type ReactNode } from 'react'
import { ExternalLink, SecretValue } from '@/components/ui'
import { resolveLinkable } from '@/lib/url-utils'
import { isSecretValueProp } from '@/lib/secrets/secretProps'
import { formatPropertyValue } from './formatters'

function linkify(item: unknown): ReactNode {
  const text = formatPropertyValue(item)
  const href = resolveLinkable(text)
  if (href) return <ExternalLink href={href}>{text}</ExternalLink>
  return text
}

/**
 * A node property as the graph views show it: a URL is a link (a full link
 * with its secret in it opens whole), and a property that holds a secret
 * (`key` on a `nodeType`, see lib/secrets/secretProps.ts) shows its last four
 * characters with a copy button.
 */
export function renderPropertyValue(value: unknown, key?: string, nodeType?: string | null): ReactNode {
  const secret = key !== undefined && isSecretValueProp(key, nodeType)
  if (Array.isArray(value) && value.length > 0) {
    return value.map((item, i) => (
      <Fragment key={i}>
        {i > 0 && (secret ? ' ' : ', ')}
        {secret ? <SecretValue value={item == null ? '' : String(item)} /> : linkify(item)}
      </Fragment>
    ))
  }
  if (secret) return <SecretValue value={value == null ? '' : String(value)} />
  return linkify(value)
}

/** A cell's tooltip: never a secret value, which the cell shows as its last four characters. */
export function propertyTitle(value: unknown, key?: string, nodeType?: string | null): string {
  if (key !== undefined && isSecretValueProp(key, nodeType)) return ''
  return String(value ?? '')
}
