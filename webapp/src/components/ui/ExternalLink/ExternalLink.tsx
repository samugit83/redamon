'use client'

import type { ReactNode, MouseEvent } from 'react'
import { isHttpUrl } from '@/lib/url-utils'
import styles from './ExternalLink.module.css'

interface ExternalLinkProps {
  href: string | null | undefined
  children?: ReactNode
  className?: string
  title?: string
}

export function ExternalLink({ href, children, className, title }: ExternalLinkProps) {
  const label = children ?? href ?? ''

  if (!isHttpUrl(href)) {
    return <>{label}</>
  }

  const handleClick = (e: MouseEvent<HTMLAnchorElement>) => {
    e.stopPropagation()
  }

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={className ? `${styles.link} ${className}` : styles.link}
      title={title ?? href}
      onClick={handleClick}
    >
      {label}
    </a>
  )
}
