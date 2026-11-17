'use client'

import { useId, useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'
import css from './form.module.css'

/** A collapsed section of the resource form with its one-line status in the header (§6.2). */
export function FormSection({ title, status, children, defaultOpen = false }: {
  title: string
  status: string
  children: ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  const id = useId()
  return (
    <section className={css.section} aria-label={title}>
      <button type="button" className={css.sectionHead} aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}>
        <ChevronDown size={15} className={`${css.chevron} ${open ? css.chevronOpen : ''}`} aria-hidden="true" />
        <span className={css.sectionTitle}>{title}</span>
        <span className={css.sectionStatus}>{status}</span>
      </button>
      {open && <div id={id} className={css.sectionBody}>{children}</div>}
    </section>
  )
}
