'use client'

import { useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { ALPHABETICAL_PRESETS, FEATURED_PRESETS, type TradecraftPreset } from '@/lib/tradecraft/presets'
import css from './form.module.css'

function matches(p: TradecraftPreset, q: string): boolean {
  return [p.name, p.url, p.description, p.type].some(s => s.toLowerCase().includes(q))
}

/** Quick add (§6.12): the Featured group first, then every preset by name; search covers both. */
export function PresetPicker({ onPick }: { onPick: (preset: TradecraftPreset) => void }) {
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const q = query.trim().toLowerCase()
  const featured = useMemo(() => FEATURED_PRESETS.filter(p => !q || matches(p, q)), [q])
  const rest = useMemo(() => ALPHABETICAL_PRESETS.filter(p => !q || matches(p, q)), [q])
  const shown = open || q.length > 0
  const pick = (p: TradecraftPreset) => {
    onPick(p)
    setQuery('')
    setOpen(false)
  }
  const item = (p: TradecraftPreset) => (
    <button key={p.key} type="button" className={css.presetItem} onClick={() => pick(p)}>
      <span>{p.name}</span>
      <span className={css.presetDesc}>{p.description}</span>
    </button>
  )
  return (
    <div className={css.stack}>
      <span className="formLabel">Quick add</span>
      <div className={css.inputRow}>
        <div className="inputWithIcon">
          <Search size={13} className="inputIcon" aria-hidden="true" />
          <input
            className="textInput" aria-label="Quick add" placeholder="Search presets by name, URL or type…" value={query}
            onChange={e => setQuery(e.target.value)}
          />
        </div>
        <button type="button" className="secondaryButton" aria-expanded={shown} onClick={() => setOpen(o => !o)}>
          {shown ? 'Hide presets' : `Browse ${FEATURED_PRESETS.length + ALPHABETICAL_PRESETS.length} presets`}
        </button>
      </div>
      {shown && (
        <div className={css.presetList} role="listbox" aria-label="Presets">
          {featured.length > 0 && <div className={css.presetGroup}>Featured</div>}
          {featured.map(item)}
          {rest.length > 0 && <div className={css.presetGroup}>All presets</div>}
          {rest.map(item)}
          {featured.length + rest.length === 0 && <div className={css.presetEmpty}>No preset matches.</div>}
        </div>
      )}
    </div>
  )
}
