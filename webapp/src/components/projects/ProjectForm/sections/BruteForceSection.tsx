'use client'

import { useState } from 'react'
import { ChevronDown, KeyRound } from 'lucide-react'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface BruteForceSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function BruteForceSection({ data, updateField }: BruteForceSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <KeyRound size={16} />
          Brute Force Credential Guess
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Configure brute force credential guessing attack parameters including speed throttling and retry limits.
          </p>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Bruteforce Speed</label>
              <select
                className="select"
                value={data.agentBruteforceSpeed}
                onChange={(e) => updateField('agentBruteforceSpeed', parseInt(e.target.value))}
              >
                <option value={5}>5 — No delay (Fastest)</option>
                <option value={4}>4 — 0.1s delay (Aggressive)</option>
                <option value={3}>3 — 0.5s delay (Normal)</option>
                <option value={2}>2 — 1s delay (Polite)</option>
                <option value={1}>1 — 15s delay (Sneaky)</option>
                <option value={0}>0 — 5 min delay (Glacial/Stealth)</option>
              </select>
              <span className={styles.fieldHint}>Delay between login attempts. Lower values reduce detection risk but take longer.</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Brute Force Max Wordlist Attempts</label>
              <input
                type="number"
                className="textInput"
                value={data.agentBruteForceMaxWordlistAttempts}
                onChange={(e) => updateField('agentBruteForceMaxWordlistAttempts', parseInt(e.target.value) || 3)}
                min={1}
                max={10}
              />
              <span className={styles.fieldHint}>Wordlist combinations to try before giving up</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
