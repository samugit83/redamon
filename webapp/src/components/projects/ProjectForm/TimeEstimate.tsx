'use client'

import { Clock } from 'lucide-react'
import styles from './ProjectForm.module.css'

interface TimeEstimateProps {
  estimate: string
}

export function TimeEstimate({ estimate }: TimeEstimateProps) {
  return (
    <span className={styles.timeEstimate}>
      <Clock size={10} />
      {estimate}
    </span>
  )
}
