'use client'

import { GlobalHeader } from '../GlobalHeader'
import { Footer } from '../Footer'
import { DisclaimerGate } from '../DisclaimerGate'
import { UpdateNotification } from '../UpdateNotification'
import { AccessNoticeToast } from '../AccessNoticeToast'
import { NavigatorRoot } from '@/components/navigator/NavigatorRoot'
import styles from './AppLayout.module.css'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className={styles.layout}>
      <GlobalHeader />
      <main className={styles.main}>
        <DisclaimerGate>
          {children}
          {/* Inside the gate: nothing of AI Navigator shows before the disclaimer is accepted. */}
          <NavigatorRoot />
        </DisclaimerGate>
      </main>
      <Footer />
      <UpdateNotification />
      <AccessNoticeToast />
    </div>
  )
}
