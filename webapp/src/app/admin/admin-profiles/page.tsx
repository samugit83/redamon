'use client'

import { SetsManager } from '../permission-sets/SetsManager'

/**
 * /admin/admin-profiles (step 6.3, GV-03): the admin profiles, built-in and custom, with the admins
 * holding each. The console shell opens it with admin_profiles:manage, which only the confirmed Root
 * holds; every write also takes Root's password (the routes' requireRootPower).
 */
export default function AdminProfilesPage() {
  return <SetsManager kind="admin" />
}
