'use client'

import { SetsManager } from './SetsManager'

/**
 * /admin/permission-sets (step 6.3, GV-02): the member permission sets, built-in and custom, with
 * their holders. The console shell opens it with roles:manage.
 */
export default function PermissionSetsPage() {
  return <SetsManager kind="member" />
}
