/** The capabilities and switch state the rule reads, as useCan / useRbacFlags answer them. */
export interface OwnPasswordDialogInput {
  /** users:read: the user directory. */
  readUsers: boolean
  /** users:impersonate: the user switcher in the user menu. */
  switchUser: boolean
  /** RBAC_PERMISSIONS_ENABLED as /api/auth/me answered it. */
  permissionsOn: boolean
}

/**
 * Whether `/settings/users?changePassword=true` opens the own-password dialog for the signed-in
 * account: the one rule the user menu's Change Password and the Users page both follow, so the menu
 * never offers an item the page does not open (the S5 red P6-01).
 *
 * With the permissions switch on, for everyone: a person may hold the directory without the switcher
 * (the User manager set), and the page shows the dialog over the directory. Off, permissions follow
 * the account type, so holding both means a Phase 1 admin, who sets their own password from their
 * row and whose switcher menu never offered the item: their typed address opens nothing (DV-30).
 */
export function opensOwnPasswordDialog({ readUsers, switchUser, permissionsOn }: OwnPasswordDialogInput): boolean {
  return permissionsOn || !(readUsers && switchUser)
}
