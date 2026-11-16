/**
 * Per-project choices (`TradecraftProjectChoice`): a row means "turned off in this project", no
 * row means on (R-059). T4.4 adds the project side; the resource side lives here.
 */
import type { Prisma } from '@prisma/client'

/**
 * Forgets every project's choice for a resource. A change of the resource's global Enabled
 * resets them in the same transaction (R-062): after it, the resource is on in every project
 * when enabled and off everywhere when disabled.
 */
export async function clearChoicesForResource(tx: Prisma.TransactionClient, resourceId: string): Promise<number> {
  const { count } = await tx.tradecraftProjectChoice.deleteMany({ where: { resourceId } })
  return count
}
