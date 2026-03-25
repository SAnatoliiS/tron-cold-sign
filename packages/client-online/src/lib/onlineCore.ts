import {
  createUnsignedTransaction as createUnsignedTransactionReal,
  createUnsignedTrc20Transfer as createUnsignedTrc20TransferReal,
  broadcastSignedTransaction as broadcastSignedTransactionReal,
  isValidTronAddress as isValidTronAddressReal,
  type UnsignedTransaction,
  type SignedTransaction,
} from "@tron-cold-sign/online-core";

export type { UnsignedTransaction, SignedTransaction };

// Thin wrappers so the UI code has a single integration boundary.
export function isValidTronAddress(address: string): boolean {
  return isValidTronAddressReal(address);
}

export function createUnsignedTransaction(
  params: Parameters<typeof createUnsignedTransactionReal>[0],
): ReturnType<typeof createUnsignedTransactionReal> {
  return createUnsignedTransactionReal(params);
}

export function createUnsignedTrc20Transfer(
  params: Parameters<typeof createUnsignedTrc20TransferReal>[0],
): ReturnType<typeof createUnsignedTrc20TransferReal> {
  return createUnsignedTrc20TransferReal(params);
}

export function broadcastSignedTransaction(
  params: Parameters<typeof broadcastSignedTransactionReal>[0],
): ReturnType<typeof broadcastSignedTransactionReal> {
  return broadcastSignedTransactionReal(params);
}

