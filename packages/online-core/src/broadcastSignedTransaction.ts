/**
 * Online-only: broadcast a signed transaction via /wallet/broadcasttransaction.
 * Never loads or uses private keys.
 */

import { TronWeb } from "tronweb";
import {
  decodeTronAddressBase58Checked,
  verifyTxIdBinding,
} from "@tron-cold-sign/core";

/** Offline-signed payload compatible with /wallet/broadcasttransaction (TronWeb uses visible on wire). */
export type SignedTransaction = {
  txID: string;
  raw_data: object;
  raw_data_hex: string;
  signature: string[];
  /** If omitted, broadcast defaults to false (protobuf-style). */
  visible?: boolean;
};

export type BroadcastResult = {
  result: boolean;
  txid?: string;
  code?: string;
  message?: string;
};

export type BroadcastSignedTransactionParams = {
  signedTx: SignedTransaction;
  fullHost: string;
};

/** TronWeb-style ECDSA signature: r (32) || s (32) || v (1) as hex = 130 chars. */
const TRON_SIGNATURE_HEX_LENGTH = 130;

const MAX_SUN = Number.MAX_SAFE_INTEGER;

function assertValidFullHost(fullHost: string): void {
  if (typeof fullHost !== "string" || fullHost.trim() === "") {
    throw new Error("fullHost must be a non-empty string");
  }
  let url: URL;
  try {
    url = new URL(fullHost.trim());
  } catch {
    throw new Error(`fullHost is not a valid URL: ${fullHost}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(
      `fullHost must use http: or https: protocol, got: ${url.protocol}`,
    );
  }
}

/**
 * Returns true if the string is a valid TRON mainnet Base58Check address (checksum verified).
 */
export function isValidTronAddress(address: string): boolean {
  try {
    decodeTronAddressBase58Checked(address);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensures amount is a positive finite integer sun value within safe integer range.
 */
export function assertValidAmount(amountSun: number): void {
  if (typeof amountSun !== "number" || Number.isNaN(amountSun)) {
    throw new Error("amountSun must be a finite number");
  }
  if (!Number.isFinite(amountSun)) {
    throw new Error("amountSun must be finite");
  }
  if (!Number.isInteger(amountSun)) {
    throw new Error("amountSun must be an integer (sun)");
  }
  if (amountSun <= 0) {
    throw new Error("amountSun must be greater than zero");
  }
  if (amountSun > MAX_SUN) {
    throw new Error("amountSun exceeds safe integer range");
  }
}

function assertValidSignedTxShape(tx: SignedTransaction): void {
  if (tx === null || typeof tx !== "object") {
    throw new Error("signedTx must be an object");
  }
  if (typeof tx.txID !== "string" || tx.txID.length === 0) {
    throw new Error("signedTx.txID must be a non-empty string");
  }
  if (typeof tx.raw_data_hex !== "string" || tx.raw_data_hex === "") {
    throw new Error("signedTx.raw_data_hex must be a non-empty string");
  }
  if (typeof tx.raw_data !== "object" || tx.raw_data === null) {
    throw new Error("signedTx.raw_data must be a non-null object");
  }
  if (!Array.isArray(tx.signature)) {
    throw new Error("signedTx.signature must be an array");
  }
  if (tx.signature.length === 0) {
    throw new Error("signedTx.signature must be non-empty (transaction is not signed)");
  }
  for (let i = 0; i < tx.signature.length; i++) {
    const sig = tx.signature[i];
    if (typeof sig !== "string" || sig.length === 0) {
      throw new Error(`signedTx.signature[${i}] must be a non-empty hex string`);
    }
    const hex = sig.replace(/^0x/i, "");
    if (hex.length !== TRON_SIGNATURE_HEX_LENGTH) {
      throw new Error(
        `signedTx.signature[${i}] must be ${TRON_SIGNATURE_HEX_LENGTH} hex characters (65 bytes), got ${hex.length}`,
      );
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error(`signedTx.signature[${i}] must contain only hexadecimal characters`);
    }
  }
}

function mapBroadcastResponse(api: Record<string, unknown>): BroadcastResult {
  const result = Boolean(api.result);
  const txid =
    typeof api.txid === "string" && api.txid.length > 0 ? api.txid : undefined;
  const code = api.code != null ? String(api.code) : undefined;
  const message = typeof api.message === "string" ? api.message : undefined;
  return {
    result,
    ...(txid !== undefined ? { txid } : {}),
    ...(code !== undefined ? { code } : {}),
    ...(message !== undefined ? { message } : {}),
  };
}

/**
 * Broadcasts a signed transaction to the given full node.
 * Validates signatures and txID binding before sending.
 */
export async function broadcastSignedTransaction(
  params: BroadcastSignedTransactionParams,
): Promise<BroadcastResult> {
  assertValidFullHost(params.fullHost);
  assertValidSignedTxShape(params.signedTx);

  const signedTx = params.signedTx;

  verifyTxIdBinding({
    txID: signedTx.txID,
    raw_data_hex: signedTx.raw_data_hex,
  });

  const tronWeb = new TronWeb({ fullHost: params.fullHost.trim() });

  const payload = {
    ...signedTx,
    visible: signedTx.visible ?? false,
  };

  try {
    // TronWeb types require their Transaction shape; runtime accepts the same JSON the node expects.
    const response = (await tronWeb.trx.sendRawTransaction(
      payload as never,
    )) as unknown;
    if (typeof response !== "object" || response === null) {
      throw new Error("Unexpected broadcast response shape");
    }
    return mapBroadcastResponse(response as Record<string, unknown>);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Broadcast failed: ${msg}`);
  }
}
