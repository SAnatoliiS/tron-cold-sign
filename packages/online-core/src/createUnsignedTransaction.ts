/**
 * Online-only: build an unsigned TRX TransferContract transaction via TronWeb.
 * Never loads or uses private keys.
 */

import { TronWeb } from "tronweb";
import {
  decodeTronAddressBase58Checked,
  verifyTxIdBinding,
} from "@tron-cold-sign/core";

export type UnsignedTransaction = {
  txID: string;
  raw_data: object;
  raw_data_hex: string;
};

export type CreateUnsignedTransactionParams = {
  from: string;
  to: string;
  amountSun: number;
  fullHost: string;
};

/** Max TRX supply order of magnitude; sun must stay within safe integer range. */
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

function validateAddresses(from: string, to: string): void {
  decodeTronAddressBase58Checked(from);
  decodeTronAddressBase58Checked(to);
  const f = String(from).trim();
  const t = String(to).trim();
  if (f === t) {
    throw new Error("from and to must be different addresses");
  }
}

function deepCloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

type TronWebTransaction = {
  txID?: string;
  raw_data?: unknown;
  raw_data_hex?: string;
  signature?: string[];
  [key: string]: unknown;
};

function stripSignature(tx: TronWebTransaction): UnsignedTransaction {
  const cloned = deepCloneJson(tx);
  if ("signature" in cloned) {
    delete cloned.signature;
  }
  if (typeof cloned.txID !== "string" || cloned.txID.length === 0) {
    throw new Error("Transaction from node is missing txID");
  }
  if (typeof cloned.raw_data_hex !== "string" || cloned.raw_data_hex === "") {
    throw new Error("Transaction from node is missing raw_data_hex");
  }
  if (typeof cloned.raw_data !== "object" || cloned.raw_data === null) {
    throw new Error("Transaction from node is missing raw_data");
  }
  if ("signature" in cloned) {
    throw new Error("Internal error: signature field was not removed");
  }
  return {
    txID: cloned.txID,
    raw_data: cloned.raw_data as object,
    raw_data_hex: cloned.raw_data_hex,
  };
}

/**
 * Creates an unsigned TRX transfer using the connected full node (ref block, etc.).
 * Strips any signature field and verifies txID = SHA256(raw_data_hex).
 */
export async function createUnsignedTransaction(
  params: CreateUnsignedTransactionParams,
): Promise<UnsignedTransaction> {
  assertValidFullHost(params.fullHost);
  assertValidAmount(params.amountSun);
  validateAddresses(params.from, params.to);

  const from = String(params.from).trim();
  const to = String(params.to).trim();

  const tronWeb = new TronWeb({ fullHost: params.fullHost.trim() });

  let built: TronWebTransaction;
  try {
    built = (await tronWeb.transactionBuilder.sendTrx(
      to,
      params.amountSun,
      from,
    )) as unknown as TronWebTransaction;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to build transaction: ${msg}`);
  }

  const unsigned = stripSignature(built);
  verifyTxIdBinding({
    txID: unsigned.txID,
    raw_data_hex: unsigned.raw_data_hex,
  });
  return unsigned;
}
