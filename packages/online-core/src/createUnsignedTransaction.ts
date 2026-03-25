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

export type CreateUnsignedTrc20TransferParams = {
  from: string;
  to: string;
  contractAddress: string;
  /** Token amount in smallest units (base-10 integer string, e.g. "1000000" for 1 USDT if decimals=6). */
  amountSmallestUnit: string;
  fullHost: string;
  /** Max fee in SUN for TriggerSmartContract (default 150 TRX = 150_000_000). */
  feeLimitSun?: number;
};

function assertValidSmallestUnitString(amount: string): void {
  const t = String(amount).trim();
  if (!/^[0-9]+$/.test(t)) {
    throw new Error("amountSmallestUnit must be a base-10 integer string");
  }
  let bi: bigint;
  try {
    bi = BigInt(t);
  } catch {
    throw new Error("amountSmallestUnit is not a valid integer");
  }
  if (bi <= 0n) {
    throw new Error("amountSmallestUnit must be greater than zero");
  }
}

function validateTrc20Addresses(from: string, to: string, contractAddress: string): void {
  decodeTronAddressBase58Checked(from);
  decodeTronAddressBase58Checked(to);
  decodeTronAddressBase58Checked(contractAddress);
  const f = String(from).trim();
  const t = String(to).trim();
  if (f === t) {
    throw new Error("from and to must be different addresses");
  }
}

const DEFAULT_TRC20_FEE_LIMIT_SUN = 150_000_000;

/**
 * Creates an unsigned TRC20 `transfer(address,uint256)` via TriggerSmartContract.
 * Strips any signature field and verifies txID = SHA256(raw_data_hex).
 */
export async function createUnsignedTrc20Transfer(
  params: CreateUnsignedTrc20TransferParams,
): Promise<UnsignedTransaction> {
  assertValidFullHost(params.fullHost);
  assertValidSmallestUnitString(params.amountSmallestUnit);
  validateTrc20Addresses(params.from, params.to, params.contractAddress);

  const from = String(params.from).trim();
  const to = String(params.to).trim();
  const contract = String(params.contractAddress).trim();
  const amount = String(params.amountSmallestUnit).trim();
  const feeLimit =
    params.feeLimitSun !== undefined ? params.feeLimitSun : DEFAULT_TRC20_FEE_LIMIT_SUN;
  if (
    typeof feeLimit !== "number" ||
    !Number.isInteger(feeLimit) ||
    feeLimit <= 0 ||
    feeLimit > MAX_SUN
  ) {
    throw new Error("feeLimitSun must be a positive integer within safe range");
  }

  const tronWeb = new TronWeb({ fullHost: params.fullHost.trim() });

  let wrapped: {
    transaction?: TronWebTransaction;
    result?: { result: boolean; message?: string };
    Error?: string;
  };
  try {
    wrapped = (await tronWeb.transactionBuilder.triggerSmartContract(
      contract,
      "transfer(address,uint256)",
      { feeLimit },
      [
        { type: "address", value: to },
        { type: "uint256", value: amount },
      ],
      from,
    )) as unknown as typeof wrapped;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to build TRC20 transaction: ${msg}`);
  }

  if (wrapped.Error) {
    throw new Error(`Failed to build TRC20 transaction: ${wrapped.Error}`);
  }
  if (wrapped.result && wrapped.result.result === false) {
    const m = wrapped.result.message ?? "unknown";
    throw new Error(`Contract trigger rejected: ${m}`);
  }
  if (!wrapped.transaction) {
    throw new Error("Node did not return a transaction for TRC20 transfer");
  }

  const unsigned = stripSignature(wrapped.transaction as unknown as TronWebTransaction);
  verifyTxIdBinding({
    txID: unsigned.txID,
    raw_data_hex: unsigned.raw_data_hex,
  });
  return unsigned;
}
