/**
 * Sign TRON txID with @noble/secp256k1 (RFC6979), TronWeb-compatible r||s||v hex.
 */

import * as secp from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseStrictHex } from "./verify-tx-id.js";

secp.hashes.hmacSha256 = (key: Uint8Array, msg: Uint8Array) =>
  hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;

/**
 * @returns hex r||s||v (TronWeb ECKeySign style)
 */
export function signTronTxId(txIdHex: string, privateKey: Buffer): string {
  if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
    throw new Error("privateKey must be a 32-byte Buffer");
  }
  const msgHash = parseStrictHex("txID", String(txIdHex), 32);
  const sig65 = secp.sign(new Uint8Array(msgHash), new Uint8Array(privateKey), {
    prehash: false,
    format: "recovered",
  });
  const r = Buffer.from(sig65.subarray(1, 33)).toString("hex");
  const s = Buffer.from(sig65.subarray(33, 65)).toString("hex");
  const v = sig65[0] + 27;
  const vHex = v.toString(16).padStart(2, "0").toUpperCase();
  return r + s + vHex;
}
