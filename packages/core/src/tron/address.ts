/**
 * TRON Base58Check address encoding from public keys (Keccak-256 over X||Y, prefix 0x41).
 * Offline-only; no I/O.
 */

import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import ecc from "../crypto/ecc-noble.js";
import { TRON_ADDRESS_VERSION_BYTE } from "./constants.js";

const tronBase58Check = createBase58check((data: Uint8Array) => sha256(data));

/** Normalize to Buffer (bip32 / @noble may return Buffer | Uint8Array). */
export function asBuffer(bytes: Buffer | Uint8Array): Buffer {
  return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
}

/**
 * TRON address from uncompressed public key (65 bytes: 0x04 || X || Y).
 */
export function publicKeyUncompressedToTronAddress(
  uncompressedPubKey: Buffer | Uint8Array,
): string {
  const pub = asBuffer(uncompressedPubKey);
  if (pub.length !== 65) {
    throw new Error(`Expected 65-byte uncompressed key, got ${pub.length}`);
  }
  if (pub[0] !== 0x04) {
    throw new Error("Uncompressed key must start with 0x04");
  }
  const xy = pub.subarray(1, 65);
  const hash = Buffer.from(keccak_256(xy));
  const payload = Buffer.concat([
    Buffer.from([TRON_ADDRESS_VERSION_BYTE]),
    hash.subarray(-20),
  ]);
  return tronBase58Check.encode(payload);
}

export function compressedPublicKeyToTronAddress(
  compressedPubKey: Buffer | Uint8Array,
): string {
  const uncompressed = ecc.pointCompress(asBuffer(compressedPubKey), false);
  if (!uncompressed) {
    throw new Error("pointCompress: failed to decompress public key");
  }
  return publicKeyUncompressedToTronAddress(asBuffer(uncompressed));
}

/** Base58 TRON address → hex payload (0x41 + 20 bytes). */
export function tronAddressBase58ToHex(base58Address: string): string {
  const raw = Buffer.from(tronBase58Check.decode(base58Address));
  return `0x${raw.toString("hex")}`;
}

/**
 * Decode and validate TRON Base58Check: checksum, 21-byte payload (0x41 + 20), mainnet prefix.
 */
export function decodeTronAddressBase58Checked(base58Address: string): Buffer {
  const s = String(base58Address).trim();
  let raw: Uint8Array;
  try {
    raw = tronBase58Check.decode(s);
  } catch {
    throw new Error("Invalid TRON address: bad Base58Check");
  }
  const buf = Buffer.from(raw);
  if (buf.length !== 21) {
    throw new Error(
      `Invalid TRON address: expected 21 bytes after decode, got ${buf.length}`,
    );
  }
  if (buf[0] !== TRON_ADDRESS_VERSION_BYTE) {
    throw new Error("Invalid TRON address: first byte must be 0x41 (mainnet)");
  }
  return buf;
}

/** Re-encode raw 21-byte payload to canonical Base58 (after validation). */
export function encodeTronBase58CheckPayload(rawPayload: Buffer | Uint8Array) {
  return tronBase58Check.encode(rawPayload);
}
