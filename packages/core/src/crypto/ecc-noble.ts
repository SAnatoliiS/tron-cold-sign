/**
 * bip32 TinySecp256k1Interface backed by @noble/secp256k1 (pure JS, no WASM).
 * Synchronous sign/verify need sha256/hmacSha256 wired below.
 */

import * as secp from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

secp.hashes.hmacSha256 = (key: Uint8Array, msg: Uint8Array) =>
  hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;

const { Point, etc, getPublicKey, sign, verify, utils } = secp;

const N = Point.CURVE().n;

function isPoint(p: Uint8Array) {
  return utils.isValidPublicKey(p);
}

function isPrivate(d: Uint8Array) {
  return utils.isValidSecretKey(d);
}

function pointFromScalar(d: Uint8Array, compressed?: boolean) {
  try {
    if (!isPrivate(d)) return null;
    return getPublicKey(d, compressed !== false);
  } catch {
    return null;
  }
}

function pointAddScalar(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean,
) {
  try {
    const point = Point.fromBytes(p);
    const tweakScalar = etc.mod(etc.bytesToNumberBE(tweak), N);
    let sum;
    if (tweakScalar === 0n) {
      sum = point;
    } else {
      sum = point.add(Point.BASE.multiply(tweakScalar));
    }
    return sum.toBytes(compressed !== false);
  } catch {
    return null;
  }
}

function privateAdd(d: Uint8Array, tweak: Uint8Array) {
  let dScalar: bigint;
  try {
    dScalar = etc.secretKeyToScalar(d);
  } catch {
    return null;
  }
  const t = etc.mod(etc.bytesToNumberBE(tweak), N);
  const sum = etc.mod(dScalar + t, N);
  if (sum === 0n) return null;
  const out = etc.numberToBytesBE(sum);
  if (!isPrivate(out)) return null;
  return out;
}

function eccSign(
  h: Uint8Array,
  d: Uint8Array,
  e?: Uint8Array,
): Uint8Array | null {
  const opts: { prehash: false; extraEntropy?: Uint8Array } = {
    prehash: false,
  };
  if (e !== undefined) opts.extraEntropy = e;
  return sign(h, d, opts);
}

function eccVerify(
  h: Uint8Array,
  q: Uint8Array,
  signature: Uint8Array,
  strict?: boolean,
) {
  return verify(signature, h, q, {
    prehash: false,
    lowS: strict !== false,
  });
}

/** tiny-secp256k1-compatible compress/decompress. */
function pointCompress(p: Uint8Array, compressed?: boolean) {
  try {
    return Point.fromBytes(p).toBytes(compressed !== false);
  } catch {
    return null;
  }
}

/** bip32-compatible ECC interface. */
export default {
  isPoint,
  isPrivate,
  pointFromScalar,
  pointAddScalar,
  privateAdd,
  sign: eccSign,
  verify: eccVerify,
  pointCompress,
};
