"use strict";

/**
 * bip32 TinySecp256k1Interface backed by @noble/secp256k1 (pure JS, no WASM).
 * Synchronous sign/verify need sha256/hmacSha256 wired below.
 */

const secp = require("@noble/secp256k1");
const { hmac } = require("@noble/hashes/hmac.js");
const { sha256 } = require("@noble/hashes/sha2.js");

secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;

const { Point, etc, getPublicKey, sign, verify, utils } = secp;

const N = Point.CURVE().n;

function isPoint(p) {
	return utils.isValidPublicKey(p);
}

function isPrivate(d) {
	return utils.isValidSecretKey(d);
}

function pointFromScalar(d, compressed) {
	try {
		if (!isPrivate(d)) return null;
		return getPublicKey(d, compressed !== false);
	} catch {
		return null;
	}
}

function pointAddScalar(p, tweak, compressed) {
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

function privateAdd(d, tweak) {
	let dScalar;
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

function eccSign(h, d, e) {
	const opts = { prehash: false };
	if (e !== undefined) opts.extraEntropy = e;
	return sign(h, d, opts);
}

function eccVerify(h, q, signature, strict) {
	return verify(signature, h, q, {
		prehash: false,
		lowS: strict !== false,
	});
}

/** tiny-secp256k1-compatible compress/decompress. */
function pointCompress(p, compressed) {
	try {
		return Point.fromBytes(p).toBytes(compressed !== false);
	} catch {
		return null;
	}
}

module.exports = {
	isPoint,
	isPrivate,
	pointFromScalar,
	pointAddScalar,
	privateAdd,
	sign: eccSign,
	verify: eccVerify,
	pointCompress,
};
