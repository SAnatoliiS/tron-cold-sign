"use strict";

/**
 * Sign TRON txID with @noble/secp256k1 (RFC6979), TronWeb-compatible r||s||v hex.
 */

const secp = require("@noble/secp256k1");
const { hmac } = require("@noble/hashes/hmac.js");
const { sha256 } = require("@noble/hashes/sha2.js");

secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;

/**
 * @param {string} txIdHex
 * @param {Buffer} privateKey
 * @returns {string} hex r||s||v (TronWeb ECKeySign style)
 */
function signTronTxId(txIdHex, privateKey) {
	if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
		throw new Error("privateKey must be a 32-byte Buffer");
	}
	const clean = String(txIdHex).replace(/^0x/i, "");
	if (clean.length !== 64) {
		throw new Error("txID must be 32 bytes (64 hex characters)");
	}
	const msgHash = Buffer.from(clean, "hex");
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

module.exports = { signTronTxId };
