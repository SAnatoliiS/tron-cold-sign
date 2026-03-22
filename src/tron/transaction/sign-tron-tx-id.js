"use strict";

/**
 * Sign TRON txID with secp256k1 (ethereum-cryptography), TronWeb-compatible encoding.
 */

const { secp256k1 } = require("ethereum-cryptography/secp256k1");

/**
 * @param {string} txIdHex
 * @param {Buffer} privateKey
 * @returns {string} hex r||s||v (TronWeb ECKeySign style)
 */
function signTronTxId(txIdHex, privateKey) {
	const clean = String(txIdHex).replace(/^0x/i, "");
	if (clean.length !== 64) {
		throw new Error("txID must be 32 bytes (64 hex characters)");
	}
	let pkHex = Buffer.from(privateKey).toString("hex");
	pkHex = pkHex.padStart(64, "0");
	const sig = secp256k1.sign(clean, pkHex);
	const r = sig.r.toString(16).padStart(64, "0");
	const s = sig.s.toString(16).padStart(64, "0");
	const v = sig.recovery + 27;
	const vHex = v.toString(16).padStart(2, "0").toUpperCase();
	return r + s + vHex;
}

module.exports = { signTronTxId };
