"use strict";

const { sha256 } = require("@noble/hashes/sha2.js");

/**
 * Ensure tx.txID matches SHA256(raw_data_hex) to mitigate tampering.
 * @param {{ raw_data_hex?: string, txID?: string }} tx
 */
function verifyTxIdBinding(tx) {
	const hex = tx.raw_data_hex;
	if (typeof hex !== "string" || hex.length < 64) {
		throw new Error("Transaction has no valid raw_data_hex");
	}
	const rawBytes = Buffer.from(hex.replace(/^0x/i, ""), "hex");
	const digest = Buffer.from(sha256(rawBytes));
	const tid = String(tx.txID || "").replace(/^0x/i, "");
	if (tid.length !== 64) {
		throw new Error("Transaction has no valid txID (64 hex)");
	}
	const expected = Buffer.from(tid, "hex");
	if (digest.length !== 32 || !digest.equals(expected)) {
		throw new Error(
			"txID does not match SHA256(raw_data_hex). Transaction may have been tampered with — signing refused.",
		);
	}
}

module.exports = { verifyTxIdBinding };
