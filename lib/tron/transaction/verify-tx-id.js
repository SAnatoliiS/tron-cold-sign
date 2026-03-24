"use strict";

const { sha256 } = require("@noble/hashes/sha2.js");

/** Max hex chars for raw_data_hex (~8 MiB raw) to avoid OOM on malicious JSON. */
const MAX_RAW_DATA_HEX_LENGTH = 16 * 1024 * 1024;

/**
 * @param {string} label field name for errors
 * @param {string} hexWithOptional0x
 * @param {number} [exactByteLen] if set, decoded length must match
 * @returns {Buffer}
 */
function parseStrictHex(label, hexWithOptional0x, exactByteLen) {
	if (typeof hexWithOptional0x !== "string") {
		throw new Error(`Transaction has no valid ${label}`);
	}
	const h = hexWithOptional0x.replace(/^0x/i, "");
	if (label === "raw_data_hex" && h.length > MAX_RAW_DATA_HEX_LENGTH) {
		throw new Error(
			`${label} is too long (max ${MAX_RAW_DATA_HEX_LENGTH} hex characters) — refusing to parse`,
		);
	}
	if (h.length < 64) {
		throw new Error(`Transaction has no valid ${label}`);
	}
	if (h.length % 2 !== 0) {
		throw new Error(`${label} must be even-length hex`);
	}
	if (!/^[0-9a-fA-F]+$/.test(h)) {
		throw new Error(`${label} must contain only hexadecimal characters`);
	}
	const rawBytes = Buffer.from(h, "hex");
	if (rawBytes.length * 2 !== h.length) {
		throw new Error(`${label} hex decoding failed`);
	}
	if (exactByteLen !== undefined && rawBytes.length !== exactByteLen) {
		throw new Error(`${label} must be ${exactByteLen} bytes (${exactByteLen * 2} hex chars)`);
	}
	return rawBytes;
}

/**
 * Ensure tx.txID matches SHA256(raw_data_hex) to mitigate tampering.
 * @param {{ raw_data_hex?: string, txID?: string }} tx
 */
function verifyTxIdBinding(tx) {
	const rawBytes = parseStrictHex("raw_data_hex", tx.raw_data_hex);
	const digest = Buffer.from(sha256(rawBytes));
	const expected = parseStrictHex("txID", String(tx.txID || ""), 32);
	if (digest.length !== 32 || !digest.equals(expected)) {
		throw new Error(
			"txID does not match SHA256(raw_data_hex). Transaction may have been tampered with — signing refused.",
		);
	}
}

module.exports = {
	verifyTxIdBinding,
	MAX_RAW_DATA_HEX_LENGTH,
	parseStrictHex,
};
