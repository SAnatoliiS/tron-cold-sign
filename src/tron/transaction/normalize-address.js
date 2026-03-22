"use strict";

const { createBase58check } = require("@scure/base");
const { sha256 } = require("@noble/hashes/sha2.js");
const {
	decodeTronAddressBase58Checked,
	encodeTronBase58CheckPayload,
} = require("../address.js");
const { TRON_ADDRESS_VERSION_BYTE } = require("../constants.js");

const tronBase58Check = createBase58check((data) => sha256(data));

/**
 * Normalize various TRON address forms to canonical Base58Check mainnet.
 * @param {unknown} value
 * @param {string} label field name for errors
 */
function normalizeTronAddress(value, label) {
	if (value === undefined || value === null) {
		throw new Error(`Contract field missing: ${label}`);
	}
	const s = String(value).trim();
	if (s.startsWith("T")) {
		const raw = decodeTronAddressBase58Checked(s);
		return encodeTronBase58CheckPayload(raw);
	}
	let h = s.replace(/^0x/i, "");
	if (h.length === 40) {
		h = "41" + h;
	}
	const buf = Buffer.from(h, "hex");
	if (buf.length !== 21 || buf[0] !== TRON_ADDRESS_VERSION_BYTE) {
		throw new Error(
			`${label}: invalid TRON hex address (expected 21 bytes starting with 0x41)`,
		);
	}
	return tronBase58Check.encode(buf);
}

module.exports = { normalizeTronAddress };
