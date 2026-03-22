"use strict";

/**
 * TRON Base58Check address encoding from public keys (Keccak-256 over X||Y, prefix 0x41).
 * Offline-only; no I/O.
 */

const ecc = require("../crypto/ecc-noble.js");
const { createBase58check } = require("@scure/base");
const { sha256 } = require("@noble/hashes/sha2.js");
const { keccak_256 } = require("@noble/hashes/sha3.js");
const { TRON_ADDRESS_VERSION_BYTE } = require("./constants.js");

const tronBase58Check = createBase58check((data) => sha256(data));

/** Normalize to Buffer (bip32 / @noble may return Buffer | Uint8Array). */
function asBuffer(bytes) {
	return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
}

/**
 * TRON address from uncompressed public key (65 bytes: 0x04 || X || Y).
 * @param {Buffer | Uint8Array} uncompressedPubKey
 * @returns {string} Base58Check mainnet address
 */
function publicKeyUncompressedToTronAddress(uncompressedPubKey) {
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

/**
 * @param {Buffer | Uint8Array} compressedPubKey
 * @returns {string} Base58Check mainnet address
 */
function compressedPublicKeyToTronAddress(compressedPubKey) {
	const uncompressed = ecc.pointCompress(asBuffer(compressedPubKey), false);
	if (!uncompressed) {
		throw new Error("pointCompress: failed to decompress public key");
	}
	return publicKeyUncompressedToTronAddress(asBuffer(uncompressed));
}

/** Base58 TRON address → hex payload (0x41 + 20 bytes). */
function tronAddressBase58ToHex(base58Address) {
	const raw = Buffer.from(tronBase58Check.decode(base58Address));
	return `0x${raw.toString("hex")}`;
}

/**
 * Decode and validate TRON Base58Check: checksum, 21-byte payload (0x41 + 20), mainnet prefix.
 * @param {string} base58Address
 * @returns {Buffer}
 */
function decodeTronAddressBase58Checked(base58Address) {
	const s = String(base58Address).trim();
	let raw;
	try {
		raw = Buffer.from(tronBase58Check.decode(s));
	} catch {
		throw new Error("Invalid TRON address: bad Base58Check");
	}
	if (raw.length !== 21) {
		throw new Error(
			`Invalid TRON address: expected 21 bytes after decode, got ${raw.length}`,
		);
	}
	if (raw[0] !== TRON_ADDRESS_VERSION_BYTE) {
		throw new Error(
			"Invalid TRON address: first byte must be 0x41 (mainnet)",
		);
	}
	return raw;
}

/** Re-encode raw 21-byte payload to canonical Base58 (after validation). */
function encodeTronBase58CheckPayload(rawPayload) {
	return tronBase58Check.encode(rawPayload);
}

module.exports = {
	asBuffer,
	publicKeyUncompressedToTronAddress,
	compressedPublicKeyToTronAddress,
	tronAddressBase58ToHex,
	decodeTronAddressBase58Checked,
	encodeTronBase58CheckPayload,
};
