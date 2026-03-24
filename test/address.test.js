"use strict";

const assert = require("node:assert");
const bip39 = require("bip39");
const bip32 = require("bip32");
const {
	ecc,
	compressedPublicKeyToTronAddress,
	decodeTronAddressBase58Checked,
	tronAddressBase58ToHex,
	publicKeyUncompressedToTronAddress,
	encodeTronBase58CheckPayload,
} = require("@tron-cold-sign/core");
const {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
} = require("./test-constants.js");

test("decodeTronAddressBase58Checked rejects invalid Base58", () => {
	assert.throws(
		() => decodeTronAddressBase58Checked("not-an-address"),
		/Invalid TRON address/,
	);
});

test("compressed public key yields stable Base58 mainnet address", () => {
	const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC);
	const root = bip32.BIP32Factory(ecc).fromSeed(seed);
	const child = root.derivePath("m/44'/195'/0'/0/0");
	const pub = child.publicKey;

	const a1 = compressedPublicKeyToTronAddress(pub);
	const a2 = compressedPublicKeyToTronAddress(pub);
	assert.strictEqual(a1, a2);
	assert.strictEqual(a1, GOLDEN_TRON_ADDRESS);
	assert.strictEqual(a1[0], "T");
	const hex = tronAddressBase58ToHex(a1);
	assert.match(hex, /^0x41[0-9a-f]{40}$/i);
});

test("publicKeyUncompressedToTronAddress rejects wrong length", () => {
	assert.throws(
		() => publicKeyUncompressedToTronAddress(Buffer.alloc(64)),
		/Expected 65-byte/,
	);
});

test("publicKeyUncompressedToTronAddress rejects non-0x04 prefix", () => {
	const bad = Buffer.alloc(65, 0x04);
	bad[0] = 0x03;
	assert.throws(
		() => publicKeyUncompressedToTronAddress(bad),
		/must start with 0x04/,
	);
});

test("decodeTronAddressBase58Checked rejects non-mainnet version byte", () => {
	const raw = Buffer.from(decodeTronAddressBase58Checked(GOLDEN_TRON_ADDRESS));
	raw[0] = 0x42;
	const badBase58 = encodeTronBase58CheckPayload(raw);
	assert.throws(
		() => decodeTronAddressBase58Checked(badBase58),
		/first byte must be 0x41/,
	);
});

test("compressedPublicKeyToTronAddress throws on invalid compressed key", () => {
	assert.throws(
		() => compressedPublicKeyToTronAddress(Buffer.alloc(33, 0)),
		/pointCompress/,
	);
});
