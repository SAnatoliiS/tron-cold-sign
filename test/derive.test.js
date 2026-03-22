"use strict";

const assert = require("node:assert");
const bip39 = require("bip39");
const bip32 = require("bip32");
const ecc = require("../src/crypto/ecc-noble.js");
const { compressedPublicKeyToTronAddress } = require("../src/tron/address.js");
const {
	deriveWalletFromMnemonic,
	generateTronWallet,
	zeroBuffer,
} = require("../src/wallet/derive.js");
const {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
} = require("./test-constants.js");

test("deriveWalletFromMnemonic matches direct BIP32 + address helper", () => {
	const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC);
	const root = bip32.BIP32Factory(ecc).fromSeed(seed);
	const child = root.derivePath("m/44'/195'/0'/0/0");
	const expected = compressedPublicKeyToTronAddress(child.publicKey);

	const w = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
	assert.strictEqual(w.address, expected);
	assert.strictEqual(w.address, GOLDEN_TRON_ADDRESS);
	assert.strictEqual(w.mnemonic, TEST_MNEMONIC);
	assert.match(w.privateKeyHex, /^[0-9a-f]{64}$/);
});

test("deriveWalletFromMnemonic rejects invalid path", () => {
	assert.throws(
		() => deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/60'/0'/0/0"),
		/Invalid derivation path/,
	);
});

test("deriveWalletFromMnemonic rejects invalid mnemonic", () => {
	const notInWordlist = Array(12).fill("zzzzzz").join(" ");
	assert.throws(
		() => deriveWalletFromMnemonic(notInWordlist, "", "m/44'/195'/0'/0/0"),
		/Invalid BIP39 mnemonic/,
	);
});

test("generateTronWallet rejects disallowed entropyBits", () => {
	assert.throws(() => generateTronWallet(100, ""), /entropyBits must be one of/);
	assert.throws(() => generateTronWallet(129, ""), /entropyBits must be one of/);
});

test("zeroBuffer is a no-op for missing buffer", () => {
	assert.doesNotThrow(() => zeroBuffer(null));
	assert.doesNotThrow(() => zeroBuffer(undefined));
});

test("deriveWalletFromMnemonic accepts custom derivation index", () => {
	const w0 = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
	const w1 = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/1");
	assert.notStrictEqual(w0.address, w1.address);
});
