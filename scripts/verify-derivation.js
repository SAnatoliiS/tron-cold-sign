#!/usr/bin/env node
"use strict";

/**
 * Regression check: our address matches TronWeb for a fixed BIP39 test mnemonic.
 * Run: npm run verify (no network required for the check itself; TronWeb is loaded locally).
 */

const bip39 = require("bip39");
const bip32 = require("bip32");
const ecc = require("../src/crypto/ecc-noble.js");
const { TronWeb } = require("tronweb");
const { compressedPublicKeyToTronAddress } = require("../src/tron/address.js");

const TEST_MNEMONIC =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC);
const root = bip32.BIP32Factory(ecc).fromSeed(seed);
const child = root.derivePath("m/44'/195'/0'/0/0");

const ours = compressedPublicKeyToTronAddress(child.publicKey);
const privHex = Buffer.from(child.privateKey).toString("hex");

const tw = new TronWeb({ fullHost: "https://api.trongrid.io" });
const reference = tw.address.fromPrivateKey(privHex);

if (!reference || reference === false) {
	console.error("verify: TronWeb could not derive address from private key");
	process.exit(1);
}

if (ours !== reference) {
	console.error("verify: address mismatch");
	console.error("  src/tron/address:", ours);
	console.error("  tronweb:         ", reference);
	process.exit(1);
}

console.log("verify: OK — address matches TronWeb:", ours);
