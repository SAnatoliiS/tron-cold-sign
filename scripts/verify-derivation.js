#!/usr/bin/env node
"use strict";

/**
 * Regression check: our address matches TronWeb for a fixed BIP39 test mnemonic.
 * Run: npm run verify (no network required for the check itself; TronWeb is loaded locally).
 */

const { TronWeb } = require("tronweb");
const { deriveWalletFromMnemonic } = require("@tron-cold-sign/core");

const TEST_MNEMONIC =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

const wallet = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
const ours = wallet.address;
const privHex = wallet.privateKeyHex;

const tw = new TronWeb({ fullHost: "https://api.trongrid.io" });
const reference = tw.address.fromPrivateKey(privHex);

if (!reference || reference === false) {
	console.error("verify: TronWeb could not derive address from private key");
	process.exit(1);
}

if (ours !== reference) {
	console.error("verify: address mismatch");
	console.error("  @tron-cold-sign/core:", ours);
	console.error("  tronweb:         ", reference);
	process.exit(1);
}

console.log("verify: OK — address matches TronWeb:", ours);
