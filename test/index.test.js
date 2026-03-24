"use strict";

const assert = require("node:assert");
const api = require("../lib/index.js");

test("public API re-exports expected symbols", () => {
	assert.ok(api.CliError);
	assert.ok(api.TRON_DERIVATION_PATH);
	assert.strictEqual(typeof api.deriveWalletFromMnemonic, "function");
	assert.strictEqual(typeof api.generateTronWallet, "function");
	assert.strictEqual(typeof api.signTronTxId, "function");
	assert.strictEqual(typeof api.verifyTxIdBinding, "function");
	assert.strictEqual(typeof api.parseTrc20CallData, "function");
});
