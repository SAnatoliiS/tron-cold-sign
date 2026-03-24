"use strict";

/**
 * Ensures private key buffer is zeroed even when signTronTxId throws.
 */

jest.mock("../cli/passphrase.js", () => ({
	readPassphraseInteractive: jest.fn(() => Promise.resolve("")),
}));

let capturedPriv;
jest.mock("@tron-cold-sign/core", () => {
	const actual = jest.requireActual("@tron-cold-sign/core");
	return {
		...actual,
		signTronTxId: jest.fn((_txId, priv) => {
			capturedPriv = priv;
			throw new Error("sign failed");
		}),
	};
});

const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("readline");
const { sha256 } = require("@noble/hashes/sha2.js");
const { main } = require("../cli/sign-transaction.js");
const {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
} = require("./test-constants.js");

function buildUnsignedTx() {
	const rawHex = "aa".repeat(32);
	const txID = Buffer.from(sha256(Buffer.from(rawHex, "hex"))).toString(
		"hex",
	);
	return {
		txID,
		raw_data_hex: rawHex,
		raw_data: {
			contract: [
				{
					type: "TransferContract",
					parameter: {
						value: {
							owner_address: GOLDEN_TRON_ADDRESS,
							to_address: GOLDEN_TRON_ADDRESS,
							amount: 1,
						},
					},
				},
			],
			fee_limit: 10,
		},
	};
}

describe("sign-transaction priv wipe on sign failure", () => {
	const oldArgv = process.argv;
	let tmpDir;
	let createInterfaceSpy;
	let consoleErrorSpy;
	let consoleLogSpy;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tron-wipe-"));
		capturedPriv = undefined;
		createInterfaceSpy = jest
			.spyOn(readline, "createInterface")
			.mockImplementation(() => ({
				question: (_q, cb) => cb("YES"),
				close: () => {},
			}));
		consoleErrorSpy = jest
			.spyOn(console, "error")
			.mockImplementation(() => {});
		consoleLogSpy = jest.spyOn(console, "log").mockImplementation(() => {});
	});

	afterEach(() => {
		process.argv = oldArgv;
		createInterfaceSpy.mockRestore();
		consoleErrorSpy.mockRestore();
		consoleLogSpy.mockRestore();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	test("zeroes private key buffer when signTronTxId throws", async () => {
		const txPath = path.join(tmpDir, "tx.json");
		fs.writeFileSync(txPath, JSON.stringify(buildUnsignedTx()), "utf8");
		const mPath = path.join(tmpDir, "m.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		process.argv = [
			"node",
			"x",
			"--tx",
			txPath,
			"--mnemonic-file",
			mPath,
			"--json",
		];

		await assert.rejects(main(), /sign failed/);
		assert.ok(capturedPriv instanceof Buffer);
		assert.strictEqual(capturedPriv.length, 32);
		assert.ok(
			capturedPriv.every((b) => b === 0),
			"expected priv buffer to be zeroed in finally",
		);
	});
});
