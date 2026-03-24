"use strict";

jest.mock("../cli/passphrase.js", () => ({
	readPassphraseInteractive: jest.fn(() => Promise.resolve("")),
}));

const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("path");
const readline = require("readline");
const { sha256 } = require("@noble/hashes/sha2.js");
const {
	parseArgs,
	printHelp,
	main,
} = require("../cli/sign-transaction.js");
const { CliError } = require("../cli/errors.js");
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

/** Valid binding; unknown contract type so summary does not validate owner_address. */
function buildUnsignedTxNoOwnerField() {
	const rawHex = "bb".repeat(32);
	const txID = Buffer.from(sha256(Buffer.from(rawHex, "hex"))).toString(
		"hex",
	);
	return {
		txID,
		raw_data_hex: rawHex,
		raw_data: {
			contract: [
				{
					type: "CustomContract",
					parameter: {
						value: {},
					},
				},
			],
			fee_limit: 10,
		},
	};
}

/** Valid binding; unparsed contract type with invalid owner_address (must fail at sign). */
function buildUnsignedTxInvalidOwner() {
	const rawHex = "ee".repeat(32);
	const txID = Buffer.from(sha256(Buffer.from(rawHex, "hex"))).toString(
		"hex",
	);
	return {
		txID,
		raw_data_hex: rawHex,
		raw_data: {
			contract: [
				{
					type: "WeirdType",
					parameter: {
						value: { owner_address: "not-a-tron-address" },
					},
				},
			],
			fee_limit: 10,
		},
	};
}

describe("parseArgs", () => {
	test("parses tx, mnemonic, derivation path, json", () => {
		const o = parseArgs([
			"node",
			"x",
			"--tx",
			"/tmp/a.json",
			"--mnemonic-file",
			"/tmp/b.txt",
			"--derivation-path",
			"m/44'/195'/0'/0/1",
			"--json",
		]);
		assert.strictEqual(o.txFile, "/tmp/a.json");
		assert.strictEqual(o.mnemonicFile, "/tmp/b.txt");
		assert.strictEqual(o.derivationPath, "m/44'/195'/0'/0/1");
		assert.strictEqual(o.json, true);
	});

	test("rejects unknown flag", () => {
		assert.throws(
			() => parseArgs(["node", "x", "--nope"]),
			/Unknown argument/,
		);
	});
});

describe("printHelp", () => {
	test("prints usage", () => {
		const lines = [];
		const spy = jest.spyOn(console, "log").mockImplementation((s) => {
			lines.push(String(s));
		});
		try {
			printHelp();
			assert.match(lines.join("\n"), /--tx/);
		} finally {
			spy.mockRestore();
		}
	});
});

describe("main", () => {
	const oldArgv = process.argv;
	let tmpDir;
	let createInterfaceSpy;
	let consoleErrorSpy;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tron-st-"));
		createInterfaceSpy = jest
			.spyOn(readline, "createInterface")
			.mockImplementation(() => ({
				question: (_q, cb) => cb("YES"),
				close: () => {},
			}));
		consoleErrorSpy = jest
			.spyOn(console, "error")
			.mockImplementation(() => {});
	});

	afterEach(() => {
		process.argv = oldArgv;
		createInterfaceSpy.mockRestore();
		consoleErrorSpy.mockRestore();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	test("--help", async () => {
		const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
		try {
			process.argv = ["node", "x", "--help"];
			assert.strictEqual(await main(), 0);
		} finally {
			logSpy.mockRestore();
		}
	});

	test("requires --tx", async () => {
		process.argv = ["node", "x", "--mnemonic-file", "/x"];
		await assert.rejects(main(), (e) => e instanceof CliError);
	});

	test("requires --mnemonic-file", async () => {
		process.argv = ["node", "x", "--tx", "/x"];
		await assert.rejects(main(), (e) => e instanceof CliError);
	});

	test("invalid JSON in tx file", async () => {
		const txPath = path.join(tmpDir, "bad.json");
		fs.writeFileSync(txPath, "{", "utf8");
		const mPath = path.join(tmpDir, "m.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		process.argv = ["node", "x", "--tx", txPath, "--mnemonic-file", mPath];
		await assert.rejects(main(), (e) => e instanceof CliError);
	});

	test("signs unsigned tx and outputs JSON signature", async () => {
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
		const lines = [];
		const logSpy = jest.spyOn(console, "log").mockImplementation((s) => {
			lines.push(String(s));
		});
		try {
			assert.strictEqual(await main(), 0);
			const signed = JSON.parse(lines[0]);
			assert.ok(Array.isArray(signed.signature));
			assert.strictEqual(signed.signature.length, 1);
			assert.match(signed.signature[0], /^[0-9a-f]+$/i);
		} finally {
			logSpy.mockRestore();
		}
	});

	test("cancels when user does not type YES", async () => {
		createInterfaceSpy.mockRestore();
		jest.spyOn(readline, "createInterface").mockImplementation(() => ({
			question: (_q, cb) => cb("NO"),
			close: () => {},
		}));
		const txPath = path.join(tmpDir, "tx.json");
		fs.writeFileSync(txPath, JSON.stringify(buildUnsignedTx()), "utf8");
		const mPath = path.join(tmpDir, "m.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		process.argv = ["node", "x", "--tx", txPath, "--mnemonic-file", mPath];
		await assert.rejects(
			main(),
			(e) => e instanceof CliError && e.exitCode === 2,
		);
	});

	test("refuses when no contract has owner_address to verify", async () => {
		const txPath = path.join(tmpDir, "tx.json");
		fs.writeFileSync(
			txPath,
			JSON.stringify(buildUnsignedTxNoOwnerField()),
			"utf8",
		);
		const mPath = path.join(tmpDir, "m.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		process.argv = ["node", "x", "--tx", txPath, "--mnemonic-file", mPath];
		await assert.rejects(
			main(),
			(e) =>
				e instanceof CliError &&
				e.exitCode === 1 &&
				/no contract with a valid owner_address/i.test(e.message),
		);
	});

	test("refuses invalid owner_address on unparsed contract", async () => {
		const txPath = path.join(tmpDir, "tx.json");
		fs.writeFileSync(
			txPath,
			JSON.stringify(buildUnsignedTxInvalidOwner()),
			"utf8",
		);
		const mPath = path.join(tmpDir, "m.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		process.argv = ["node", "x", "--tx", txPath, "--mnemonic-file", mPath];
		await assert.rejects(
			main(),
			(e) =>
				e instanceof CliError &&
				e.exitCode === 1 &&
				/invalid owner_address/i.test(e.message),
		);
	});
});
