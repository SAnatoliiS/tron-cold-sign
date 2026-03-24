"use strict";

jest.mock("../cli/passphrase.js", () => ({
	readPassphraseInteractive: jest.fn(() => Promise.resolve("")),
}));

const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("path");
const { spawnSync } = require("node:child_process");
const {
	parseArgs,
	printHelp,
	outputWallet,
	main,
} = require("../cli/generate-wallet.js");
const { CliError } = require("../cli/errors.js");
const passphraseMod = require("../cli/passphrase.js");
const { deriveWalletFromMnemonic } = require("../lib/wallet/derive.js");
const {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
} = require("./test-constants.js");

const repoRoot = path.join(__dirname, "..");

describe("parseArgs", () => {
	test("full flag set", () => {
		const o = parseArgs([
			"node",
			"x",
			"--print-secrets",
			"--json",
			"--entropy-bits",
			"128",
			"--mnemonic-file",
			"/tmp/seed.txt",
			"--expect-address",
			"TTest",
		]);
		assert.strictEqual(o.printSecrets, true);
		assert.strictEqual(o.json, true);
		assert.strictEqual(o.entropyBits, 128);
		assert.strictEqual(o.mnemonicFile, "/tmp/seed.txt");
		assert.strictEqual(o.expectAddress, "TTest");
	});

	test("--expect-address without value throws", () => {
		assert.throws(
			() =>
				parseArgs([
					"node",
					"x",
					"--mnemonic-file",
					"/tmp/m.txt",
					"--expect-address",
				]),
			/Base58 address/,
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
			const text = lines.join("\n");
			assert.match(text, /generate-wallet\.secure\.js/);
			assert.match(text, /--mnemonic-file/);
		} finally {
			spy.mockRestore();
		}
	});
});

describe("outputWallet", () => {
	const wallet = {
		address: "TAddr",
		addressHex: "0x41aa",
		derivationPath: "m/44'/195'/0'/0/0",
		mnemonic: "a b c",
		privateKeyHex: "abcd",
	};

	test("plain text generate without secrets", () => {
		const lines = [];
		const spy = jest.spyOn(console, "log").mockImplementation((...a) => {
			lines.push(a.join(" "));
		});
		try {
			outputWallet(
				wallet,
				{ json: false, printSecrets: false, entropyBits: 256 },
				"generate",
			);
			const t = lines.join("\n");
			assert.match(t, /TAddr/);
			assert.match(t, /Entropy/);
			assert.match(t, /hidden/);
		} finally {
			spy.mockRestore();
		}
	});

	test("JSON verify without secrets includes hint", () => {
		const lines = [];
		const spy = jest.spyOn(console, "log").mockImplementation((s) => {
			lines.push(String(s));
		});
		try {
			outputWallet(wallet, { json: true, printSecrets: false }, "verify");
			const obj = JSON.parse(lines[0]);
			assert.strictEqual(obj.secretsIncluded, false);
			assert.ok(obj.hint);
		} finally {
			spy.mockRestore();
		}
	});

	test("JSON with secrets includes mnemonic and entropy in generate mode", () => {
		const lines = [];
		const spy = jest.spyOn(console, "log").mockImplementation((s) => {
			lines.push(String(s));
		});
		try {
			outputWallet(
				wallet,
				{ json: true, printSecrets: true, entropyBits: 256 },
				"generate",
			);
			const obj = JSON.parse(lines[0]);
			assert.strictEqual(obj.mnemonic, "a b c");
			assert.strictEqual(obj.privateKeyHex, "abcd");
			assert.strictEqual(obj.entropyBits, 256);
		} finally {
			spy.mockRestore();
		}
	});
});

describe("main", () => {
	const oldArgv = process.argv;
	const oldErr = console.error;
	let consoleLogSpy;

	beforeEach(() => {
		consoleLogSpy = jest
			.spyOn(console, "log")
			.mockImplementation(() => {});
	});

	afterEach(() => {
		process.argv = oldArgv;
		console.error = oldErr;
		consoleLogSpy.mockRestore();
		passphraseMod.readPassphraseInteractive.mockResolvedValue("");
	});

	test("help exits without passphrase", async () => {
		process.argv = ["node", "x", "--help"];
		const code = await main();
		assert.strictEqual(code, 0);
	});

	test("--expect-address without --mnemonic-file throws", async () => {
		process.argv = ["node", "x", "--expect-address", GOLDEN_TRON_ADDRESS];
		await assert.rejects(main(), (e) => e instanceof CliError);
	});

	test("verify flow with matching address", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gw-mn-"));
		try {
			const mPath = path.join(tmpDir, "m.txt");
			fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
			const errLines = [];
			console.error = (...a) => {
				errLines.push(a.join(" "));
			};
			process.argv = [
				"node",
				"x",
				"--mnemonic-file",
				mPath,
				"--expect-address",
				GOLDEN_TRON_ADDRESS,
			];
			const code = await main();
			assert.strictEqual(code, 0);
			assert.ok(errLines.some((l) => /Address matches/.test(l)));
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	test("verify flow address mismatch", async () => {
		const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gw-mn-"));
		try {
			const other = deriveWalletFromMnemonic(
				TEST_MNEMONIC,
				"",
				"m/44'/195'/0'/0/1",
			);
			const mPath = path.join(tmpDir, "m.txt");
			fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
			process.argv = [
				"node",
				"x",
				"--mnemonic-file",
				mPath,
				"--expect-address",
				other.address,
			];
			await assert.rejects(
				main(),
				(e) => e instanceof CliError && e.exitCode === 1,
			);
		} finally {
			errSpy.mockRestore();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	test("print-secrets warns on stderr", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gw-mn-"));
		try {
			const mPath = path.join(tmpDir, "m.txt");
			fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
			const errLines = [];
			console.error = (...a) => {
				errLines.push(a.join(" "));
			};
			process.argv = [
				"node",
				"x",
				"--mnemonic-file",
				mPath,
				"--expect-address",
				GOLDEN_TRON_ADDRESS,
				"--print-secrets",
			];
			await main();
			assert.ok(errLines.some((l) => /WARNING.*print-secrets/.test(l)));
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});

test("integration: generate-wallet.secure.js verify via subprocess", () => {
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gw-int-"));
	try {
		const mPath = path.join(tmpDir, "seed.txt");
		fs.writeFileSync(mPath, TEST_MNEMONIC, "utf8");
		const r = spawnSync(
			process.execPath,
			[
				path.join(repoRoot, "generate-wallet.secure.js"),
				"--mnemonic-file",
				mPath,
				"--expect-address",
				GOLDEN_TRON_ADDRESS,
			],
			{ cwd: repoRoot, encoding: "utf8", input: "\n" },
		);
		assert.strictEqual(r.status, 0, r.stderr);
		assert.match(r.stdout, /TUJ2YbSDGtCqzRz7quPQidRCMC98jDAPXc/);
	} finally {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	}
});
