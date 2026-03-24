#!/usr/bin/env node
"use strict";

/**
 * Offline signing of an unsigned TRON transaction (JSON: txID, raw_data, raw_data_hex).
 *
 * Recomputes txID = SHA256(raw_data_hex); shows recipient, amounts, fee; TRC20 transfer/transferFrom;
 * signs only after manual YES confirmation. No network. Signature compatible with TronWeb.
 */

const fs = require("fs");
const readline = require("readline");
const { CliError } = require("./errors.js");
const {
	TRON_DERIVATION_PATH,
	deriveWalletFromMnemonic,
	signTronTxId,
	verifyTxIdBinding,
	formatHumanSummary,
	normalizeTronAddress,
} = require("@tron-cold-sign/core");
const { readPassphraseInteractive } = require("./passphrase.js");

function readMnemonicFromFile(filePath) {
	const p = String(filePath).trim();
	const data = fs.readFileSync(p, "utf8");
	return data.trim().replace(/\s+/g, " ");
}

function readLine(question) {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});
		rl.question(question, (answer) => {
			rl.close();
			resolve(String(answer).trim());
		});
	});
}

function parseArgs(argv) {
	const opts = {
		txFile: null,
		mnemonicFile: null,
		derivationPath: TRON_DERIVATION_PATH,
		json: false,
		help: false,
	};

	for (let i = 2; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--help" || a === "-h") {
			opts.help = true;
		} else if (a === "--tx") {
			const v = argv[++i];
			if (!v) throw new CliError("Expected path after --tx");
			opts.txFile = v;
		} else if (a === "--mnemonic-file") {
			const v = argv[++i];
			if (!v) throw new CliError("Expected path after --mnemonic-file");
			opts.mnemonicFile = v;
		} else if (a === "--derivation-path") {
			const v = argv[++i];
			if (!v) throw new CliError("Expected derivation path after --derivation-path");
			opts.derivationPath = v;
		} else if (a === "--json") {
			opts.json = true;
		} else {
			throw new CliError(`Unknown argument: ${a} (see --help)`);
		}
	}

	return opts;
}

function printHelp() {
	console.log(`
Offline TRON transaction signing (no network).

Input: unsigned transaction JSON (e.g. TronGrid / wallet): txID, raw_data, raw_data_hex.

Before signing:
  — Verifies txID = SHA256(raw_data_hex);
  — Prints recipient, amount: TRX (TransferContract), TRC20 transfer/transferFrom (raw amount);
  — fee_limit;
  — You must type YES to confirm.

Risk: the review text comes from JSON raw_data; txID and the signature bind only to raw_data_hex.
This tool does not prove they match—use a trusted unsigned tx file or decode raw_data_hex elsewhere
and compare before YES.

Mnemonic: from file only (--mnemonic-file); file content is not logged. BIP39 passphrase
  is prompted the same way as generate-wallet.secure.js.

Options:
  --tx <file>               Unsigned transaction JSON (required)
  --mnemonic-file <file>    BIP39 mnemonic (one line or multiple words)
  --derivation-path <path>  Default ${TRON_DERIVATION_PATH}
  --json                    Signed transaction as one-line JSON on stdout
  --help, -h

Example:
  node sign-transaction.secure.js --tx unsigned.json --mnemonic-file seed.txt
`);
}

async function main() {
	const opts = parseArgs(process.argv);

	if (opts.help) {
		printHelp();
		return 0;
	}

	if (!opts.txFile) {
		throw new CliError(
			"Provide --tx <file.json> with an unsigned transaction.",
		);
	}

	if (!opts.mnemonicFile) {
		throw new CliError(
			"Provide --mnemonic-file <file> with the mnemonic (do not pass the phrase on the command line).",
		);
	}

	let txRaw;
	try {
		txRaw = fs.readFileSync(opts.txFile, "utf8");
	} catch (e) {
		throw new CliError(
			"Failed to read --tx: " + String(e.message || e),
		);
	}

	let tx;
	try {
		tx = JSON.parse(txRaw);
	} catch (e) {
		throw new CliError(
			"Invalid JSON in --tx: " + String(e.message || e),
		);
	}

	verifyTxIdBinding(tx);

	if (!tx.raw_data || typeof tx.raw_data !== "object") {
		throw new CliError("Transaction has no raw_data");
	}

	console.error("\n--- Review (offline) ---\n");
	console.error(formatHumanSummary(tx.raw_data));
	console.error("\ntxID (bound to raw_data_hex):", String(tx.txID).replace(/^0x/i, ""));
	console.error("---\n");
	console.error(
		"Warning: summary is from raw_data JSON; signature binds only to raw_data_hex. If unsure, verify hex independently.\n",
	);

	const answer = await readLine('Type YES to sign (or press Enter to cancel): ');
	if (answer !== "YES") {
		throw new CliError("Cancelled.", 2);
	}

	let mnemonic;
	try {
		mnemonic = readMnemonicFromFile(opts.mnemonicFile);
	} catch (e) {
		throw new CliError(
			"Failed to read --mnemonic-file: " + String(e.message || e),
		);
	}

	const passphrase = await readPassphraseInteractive();

	const wallet = deriveWalletFromMnemonic(
		mnemonic,
		passphrase,
		opts.derivationPath,
	);

	const contracts = tx.raw_data.contract || [];
	let ownerChecks = 0;
	for (let i = 0; i < contracts.length; i++) {
		const val = contracts[i].parameter && contracts[i].parameter.value;
		if (!val || val.owner_address == null) {
			continue;
		}
		let ownerExpected;
		try {
			ownerExpected = normalizeTronAddress(val.owner_address, "owner_address");
		} catch (e) {
			throw new CliError(
				`Contract #${i + 1}: invalid owner_address — ${e.message || e}`,
				1,
			);
		}
		ownerChecks += 1;
		if (ownerExpected !== wallet.address) {
			console.error("Error: derived address does not match contract owner.");
			console.error(`  Contract #${i + 1}: expected owner_address`, ownerExpected);
			console.error("  Wallet (derive):              ", wallet.address);
			throw new CliError("", 1);
		}
	}
	if (ownerChecks === 0) {
		throw new CliError(
			"No contract with a valid owner_address to verify against your wallet — signing refused.",
			1,
		);
	}

	if (Array.isArray(tx.signature) && tx.signature.length > 0) {
		throw new CliError(
			"Transaction already has signature(s) — refused (remove signatures from JSON or use a new unsigned tx).",
		);
	}

	const priv = Buffer.from(wallet.privateKeyHex, "hex");
	let sigHex;
	try {
		sigHex = signTronTxId(tx.txID, priv);
	} finally {
		priv.fill(0);
	}

	const signed = { ...tx, signature: [sigHex] };

	if (opts.json) {
		console.log(JSON.stringify(signed));
	} else {
		console.log(JSON.stringify(signed, null, 2));
	}
	return 0;
}

function runCli() {
	main()
		.then((code) => process.exit(code ?? 0))
		.catch((e) => {
			if (e instanceof CliError) {
				if (e.message) {
					console.error(e.message);
				}
				process.exit(e.exitCode);
				return;
			}
			console.error(String(e && e.message ? e.message : e));
			process.exit(1);
		});
}

if (require.main === module) {
	runCli();
}

module.exports = {
	parseArgs,
	printHelp,
	main,
	runCli,
};
