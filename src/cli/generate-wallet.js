#!/usr/bin/env node
"use strict";

/**
 * Offline TRON HD wallet generation.
 *
 * - Compressed BIP32 pubkey → Keccak-256(X||Y), 0x41 prefix, Base58Check.
 * - Secrets never written to disk — stdout only with --print-secrets.
 * - Seed buffer zeroed after use; two independent derives on generate for determinism check.
 * - Bundle: npm run build → dist/bundle.js. Curve: @noble/secp256k1 (pure JS).
 */

const { CliError } = require("./errors.js");
const { TRON_DERIVATION_PATH } = require("../tron/constants.js");
const {
	decodeTronAddressBase58Checked,
	encodeTronBase58CheckPayload,
} = require("../tron/address.js");
const {
	deriveWalletFromMnemonic,
	generateTronWallet,
} = require("../wallet/derive.js");
const { readPassphraseInteractive } = require("./passphrase.js");

function parseArgs(argv) {
	const opts = {
		entropyBits: 256,
		printSecrets: false,
		json: false,
		help: false,
		fromMnemonic: null,
		expectAddress: null,
	};

	for (let i = 2; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--help" || a === "-h") {
			opts.help = true;
		} else if (a === "--print-secrets") {
			opts.printSecrets = true;
		} else if (a === "--json") {
			opts.json = true;
		} else if (a === "--entropy-bits") {
			const v = argv[++i];
			if (v === undefined)
				throw new CliError("Expected value after --entropy-bits");
			opts.entropyBits = parseInt(v, 10);
		} else if (a === "--from-mnemonic") {
			const v = argv[++i];
			if (v === undefined)
				throw new CliError("Expected mnemonic after --from-mnemonic");
			opts.fromMnemonic = v;
		} else if (a === "--expect-address") {
			const v = argv[++i];
			if (v === undefined)
				throw new CliError("Expected Base58 address after --expect-address");
			opts.expectAddress = v;
		} else {
			throw new CliError(`Unknown argument: ${a} (use --help)`);
		}
	}

	return opts;
}

function printHelp() {
	console.log(`
Usage: node generate-wallet.secure.js [options]

  Secrets are never written to files. Mnemonic and private key go to stdout only with
  --print-secrets (offline, manual copy). Writing seed to a file is intentionally disabled.

  A BIP39 passphrase is requested before derivation (hidden input); empty = none.

Options:
  --entropy-bits <N>      Entropy: 128, 160, 192, 224, or 256 (default 256).
  --print-secrets         Print mnemonic and private key hex to stdout.
  --json                  JSON output.
  --from-mnemonic <words> Verify mode: derive from existing mnemonic (no generation).
  --expect-address <T>    With --from-mnemonic: require matching Base58 address (0x41 prefix); else exit 1.
  --help, -h              This help.

Public fields (always): Base58 address, hex address (0x41…), derivation path ${TRON_DERIVATION_PATH}.

Examples:
  node generate-wallet.secure.js --print-secrets
  node generate-wallet.secure.js --from-mnemonic "legal winner thank year ... yellow" --expect-address T...
`);
}

function outputWallet(wallet, opts, mode) {
	const pub = {
		address: wallet.address,
		addressHex: wallet.addressHex,
		derivationPath: wallet.derivationPath,
	};

	if (opts.json) {
		const out = {
			...pub,
			entropyBits: mode === "generate" ? opts.entropyBits : undefined,
		};
		if (opts.printSecrets) {
			Object.assign(out, {
				mnemonic: wallet.mnemonic,
				privateKeyHex: wallet.privateKeyHex,
			});
		} else {
			out.secretsIncluded = false;
			out.hint =
				"Mnemonic and key appear in JSON only with --print-secrets (secrets are not written to files).";
		}
		console.log(JSON.stringify(out, null, 2));
		return;
	}

	console.log("--- Public data ---");
	console.log("Address (Base58):", wallet.address);
	console.log("Address (hex):   ", wallet.addressHex);
	console.log("Derivation path: ", wallet.derivationPath);
	if (mode === "generate") {
		console.log("Entropy (bits):  ", opts.entropyBits);
	}

	if (opts.printSecrets) {
		console.log("\n--- SECRET DATA ---");
		console.log("Mnemonic:", wallet.mnemonic);
		console.log("Private key (hex):", wallet.privateKeyHex);
	} else {
		console.log(
			"\n[i] Mnemonic and private key are hidden. Use --print-secrets (offline).",
		);
	}
}

async function main() {
	const opts = parseArgs(process.argv);

	if (opts.help) {
		printHelp();
		return 0;
	}

	if (opts.expectAddress !== null && opts.fromMnemonic === null) {
		throw new CliError("--expect-address requires --from-mnemonic");
	}

	let expectAddressCanonical = null;
	if (opts.fromMnemonic !== null && opts.expectAddress !== null) {
		const raw = decodeTronAddressBase58Checked(opts.expectAddress);
		expectAddressCanonical = encodeTronBase58CheckPayload(raw);
	}

	if (opts.printSecrets) {
		console.error(
			"\n[!] WARNING: --print-secrets prints mnemonic and key to the terminal. Risk: logs, history, screenshots.\n",
		);
	}

	const passphrase = await readPassphraseInteractive();

	if (opts.fromMnemonic) {
		const wallet = deriveWalletFromMnemonic(opts.fromMnemonic, passphrase);

		if (
			expectAddressCanonical !== null &&
			wallet.address !== expectAddressCanonical
		) {
			console.error("Address check failed.");
			console.error("  Expected (--expect-address):", expectAddressCanonical);
			console.error("  Derived:                    ", wallet.address);
			throw new CliError("Address check failed.", 1);
		}

		if (expectAddressCanonical !== null) {
			console.error("[i] Address matches --expect-address.");
		}

		outputWallet(wallet, opts, "verify");
		return 0;
	}

	const wallet = generateTronWallet(opts.entropyBits, passphrase);
	outputWallet(wallet, opts, "generate");
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
	outputWallet,
	main,
	runCli,
};
