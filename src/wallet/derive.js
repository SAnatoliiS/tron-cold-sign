"use strict";

/**
 * BIP39 seed → BIP44 TRON derivation. Wipes seed buffer after use.
 * No filesystem or network.
 */

const bip39 = require("bip39");
const bip32 = require("bip32");
const ecc = require("../crypto/ecc-noble.js");
const {
	compressedPublicKeyToTronAddress,
	tronAddressBase58ToHex,
} = require("../tron/address.js");
const {
	TRON_DERIVATION_PATH,
	TRON_PATH_RE,
	ALLOWED_ENTROPY_BITS,
} = require("../tron/constants.js");

function zeroBuffer(buf) {
	if (buf && typeof buf.fill === "function") {
		buf.fill(0);
	}
}

/**
 * Derive wallet from mnemonic; seed buffer is zeroed in a finally block.
 * @param {string} passphrase BIP39 passphrase (empty = none).
 * @param {string} [derivationPath] defaults to {@link TRON_DERIVATION_PATH}.
 */
function deriveWalletFromMnemonic(
	mnemonic,
	passphrase = "",
	derivationPath = TRON_DERIVATION_PATH,
) {
	const normalized = mnemonic.trim().replace(/\s+/g, " ");
	if (!bip39.validateMnemonic(normalized)) {
		throw new Error("Invalid BIP39 mnemonic");
	}

	if (
		typeof derivationPath !== "string" ||
		!TRON_PATH_RE.test(derivationPath.trim())
	) {
		throw new Error(
			`Invalid derivation path (expected e.g. m/44'/195'/0'/0/0): ${derivationPath}`,
		);
	}
	const pathUsed = derivationPath.trim();

	const seed = bip39.mnemonicToSeedSync(normalized, passphrase);
	try {
		const root = bip32.BIP32Factory(ecc).fromSeed(seed);
		const child = root.derivePath(pathUsed);

		const privateKey = child.privateKey;
		if (!privateKey || privateKey.every((b) => b === 0)) {
			throw new Error(
				"Derived node has no private key or zero key (unexpected for standard path)",
			);
		}

		const address = compressedPublicKeyToTronAddress(child.publicKey);
		const addressHex = tronAddressBase58ToHex(address);
		const privateKeyHex = Buffer.from(privateKey).toString("hex");

		return {
			mnemonic: normalized,
			derivationPath: pathUsed,
			privateKeyHex,
			address,
			addressHex,
		};
	} finally {
		zeroBuffer(seed);
	}
}

/**
 * Generate new mnemonic and wallet; two independent derives to verify determinism.
 * @param {string} passphrase BIP39 passphrase (empty = none).
 */
function generateTronWallet(entropyBits, passphrase = "") {
	if (!ALLOWED_ENTROPY_BITS.has(entropyBits)) {
		throw new Error(
			`entropyBits must be one of: ${[...ALLOWED_ENTROPY_BITS].join(", ")}`,
		);
	}

	const mnemonic = bip39.generateMnemonic(entropyBits);
	const a = deriveWalletFromMnemonic(mnemonic, passphrase);
	const b = deriveWalletFromMnemonic(mnemonic, passphrase);

	if (a.address !== b.address || a.privateKeyHex !== b.privateKeyHex) {
		throw new Error(
			"Determinism check failed: two derivation passes produced different results",
		);
	}

	return a;
}

module.exports = {
	deriveWalletFromMnemonic,
	generateTronWallet,
	zeroBuffer,
};
