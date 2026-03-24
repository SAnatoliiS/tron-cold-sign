"use strict";

/**
 * Public API for tests, browser bundle, and programmatic use (no CLI side effects).
 */

const { CliError } = require("./errors.js");
const {
	TRON_DERIVATION_PATH,
	TRON_PATH_RE,
	ALLOWED_ENTROPY_BITS,
	TRON_ADDRESS_VERSION_BYTE,
} = require("./tron/constants.js");
const {
	asBuffer,
	publicKeyUncompressedToTronAddress,
	compressedPublicKeyToTronAddress,
	tronAddressBase58ToHex,
	decodeTronAddressBase58Checked,
	encodeTronBase58CheckPayload,
} = require("./tron/address.js");
const {
	deriveWalletFromMnemonic,
	generateTronWallet,
	zeroBuffer,
} = require("./wallet/derive.js");
const { signTronTxId } = require("./tron/transaction/sign-tron-tx-id.js");
const { verifyTxIdBinding } = require("./tron/transaction/verify-tx-id.js");
const { formatHumanSummary } = require("./tron/transaction/format-summary.js");
const { normalizeTronAddress } = require("./tron/transaction/normalize-address.js");
const { parseTrc20CallData } = require("./tron/transaction/parse-trc20.js");

module.exports = {
	CliError,
	TRON_DERIVATION_PATH,
	TRON_PATH_RE,
	ALLOWED_ENTROPY_BITS,
	TRON_ADDRESS_VERSION_BYTE,
	asBuffer,
	publicKeyUncompressedToTronAddress,
	compressedPublicKeyToTronAddress,
	tronAddressBase58ToHex,
	decodeTronAddressBase58Checked,
	encodeTronBase58CheckPayload,
	deriveWalletFromMnemonic,
	generateTronWallet,
	zeroBuffer,
	signTronTxId,
	verifyTxIdBinding,
	formatHumanSummary,
	normalizeTronAddress,
	parseTrc20CallData,
};
