"use strict";

/** BIP39 Trezor test vector #2 + known TRON Base58 for m/44'/195'/0'/0/0 (matches scripts/verify-derivation.js). */
const TEST_MNEMONIC =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

const GOLDEN_TRON_ADDRESS = "TUJ2YbSDGtCqzRz7quPQidRCMC98jDAPXc";

module.exports = {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
};
