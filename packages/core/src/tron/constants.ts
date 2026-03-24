/** BIP44 coin type 195 for TRON (SLIP-0044). */
export const TRON_DERIVATION_PATH = "m/44'/195'/0'/0/0";

/** Mainnet TRON address version byte (decimal 65, hex 0x41). */
export const TRON_ADDRESS_VERSION_BYTE = 0x41;

/** Allowed BIP39 mnemonic entropy sizes (bits). */
export const ALLOWED_ENTROPY_BITS = new Set([128, 160, 192, 224, 256]);

/** BIP44 TRON path: m/44'/195'/account'/change/index */
export const TRON_PATH_RE = /^m\/44'\/195'\/\d+'\/\d+\/\d+$/;
