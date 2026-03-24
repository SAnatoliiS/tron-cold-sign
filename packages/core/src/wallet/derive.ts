/**
 * BIP39 seed → BIP44 TRON derivation. Wipes seed buffer after use.
 * No filesystem or network.
 */

import * as bip39 from "bip39";
import BIP32Factory from "bip32";
import ecc from "../crypto/ecc-noble.js";
import {
  compressedPublicKeyToTronAddress,
  tronAddressBase58ToHex,
} from "../tron/address.js";
import {
  TRON_DERIVATION_PATH,
  TRON_PATH_RE,
  ALLOWED_ENTROPY_BITS,
} from "../tron/constants.js";

const bip32 = BIP32Factory(ecc);

export function zeroBuffer(buf: Buffer | null | undefined) {
  if (buf && typeof buf.fill === "function") {
    buf.fill(0);
  }
}

/**
 * Derive wallet from mnemonic; seed buffer is zeroed in a finally block.
 */
export function deriveWalletFromMnemonic(
  mnemonic: string,
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
    const root = bip32.fromSeed(seed);
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
 */
export function generateTronWallet(entropyBits: number, passphrase = "") {
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
