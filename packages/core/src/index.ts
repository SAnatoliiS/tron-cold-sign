/**
 * Public API for tests, browser bundle, and programmatic use (no CLI side effects).
 */

import { CliError } from "./errors.js";
import {
  TRON_DERIVATION_PATH,
  TRON_PATH_RE,
  ALLOWED_ENTROPY_BITS,
  TRON_ADDRESS_VERSION_BYTE,
} from "./tron/constants.js";
import {
  asBuffer,
  publicKeyUncompressedToTronAddress,
  compressedPublicKeyToTronAddress,
  tronAddressBase58ToHex,
  decodeTronAddressBase58Checked,
  encodeTronBase58CheckPayload,
} from "./tron/address.js";
import {
  deriveWalletFromMnemonic,
  generateTronWallet,
  zeroBuffer,
} from "./wallet/derive.js";
import { signTronTxId } from "./tron/transaction/sign-tron-tx-id.js";
import {
  verifyTxIdBinding,
  MAX_RAW_DATA_HEX_LENGTH,
  parseStrictHex,
} from "./tron/transaction/verify-tx-id.js";
import {
  formatHumanSummary,
  buildUiSummaryFromRawData,
} from "./tron/transaction/format-summary.js";
import { normalizeTronAddress } from "./tron/transaction/normalize-address.js";
import { parseTrc20CallData } from "./tron/transaction/parse-trc20.js";
import { SUN, SEL_TRANSFER, SEL_TRANSFER_FROM } from "./tron/transaction/constants.js";
import ecc from "./crypto/ecc-noble.js";

export {
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
  MAX_RAW_DATA_HEX_LENGTH,
  parseStrictHex,
  formatHumanSummary,
  buildUiSummaryFromRawData,
  normalizeTronAddress,
  parseTrc20CallData,
  SUN,
  SEL_TRANSFER,
  SEL_TRANSFER_FROM,
  ecc,
};

/** Public surface used by the React client (import types from this package). */
export interface TronColdSignApi {
  TRON_DERIVATION_PATH: string;
  generateTronWallet(
    entropyBits: number,
    passphrase?: string,
  ): {
    mnemonic: string;
    derivationPath: string;
    privateKeyHex: string;
    address: string;
    addressHex: string;
  };
  deriveWalletFromMnemonic(
    mnemonic: string,
    passphrase?: string,
    derivationPath?: string,
  ): {
    mnemonic: string;
    derivationPath: string;
    privateKeyHex: string;
    address: string;
    addressHex: string;
  };
  verifyTxIdBinding(tx: { raw_data_hex?: string; txID?: string }): void;
  signTronTxId(txIdHex: string, privateKey: Buffer): string;
  normalizeTronAddress(value: unknown, label: string): string;
  buildUiSummaryFromRawData(rawData: object): {
    summary: {
      typeLabel: string;
      from: string;
      to: string;
      tokenContract?: string;
      tokenLabel?: string;
      amountText: string;
      feeLimitText: string;
    };
    warnings: string[];
  };
}

const tronLib: TronColdSignApi & Record<string, unknown> = {
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
  MAX_RAW_DATA_HEX_LENGTH,
  parseStrictHex,
  formatHumanSummary,
  buildUiSummaryFromRawData,
  normalizeTronAddress,
  parseTrc20CallData,
  SUN,
  SEL_TRANSFER,
  SEL_TRANSFER_FROM,
  ecc,
};

export default tronLib;
