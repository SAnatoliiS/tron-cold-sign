/**
 * Public API of the root package `tron-cold-sign`.
 * Browser ESM is built to `dist/tron-lib-esm.mjs` (`npm run build:lib`).
 * Node uses `lib/index.js` (CommonJS) via `require`.
 */

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

declare const tronLib: TronColdSignApi;
export default tronLib;
