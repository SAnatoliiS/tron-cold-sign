import tronLib from "@tron-cold-sign/core";
import type { TronColdSignApi } from "@tron-cold-sign/core";

const {
  generateTronWallet,
  deriveWalletFromMnemonic,
  verifyTxIdBinding,
  signTronTxId,
  normalizeTronAddress,
  buildUiSummaryFromRawData,
} = tronLib as TronColdSignApi;

export type GenerateWalletParams = {
  wordCount: 12 | 24;
  passphrase?: string;
};

export type GeneratedWallet = {
  mnemonic: string;
  addressBase58: string;
  addressHex?: string;
  derivationPath: string;
};

export type ParseUnsignedResult = {
  summary: {
    typeLabel: string;
    from: string;
    to: string;
    tokenContract?: string;
    tokenLabel?: string;
    amountText: string;
    feeLimitText: string;
  };
  txId: string;
  rawDataHex: string;
  warnings: string[];
};

function mapError(e: unknown): Error {
  if (e instanceof Error) {
    return e;
  }
  return new Error(String(e));
}

function entropyFromWordCount(wordCount: 12 | 24): number {
  return wordCount === 24 ? 256 : 128;
}

/**
 * Generate a new TRON wallet (BIP39 + BIP44 m/44'/195'/0'/0/0 by default from lib).
 */
export async function generateWallet(
  p: GenerateWalletParams,
): Promise<GeneratedWallet> {
  try {
    const w = generateTronWallet(
      entropyFromWordCount(p.wordCount),
      p.passphrase ?? "",
    );
    return {
      mnemonic: w.mnemonic,
      addressBase58: w.address,
      addressHex: w.addressHex,
      derivationPath: w.derivationPath,
    };
  } catch (e) {
    throw mapError(e);
  }
}

/** SHA-256 hex (lowercase) of file bytes. */
export async function hashFile(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Parse unsigned TRON transaction JSON; verify txID vs raw_data_hex; build UI summary.
 */
export async function parseUnsignedTransaction(
  fileText: string,
): Promise<ParseUnsignedResult> {
  let tx: Record<string, unknown>;
  try {
    tx = JSON.parse(fileText) as Record<string, unknown>;
  } catch {
    throw new Error("Invalid JSON in transaction file");
  }

  try {
    verifyTxIdBinding(tx as { raw_data_hex?: string; txID?: string });
  } catch (e) {
    throw mapError(e);
  }

  const raw = tx.raw_data;
  if (!raw || typeof raw !== "object") {
    throw new Error("Transaction has no raw_data");
  }

  const { summary, warnings } = buildUiSummaryFromRawData(
    raw as Record<string, unknown>,
  );

  const txId = String(tx.txID ?? "").replace(/^0x/i, "");
  const rawDataHex = String(tx.raw_data_hex ?? "").replace(/^0x/i, "");

  return {
    summary,
    txId,
    rawDataHex,
    warnings,
  };
}

function sha256HexUtf8(text: string): Promise<string> {
  const enc = new TextEncoder();
  return crypto.subtle
    .digest("SHA-256", enc.encode(text))
    .then((digest) =>
      Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    );
}

/**
 * Sign unsigned transaction JSON with derived key (same checks as CLI).
 */
export async function signTransaction(args: {
  fileText: string;
  mnemonic: string;
  passphrase?: string;
  derivationPath: string;
}): Promise<{ signedJsonText: string; signedSha256: string }> {
  let tx: Record<string, unknown> & {
    raw_data?: { contract?: unknown[] };
    signature?: unknown[];
  };
  try {
    tx = JSON.parse(args.fileText) as typeof tx;
  } catch {
    throw new Error("Invalid JSON in transaction file");
  }

  try {
    verifyTxIdBinding(tx as { raw_data_hex?: string; txID?: string });
  } catch (e) {
    throw mapError(e);
  }

  if (!tx.raw_data || typeof tx.raw_data !== "object") {
    throw new Error("Transaction has no raw_data");
  }

  if (Array.isArray(tx.signature) && tx.signature.length > 0) {
    throw new Error(
      "Transaction already has signature(s) — use an unsigned transaction.",
    );
  }

  let wallet;
  try {
    wallet = deriveWalletFromMnemonic(
      args.mnemonic,
      args.passphrase ?? "",
      args.derivationPath,
    );
  } catch (e) {
    throw mapError(e);
  }

  const contracts = tx.raw_data.contract || [];
  let ownerChecks = 0;
  for (let i = 0; i < contracts.length; i++) {
    const c = contracts[i] as {
      parameter?: { value?: Record<string, unknown> };
    };
    const val = c.parameter && c.parameter.value;
    if (!val || val.owner_address == null) {
      continue;
    }
    let ownerExpected: string;
    try {
      ownerExpected = normalizeTronAddress(
        val.owner_address,
        "owner_address",
      );
    } catch (e) {
      throw new Error(
        `Contract #${i + 1}: invalid owner_address — ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    ownerChecks += 1;
    if (ownerExpected !== wallet.address) {
      throw new Error(
        `Derived address does not match transaction owner (contract #${i + 1}).`,
      );
    }
  }

  if (ownerChecks === 0) {
    throw new Error(
      "No contract with a valid owner_address to verify — signing refused.",
    );
  }

  const priv = Buffer.from(wallet.privateKeyHex, "hex");
  let sigHex: string;
  try {
    sigHex = signTronTxId(String(tx.txID), priv);
  } catch (e) {
    throw mapError(e);
  } finally {
    priv.fill(0);
  }

  const signed = { ...tx, signature: [sigHex] };
  const signedJsonText = JSON.stringify(signed, null, 2);
  const signedSha256 = await sha256HexUtf8(signedJsonText);

  return { signedJsonText, signedSha256 };
}
