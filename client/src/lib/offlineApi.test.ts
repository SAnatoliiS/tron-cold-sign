import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import tronLib from "@tron-cold-sign/core";
import type { TronColdSignApi } from "@tron-cold-sign/core";
import { describe, expect, it } from "vitest";
import {
  generateWallet,
  hashFile,
  parseUnsignedTransaction,
  signTransaction,
} from "./offlineApi";

const { deriveWalletFromMnemonic } = tronLib as TronColdSignApi;

const require = createRequire(import.meta.url);
const { TEST_MNEMONIC, GOLDEN_TRON_ADDRESS } = require(
  "../../../test/test-constants.js",
);

/** Same mnemonic, different index — valid Base58, not m/44'/195'/0'/0/0. */
const OTHER_TRON_ADDRESS = deriveWalletFromMnemonic(
  TEST_MNEMONIC,
  "",
  "m/44'/195'/0'/0/1",
).address;

function buildUnsignedTx() {
  const rawHex = "aa".repeat(32);
  const txID = createHash("sha256")
    .update(Buffer.from(rawHex, "hex"))
    .digest("hex");
  return {
    txID,
    raw_data_hex: rawHex,
    raw_data: {
      contract: [
        {
          type: "TransferContract",
          parameter: {
            value: {
              owner_address: GOLDEN_TRON_ADDRESS,
              to_address: GOLDEN_TRON_ADDRESS,
              amount: 1,
            },
          },
        },
      ],
      fee_limit: 10,
    },
  };
}

/** Same binding as buildUnsignedTx but contracts empty (for signTransaction ownerChecks === 0). */
function buildUnsignedTxEmptyContracts() {
  const rawHex = "cc".repeat(32);
  const txID = createHash("sha256")
    .update(Buffer.from(rawHex, "hex"))
    .digest("hex");
  return {
    txID,
    raw_data_hex: rawHex,
    raw_data: {
      contract: [],
      fee_limit: 10,
    },
  };
}

describe("offlineApi", () => {
  it("generateWallet returns 12 words", async () => {
    const w = await generateWallet({ wordCount: 12 });
    expect(w.mnemonic.split(/\s+/).length).toBe(12);
    expect(w.addressBase58).toMatch(/^T/);
  });

  it("generateWallet returns 24 words", async () => {
    const w = await generateWallet({ wordCount: 24 });
    expect(w.mnemonic.split(/\s+/).length).toBe(24);
    expect(w.addressBase58).toMatch(/^T/);
  });

  it("hashFile returns SHA-256 hex of bytes", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const expected = createHash("sha256").update(Buffer.from(bytes)).digest("hex");
    const file = new File([bytes], "t.bin");
    await expect(hashFile(file)).resolves.toBe(expected);
  });

  it("parseUnsignedTransaction parses transfer", async () => {
    const tx = buildUnsignedTx();
    const r = await parseUnsignedTransaction(JSON.stringify(tx));
    expect(r.summary.typeLabel).toContain("TransferContract");
    expect(r.txId).toBe(tx.txID);
  });

  it("parseUnsignedTransaction strips 0x from txID and raw_data_hex in result", async () => {
    const base = buildUnsignedTx();
    const tx = {
      ...base,
      txID: `0x${base.txID}`,
      raw_data_hex: `0x${base.raw_data_hex}`,
    };
    const r = await parseUnsignedTransaction(JSON.stringify(tx));
    expect(r.txId).toBe(base.txID);
    expect(r.rawDataHex).toBe(base.raw_data_hex);
  });

  it("parseUnsignedTransaction rejects invalid JSON", async () => {
    await expect(parseUnsignedTransaction("{")).rejects.toThrow(
      "Invalid JSON in transaction file",
    );
  });

  it("parseUnsignedTransaction rejects txID not matching raw_data_hex", async () => {
    const tx = buildUnsignedTx();
    tx.txID = "00".repeat(32);
    await expect(parseUnsignedTransaction(JSON.stringify(tx))).rejects.toThrow(
      /txID does not match/,
    );
  });

  it("parseUnsignedTransaction rejects missing raw_data", async () => {
    const tx = buildUnsignedTx();
    const { raw_data: _, ...rest } = tx;
    await expect(parseUnsignedTransaction(JSON.stringify(rest))).rejects.toThrow(
      "Transaction has no raw_data",
    );
  });

  it("signTransaction signs with matching mnemonic", async () => {
    const tx = buildUnsignedTx();
    const out = await signTransaction({
      fileText: JSON.stringify(tx),
      mnemonic: TEST_MNEMONIC,
      derivationPath: "m/44'/195'/0'/0/0",
    });
    const signed = JSON.parse(out.signedJsonText) as {
      signature: string[];
    };
    expect(signed.signature).toHaveLength(1);
    expect(out.signedSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("signTransaction rejects invalid JSON", async () => {
    await expect(
      signTransaction({
        fileText: "{",
        mnemonic: TEST_MNEMONIC,
        derivationPath: "m/44'/195'/0'/0/0",
      }),
    ).rejects.toThrow("Invalid JSON in transaction file");
  });

  it("signTransaction rejects already signed transaction", async () => {
    const tx = buildUnsignedTx();
    const withSig = { ...tx, signature: ["abc"] };
    await expect(
      signTransaction({
        fileText: JSON.stringify(withSig),
        mnemonic: TEST_MNEMONIC,
        derivationPath: "m/44'/195'/0'/0/0",
      }),
    ).rejects.toThrow(/already has signature/);
  });

  it("signTransaction rejects when owner_address does not match derived wallet", async () => {
    const tx = buildUnsignedTx();
    (tx.raw_data.contract[0] as { parameter: { value: { owner_address: string } } })
      .parameter.value.owner_address = OTHER_TRON_ADDRESS;
    await expect(
      signTransaction({
        fileText: JSON.stringify(tx),
        mnemonic: TEST_MNEMONIC,
        derivationPath: "m/44'/195'/0'/0/0",
      }),
    ).rejects.toThrow(/Derived address does not match/);
  });

  it("signTransaction rejects when no contract has valid owner_address", async () => {
    const tx = buildUnsignedTxEmptyContracts();
    await expect(
      signTransaction({
        fileText: JSON.stringify(tx),
        mnemonic: TEST_MNEMONIC,
        derivationPath: "m/44'/195'/0'/0/0",
      }),
    ).rejects.toThrow(/No contract with a valid owner_address/);
  });
});
