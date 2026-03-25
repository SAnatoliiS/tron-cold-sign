import { createHash } from "node:crypto";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { deriveWalletFromMnemonic } from "@tron-cold-sign/core";

const { mockSendTrx } = vi.hoisted(() => ({
  mockSendTrx: vi.fn(),
}));

vi.mock("tronweb", () => ({
  TronWeb: class MockTronWeb {
    transactionBuilder = { sendTrx: mockSendTrx };
  },
}));

import {
  assertValidAmount,
  createUnsignedTransaction,
  isValidTronAddress,
} from "./createUnsignedTransaction.js";

const TEST_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";

beforeEach(() => {
  mockSendTrx.mockReset();
});

describe("assertValidAmount", () => {
  it("accepts positive integers", () => {
    expect(() => assertValidAmount(1)).not.toThrow();
    expect(() => assertValidAmount(1_000_000)).not.toThrow();
  });

  it("rejects non-positive and non-integers", () => {
    expect(() => assertValidAmount(0)).toThrow(/greater than zero/);
    expect(() => assertValidAmount(-1)).toThrow();
    expect(() => assertValidAmount(1.5)).toThrow(/integer/);
    expect(() => assertValidAmount(Number.NaN)).toThrow();
  });
});

describe("isValidTronAddress", () => {
  it("returns true for a valid derived address", () => {
    const w = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
    expect(isValidTronAddress(w.address)).toBe(true);
  });

  it("returns false for invalid input", () => {
    expect(isValidTronAddress("not-an-address")).toBe(false);
  });
});

describe("createUnsignedTransaction", () => {
  it("strips signature, verifies txID binding, and does not mutate TronWeb output in place", async () => {
    const rawHex = "aa".repeat(32);
    const txID = createHash("sha256")
      .update(Buffer.from(rawHex, "hex"))
      .digest("hex");

    const nodeTx = {
      txID,
      raw_data_hex: rawHex,
      raw_data: { contract: [] as unknown[] },
      signature: ["00".repeat(65)],
    };
    mockSendTrx.mockResolvedValue(nodeTx);

    const w0 = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
    const w1 = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/1");

    const out = await createUnsignedTransaction({
      from: w0.address,
      to: w1.address,
      amountSun: 1_000_000,
      fullHost: "https://api.shasta.trongrid.io",
    });

    expect(out).toEqual({
      txID,
      raw_data_hex: rawHex,
      raw_data: { contract: [] },
    });
    expect("signature" in out).toBe(false);
    expect("signature" in nodeTx).toBe(true);
  });

  it("rejects invalid fullHost", async () => {
    await expect(
      createUnsignedTransaction({
        from: "T",
        to: "T",
        amountSun: 1,
        fullHost: "ftp://example.com",
      }),
    ).rejects.toThrow(/http:|https:/);
  });

  it("rejects same from and to", async () => {
    const w0 = deriveWalletFromMnemonic(TEST_MNEMONIC, "", "m/44'/195'/0'/0/0");
    await expect(
      createUnsignedTransaction({
        from: w0.address,
        to: w0.address,
        amountSun: 1,
        fullHost: "https://api.shasta.trongrid.io",
      }),
    ).rejects.toThrow(/different/);
  });
});
