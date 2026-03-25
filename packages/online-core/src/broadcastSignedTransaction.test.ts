import { createHash } from "node:crypto";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockSendRaw } = vi.hoisted(() => ({
  mockSendRaw: vi.fn(),
}));

vi.mock("tronweb", () => ({
  TronWeb: class MockTronWeb {
    trx = { sendRawTransaction: mockSendRaw };
  },
}));

import {
  assertValidAmount,
  broadcastSignedTransaction,
  isValidTronAddress,
} from "./broadcastSignedTransaction.js";
import type { SignedTransaction } from "./broadcastSignedTransaction.js";

beforeEach(() => {
  mockSendRaw.mockReset();
});

function makeValidSignedTx(): SignedTransaction {
  const rawHex = "cc".repeat(32);
  const txID = createHash("sha256")
    .update(Buffer.from(rawHex, "hex"))
    .digest("hex");
  const sig = `${"ab".repeat(32)}${"cd".repeat(32)}1b`;
  expect(sig.length).toBe(130);
  return {
    txID,
    raw_data_hex: rawHex,
    raw_data: { contract: [] },
    signature: [sig],
    visible: false,
  };
}

describe("broadcastSignedTransaction", () => {
  it("broadcasts and maps API result", async () => {
    mockSendRaw.mockResolvedValue({
      result: true,
      txid: "deadbeef",
    });

    const signedTx = makeValidSignedTx();
    const out = await broadcastSignedTransaction({
      signedTx,
      fullHost: "https://api.shasta.trongrid.io",
    });

    expect(out).toEqual({ result: true, txid: "deadbeef" });
    expect(mockSendRaw).toHaveBeenCalledTimes(1);
    const arg = mockSendRaw.mock.calls[0][0] as SignedTransaction;
    expect(arg.visible).toBe(false);
    expect(arg.signature.length).toBe(1);
  });

  it("rejects empty signature array", async () => {
    const rawHex = "dd".repeat(32);
    const txID = createHash("sha256")
      .update(Buffer.from(rawHex, "hex"))
      .digest("hex");

    await expect(
      broadcastSignedTransaction({
        signedTx: {
          txID,
          raw_data_hex: rawHex,
          raw_data: {},
          signature: [],
        },
        fullHost: "https://api.shasta.trongrid.io",
      }),
    ).rejects.toThrow(/not signed/);
  });

  it("rejects wrong signature hex length", async () => {
    const rawHex = "ee".repeat(32);
    const txID = createHash("sha256")
      .update(Buffer.from(rawHex, "hex"))
      .digest("hex");

    await expect(
      broadcastSignedTransaction({
        signedTx: {
          txID,
          raw_data_hex: rawHex,
          raw_data: {},
          signature: ["abcd"],
        },
        fullHost: "https://api.shasta.trongrid.io",
      }),
    ).rejects.toThrow(/130/);
  });

  it("rejects txID mismatch with raw_data_hex", async () => {
    const rawHex = "ff".repeat(32);
    await expect(
      broadcastSignedTransaction({
        signedTx: {
          txID: "00".repeat(32),
          raw_data_hex: rawHex,
          raw_data: {},
          signature: [`${"ab".repeat(32)}${"cd".repeat(32)}1b`],
        },
        fullHost: "https://api.shasta.trongrid.io",
      }),
    ).rejects.toThrow(/txID does not match/);
  });
});

describe("broadcast helpers", () => {
  it("exports assertValidAmount and isValidTronAddress", () => {
    expect(() => assertValidAmount(1)).not.toThrow();
    expect(isValidTronAddress("not")).toBe(false);
  });
});
