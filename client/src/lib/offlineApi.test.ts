import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import {
  generateWallet,
  parseUnsignedTransaction,
  signTransaction,
} from "./offlineApi";

const require = createRequire(import.meta.url);
const { TEST_MNEMONIC, GOLDEN_TRON_ADDRESS } = require(
  "../../../test/test-constants.js",
);

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

describe("offlineApi", () => {
  it("generateWallet returns 12 words", async () => {
    const w = await generateWallet({ wordCount: 12 });
    expect(w.mnemonic.split(/\s+/).length).toBe(12);
    expect(w.addressBase58).toMatch(/^T/);
  });

  it("parseUnsignedTransaction parses transfer", async () => {
    const tx = buildUnsignedTx();
    const r = await parseUnsignedTransaction(JSON.stringify(tx));
    expect(r.summary.typeLabel).toContain("TransferContract");
    expect(r.txId).toBe(tx.txID);
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
});
