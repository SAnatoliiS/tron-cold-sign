// ---- Types ----

export type UnsignedTransaction = {
  txID: string;
  raw_data: object;
  raw_data_hex: string;
};

export type CreateUnsignedTransactionParams = {
  from: string;
  to: string;
  amountSun: number;
  fullHost: string;
};

export type CreateUnsignedTrc20TransferParams = {
  from: string;
  to: string;
  contractAddress: string;
  amountSmallestUnit: string;
  fullHost: string;
  feeLimitSun?: number;
};

export type SignedTransaction = {
  txID: string;
  raw_data: object;
  raw_data_hex: string;
  signature: string[];
  visible?: boolean;
};

export type BroadcastResult = {
  result: boolean;
  txid?: string;
  code?: string;
  message?: string;
};

export type BroadcastSignedTransactionParams = {
  signedTx: SignedTransaction;
  fullHost: string;
};

// ---- Helpers ----

async function sha256hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function delay(min: number, max: number): Promise<void> {
  const ms = min + Math.floor(Math.random() * (max - min));
  return new Promise((r) => setTimeout(r, ms));
}

// ---- Functions ----

export function isValidTronAddress(address: string): boolean {
  return /^T[a-zA-Z0-9]{33,39}$/.test(address);
}

export async function createUnsignedTransaction(
  params: CreateUnsignedTransactionParams
): Promise<UnsignedTransaction> {
  await delay(300, 800);
  const txID = await sha256hex(JSON.stringify(params));
  const raw_data = {
    mock: true,
    kind: "trx" as const,
    from: params.from,
    to: params.to,
    amountSun: params.amountSun,
  };
  return { txID, raw_data, raw_data_hex: txID };
}

export async function createUnsignedTrc20Transfer(
  params: CreateUnsignedTrc20TransferParams
): Promise<UnsignedTransaction> {
  await delay(300, 800);
  const txID = await sha256hex(JSON.stringify(params));
  const raw_data = {
    mock: true,
    kind: "trc20" as const,
    from: params.from,
    to: params.to,
    contractAddress: params.contractAddress,
    amountSmallestUnit: params.amountSmallestUnit,
    feeLimitSun: params.feeLimitSun,
  };
  return { txID, raw_data, raw_data_hex: txID };
}

export async function broadcastSignedTransaction(
  params: BroadcastSignedTransactionParams
): Promise<BroadcastResult> {
  await delay(100, 400);
  if (!params.signedTx.signature || params.signedTx.signature.length === 0) {
    throw new Error("Transaction has no signatures. Cannot broadcast an unsigned transaction.");
  }
  return { result: true, txid: params.signedTx.txID };
}

// ---- Preview Decoder ----

export interface PreviewSummary {
  typeLabel: string;
  from: string;
  to: string;
  amountText: string;
  feeLimitText?: string;
  tokenContract?: string;
  tokenLabel?: string;
}

export function buildPreviewFromRawData(raw_data: object): {
  summary: PreviewSummary;
  warnings: string[];
} {
  const warnings: string[] = [];
  const d = raw_data as Record<string, unknown>;

  if (!d || d.mock !== true) {
    warnings.push("Transaction was not built by this prototype tool.");
    return {
      summary: {
        typeLabel: "Unknown",
        from: typeof d.from === "string" ? d.from : "Unknown",
        to: typeof d.to === "string" ? d.to : "Unknown",
        amountText: "Unknown",
      },
      warnings,
    };
  }

  if (d.kind === "trx") {
    const amountSun = typeof d.amountSun === "number" ? d.amountSun : 0;
    return {
      summary: {
        typeLabel: "TRX Transfer",
        from: typeof d.from === "string" ? d.from : "Unknown",
        to: typeof d.to === "string" ? d.to : "Unknown",
        amountText: `${amountSun / 1_000_000} TRX (${amountSun} SUN)`,
      },
      warnings,
    };
  }

  if (d.kind === "trc20") {
    const feeLimitSun = typeof d.feeLimitSun === "number" ? d.feeLimitSun : undefined;
    return {
      summary: {
        typeLabel: "TRC20 Transfer",
        from: typeof d.from === "string" ? d.from : "Unknown",
        to: typeof d.to === "string" ? d.to : "Unknown",
        amountText: typeof d.amountSmallestUnit === "string" ? d.amountSmallestUnit : "Unknown",
        feeLimitText: feeLimitSun ? `${feeLimitSun} SUN` : undefined,
        tokenContract: typeof d.contractAddress === "string" ? d.contractAddress : undefined,
        tokenLabel: typeof d.tokenLabel === "string" ? d.tokenLabel : undefined,
      },
      warnings,
    };
  }

  warnings.push("Unknown transaction kind.");
  return {
    summary: {
      typeLabel: "Unknown",
      from: typeof d.from === "string" ? d.from : "Unknown",
      to: typeof d.to === "string" ? d.to : "Unknown",
      amountText: "Unknown",
    },
    warnings,
  };
}
