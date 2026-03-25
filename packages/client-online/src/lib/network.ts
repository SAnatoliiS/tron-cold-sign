export type NetworkPreset = "mainnet" | "shasta";

const DEFAULTS: Record<NetworkPreset, string> = {
  mainnet: "https://api.trongrid.io",
  shasta: "https://api.shasta.trongrid.io",
};

export const USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
export const USDT_DECIMALS = 6;

export function resolveFullHost(preset: NetworkPreset, override?: string): string {
  const trimmed = (override ?? "").trim();
  if (trimmed.length > 0) return trimmed;
  return DEFAULTS[preset];
}

export function isValidHttpUrl(s: string): boolean {
  if (s.trim().length === 0) return true;
  try {
    const u = new URL(s.trim());
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}
