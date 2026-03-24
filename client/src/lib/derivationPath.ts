/**
 * Single source of truth for TRON BIP44 derivation paths.
 * Coin type 195 = TRON.
 */
export function buildDerivationPath(index: number): string {
  return `m/44'/195'/0'/0/${index}`;
}
