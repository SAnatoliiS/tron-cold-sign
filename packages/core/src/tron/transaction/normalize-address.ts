import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  decodeTronAddressBase58Checked,
  encodeTronBase58CheckPayload,
} from "../address.js";
import { TRON_ADDRESS_VERSION_BYTE } from "../constants.js";

const tronBase58Check = createBase58check((data: Uint8Array) => sha256(data));

/**
 * Normalize various TRON address forms to canonical Base58Check mainnet.
 */
export function normalizeTronAddress(value: unknown, label: string): string {
  if (value === undefined || value === null) {
    throw new Error(`Contract field missing: ${label}`);
  }
  const s = String(value).trim();
  if (s.startsWith("T")) {
    const raw = decodeTronAddressBase58Checked(s);
    return encodeTronBase58CheckPayload(raw);
  }
  let h = s.replace(/^0x/i, "");
  if (h.length === 40) {
    h = "41" + h;
  }
  const buf = Buffer.from(h, "hex");
  if (buf.length !== 21 || buf[0] !== TRON_ADDRESS_VERSION_BYTE) {
    throw new Error(
      `${label}: invalid TRON hex address (expected 21 bytes starting with 0x41)`,
    );
  }
  return tronBase58Check.encode(buf);
}
