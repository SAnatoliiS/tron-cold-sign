"use strict";

const { normalizeTronAddress } = require("./normalize-address.js");
const { SEL_TRANSFER, SEL_TRANSFER_FROM } = require("./constants.js");

/**
 * Parse TRC20 calldata (Ethereum-style ABI): transfer / transferFrom.
 * @returns {{ kind: 'transfer', to: string, amount: bigint } | { kind: 'transferFrom', from: string, to: string, amount: bigint } | { kind: 'unknown', selector: string }}
 */
function parseTrc20CallData(dataHex) {
	const h = String(dataHex).replace(/^0x/i, "").toLowerCase();
	if (h.length < 8) {
		return { kind: "unknown", selector: h || "(empty)" };
	}
	const sel = h.slice(0, 8);
	if (sel === SEL_TRANSFER && h.length >= 8 + 128) {
		const addrPadded = h.slice(8, 8 + 64);
		const to20 = addrPadded.slice(24);
		if (!/^[0-9a-f]{40}$/.test(to20)) {
			return { kind: "unknown", selector: sel };
		}
		let to;
		try {
			to = normalizeTronAddress("41" + to20, "to");
		} catch {
			return { kind: "unknown", selector: sel };
		}
		const amount = BigInt("0x" + h.slice(8 + 64, 8 + 128));
		return { kind: "transfer", to, amount };
	}
	if (sel === SEL_TRANSFER_FROM && h.length >= 8 + 192) {
		const from20 = h.slice(8 + 24, 8 + 64);
		const to20 = h.slice(8 + 64 + 24, 8 + 128);
		if (!/^[0-9a-f]{40}$/.test(from20) || !/^[0-9a-f]{40}$/.test(to20)) {
			return { kind: "unknown", selector: sel };
		}
		let from;
		let to;
		try {
			from = normalizeTronAddress("41" + from20, "from");
			to = normalizeTronAddress("41" + to20, "to");
		} catch {
			return { kind: "unknown", selector: sel };
		}
		const amount = BigInt("0x" + h.slice(8 + 128, 8 + 192));
		return { kind: "transferFrom", from, to, amount };
	}
	return { kind: "unknown", selector: sel };
}

module.exports = { parseTrc20CallData };
