"use strict";

const { SUN } = require("./constants.js");
const { normalizeTronAddress } = require("./normalize-address.js");
const { parseTrc20CallData } = require("./parse-trc20.js");

const SUN_PER_TRX = BigInt(SUN);

/**
 * Parse non-negative SUN amount from JSON (number, decimal string, or bigint).
 * Avoids Number precision loss for large transfers.
 * @param {unknown} value
 * @param {string} fieldLabel
 * @returns {bigint}
 */
function parseNonNegativeSun(value, fieldLabel) {
	if (value === undefined || value === null) {
		throw new Error(`${fieldLabel}: invalid amount`);
	}
	if (typeof value === "bigint") {
		if (value < 0n) {
			throw new Error(`${fieldLabel}: invalid amount`);
		}
		return value;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
			throw new Error(`${fieldLabel}: invalid amount`);
		}
		if (value > Number.MAX_SAFE_INTEGER) {
			throw new Error(
				`${fieldLabel}: amount exceeds safe JSON number range — use a decimal string`,
			);
		}
		return BigInt(value);
	}
	if (typeof value === "string") {
		const t = value.trim();
		if (t === "" || !/^[0-9]+$/.test(t)) {
			throw new Error(`${fieldLabel}: invalid amount`);
		}
		return BigInt(t);
	}
	throw new Error(`${fieldLabel}: invalid amount`);
}

/** @param {bigint} sun */
function formatTrxFromSun(sun) {
	const whole = sun / SUN_PER_TRX;
	const frac = sun % SUN_PER_TRX;
	const fracStr = frac.toString().padStart(6, "0");
	return `${whole}.${fracStr}`;
}

/**
 * Human-readable offline summary of raw_data for user review before signing.
 * @param {object} rawData transaction raw_data object
 * @returns {string} multi-line summary
 */
function formatHumanSummary(rawData) {
	const lines = [];
	const contracts = rawData.contract;
	if (!Array.isArray(contracts) || contracts.length === 0) {
		throw new Error("raw_data.contract is missing or empty");
	}

	for (let i = 0; i < contracts.length; i++) {
		const c = contracts[i];
		const type = c.type || "?";
		const val = c.parameter && c.parameter.value;

		if (type === "TransferContract" && val) {
			const from = normalizeTronAddress(val.owner_address, "owner_address");
			const to = normalizeTronAddress(val.to_address, "to_address");
			const amountSun = parseNonNegativeSun(val.amount, "TransferContract amount");
			lines.push(`Contract #${i + 1}: TransferContract (TRX)`);
			lines.push(`  From:    ${from}`);
			lines.push(`  To:      ${to}`);
			lines.push(
				`  Amount:  ${formatTrxFromSun(amountSun)} TRX  (${amountSun.toString()} SUN)`,
			);
		} else if (type === "TriggerSmartContract" && val) {
			const owner = normalizeTronAddress(val.owner_address, "owner_address");
			const token = normalizeTronAddress(val.contract_address, "contract_address");
			lines.push(
				`Contract #${i + 1}: TriggerSmartContract (contract call, often TRC20)`,
			);
			lines.push(`  Owner:            ${owner}`);
			lines.push(`  Contract address: ${token}`);
			const cv = val.call_value;
			if (cv !== undefined && cv !== null) {
				const cvSun = parseNonNegativeSun(cv, "call_value");
				if (cvSun > 0n) {
					lines.push(
						`  TRX with call:    ${formatTrxFromSun(cvSun)} TRX  (${cvSun.toString()} SUN)`,
					);
				}
			}
			const data = val.data;
			if (typeof data === "string" && data.length > 0) {
				const parsed = parseTrc20CallData(data);
				if (parsed.kind === "transfer") {
					lines.push(`  Call:             transfer(address,uint256)`);
					lines.push(`  To (token):       ${parsed.to}`);
					lines.push(`  Amount (raw):     ${parsed.amount.toString()} smallest units`);
					lines.push(
						`                    (human amount = raw / 10^decimals; decimals not queried offline)`,
					);
				} else if (parsed.kind === "transferFrom") {
					lines.push(`  Call:             transferFrom(address,address,uint256)`);
					lines.push(`  From (token):     ${parsed.from}`);
					lines.push(`  To (token):       ${parsed.to}`);
					lines.push(`  Amount (raw):     ${parsed.amount.toString()} smallest units`);
					lines.push(
						`                    (human amount = raw / 10^decimals; decimals not queried offline)`,
					);
				} else {
					lines.push(`  data (selector):  0x${parsed.selector}`);
					lines.push(
						`  Not transfer / transferFrom — verify calldata in an explorer or raw_data_hex.`,
					);
				}
			} else {
				lines.push(`  data:             (empty — not TRC20 transfer by calldata)`);
			}
		} else {
			lines.push(`Contract #${i + 1}: ${type}`);
			lines.push(
				`  (details not parsed — verify raw_data_hex / contract in a trusted viewer)`,
			);
		}
	}

	const fee = rawData.fee_limit;
	if (fee !== undefined && fee !== null) {
		try {
			const feeSun = parseNonNegativeSun(fee, "fee_limit");
			lines.push(
				`Fee limit (fee_limit): ${feeSun.toString()} SUN (${formatTrxFromSun(feeSun)} TRX)`,
			);
		} catch {
			lines.push(`Fee limit (fee_limit): ${String(fee)} (unparsed)`);
		}
	} else {
		lines.push(`Fee limit (fee_limit): (not set in JSON)`);
	}

	return lines.join("\n");
}

module.exports = { formatHumanSummary };
