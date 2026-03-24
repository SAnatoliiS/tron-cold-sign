"use strict";

const assert = require("node:assert");
const { formatHumanSummary } = require("../lib/tron/transaction/format-summary.js");
const { SUN } = require("../lib/tron/transaction/constants.js");
const {
	TEST_MNEMONIC,
	GOLDEN_TRON_ADDRESS,
} = require("./test-constants.js");
const { deriveWalletFromMnemonic } = require("../lib/wallet/derive.js");

test("formatHumanSummary throws when contract missing", () => {
	assert.throws(
		() => formatHumanSummary({ contract: [] }),
		/missing or empty/,
	);
	assert.throws(() => formatHumanSummary({}), /missing or empty/);
});

test("formatHumanSummary TransferContract invalid amount", () => {
	assert.throws(
		() =>
			formatHumanSummary({
				contract: [
					{
						type: "TransferContract",
						parameter: {
							value: {
								owner_address: GOLDEN_TRON_ADDRESS,
								to_address: GOLDEN_TRON_ADDRESS,
								amount: Number.NaN,
							},
						},
					},
				],
			}),
		/TransferContract amount: invalid amount/,
	);
});

test("formatHumanSummary TransferContract large SUN as decimal string", () => {
	const bigSun = "90071992547409930000000";
	const summary = formatHumanSummary({
		contract: [
			{
				type: "TransferContract",
				parameter: {
					value: {
						owner_address: GOLDEN_TRON_ADDRESS,
						to_address: GOLDEN_TRON_ADDRESS,
						amount: bigSun,
					},
				},
			},
		],
	});
	assert.ok(summary.includes(bigSun));
	assert.match(summary, /Amount:/);
});

test("formatHumanSummary TriggerSmartContract with call_value and unknown calldata", () => {
	const w = deriveWalletFromMnemonic(TEST_MNEMONIC, "");
	const summary = formatHumanSummary({
		contract: [
			{
				type: "TriggerSmartContract",
				parameter: {
					value: {
						owner_address: w.address,
						contract_address: w.address,
						call_value: SUN,
						data: "0xdeadbeef",
					},
				},
			},
		],
		fee_limit: 10,
	});
	assert.match(summary, /TRX with call/);
	assert.match(summary, /data \(selector\)/);
});

test("formatHumanSummary TriggerSmartContract empty data branch", () => {
	const w = deriveWalletFromMnemonic(TEST_MNEMONIC, "");
	const summary = formatHumanSummary({
		contract: [
			{
				type: "TriggerSmartContract",
				parameter: {
					value: {
						owner_address: w.address,
						contract_address: w.address,
						data: "",
					},
				},
			},
		],
	});
	assert.match(summary, /empty — not TRC20/);
});

test("formatHumanSummary unknown contract type falls back to generic block", () => {
	const summary = formatHumanSummary({
		contract: [
			{
				type: "FreezeBalanceV2Contract",
				parameter: { value: {} },
			},
		],
	});
	assert.match(summary, /FreezeBalanceV2Contract/);
	assert.match(summary, /details not parsed/);
});

test("formatHumanSummary omits fee_limit when absent", () => {
	const summary = formatHumanSummary({
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
	});
	assert.match(summary, /not set in JSON/);
});
