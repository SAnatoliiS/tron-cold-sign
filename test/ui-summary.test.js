"use strict";

const assert = require("node:assert");
const { buildUiSummaryFromRawData } = require("@tron-cold-sign/core");
const { GOLDEN_TRON_ADDRESS } = require("./test-constants.js");

test("buildUiSummaryFromRawData TransferContract", () => {
	const { summary, warnings } = buildUiSummaryFromRawData({
		contract: [
			{
				type: "TransferContract",
				parameter: {
					value: {
						owner_address: GOLDEN_TRON_ADDRESS,
						to_address: GOLDEN_TRON_ADDRESS,
						amount: 1_000_000,
					},
				},
			},
		],
		fee_limit: 10_000_000,
	});
	assert.strictEqual(summary.typeLabel, "TransferContract (TRX)");
	assert.strictEqual(summary.from, GOLDEN_TRON_ADDRESS);
	assert.strictEqual(summary.to, GOLDEN_TRON_ADDRESS);
	assert.match(summary.amountText, /1\.000000 TRX/);
	assert.match(summary.feeLimitText, /10\.000000 TRX/);
	assert.ok(warnings.length >= 1);
});

test("buildUiSummaryFromRawData multiple contracts", () => {
	const { summary, warnings } = buildUiSummaryFromRawData({
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
			{
				type: "TransferContract",
				parameter: {
					value: {
						owner_address: GOLDEN_TRON_ADDRESS,
						to_address: GOLDEN_TRON_ADDRESS,
						amount: 2,
					},
				},
			},
		],
	});
	assert.match(summary.typeLabel, /2 contracts/);
	assert.ok(warnings.some((w) => /Multiple contracts/i.test(w)));
});

test("buildUiSummaryFromRawData throws when contract empty", () => {
	assert.throws(
		() => buildUiSummaryFromRawData({ contract: [] }),
		/missing or empty/,
	);
});

test("buildUiSummaryFromRawData exports from index", () => {
	const api = require("@tron-cold-sign/core");
	assert.strictEqual(typeof api.buildUiSummaryFromRawData, "function");
});
