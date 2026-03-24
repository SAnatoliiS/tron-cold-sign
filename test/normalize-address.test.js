"use strict";

const assert = require("node:assert");
const path = require("path");
const { normalizeTronAddress } = require("@tron-cold-sign/core");
const { GOLDEN_TRON_ADDRESS } = require("./test-constants.js");

test("normalizeTronAddress accepts Base58 and returns canonical Base58", () => {
	const a = normalizeTronAddress(GOLDEN_TRON_ADDRESS, "x");
	assert.strictEqual(a, GOLDEN_TRON_ADDRESS);
});

test("normalizeTronAddress accepts 40-char hex with 0x", () => {
	const a = normalizeTronAddress(
		"0xc901705cc4cbfdecf051f779d0de8b22759dd260",
		"x",
	);
	assert.strictEqual(a, GOLDEN_TRON_ADDRESS);
});

test("normalizeTronAddress accepts 40-char body without prefix", () => {
	const a = normalizeTronAddress("c901705cc4cbfdecf051f779d0de8b22759dd260", "x");
	assert.strictEqual(a, GOLDEN_TRON_ADDRESS);
});

test("normalizeTronAddress rejects missing value", () => {
	assert.throws(
		() => normalizeTronAddress(null, "owner_address"),
		/Contract field missing: owner_address/,
	);
});

test("normalizeTronAddress rejects wrong TRON address version in hex", () => {
	assert.throws(
		() =>
			normalizeTronAddress(
				"420000000000000000000000000000000000000000",
				"x",
			),
		/invalid TRON hex address/,
	);
});

test("formatHumanSummary fixture raw-transfer expected lines", () => {
	const { formatHumanSummary } = require("@tron-cold-sign/core");
	const raw = require(path.join(__dirname, "fixtures", "raw-transfer.json"));
	const out = formatHumanSummary(raw);
	assert.match(out, /TransferContract \(TRX\)/);
	assert.match(out, /From:\s+TUJ2YbSDGtCqzRz7quPQidRCMC98jDAPXc/);
	assert.match(out, /To:\s+TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK/);
	assert.match(out, /2\.000000 TRX/);
	assert.match(out, /2000000 SUN/);
	assert.match(out, /Fee limit \(fee_limit\): 50000000 SUN/);
});

test("formatHumanSummary fixture raw-trigger-transfer TRC20 transfer", () => {
	const { formatHumanSummary } = require("@tron-cold-sign/core");
	const raw = require(path.join(__dirname, "fixtures", "raw-trigger-transfer.json"));
	const out = formatHumanSummary(raw);
	assert.match(out, /TriggerSmartContract/);
	assert.match(out, /transfer\(address,uint256\)/);
	assert.match(out, /To \(token\):\s+TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK/);
	assert.match(out, /1000 smallest units/);
});

test("formatHumanSummary fixture raw-trigger-transferfrom", () => {
	const { formatHumanSummary } = require("@tron-cold-sign/core");
	const raw = require(path.join(__dirname, "fixtures", "raw-trigger-transferfrom.json"));
	const out = formatHumanSummary(raw);
	assert.match(out, /transferFrom\(address,address,uint256\)/);
	assert.match(out, /From \(token\):\s+TUJ2YbSDGtCqzRz7quPQidRCMC98jDAPXc/);
	assert.match(out, /To \(token\):\s+TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK/);
});
