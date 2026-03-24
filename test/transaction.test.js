"use strict";

const assert = require("node:assert");
const { sha256 } = require("@noble/hashes/sha2.js");
const { signTronTxId } = require("../lib/tron/transaction/sign-tron-tx-id.js");
const {
	verifyTxIdBinding,
	MAX_RAW_DATA_HEX_LENGTH,
} = require("../lib/tron/transaction/verify-tx-id.js");
const { parseTrc20CallData } = require("../lib/tron/transaction/parse-trc20.js");

test("verifyTxIdBinding accepts matching txID and raw_data_hex", () => {
	const rawHex = "aa".repeat(32);
	const rawBytes = Buffer.from(rawHex, "hex");
	const tid = Buffer.from(sha256(rawBytes)).toString("hex");
	verifyTxIdBinding({
		raw_data_hex: rawHex,
		txID: tid,
	});
});

test("verifyTxIdBinding rejects txID mismatch", () => {
	const rawHex = "bb".repeat(32);
	assert.throws(
		() =>
			verifyTxIdBinding({
				raw_data_hex: rawHex,
				txID: "00".repeat(32),
			}),
		/does not match SHA256/,
	);
});

test("verifyTxIdBinding rejects too short raw_data_hex", () => {
	assert.throws(
		() => verifyTxIdBinding({ raw_data_hex: "aa", txID: "00".repeat(32) }),
		/no valid raw_data_hex/,
	);
});

test("verifyTxIdBinding rejects invalid txID length", () => {
	assert.throws(
		() =>
			verifyTxIdBinding({
				raw_data_hex: "aa".repeat(32),
				txID: "abcd",
			}),
		/no valid txID/,
	);
});

test("verifyTxIdBinding rejects odd-length raw_data_hex", () => {
	assert.throws(
		() =>
			verifyTxIdBinding({
				raw_data_hex: "a".repeat(65),
				txID: "00".repeat(32),
			}),
		/even-length hex/,
	);
});

test("verifyTxIdBinding rejects non-hex in raw_data_hex", () => {
	assert.throws(
		() =>
			verifyTxIdBinding({
				raw_data_hex: "gg" + "aa".repeat(31),
				txID: "00".repeat(32),
			}),
		/only hexadecimal/,
	);
});

test("verifyTxIdBinding rejects oversized raw_data_hex", () => {
	const huge = "aa".repeat((MAX_RAW_DATA_HEX_LENGTH + 2) / 2);
	assert.throws(
		() =>
			verifyTxIdBinding({
				raw_data_hex: huge,
				txID: "00".repeat(32),
			}),
		/too long/,
	);
});

test("signTronTxId is deterministic for fixed key and txID", () => {
	const txId = "aa".repeat(32);
	const pk = Buffer.alloc(32, 7);
	const s1 = signTronTxId(txId, pk);
	const s2 = signTronTxId(txId, pk);
	assert.strictEqual(s1, s2);
	assert.strictEqual(s1.length, 64 + 64 + 2);
});

test("signTronTxId rejects too short txID hex", () => {
	assert.throws(
		() => signTronTxId("abcd", Buffer.alloc(32, 1)),
		/no valid txID/,
	);
});

test("signTronTxId rejects non-hex in txID", () => {
	const badTxId = "gg" + "aa".repeat(31);
	assert.throws(
		() => signTronTxId(badTxId, Buffer.alloc(32, 1)),
		/only hexadecimal/,
	);
});

test("signTronTxId rejects non-32-byte private key", () => {
	assert.throws(
		() => signTronTxId("aa".repeat(32), Buffer.alloc(31, 1)),
		/32-byte Buffer/,
	);
});

test("parseTrc20CallData parses transfer", () => {
	const addr20 = "a".repeat(40);
	const toPadded = "0".repeat(24) + addr20;
	const amount =
		"00000000000000000000000000000000000000000000000000000000000003e8";
	const data = "0xa9059cbb" + toPadded + amount;
	const p = parseTrc20CallData(data);
	assert.strictEqual(p.kind, "transfer");
	assert.strictEqual(p.amount, 1000n);
	assert.ok(p.to.startsWith("T"));
});

test("parseTrc20CallData unknown short calldata", () => {
	const p = parseTrc20CallData("0x01");
	assert.strictEqual(p.kind, "unknown");
});

test("parseTrc20CallData transfer with invalid padded address hex", () => {
	const amount =
		"00000000000000000000000000000000000000000000000000000000000003e8";
	const data =
		"0xa9059cbb" + "0".repeat(24) + "gggggggggggggggggggggggggggggggggggggggg" + amount;
	const p = parseTrc20CallData(data);
	assert.strictEqual(p.kind, "unknown");
	assert.strictEqual(p.selector, "a9059cbb");
});

test("parseTrc20CallData parses transferFrom", () => {
	const from20 = "c8599111f29c1e1e061265b4af93ea1f274ad78a";
	const to20 = "b6e708a39781c96bd399c7657780ff9fe9f052a8";
	const fromPadded = "0".repeat(24) + from20;
	const toPadded = "0".repeat(24) + to20;
	const amount =
		"00000000000000000000000000000000000000000000000000000000000f4240";
	const data = "0x23b872dd" + fromPadded + toPadded + amount;
	const p = parseTrc20CallData(data);
	assert.strictEqual(p.kind, "transferFrom");
	assert.strictEqual(p.amount, 1_000_000n);
	assert.ok(p.from.startsWith("T"));
	assert.ok(p.to.startsWith("T"));
});

test("parseTrc20CallData transferFrom selector but invalid hex in address slots → unknown", () => {
	const bad = "g".repeat(40);
	const fromPadded = "0".repeat(24) + bad;
	const toPadded = "0".repeat(24) + "b6e708a39781c96bd399c7657780ff9fe9f052a8";
	const amount =
		"00000000000000000000000000000000000000000000000000000000000003e8";
	const data = "0x23b872dd" + fromPadded + toPadded + amount;
	const p = parseTrc20CallData(data);
	assert.strictEqual(p.kind, "unknown");
	assert.strictEqual(p.selector, "23b872dd");
});

test("parseTrc20CallData transferFrom too short for full args → unknown", () => {
	const p = parseTrc20CallData("0x23b872dd" + "00".repeat(10));
	assert.strictEqual(p.kind, "unknown");
	assert.strictEqual(p.selector, "23b872dd");
});
