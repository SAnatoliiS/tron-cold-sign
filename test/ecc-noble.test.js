"use strict";

const assert = require("node:assert");
const ecc = require("../lib/crypto/ecc-noble.js");

test("pointFromScalar returns null for invalid secret", () => {
	assert.strictEqual(ecc.pointFromScalar(Buffer.alloc(32, 0)), null);
});

test("pointFromScalar respects compressed flag", () => {
	const sk = Buffer.from(
		"0000000000000000000000000000000000000000000000000000000000000001",
		"hex",
	);
	const c = ecc.pointFromScalar(sk, true);
	const u = ecc.pointFromScalar(sk, false);
	assert.ok(c && c.length === 33);
	assert.ok(u && u.length === 65);
});

test("pointAddScalar with zero tweak returns same point bytes", () => {
	const sk = Buffer.from(
		"0000000000000000000000000000000000000000000000000000000000000001",
		"hex",
	);
	const p = ecc.pointFromScalar(sk, true);
	const again = ecc.pointAddScalar(p, Buffer.alloc(32, 0), true);
	assert.ok(Buffer.compare(p, again) === 0);
});

test("pointAddScalar returns null on bad input", () => {
	assert.strictEqual(
		ecc.pointAddScalar(Buffer.alloc(1), Buffer.alloc(32, 1), true),
		null,
	);
});

test("privateAdd returns null on invalid secret", () => {
	assert.strictEqual(ecc.privateAdd(Buffer.alloc(1), Buffer.alloc(32, 1)), null);
});

test("pointCompress returns null on invalid point", () => {
	assert.strictEqual(ecc.pointCompress(Buffer.alloc(5), true), null);
});

test("eccVerify strict false uses lowS false branch", () => {
	const sk = Buffer.from(
		"0000000000000000000000000000000000000000000000000000000000000001",
		"hex",
	);
	const msg = Buffer.alloc(32, 7);
	const sig = ecc.sign(msg, sk);
	const pub = ecc.pointFromScalar(sk, false);
	assert.ok(ecc.verify(msg, pub, sig, false));
});
