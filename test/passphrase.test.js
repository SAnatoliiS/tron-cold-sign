"use strict";

const assert = require("node:assert");
const { utf8PopLastChar } = require("../src/cli/passphrase.js");

test("utf8PopLastChar empty buffer unchanged", () => {
	const b = Buffer.alloc(0);
	assert.strictEqual(utf8PopLastChar(b).length, 0);
});

test("utf8PopLastChar removes last ASCII byte", () => {
	assert.strictEqual(
		utf8PopLastChar(Buffer.from("ab", "utf8")).toString(),
		"a",
	);
});

test("utf8PopLastChar removes last UTF-8 code point (2-byte)", () => {
	const b = Buffer.from("aé", "utf8");
	assert.strictEqual(utf8PopLastChar(b).toString(), "a");
});

test("utf8PopLastChar removes last UTF-8 code point (3-byte)", () => {
	const b = Buffer.from("€", "utf8");
	assert.strictEqual(utf8PopLastChar(b).length, 0);
});
