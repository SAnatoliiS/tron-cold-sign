"use strict";

const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const path = require("path");
const { parseArgs } = require("../cli/generate-wallet.js");
const { CliError } = require("../cli/errors.js");

const repoRoot = path.join(__dirname, "..");

test("parseArgs sets help for --help", () => {
	const o = parseArgs(["node", "x", "--help"]);
	assert.strictEqual(o.help, true);
});

test("parseArgs rejects unknown flag", () => {
	assert.throws(
		() => parseArgs(["node", "x", "--not-a-flag"]),
		(e) => e instanceof CliError && /Unknown argument/.test(e.message),
	);
});

test("parseArgs requires value after --entropy-bits", () => {
	assert.throws(
		() => parseArgs(["node", "x", "--entropy-bits"]),
		(e) =>
			e instanceof CliError && /Expected value after --entropy-bits/.test(e.message),
	);
});

test("generate-wallet.secure.js --help exits 0 with usage", () => {
	const r = spawnSync(
		process.execPath,
		[path.join(repoRoot, "generate-wallet.secure.js"), "--help"],
		{ cwd: repoRoot, encoding: "utf8" },
	);
	assert.strictEqual(r.status, 0);
	assert.match(r.stdout, /generate-wallet\.secure\.js/);
	assert.match(r.stdout, /--entropy-bits/);
});
