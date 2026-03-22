#!/usr/bin/env node
"use strict";

/**
 * Compares current files to INTEGRITY.sha256 (format: hexhash  path).
 * Run before offline use: node scripts/verify-integrity.js
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "INTEGRITY.sha256");

function sha256File(absPath) {
	const data = fs.readFileSync(absPath);
	return crypto.createHash("sha256").update(data).digest("hex");
}

function parseManifest(content) {
	const entries = [];
	for (const line of content.split(/\r?\n/)) {
		const t = line.trim();
		if (!t) continue;
		const m = /^([0-9a-f]{64})\s+(.+)$/.exec(t);
		if (!m) {
			throw new Error(`Invalid manifest line: ${line}`);
		}
		entries.push({ hash: m[1], rel: m[2] });
	}
	return entries;
}

/** Reject paths that escape ROOT (traversal or absolute paths in manifest). */
function resolveUnderRoot(rel) {
	const resolved = path.resolve(ROOT, rel);
	const relFromRoot = path.relative(ROOT, resolved);
	if (relFromRoot.startsWith("..") || path.isAbsolute(relFromRoot)) {
		throw new Error(`Invalid manifest path (outside project root): ${rel}`);
	}
	return resolved;
}

function main() {
	if (!fs.existsSync(MANIFEST)) {
		console.error(`verify-integrity: missing file ${MANIFEST}`);
		console.error("  Create manifest: npm run integrity:write");
		process.exit(1);
	}

	const raw = fs.readFileSync(MANIFEST, "utf8");
	let entries;
	try {
		entries = parseManifest(raw);
	} catch (e) {
		console.error(String(e.message || e));
		process.exit(1);
	}

	let ok = true;
	for (const { hash: expected, rel } of entries) {
		let abs;
		try {
			abs = resolveUnderRoot(rel);
		} catch (e) {
			console.error(String(e.message || e));
			ok = false;
			continue;
		}
		if (!fs.existsSync(abs)) {
			console.error(`MISSING  ${rel}`);
			ok = false;
			continue;
		}
		const actual = sha256File(abs);
		if (actual !== expected) {
			console.error(`MISMATCH ${rel}`);
			console.error(`  expected ${expected}`);
			console.error(`  actual   ${actual}`);
			ok = false;
		} else {
			console.error(`OK       ${rel}`);
		}
	}

	if (!ok) {
		console.error("\nverify-integrity: check failed.");
		process.exit(1);
	}
	console.error("\nverify-integrity: all hashes match.");
}

main();
