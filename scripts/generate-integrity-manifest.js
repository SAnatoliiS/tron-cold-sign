#!/usr/bin/env node
"use strict";

/**
 * Writes INTEGRITY.sha256 — SHA-256 over a fixed list of project files (no node_modules).
 * Generate on a trusted machine after locking dependencies; on an offline copy run
 * npm run integrity:check before use.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const OUT_FILE = path.join(ROOT, "INTEGRITY.sha256");

/** Collect all .js files under relDir, sorted by full relative path. */
function walkJs(relDir) {
	const out = [];
	const base = path.join(ROOT, relDir);
	if (!fs.existsSync(base)) {
		return out;
	}
	function walk(dir, prefix) {
		for (const name of fs.readdirSync(dir).sort()) {
			const full = path.join(dir, name);
			const rel = path.join(prefix, name).replace(/\\/g, "/");
			const st = fs.statSync(full);
			if (st.isDirectory()) {
				walk(full, rel);
			} else if (name.endsWith(".js")) {
				out.push(rel);
			}
		}
	}
	walk(base, relDir);
	return out;
}

/** Like walkJs but multiple extensions; skips node_modules / dist. */
function walkSource(relDir, exts) {
	const out = [];
	const skipDir = new Set(["node_modules", "dist", ".git"]);
	const base = path.join(ROOT, relDir);
	if (!fs.existsSync(base)) {
		return out;
	}
	function walk(dir, prefix) {
		for (const name of fs.readdirSync(dir).sort()) {
			if (skipDir.has(name)) {
				continue;
			}
			const full = path.join(dir, name);
			const rel = path.join(prefix, name).replace(/\\/g, "/");
			const st = fs.statSync(full);
			if (st.isDirectory()) {
				walk(full, rel);
			} else if (exts.some((ext) => name.endsWith(ext))) {
				out.push(rel);
			}
		}
	}
	walk(base, relDir);
	return out;
}

const TRACKED_FILES = [
	"generate-wallet.secure.js",
	"sign-transaction.secure.js",
	"package-lock.json",
	"package.json",
	"scripts/generate-integrity-manifest.js",
	"scripts/verify-derivation.js",
	"scripts/verify-integrity.js",
	"packages/core/package.json",
	"packages/core/tsconfig.json",
	"packages/core/tsup.config.ts",
	...walkSource("packages/core/src", [".ts"]),
	...walkJs("cli"),
	...walkJs("test"),
	"packages/client-offline/package.json",
	"packages/client-offline/index.html",
	"packages/client-offline/vite.config.ts",
	"packages/client-offline/vitest.config.ts",
	"packages/client-offline/tsconfig.json",
	"packages/client-offline/tsconfig.app.json",
	"packages/client-offline/tsconfig.node.json",
	"packages/client-offline/eslint.config.js",
	"packages/client-offline/postcss.config.js",
	"packages/client-offline/tailwind.config.ts",
	"packages/client-offline/components.json",
	...walkSource("packages/client-offline/src", [".ts", ".tsx", ".css"]),
].sort();

function sha256File(absPath) {
	const data = fs.readFileSync(absPath);
	return crypto.createHash("sha256").update(data).digest("hex");
}

function main() {
	const write = process.argv.includes("--write");
	const lines = [];

	for (const rel of TRACKED_FILES) {
		const abs = path.join(ROOT, rel);
		if (!fs.existsSync(abs)) {
			console.error(`generate-integrity-manifest: missing file: ${rel}`);
			process.exit(1);
		}
		const hash = sha256File(abs);
		lines.push(`${hash}  ${rel}`);
	}

	const body = lines.join("\n") + "\n";

	if (write) {
		fs.writeFileSync(OUT_FILE, body, "utf8");
		console.error(`[i] Written: ${OUT_FILE}`);
	}
	process.stdout.write(body);
}

main();
