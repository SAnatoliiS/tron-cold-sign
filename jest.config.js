"use strict";

/** @type {import("jest").Config} */
module.exports = {
	testEnvironment: "node",
	/** Avoid relying on Watchman (broken in some sandboxes / minimal CI images). */
	watchman: false,
	testMatch: ["<rootDir>/test/**/*.test.js"],
	collectCoverageFrom: ["lib/**/*.js", "cli/**/*.js"],
	coverageDirectory: "coverage",
	coverageReporters: ["text", "text-summary"],
	coveragePathIgnorePatterns: ["/node_modules/"],
	coverageThreshold: {
		global: {
			statements: 80,
			branches: 70,
			lines: 80,
			functions: 70,
		},
	},
	/** Allow transforming ESM-only deps (Jest runs tests as CJS by default). */
	transformIgnorePatterns: ["/node_modules/(?!(@noble/|@scure/))"],
};
