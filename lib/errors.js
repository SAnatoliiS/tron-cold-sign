"use strict";

/**
 * Typed errors with exit code (CLI uses exitCode; same class is safe in browser).
 */
class CliError extends Error {
	/**
	 * @param {string} message
	 * @param {number} [exitCode=1]
	 */
	constructor(message, exitCode = 1) {
		super(message);
		this.name = "CliError";
		this.exitCode = exitCode;
	}
}

module.exports = { CliError };
