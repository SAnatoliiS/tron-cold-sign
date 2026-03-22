"use strict";

/**
 * CLI errors: exit code is attached; only the entrypoint calls process.exit.
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
