"use strict";

const readline = require("readline");
const { CliError } = require("./errors.js");

/** Remove last UTF-8 character from buffer (Backspace in raw mode). */
function utf8PopLastChar(buf) {
	if (buf.length === 0) {
		return buf;
	}
	let i = buf.length - 1;
	while (i > 0 && (buf[i] & 0xc0) === 0x80) {
		i -= 1;
	}
	return buf.subarray(0, i);
}

/**
 * Interactive BIP39 passphrase without echo (TTY).
 * Empty line = no passphrase. Ctrl+C exits with code 130.
 */
function readPassphraseInteractive() {
	return new Promise((resolve, reject) => {
		const prompt =
			"BIP39 passphrase (optional; Enter for none; input hidden): ";

		if (!process.stdin.isTTY) {
			console.error(
				"[i] stdin is not a TTY — passphrase will be visible; use a real terminal for hidden input.",
			);
			const rl = readline.createInterface({
				input: process.stdin,
				output: process.stdout,
			});
			rl.question(prompt, (answer) => {
				rl.close();
				resolve(answer.replace(/\r$/, ""));
			});
			return;
		}

		process.stdout.write(prompt);
		process.stdin.setRawMode(true);
		process.stdin.resume();

		let acc = Buffer.alloc(0);

		const cleanup = () => {
			process.stdin.setRawMode(false);
			process.stdin.removeListener("data", onData);
		};

		function onData(data) {
			const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
			for (let k = 0; k < chunk.length; k++) {
				const b = chunk[k];
				if (b === 0x03) {
					cleanup();
					process.stdout.write("\n");
					reject(new CliError("", 130));
					return;
				}
				if (b === 0x0d || b === 0x0a) {
					cleanup();
					process.stdout.write("\n");
					resolve(acc.toString("utf8"));
					return;
				}
				if (b === 0x7f || b === 0x08) {
					acc = utf8PopLastChar(acc);
					continue;
				}
				acc = Buffer.concat([acc, Buffer.from([b])]);
			}
		}

		process.stdin.on("data", onData);
	});
}

module.exports = { readPassphraseInteractive, utf8PopLastChar };
