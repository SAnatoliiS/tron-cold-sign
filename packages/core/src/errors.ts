/**
 * Typed errors with exit code (CLI uses exitCode; same class is safe in browser).
 */
export class CliError extends Error {
  exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}
