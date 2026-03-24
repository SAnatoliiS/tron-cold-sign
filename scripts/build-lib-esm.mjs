#!/usr/bin/env node
import esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const entry = path.join(repoRoot, "lib", "index.js");
const outdir = path.join(repoRoot, "dist");
const outfile = path.join(outdir, "tron-lib-esm.mjs");

fs.mkdirSync(outdir, { recursive: true });

await esbuild.build({
  absWorkingDir: repoRoot,
  entryPoints: [entry],
  bundle: true,
  platform: "browser",
  format: "esm",
  outfile,
  logLevel: "info",
});
