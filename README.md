# tron-cold-sign

Offline tools for a **TRON** HD wallet ([BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) / [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) coin type **195**, [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)) and for **signing unsigned transactions** without contacting the network. Intended for cold / air-gapped use. The long-term UI is a **static offline site** (React/Vite under **`client/`**); **`lib/`** holds shared crypto logic usable from Node or the browser.

## Repository layout

- **`lib/`** — wallet / TRON / signing logic (no Node-only APIs); Node loads CommonJS `lib/index.js`. The Vite app imports the workspace package **`tron-cold-sign`**, which resolves to a browser ESM bundle in **`dist/tron-lib-esm.mjs`** (run **`npm run build:lib`** once after clone or when `lib/` changes; root `dev:client` / `build:client` / `test:client` run it automatically).
- **`cli/`** — Node CLIs (`generate-wallet`, `sign-transaction`, interactive passphrase).
- **`client/`** — Vite + React UI (`tron-cold-sign-client` workspace). Static build: `client/dist/` (open offline or host as static files).
- **`generate-wallet.secure.js`**, **`sign-transaction.secure.js`** — thin entrypoints at the repo root.
- **`scripts/`** — integrity manifest and TronWeb regression check (dev-only).
- **`test/`** — unit tests ([Jest](https://jestjs.io/)); `babel.config.cjs` is only for the test runner (ESM deps such as `@noble/*` / `@scure/*`), not for shipping code.

### Vite and `tron-cold-sign`

The client depends on the root package **`tron-cold-sign`**: **`client/package.json`** uses **`"tron-cold-sign": "file:.."`** so the workspace always resolves to this repo (portable across npm versions; **`workspace:*`** also works on npm 7+ if you prefer). The root **`package.json`** `exports` map sends **`import`** to **`dist/tron-lib-esm.mjs`** (built from `lib/` by **`npm run build:lib`**) and **`require`** to **`lib/index.js`**, so Jest/CLI keep using CommonJS unchanged. Types: **`types/tron-cold-sign.d.ts`**. The app loads a **`buffer`** polyfill before other modules (`client/src/buffer-polyfill.ts`).

## Requirements

**Node.js 20+** recommended.

```bash
npm install
```

Installs the root package and the **`client`** workspace (hoisted `node_modules` at the repo root).

## Commands

| Command | Purpose |
|--------|---------|
| `node generate-wallet.secure.js` | Generate or recover wallet; see `--help` for options. |
| `node sign-transaction.secure.js` | Sign an unsigned tx JSON offline; see `--help`. |
| `npm run build:lib` | Bundle `lib/` → `dist/tron-lib-esm.mjs` (browser ESM for the client). |
| `npm run dev:client` | Runs `build:lib`, then Vite dev server for the React UI (`client/`). |
| `npm run build:client` | Runs `build:lib`, then production static build → `client/dist/`. |
| `npm run test:client` | Runs `build:lib`, then Vitest for `client/`. |
| `npm test` | Jest unit tests (`lib/`, `cli/`). |
| `npm run test:coverage` | `jest --coverage` — line coverage for `lib/` and `cli/` (see terminal summary and `coverage/`). |
| `npm run verify` | Compare derived address with TronWeb on a fixed test mnemonic (no live network call required for the check). |
| `npm run test:all` | Unit tests + `verify`. |
| `npm run build` | Bundle wallet CLI to `dist/bundle.js` (optional air-gap artifact). |
| `npm run integrity:write` / `integrity:check` | Maintain / verify `INTEGRITY.sha256` over tracked project files (includes `client/src` sources). |

By default the wallet CLI prints **non-secret** fields only. Secrets require **`--print-secrets`** (understand the risk: logs, shell history, screenshots).

## Programmatic use

```javascript
const api = require("./lib/index.js");
// e.g. api.deriveWalletFromMnemonic, api.compressedPublicKeyToTronAddress, …
```

## Security (short)

Runs **offline** by design: no RPC calls in the wallet/signing path. Protect the machine, the mnemonic, and any file you pass to `--mnemonic-file`. Review transaction details before confirming signature. Dependencies should be installed from a trusted lockfile; for integrity of copied trees, use the manifest workflow above.

### Unsigned transaction JSON: `raw_data` vs `raw_data_hex`

**`txID` and the signature depend only on `raw_data_hex`** (the tool checks `txID === SHA256(raw_data_hex)` and signs that hash). The human-readable review (amounts, recipients, fee, owner checks) is built from the **`raw_data`** object in the same JSON file. This tool does **not** verify that `raw_data` serializes to the same bytes as `raw_data_hex`.

If a file were tampered with or corrupted, the on-screen summary could disagree with what you actually sign. Treat the summary as a **hint**; the **authoritative** payload is `raw_data_hex`. Prefer unsigned transactions from a **trusted** source; if anything is unclear, decode `raw_data_hex` with an independent tool and compare fields before typing `YES`.

## License

See `package.json` (ISC unless changed).
