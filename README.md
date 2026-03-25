# tron-cold-sign

Offline tools for a **TRON** HD wallet ([BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) / [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) coin type **195**, [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)) and for **signing unsigned transactions** without contacting the network. Intended for cold / air-gapped use. The long-term UI is a **static offline site** (React/Vite under **`client/`**); shared crypto lives in **`packages/core`** (`@tron-cold-sign/core`).

## Repository layout

Monorepo **`workspaces`**: **`packages/core`**, **`client`**.

- **`packages/core`** (`@tron-cold-sign/core`) — wallet / TRON / signing logic (TypeScript). Built with **`tsup`** to **`dist/`**: `index.js` (CJS for Node), `index.mjs` (ESM for Vite), `index.d.ts` (types). The **`core`** package does not use the root **`npm run build`** (that command is a separate optional **esbuild** bundle of the wallet CLI → `dist/bundle.js`).
- **`cli/`** — Node CLIs (`generate-wallet`, `sign-transaction`, interactive passphrase).
- **`client/`** — Vite + React UI (`tron-cold-sign-client` workspace). Depends on **`@tron-cold-sign/core`** as **`"*"`** (в режиме workspaces npm подставляет локальный `packages/core`; то же можно записать как **`workspace:*`**, если ваш `npm install` принимает этот протокол — npm 7.14+). Production build emits **`client/dist/index.html`** only (single inlined bundle; `public/` is not copied into `dist`).
- **`generate-wallet.secure.js`**, **`sign-transaction.secure.js`** — thin entrypoints at the repo root.
- **`scripts/`** — integrity manifest and TronWeb regression check (dev-only).
- **`test/`** — unit tests ([Jest](https://jestjs.io/)); `babel.config.cjs` is only for the test runner (ESM deps such as `@noble/*` / `@scure/*`), not for shipping code.

### Build tool choice (`core`)

**tsup** (esbuild + `dts`) emits dual **CJS + ESM** from one `src/index.ts` entry, plus **`.d.ts`**, without maintaining a separate browser bundle. The client and Node both resolve the same package. In dev, Vite **does not** pre-bundle `@tron-cold-sign/core` (see `client/vite.config.ts` `optimizeDeps.exclude`) so edits to the workspace package are not stuck behind a stale `node_modules/.vite` cache; other deps are still optimized as usual.

### Client workflow (no manual `build:lib`)

- **`npm run dev:client`** (repo root) runs **`concurrently`**: `tsup --watch` in **`packages/core`** and the Vite dev server in **`client/`**.
- **`npm run build:client`** runs **`vite build`** in the client workspace; the client’s **`prebuild`** runs **`npm run build:core`** so the core package is built before the static bundle. The client uses **`vite-plugin-singlefile`**, so **`client/dist/index.html`** inlines the app JS/CSS (one large HTML). You can open it via **`file://`**; a plain Vite build without that plugin leaves separate **`assets/*.js`** chunks, which **do not load** from `file://` in typical browsers (ES module `src` restrictions).
- **`npm run test:client`** runs Vitest; the client’s **`pretest`** runs **`build:core`** first.
- After **`npm install`**, **`packages/core`** runs **`prepare`** → **`npm run build`**, so `dist/` exists for tools that expect a built `core` (first clone / CI).

### Dev: editing `packages/core` (reload / hot)

While **`npm run dev:client`** is running:

1. Saving **`packages/core/src/**/*.ts`** triggers **`tsup --watch`**, which rebuilds **`packages/core/dist/`** (ESM/CJS).
2. Vite is configured to **watch** the linked package under `node_modules/@tron-cold-sign/core` and to **exclude** it from dependency pre-bundling, so the dev server picks up new `dist` output. Expect a **full reload** (or dependency invalidation), not fine-grained React HMR *inside* the library — that is normal.
3. If the UI still looks stale after a core change, remove the Vite cache **`client/node_modules/.vite`** and restart the dev server (or run `vite` with `--force` once).

### Imports

- React app: `import … from "@tron-cold-sign/core"` (types from the same package).
- Node / Jest / CLI: `require("@tron-cold-sign/core")` (CJS `dist/index.js`).

The app loads a **`buffer`** polyfill before other modules (`client/src/buffer-polyfill.ts`).

## Requirements

**Node.js 20+** recommended.

```bash
npm install
```

Installs the root package and workspaces (hoisted `node_modules` at the repo root).

## Commands

| Command | Purpose |
|--------|---------|
| `node generate-wallet.secure.js` | Generate or recover wallet; see `--help` for options. |
| `node sign-transaction.secure.js` | Sign an unsigned tx JSON offline; see `--help`. |
| `npm run build:core` | Build `packages/core` → `dist/` (CJS + ESM + `.d.ts`). |
| `npm run dev:client` | Watch `core` + Vite dev server for the React UI (`client/`). |
| `npm run build:client` | Production static build → `client/dist/` (runs `build:core` via client `prebuild`). |
| `npm run test:client` | Vitest for `client/` (runs `build:core` via client `pretest`). |
| `npm run test:coverage:client` | Vitest with coverage for `client/src` (builds `core` first); reports under `client/coverage/`. |
| `npm test` | Jest unit tests (`pretest` builds `core` first). |
| `npm run test:coverage` | `jest --coverage` — line coverage for `packages/core` and `cli/` (see terminal summary and `coverage/`). |
| `npm run verify` | Compare derived address with TronWeb on a fixed test mnemonic (no live network call required for the check). |
| `npm run test:all` | Unit tests + `verify`. |
| `npm run build` | Bundle wallet CLI to `dist/bundle.js` (optional air-gap artifact). |
| `npm run integrity:write` / `integrity:check` | Maintain / verify `INTEGRITY.sha256` over tracked project files (includes `client/src` and `packages/core/src`). |

By default the wallet CLI prints **non-secret** fields only. Secrets require **`--print-secrets`** (understand the risk: logs, shell history, screenshots).

## Programmatic use

```javascript
const api = require("@tron-cold-sign/core");
// e.g. api.deriveWalletFromMnemonic, api.compressedPublicKeyToTronAddress, …
```

## Security (short)

Runs **offline** by design: no RPC calls in the wallet/signing path. Protect the machine, the mnemonic, and any file you pass to `--mnemonic-file`. Review transaction details before confirming signature. Dependencies should be installed from a trusted lockfile; for integrity of copied trees, use the manifest workflow above.

### Unsigned transaction JSON: `raw_data` vs `raw_data_hex`

**`txID` and the signature depend only on `raw_data_hex`** (the tool checks `txID === SHA256(raw_data_hex)` and signs that hash). The human-readable review (amounts, recipients, fee, owner checks) is built from the **`raw_data`** object in the same JSON file. This tool does **not** verify that `raw_data` serializes to the same bytes as `raw_data_hex`.

If a file were tampered with or corrupted, the on-screen summary could disagree with what you actually sign. Treat the summary as a **hint**; the **authoritative** payload is `raw_data_hex`. Prefer unsigned transactions from a **trusted** source; if anything is unclear, decode `raw_data_hex` with an independent tool and compare fields before typing `YES`.

## License

See `package.json` (ISC unless changed).
