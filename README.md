# TronOffline

Offline tools for a **TRON** HD wallet ([BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) / [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) coin type **195**, [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)) and for **signing unsigned transactions** without contacting the network. Intended for cold / air-gapped use.

## Repository layout

- **`src/`** — libraries and CLI implementation.
- **`generate-wallet.secure.js`**, **`sign-transaction.secure.js`** — thin entrypoints at the repo root.
- **`scripts/`** — integrity manifest and TronWeb regression check (dev-only).
- **`test/`** — unit tests ([Jest](https://jestjs.io/)); `babel.config.cjs` is only for the test runner (ESM deps such as `@noble/*` / `@scure/*`), not for shipping code.

## Requirements

**Node.js 20+** recommended.

```bash
npm install
```

## Commands

| Command | Purpose |
|--------|---------|
| `node generate-wallet.secure.js` | Generate or recover wallet; see `--help` for options. |
| `node sign-transaction.secure.js` | Sign an unsigned tx JSON offline; see `--help`. |
| `npm test` | Unit tests. |
| `npm run test:coverage` | `jest --coverage` — line coverage for `src/` (see terminal summary and `coverage/`). |
| `npm run verify` | Compare derived address with TronWeb on a fixed test mnemonic (no live network call required for the check). |
| `npm run test:all` | Unit tests + `verify`. |
| `npm run build` | Bundle wallet CLI to `dist/bundle.js` (optional air-gap artifact). |
| `npm run integrity:write` / `integrity:check` | Maintain / verify `INTEGRITY.sha256` over tracked project files. |

By default the wallet CLI prints **non-secret** fields only. Secrets require **`--print-secrets`** (understand the risk: logs, shell history, screenshots).

## Programmatic use

```javascript
const api = require("./src/index.js");
// e.g. api.deriveWalletFromMnemonic, api.compressedPublicKeyToTronAddress, …
```

## Security (short)

Runs **offline** by design: no RPC calls in the wallet/signing path. Protect the machine, the mnemonic, and any file you pass to `--mnemonic-file`. Review transaction details before confirming signature. Dependencies should be installed from a trusted lockfile; for integrity of copied trees, use the manifest workflow above.

### Unsigned transaction JSON: `raw_data` vs `raw_data_hex`

**`txID` and the signature depend only on `raw_data_hex`** (the tool checks `txID === SHA256(raw_data_hex)` and signs that hash). The human-readable review (amounts, recipients, fee, owner checks) is built from the **`raw_data`** object in the same JSON file. This tool does **not** verify that `raw_data` serializes to the same bytes as `raw_data_hex`.

If a file were tampered with or corrupted, the on-screen summary could disagree with what you actually sign. Treat the summary as a **hint**; the **authoritative** payload is `raw_data_hex`. Prefer unsigned transactions from a **trusted** source; if anything is unclear, decode `raw_data_hex` with an independent tool and compare fields before typing `YES`.

## License

See `package.json` (ISC unless changed).
