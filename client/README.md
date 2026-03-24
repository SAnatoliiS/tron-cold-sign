# tron-cold-sign-client

Vite + React UI. Shared crypto lives in **`packages/core`** (`@tron-cold-sign/core`).

From the **repository root**, use **`npm run dev:client`** (watch core + Vite) or **`npm run build:client`**. If you run **`vite`** or **`vite build`** only inside **`client/`**, **`prebuild`** / **`pretest`** still run **`npm run build:core`** so `@tron-cold-sign/core` is built before bundling or Vitest.
