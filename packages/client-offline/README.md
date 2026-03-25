# tron-cold-sign-offline-client

Vite + React UI. Shared crypto lives in **`packages/core`** (`@tron-cold-sign/core`).

From the **repository root**, use **`npm run dev:client-offline`** (watch core + Vite) or **`npm run build:client-offline`**. If you run **`vite`** or **`vite build`** only inside **`packages/client-offline/`**, **`prebuild`** / **`pretest`** still run **`npm run build:core`** so `@tron-cold-sign/core` is built before bundling or Vitest.

Coverage (Vitest): **`npm run test:coverage`** here, or **`npm run test:coverage:client-offline`** from the repo root.
