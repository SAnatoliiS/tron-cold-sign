import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  base: "./",
  build: {
    commonjsOptions: {
      include: [/node_modules/],
    },
  },
  server: {
    host: "::",
    port: 8080,
    hmr: {
      overlay: false,
    },
    /** Workspace `@tron-cold-sign/core` lives under `node_modules` (symlink); watch it so `tsup --watch` rebuilds trigger reload. */
    watch: {
      ignored: [
        "**/node_modules/**",
        "!**/node_modules/@tron-cold-sign/core/**",
      ],
    },
  },
  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      buffer: "buffer",
    },
    dedupe: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime"],
  },
  optimizeDeps: {
    /** Pre-bundle is stale for linked workspace deps; exclude so edits to `packages/core/dist` apply without cache fight. */
    exclude: ["@tron-cold-sign/core"],
    include: [
      "buffer",
      "bip39",
      "bip32",
      "@noble/secp256k1",
      "@noble/hashes/sha2.js",
      "@noble/hashes/sha3.js",
      "@noble/hashes/hmac.js",
      "@scure/base",
    ],
  },
}));
