import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

export default defineConfig({
  base: "./",
  build: {
    commonjsOptions: {
      include: [/node_modules/],
    },
  },
  server: {
    host: "::",
    port: 8081,
    hmr: { overlay: false },
    watch: {
      ignored: [
        "**/node_modules/**",
        "!**/node_modules/@tron-cold-sign/core/**",
        "!**/node_modules/@tron-cold-sign/online-core/**",
      ],
    },
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      buffer: "buffer",
    },
    dedupe: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime"],
  },
  optimizeDeps: {
    exclude: ["@tron-cold-sign/core", "@tron-cold-sign/online-core"],
    include: ["buffer"],
  },
});
