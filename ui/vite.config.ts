import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const viteCacheDir = (
  globalThis as { process?: { env?: Record<string, string | undefined> } }
).process?.env?.AEGISPROXY_VITE_CACHE_DIR;

export default defineConfig({
  cacheDir: viteCacheDir ?? "node_modules/.vite",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
