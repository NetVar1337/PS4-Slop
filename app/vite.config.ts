import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// `tauri build --debug` (and `tauri dev`) export TAURI_ENV_DEBUG=true. Release
// bundles ship without sourcemaps: the installer would otherwise carry the
// complete TypeScript sources. SOURCEMAP=1 forces them on for local profiling.
const debugBuild = process.env.TAURI_ENV_DEBUG === "true" || process.env.SOURCEMAP === "1";

// Tauri drives this: it starts `npm run dev` and points the webview at
// devUrl. The fixed port matters because tauri.conf.json and the engine's
// CORS allow-list both name it explicitly.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    target: "chrome110",
    sourcemap: debugBuild,
  },
});
