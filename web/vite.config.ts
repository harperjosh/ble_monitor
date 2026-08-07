import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build lands directly inside the Python package, so `pip install
// ble-monitor` ships the dashboard and there is no Node.js at runtime.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "../src/blemon/web",
    emptyOutDir: true,
    target: "es2020",
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8420",
      "/ws": { target: "ws://127.0.0.1:8420", ws: true },
    },
  },
});
