import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backendPort = process.env.PORT || 4000;

export default defineConfig({
  plugins: [react()],
  base: "/dashboard/",
  server: {
    port: 5173,
    proxy: {
      "/incidents": `http://localhost:${backendPort}`,
      "/webhooks": `http://localhost:${backendPort}`
    }
  },
  build: {
    outDir: "../public/dashboard",
    emptyOutDir: true
  }
});
