import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icon.svg"],
      manifest: {
        name: "QR Shield",
        short_name: "QR Shield",
        description: "UPI-aware QR code safety scanner",
        theme_color: "#080909",
        background_color: "#080909",
        display: "standalone",
        start_url: "/",
        icons: [
          { src: "icon-192.png", sizes: "192x192", type: "image/png" },
          { src: "icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,png,wasm}"],
        maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        navigateFallbackDenylist: [/^\/api/, /^\/demo/],
      },
    }),
  ],
  server: { host: true, proxy: { "/api": "http://127.0.0.1:8000", "/demo": "http://127.0.0.1:8000" } },
});
